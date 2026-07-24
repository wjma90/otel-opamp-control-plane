package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"log"
	"math"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/open-telemetry/opamp-go/protobufs"
	opamp "github.com/open-telemetry/opamp-go/server"
	"github.com/open-telemetry/opamp-go/server/types"
)

type Config struct {
	ID, Target, Body, Hash string
	Version                int
	// SourceVersion identifies the original PUBLISHED revision whose content is
	// currently effective.  It deliberately differs from Version for rollback
	// journal entries, so consecutive semantic rollbacks walk backwards instead
	// of oscillating between copied rows.
	SourceVersion int
	Active        bool
	UpdatedAt     time.Time
	Selector      AgentSelector
	CreatedBy     string
	Action        string
	// Base marks an ephemeral, read-only Collector configuration assembled from
	// Supervisor metadata. Base configurations never enter PostgreSQL history.
	Base bool `json:",omitempty"`
}
type AgentSelector struct {
	InstanceUIDs []string
	Services     []string
	Attributes   map[string]string
}
type Agent struct {
	UID, Kind, Service, ConnectionStatus, ConfigStatus, ConfigID string
	ConfigHash                                                   string
	PolicyVersions                                               map[string]int
	Version                                                      int
	RemoteConfig                                                 bool
	LastSeen                                                     time.Time
	Attributes                                                   map[string]string
	EffectiveConfig                                              map[string]ReportedConfigFile
	Transport                                                    string
	PollIntervalSeconds                                          int
	NextExpectedAt                                               time.Time
	BaseConfig                                                   BaseConfig
	EffectiveConfigOrigin                                        string
	LastManagedConfigID                                          string
	LastManagedConfigVersion                                     int
	// LiveStatus describes only the freshness of the OpAMP signal. The Control
	// Plane has no authoritative Kubernetes workload watch, so it must not infer
	// that an unreachable UID is an existing offline pod or a deleted pod.
	LiveStatus           string
	InfrastructureStatus string
}

type BaseConfig struct {
	ID        string
	Source    string
	Revision  string
	Immutable bool
	Behavior  string
}
type ReportedConfigFile struct {
	Body        string
	ContentType string
}
type State struct {
	sync.RWMutex
	Configs    map[string][]Config
	Agents     map[string]Agent
	Conns      map[string]types.Connection
	UIDs       map[string][]byte
	PollOffers map[string]string
}

var state = &State{
	Configs:    map[string][]Config{},
	Agents:     map[string]Agent{},
	Conns:      map[string]types.Connection{},
	UIDs:       map[string][]byte{},
	PollOffers: map[string]string{},
}
var database *PostgresStore
var agentUpdates chan agentPersistenceUpdate
var deploymentUpdates chan DeploymentUpdate
var securityPolicyMu sync.RWMutex
var policyLifecycleMu sync.Mutex
var auditLogger = log.New(os.Stdout, "", 0)

type DeploymentUpdate struct {
	Config          Config
	Agent           Agent
	Status          string
	BundleHash      string
	DesiredPresence bool
}

type agentPersistenceUpdate struct {
	Agent            *Agent
	DeleteUID        string
	DeleteAtOrBefore time.Time
}

type policySetEntry struct {
	ID      string          `json:"id"`
	Version int             `json:"version"`
	Policy  json.RawMessage `json:"policy"`
}

type policySetEnvelope struct {
	APIVersion string           `json:"apiVersion"`
	Kind       string           `json:"kind"`
	Revision   string           `json:"revision"`
	Policies   []policySetEntry `json:"policies"`
}

var policyIDPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)

const (
	maxPoliciesPerSet          = 64
	maxPolicySetBytes          = 1 << 20
	maxHTTPMetricPolicies      = 64
	maxMethodPolicies          = 64
	maxMethodCaptures          = 32
	maxMethodMetrics           = 16
	maxMessagingEventPolicies  = 32
	maxMessagingMetricPolicies = 64
	maxExplicitBuckets         = 64
	maxLifetimeMetricNames     = 256
	maxMetricDimensions        = 8
	maxMetricCardinality       = 4096
	collectorBaseIDPrefix      = "collector-base."
	collectorBaseBehavior      = "NOP_ALL_SIGNALS"
	collectorBaseRemoteMarker  = "service: {}\n"
	collectorOriginBase        = "BASE"
	collectorOriginManaged     = "MANAGED"
	collectorBaseConfigVersion = 0
)

func isConfigActive(config Config) bool {
	// Action is empty only in lightweight unit fixtures and pre-migration
	// in-memory values. Persisted lifecycle entries always carry both fields.
	return config.Active || config.Action != "DEACTIVATED"
}

//go:embed web
var webFiles embed.FS

func main() {
	databaseURL := strings.TrimSpace(os.Getenv("DATABASE_URL"))
	if databaseURL == "" {
		log.Fatal("DATABASE_URL is required")
	}
	startupContext, startupCancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer startupCancel()
	var err error
	for startupContext.Err() == nil {
		database, err = newPostgresStore(startupContext, databaseURL)
		if err == nil {
			break
		}
		log.Printf("waiting for PostgreSQL: %v", err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("initialize PostgreSQL: %v", err)
	}
	defer database.close()
	configsFromDatabase, err := database.loadConfigs(startupContext)
	if err != nil {
		log.Fatalf("load persisted configurations: %v", err)
	}
	inventoryCutoff := time.Now().UTC().Add(-agentInventoryTTL)
	prunedAgents, err := database.pruneAgentsSeenBefore(startupContext, inventoryCutoff)
	if err != nil {
		log.Fatalf("prune expired OpAMP agents: %v", err)
	}
	if prunedAgents > 0 {
		log.Printf("pruned %d expired OpAMP inventory entries", prunedAgents)
	}
	agentsFromDatabase, err := database.loadAgents(startupContext)
	if err != nil {
		log.Fatalf("load persisted agents: %v", err)
	}
	// Defensive mirror of the database retention predicate. This also keeps an
	// alternate/mock store from hydrating expired entries into process memory.
	pruneExpiredAgentMap(agentsFromDatabase, inventoryCutoff)
	state.Configs = configsFromDatabase
	state.Agents = agentsFromDatabase
	agentUpdates = make(chan agentPersistenceUpdate, 256)
	deploymentUpdates = make(chan DeploymentUpdate, 512)
	workerContext, stopWorker := context.WithCancel(context.Background())
	defer stopWorker()
	go persistAgentUpdates(workerContext)

	opampAuthentication, err := opampAuthenticationFromEnvironment()
	if err != nil {
		log.Fatalf("configure OpAMP authentication: %v", err)
	}
	authenticator, err = newAuthenticator()
	if err != nil {
		log.Fatalf("configure public network: %v", err)
	}
	if err = initializeLocalIdentity(startupContext, database, authenticator); err != nil {
		log.Fatalf("initialize local identity: %v", err)
	}
	samlFlows = database
	if providerRecords, providerErr := database.authProviders(context.Background()); providerErr != nil {
		log.Printf("load auth providers: %v", providerErr)
	} else if providerErr = authenticator.applyStoredProviders(providerRecords); providerErr != nil {
		log.Printf("activate auth providers: %v", providerErr)
	}
	callbacks := types.Callbacks{OnConnecting: func(r *http.Request) types.ConnectionResponse {
		if !opampAuthentication.authorized(r.Header.Get("Authorization")) {
			return types.ConnectionResponse{HTTPStatusCode: 401}
		}
		hints := agentHints(r)
		return types.ConnectionResponse{Accept: true, ConnectionCallbacks: types.ConnectionCallbacks{
			OnMessage: func(ctx context.Context, conn types.Connection, message *protobufs.AgentToServer) *protobufs.ServerToAgent {
				return onMessage(ctx, conn, message, hints)
			},
			OnConnectionClose: connectionClosed,
		}}
	}}
	srv := opamp.New(nil)
	opampHandler, opampConnContext, err := srv.Attach(opamp.Settings{Callbacks: callbacks})
	if err != nil {
		log.Fatal(err)
	}
	opampMux := http.NewServeMux()
	opampMux.Handle(
		"/v1/opamp",
		opampRequestMiddleware(opampAuthentication, http.HandlerFunc(opampHandler)),
	)
	opampHTTPServer := newOpAMPHTTPServer(opampMux, opampConnContext)
	opampTLS := authenticator.network.OPAMPTLS
	go func() {
		if err := serveOpAMPHTTPServer(opampHTTPServer, opampTLS); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	mux := http.NewServeMux()
	if err := registerEmailAdministration(mux, database, authenticator); err != nil {
		log.Fatalf("initialize email administration: %v", err)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { jsonOut(w, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", readiness)
	mux.HandleFunc("POST /api/auth/login", authLogin)
	mux.HandleFunc("POST /api/auth/logout", authLogout)
	mux.HandleFunc("GET /api/auth/password-recovery/status", passwordRecoveryStatus)
	mux.HandleFunc("POST /api/auth/password/forgot", forgotLocalPassword)
	mux.HandleFunc("POST /api/auth/password/reset", resetLocalPassword)
	mux.HandleFunc("GET /api/auth/public-providers", authPublicProviders)
	mux.HandleFunc("GET /api/auth/oidc/{provider}/start", authOIDCStart)
	mux.HandleFunc("GET /api/auth/oidc/{provider}/callback", authOIDCCallback)
	mux.HandleFunc("GET /api/auth/saml/{provider}/metadata", authSAMLMetadata)
	mux.HandleFunc("GET /api/auth/saml/{provider}/start", authSAMLStart)
	mux.HandleFunc("POST /api/auth/saml/{provider}/acs", authSAMLACS)
	mux.Handle("GET /api/auth/session", requirePermission("agents.view", authSession))
	mux.Handle("GET /api/auth/profile", requirePermission("agents.view", authProfile))
	mux.Handle("PUT /api/auth/profile", requirePermission("agents.view", updateAuthProfile))
	mux.Handle("POST /api/auth/password/change", requirePermission("agents.view", changeLocalPassword))
	mux.Handle("GET /api/auth/users", requirePermission("auth.admin", listLocalUsers))
	mux.Handle("POST /api/auth/users", requirePermission("auth.admin", createLocalUserHandler))
	mux.Handle("GET /api/auth/users/{username}", requirePermission("auth.admin", getLocalUserHandler))
	mux.Handle("PUT /api/auth/users/{username}", requirePermission("auth.admin", updateLocalUserHandler))
	mux.Handle("DELETE /api/auth/users/{username}", requirePermission("auth.admin", deleteLocalUserHandler))
	mux.Handle("POST /api/auth/users/{username}/password-reset", requirePermission("auth.admin", adminPasswordReset))
	mux.Handle("GET /api/auth/roles", requirePermission("auth.admin", authRoles))
	mux.Handle("GET /api/auth/providers", requirePermission("agents.view", authProviders))
	mux.Handle("PUT /api/auth/providers/{provider}", requirePermission("auth.admin", updateAuthProvider))
	mux.Handle("DELETE /api/auth/providers/{provider}", requirePermission("auth.admin", deleteAuthProvider))
	mux.Handle("POST /api/auth/providers/{provider}/preflight", requirePermission("auth.admin", preflightAuthProvider))
	mux.Handle("GET /api/auth/providers/{provider}/role-mappings", requirePermission("auth.admin", authProviderRoleMappings))
	mux.Handle("PUT /api/auth/providers/{provider}/role-mappings", requirePermission("auth.admin", updateAuthProviderRoleMappings))
	mux.Handle("GET /api/agents", requirePermission("agents.view", agents))
	mux.Handle("GET /api/configs", requirePermission("audit.view", configs))
	mux.Handle("GET /api/audit", requirePermission("audit.view", audit))
	mux.Handle("GET /api/deployments", requirePermission("audit.view", deployments))
	mux.Handle("GET /api/collector-base-configs", requirePermission("agents.view", collectorBaseConfigs))
	mux.Handle("GET /api/storage", requirePermission("audit.view", storage))
	mux.Handle("GET /api/system/network", requirePermission("agents.view", systemNetwork))
	mux.Handle("GET /api/policy-metadata", requirePermission("business-events.view", policyMetadata))
	mux.Handle("GET /api/metric-names", requirePermission("business-events.view", metricNames))
	mux.Handle("GET /api/security/denylist", requirePermission("security.view", securityDenylist))
	mux.Handle("POST /api/configs/validate", requirePermission("collectors.edit", collectorValidation))
	mux.HandleFunc("POST /api/configs", saveConfig)
	mux.Handle("PUT /api/security/denylist", requirePermission("security.edit", updateSecurityDenylist))
	mux.HandleFunc("POST /api/configs/{id}/versions/{version}/rollback", rollbackConfig)
	mux.Handle("POST /api/collector-configs/{id}/deactivate", requirePermission("collectors.edit", deactivateCollectorConfig))
	mux.Handle("POST /api/policies/{id}/rollback", requirePermission("business-events.edit", rollbackPolicy))
	mux.Handle("POST /api/policies/{id}/deactivate", requirePermission("business-events.edit", deactivatePolicy))
	staticFiles, err := fs.Sub(webFiles, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.HandleFunc("GET /", staticUIHandler(staticFiles))
	httpSrv := newAdminHTTPServer(webSecurityMiddleware(mux))
	go func() {
		opampScheme := "HTTP"
		if opampTLS.Enabled {
			opampScheme = "HTTPS"
		}
		log.Printf("UI http://localhost:8080 | OpAMP %s :4320/v1/opamp", opampScheme)
		if err := httpSrv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)
	<-stop
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
	_ = opampHTTPServer.Shutdown(ctx)
	_ = srv.Stop(ctx)
}

func newAdminHTTPServer(handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":8080",
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
}

func staticUIHandler(staticFiles fs.FS) http.HandlerFunc {
	staticServer := http.FileServer(http.FS(staticFiles))
	serveIndex := func(w http.ResponseWriter) {
		index, err := fs.ReadFile(staticFiles, "index.html")
		if err != nil {
			http.Error(w, "UI index unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		_, _ = w.Write(index)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			serveIndex(w)
			return
		}
		if !fs.ValidPath(name) {
			http.NotFound(w, r)
			return
		}
		if _, err := fs.Stat(staticFiles, name); err != nil {
			serveIndex(w)
			return
		}
		staticServer.ServeHTTP(w, r)
	}
}

func connectionClosed(conn types.Connection) {
	state.Lock()
	updated := []Agent{}
	for uid, active := range state.Conns {
		if active != conn {
			continue
		}
		agent := state.Agents[uid]
		agent.ConnectionStatus = "DISCONNECTED"
		agent.LastSeen = time.Now().UTC()
		state.Agents[uid] = agent
		delete(state.Conns, uid)
		delete(state.UIDs, uid)
		updated = append(updated, agent)
	}
	state.Unlock()
	for _, agent := range updated {
		queueAgentUpdate(agent)
	}
}

type connectionHints struct {
	service             string
	attributes          map[string]string
	transport           string
	pollIntervalSeconds int
	opampEndpoint       string
	baseConfig          BaseConfig
}

func agentHints(r *http.Request) connectionHints {
	header := r.Header
	attributes := map[string]string{}
	for headerName, attributeName := range map[string]string{
		"X-O11y-Cluster":            "k8s.cluster.name",
		"X-O11y-Collector-Role":     "collector.role",
		"X-O11y-Managed-By":         "managed_by",
		"X-O11y-Collector-Version":  "o11y.collector.version",
		"X-O11y-Supervisor-Version": "o11y.supervisor.version",
	} {
		if value := strings.TrimSpace(header.Get(headerName)); value != "" {
			attributes[attributeName] = value
		}
	}
	transport := strings.TrimSpace(header.Get("X-O11y-Transport"))
	if transport == "" {
		if r.Method == http.MethodPost {
			transport = "http-poll"
		} else {
			transport = "websocket"
		}
	}
	pollIntervalSeconds := 0
	opampEndpoint := strings.TrimSpace(header.Get("X-O11y-OpAMP-Endpoint"))
	if transport == "http-poll" {
		pollIntervalSeconds = 10
		if configured, err := strconv.Atoi(header.Get("X-O11y-Poll-Interval-Seconds")); err == nil && configured >= 2 && configured <= 300 {
			pollIntervalSeconds = configured
		}
		if opampEndpoint == "" && r.Host != "" {
			scheme := "http"
			if r.TLS != nil {
				scheme = "https"
			}
			opampEndpoint = scheme + "://" + r.Host + r.URL.Path
		}
	}
	attributes["o11y.opamp.transport"] = transport
	if pollIntervalSeconds > 0 {
		attributes["o11y.opamp.poll_interval_seconds"] = strconv.Itoa(pollIntervalSeconds)
	}
	baseConfig := baseConfigFromHeaders(header)
	return connectionHints{
		service:             strings.TrimSpace(header.Get("X-Service-Name")),
		attributes:          attributes,
		transport:           transport,
		pollIntervalSeconds: pollIntervalSeconds,
		opampEndpoint:       opampEndpoint,
		baseConfig:          baseConfig,
	}
}

func baseConfigFromHeaders(header http.Header) BaseConfig {
	base := BaseConfig{
		ID:        strings.TrimSpace(header.Get("X-O11y-Base-Config-ID")),
		Source:    strings.TrimSpace(header.Get("X-O11y-Base-Config-Source")),
		Revision:  strings.TrimSpace(header.Get("X-O11y-Base-Config-Revision")),
		Immutable: true,
		Behavior:  collectorBaseBehavior,
	}
	if !validCollectorBaseConfig(base) {
		return BaseConfig{}
	}
	return base
}

func validCollectorBaseConfig(base BaseConfig) bool {
	return strings.HasPrefix(base.ID, collectorBaseIDPrefix) &&
		len(base.ID) <= 128 &&
		base.Source != "" && len(base.Source) <= 256 &&
		base.Revision != "" && len(base.Revision) <= 128
}

func canonicalAttributeKey(key string) string {
	key = strings.TrimSpace(key)
	delimiter := strings.IndexByte(key, '.')
	if delimiter > 0 && strings.HasPrefix(strings.ToLower(key[:delimiter]), "o11y") {
		return "o11y" + key[delimiter:]
	}
	return key
}

func onMessage(_ context.Context, conn types.Connection, m *protobufs.AgentToServer, hints connectionHints) *protobufs.ServerToAgent {
	if err := validateAgentMessageLimits(m); err != nil {
		return opampProtocolError(err.Error())
	}
	if len(m.InstanceUid) != 16 {
		return opampProtocolError("instance_uid must contain exactly 16 bytes")
	}
	uid := hex.EncodeToString(m.InstanceUid)
	state.RLock()
	previous, known := state.Agents[uid]
	state.RUnlock()
	kind, service := "java-extension", "unknown"
	if known {
		kind, service = previous.Kind, previous.Service
	}
	attributesMap := map[string]string{}
	for key, value := range previous.Attributes {
		attributesMap[canonicalAttributeKey(key)] = value
	}
	if m.AgentDescription != nil {
		attributes := append(
			append([]*protobufs.KeyValue{}, m.AgentDescription.IdentifyingAttributes...),
			m.AgentDescription.NonIdentifyingAttributes...,
		)
		for _, a := range attributes {
			key := canonicalAttributeKey(a.Key)
			attributesMap[key] = a.Value.GetStringValue()
			if a.Key == "service.name" {
				service = a.Value.GetStringValue()
			}
			if a.Key == "agent.type" && a.Value.GetStringValue() == "collector-supervisor" {
				kind = "collector"
			}
		}
	}
	for key, value := range hints.attributes {
		attributesMap[key] = value
	}
	if hints.service != "" {
		service = hints.service
	}
	if len(service) > maxReportedAttributeValueBytes || !utf8.ValidString(service) {
		return opampProtocolError("reported service name is invalid or too large")
	}
	if err := validateReportedAttributeMap(attributesMap); err != nil {
		return opampProtocolError(err.Error())
	}
	if m.Capabilities&uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig) != 0 ||
		m.Capabilities&uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsHealth) != 0 {
		kind = "collector"
		if service == "unknown" {
			service = "otel-collector-supervisor"
		}
	}
	if strings.Contains(strings.ToLower(service), "supervisor") || strings.Contains(strings.ToLower(service), "collector") {
		kind = "collector"
	}
	a := previous
	connectionStatus := "CONNECTED"
	if hints.transport == "http-poll" {
		connectionStatus = "ONLINE"
	}
	a.UID, a.Kind, a.Service, a.ConnectionStatus, a.LastSeen = uid, kind, service, connectionStatus, time.Now().UTC()
	a.Attributes = attributesMap
	a.Transport = hints.transport
	a.PollIntervalSeconds = hints.pollIntervalSeconds
	if kind == "collector" {
		// The metadata is supplied by the Supervisor itself. Clearing it when the
		// headers disappear is safer than retaining a stale reset target.
		a.BaseConfig = hints.baseConfig
	}
	if m.Capabilities != 0 {
		a.RemoteConfig = m.Capabilities&uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig) != 0
	}
	if a.ConfigStatus == "" {
		a.ConfigStatus = "NOT_REPORTED"
	}
	if m.RemoteConfigStatus != nil {
		reportedStatus := strings.TrimPrefix(m.RemoteConfigStatus.Status.String(), "RemoteConfigStatuses_")
		if reportedStatus == "UNSET" {
			reportedStatus = "NOT_REPORTED"
		}
		a.ConfigStatus = reportedStatus
	}
	if m.EffectiveConfig != nil && m.EffectiveConfig.ConfigMap != nil {
		a.EffectiveConfig = reportedEffectiveConfig(m.EffectiveConfig.ConfigMap)
	}
	if kind == "collector" {
		hydrateLastManagedCollectorConfig(&a, m.RemoteConfigStatus)
	}
	state.Lock()
	evicted, admitted := ensureAgentInventoryCapacityLocked(
		uid,
		time.Now().UTC(),
		maxKnownOpAMPAgents,
	)
	if !admitted {
		state.Unlock()
		return opampProtocolError("agent inventory limit reached")
	}
	if evicted != nil && !queueAgentDeletion(evicted.UID, evicted.LastSeen) {
		state.Agents[evicted.UID] = *evicted
		state.Unlock()
		return opampProtocolError("agent inventory persistence is busy")
	}
	state.Agents[uid] = a
	if hints.transport == "websocket" {
		state.Conns[uid] = conn
		state.UIDs[uid] = append([]byte(nil), m.InstanceUid...)
	} else {
		delete(state.Conns, uid)
		delete(state.UIDs, uid)
	}
	state.Unlock()
	resp := &protobufs.ServerToAgent{InstanceUid: m.InstanceUid, Capabilities: serverCapabilities()}
	resp.ConnectionSettings = pollingConnectionSettingsForAgent(uid, kind, m.Capabilities, hints)
	// A compressed OpAMP message may omit AgentDescription. Ask for one full-state
	// report before evaluating selectors or offering the reported Collector YAML.
	reportsEffectiveConfig := m.Capabilities&uint64(protobufs.AgentCapabilities_AgentCapabilities_ReportsEffectiveConfig) != 0
	if needsFullStateReport(a, reportsEffectiveConfig) {
		resp.Flags = uint64(protobufs.ServerToAgentFlags_ServerToAgentFlags_ReportFullState)
	}
	if kind == "java-extension" {
		bundle, policies, err := effectiveJavaPolicySet(a)
		if err != nil {
			log.Printf("compose Java policy set for %s: %v", a.UID, err)
			queueAgentUpdate(a)
			return resp
		}
		if err := validatePolicySchemasForAgent(policies, a); err != nil {
			log.Printf("skip incompatible Java policy set for %s: %v", a.UID, err)
			a.ConfigStatus = "FAILED"
			state.Lock()
			state.Agents[a.UID] = a
			state.Unlock()
			queueJavaPolicyDeployments(bundle, policies, a, "FAILED")
			queueAgentUpdate(a)
			return resp
		}
		deploymentAgent := a
		hasLatestConfig := hasLatestRemoteConfig(a, m.RemoteConfigStatus, bundle)
		a.ConfigID = bundle.ID
		a.Version = 0
		deploymentStatus := a.ConfigStatus
		if hasLatestConfig && a.ConfigStatus == "APPLIED" {
			a.ConfigHash = bundle.Hash
			a.PolicyVersions = policyVersionMap(policies)
		} else if !hasLatestConfig {
			resp.RemoteConfig = remote(kind, bundle)
			a.ConfigStatus = "CONFIG_PENDING"
			deploymentStatus = "CONFIG_PENDING"
		}
		state.Lock()
		state.Agents[uid] = a
		state.Unlock()
		deploymentAgent.ConfigStatus = a.ConfigStatus
		queueJavaPolicyDeployments(bundle, policies, deploymentAgent, deploymentStatus)
	} else if c, desiredOrigin, ok := desiredCollectorConfig(a); ok {
		hasLatestConfig := hasLatestRemoteConfig(a, m.RemoteConfigStatus, c)
		desiredApplied := hasLatestConfig && a.ConfigStatus == "APPLIED"
		removalAgent := a
		a.ConfigID = c.ID
		a.Version = c.Version
		deploymentStatus := a.ConfigStatus
		if hasLatestConfig && a.ConfigStatus == "APPLIED" {
			a.ConfigHash = c.Hash
			a.EffectiveConfigOrigin = desiredOrigin
			if desiredOrigin == collectorOriginManaged {
				a.LastManagedConfigID = c.ID
				a.LastManagedConfigVersion = c.Version
			}
		} else if !hasLatestConfig {
			resp.RemoteConfig = remote(kind, c)
			a.ConfigStatus = "CONFIG_PENDING"
			deploymentStatus = "CONFIG_PENDING"
		}
		state.Lock()
		state.Agents[uid] = a
		state.Unlock()
		if desiredOrigin == collectorOriginManaged {
			queueDeploymentUpdate(c, a, deploymentStatus)
		}
		queueCollectorRemovalDeployments(c, removalAgent, deploymentStatus, desiredApplied)
	}
	queueAgentUpdate(a)
	return resp
}

func hydrateLastManagedCollectorConfig(agent *Agent, status *protobufs.RemoteConfigStatus) {
	if agent.LastManagedConfigID != "" {
		return
	}
	hash := agent.ConfigHash
	if status != nil &&
		status.Status == protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED &&
		len(status.LastRemoteConfigHash) > 0 {
		hash = string(status.LastRemoteConfigHash)
	}
	state.RLock()
	defer state.RUnlock()
	var found Config
	for _, versions := range state.Configs {
		for index := len(versions) - 1; index >= 0; index-- {
			candidate := versions[index]
			if candidate.Target != "collector" || !isConfigActive(candidate) ||
				!matches(candidate.Selector, *agent) {
				continue
			}
			identityMatch := agent.ConfigID == candidate.ID && agent.Version == candidate.Version
			hashMatch := hash != "" && candidate.Hash == hash
			if (identityMatch || hashMatch) && candidate.Version > found.Version {
				found = candidate
			}
		}
	}
	if found.ID != "" {
		agent.LastManagedConfigID = found.ID
		agent.LastManagedConfigVersion = found.Version
	}
}

func policyVersionMap(policies []Config) map[string]int {
	versions := make(map[string]int, len(policies))
	for _, policy := range policies {
		versions[policy.ID] = policy.Version
	}
	return versions
}

func needsFullStateReport(agent Agent, reportsEffectiveConfig bool) bool {
	missingJavaDescription := agent.Kind == "java-extension" &&
		strings.TrimSpace(agent.Attributes["agent.type"]) == ""
	missingCollectorConfig := agent.Kind == "collector" && reportsEffectiveConfig &&
		len(agent.EffectiveConfig) == 0
	return missingJavaDescription || missingCollectorConfig
}

func serverCapabilities() uint64 {
	return uint64(
		protobufs.ServerCapabilities_ServerCapabilities_OffersRemoteConfig |
			protobufs.ServerCapabilities_ServerCapabilities_AcceptsEffectiveConfig |
			protobufs.ServerCapabilities_ServerCapabilities_OffersConnectionSettings,
	)
}

func pollingConnectionSettings(
	kind string,
	capabilities uint64,
	hints connectionHints,
) *protobufs.ConnectionSettingsOffers {
	reportsHeartbeat := capabilities&uint64(
		protobufs.AgentCapabilities_AgentCapabilities_ReportsHeartbeat,
	) != 0
	if kind != "collector" ||
		hints.transport != "http-poll" ||
		!reportsHeartbeat ||
		hints.pollIntervalSeconds <= 0 ||
		hints.opampEndpoint == "" {
		return nil
	}

	hash := sha256.Sum256([]byte(fmt.Sprintf(
		"%s\n%d",
		hints.opampEndpoint,
		hints.pollIntervalSeconds,
	)))
	return &protobufs.ConnectionSettingsOffers{
		Hash: hash[:],
		Opamp: &protobufs.OpAMPConnectionSettings{
			DestinationEndpoint:      hints.opampEndpoint,
			HeartbeatIntervalSeconds: uint64(hints.pollIntervalSeconds),
		},
	}
}

func pollingConnectionSettingsForAgent(
	uid string,
	kind string,
	capabilities uint64,
	hints connectionHints,
) *protobufs.ConnectionSettingsOffers {
	offer := pollingConnectionSettings(kind, capabilities, hints)
	if offer == nil {
		return nil
	}

	hash := hex.EncodeToString(offer.Hash)
	state.Lock()
	defer state.Unlock()
	if state.PollOffers[uid] == hash {
		return nil
	}
	state.PollOffers[uid] = hash
	return offer
}

func reportedEffectiveConfig(configMap *protobufs.AgentConfigMap) map[string]ReportedConfigFile {
	reported := make(map[string]ReportedConfigFile, len(configMap.ConfigMap))
	for name, file := range configMap.ConfigMap {
		if file == nil {
			continue
		}
		reported[name] = ReportedConfigFile{
			Body:        string(file.Body),
			ContentType: file.ContentType,
		}
	}
	return reported
}

func hasLatestRemoteConfig(agent Agent, status *protobufs.RemoteConfigStatus, config Config) bool {
	if status != nil {
		return bytes.Equal(status.LastRemoteConfigHash, []byte(config.Hash))
	}
	if config.Target == "java-extension" || config.Base {
		// PolicySet Version is intentionally 0 and shared by every bundle. Only
		// the acknowledged hash proves that this exact effective set is applied.
		// Collector bases also use Version 0 across ConfigMap revisions, so their
		// deterministic hash is the only safe acknowledgement.
		return agent.ConfigHash != "" && agent.ConfigHash == config.Hash
	}
	if agent.ConfigHash != "" {
		return agent.ConfigHash == config.Hash
	}
	return agent.ConfigID == config.ID && agent.Version == config.Version
}

func remote(kind string, c Config) *protobufs.AgentRemoteConfig {
	key := ""
	contentType := "text/yaml"
	if kind == "java-extension" {
		key = "dev.o11y/http-headers.json"
		contentType = "application/json"
	}
	return &protobufs.AgentRemoteConfig{ConfigHash: []byte(c.Hash), Config: &protobufs.AgentConfigMap{ConfigMap: map[string]*protobufs.AgentConfigFile{key: {Body: []byte(c.Body), ContentType: contentType}}}}
}
func push(c Config) {
	if c.Target == "java-extension" {
		pushJavaPolicySets()
		return
	}
	if c.Target == "collector" {
		pushCollectorDesired(c)
		return
	}
	state.RLock()
	defer state.RUnlock()
	for id, a := range state.Agents {
		if a.Kind != c.Target || (a.Kind == "collector" && !a.RemoteConfig) || !matches(c.Selector, a) {
			continue
		}
		conn, ok := state.Conns[id]
		if !ok {
			queueDeploymentUpdate(c, a, "MATCHED")
			continue
		}
		queueDeploymentUpdate(c, a, "CONFIG_PENDING")
		uid := state.UIDs[id]
		go func(id string, conn types.Connection, uid []byte) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := conn.Send(ctx, &protobufs.ServerToAgent{InstanceUid: uid, Capabilities: serverCapabilities(), RemoteConfig: remote(c.Target, c)}); err == nil {
				state.Lock()
				a := state.Agents[id]
				a.ConfigStatus = "CONFIG_PENDING"
				a.ConfigID = c.ID
				a.Version = c.Version
				state.Agents[id] = a
				state.Unlock()
				queueAgentUpdate(a)
			}
		}(id, conn, uid)
	}
}

func pushCollectorDesired(trigger Config) {
	state.RLock()
	agents := make([]Agent, 0, len(state.Agents))
	for _, agent := range state.Agents {
		if agent.Kind != "collector" || !agent.RemoteConfig {
			continue
		}
		previouslyManaged := agent.ConfigID == trigger.ID ||
			agent.LastManagedConfigID == trigger.ID
		affected := (isConfigActive(trigger) && matches(trigger.Selector, agent)) ||
			previouslyManaged
		if affected {
			agents = append(agents, agent)
		}
	}
	state.RUnlock()

	for _, agent := range agents {
		previouslyManaged := agent.ConfigID == trigger.ID ||
			agent.LastManagedConfigID == trigger.ID
		stillSelected := isConfigActive(trigger) && matches(trigger.Selector, agent)
		removingTrigger := previouslyManaged && !stillSelected
		desired, origin, ok := desiredCollectorConfig(agent)
		if !ok {
			// Backward compatibility: a Supervisor that has not declared an
			// immutable base must keep its last known-good configuration.
			if removingTrigger {
				queueDeploymentUpdateWithBundle(trigger, agent, "BASE_UNAVAILABLE", "", false)
			}
			continue
		}
		if origin == collectorOriginManaged {
			queueDeploymentUpdate(desired, agent, "CONFIG_PENDING")
		}
		if removingTrigger {
			queueDeploymentUpdateWithBundle(trigger, agent, "REMOVAL_PENDING", desired.Hash, false)
		}

		state.RLock()
		conn, connected := state.Conns[agent.UID]
		uid := append([]byte(nil), state.UIDs[agent.UID]...)
		state.RUnlock()
		if !connected {
			continue
		}
		go sendCollectorDesired(agent.UID, conn, uid, desired)
	}
}

func sendCollectorDesired(agentUID string, conn types.Connection, uid []byte, desired Config) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.Send(ctx, &protobufs.ServerToAgent{
		InstanceUid:  uid,
		Capabilities: serverCapabilities(),
		RemoteConfig: remote("collector", desired),
	}); err != nil {
		return
	}
	state.Lock()
	agent := state.Agents[agentUID]
	agent.ConfigStatus = "CONFIG_PENDING"
	agent.ConfigID = desired.ID
	agent.Version = desired.Version
	state.Agents[agentUID] = agent
	state.Unlock()
	queueAgentUpdate(agent)
}

// effectiveJavaPolicySet composes every independently managed, active policy
// matching an agent into one deterministic OpAMP file. The Java extension
// swaps this complete set atomically, so publishing one policy never replaces
// another and an empty set explicitly removes all dynamic policies.
func effectiveJavaPolicySet(agent Agent) (Config, []Config, error) {
	state.RLock()
	defer state.RUnlock()
	return effectiveJavaPolicySetLocked(agent)
}

func effectiveJavaPolicySetLocked(agent Agent) (Config, []Config, error) {
	policies := make([]Config, 0)
	for _, versions := range state.Configs {
		if len(versions) == 0 {
			continue
		}
		current := versions[len(versions)-1]
		if current.Target == "java-extension" && isConfigActive(current) && matches(current.Selector, agent) {
			policies = append(policies, current)
		}
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i].ID < policies[j].ID })
	body, _, err := encodePolicySet(policies)
	if err != nil {
		return Config{}, nil, err
	}

	var updatedAt time.Time
	for _, policy := range policies {
		if policy.UpdatedAt.After(updatedAt) {
			updatedAt = policy.UpdatedAt
		}
	}
	bundleHash := sha256.Sum256(body)
	return Config{
		ID:        "java-policy-set",
		Target:    "java-extension",
		Body:      string(body),
		Hash:      hex.EncodeToString(bundleHash[:]),
		Active:    true,
		UpdatedAt: updatedAt,
	}, policies, nil
}

func encodePolicySet(policies []Config) ([]byte, string, error) {
	if len(policies) > maxPoliciesPerSet {
		return nil, "", fmt.Errorf("policy set exceeds its limit of %d policies", maxPoliciesPerSet)
	}
	sorted := append([]Config(nil), policies...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	entries := make([]policySetEntry, 0, len(sorted))
	for _, policy := range sorted {
		compact := &bytes.Buffer{}
		if err := json.Compact(compact, []byte(policy.Body)); err != nil {
			return nil, "", fmt.Errorf("compact policy %s: %w", policy.ID, err)
		}
		entries = append(entries, policySetEntry{
			ID:      policy.ID,
			Version: policy.Version,
			Policy:  append(json.RawMessage(nil), compact.Bytes()...),
		})
	}
	revisionInput, err := json.Marshal(entries)
	if err != nil {
		return nil, "", fmt.Errorf("encode policy set revision: %w", err)
	}
	revisionHash := sha256.Sum256(revisionInput)
	revision := hex.EncodeToString(revisionHash[:])
	body, err := json.Marshal(policySetEnvelope{
		APIVersion: "o11y.dev/v1",
		Kind:       "PolicySet",
		Revision:   revision,
		Policies:   entries,
	})
	if err != nil {
		return nil, "", fmt.Errorf("encode policy set: %w", err)
	}
	if len(body) > maxPolicySetBytes {
		return nil, "", fmt.Errorf("policy set exceeds its limit of %d bytes", maxPolicySetBytes)
	}
	return body, revision, nil
}

func validatePolicySetCapacity(candidate Config) error {
	state.RLock()
	policies := make([]Config, 0, len(state.Configs)+1)
	replaced := false
	for id, versions := range state.Configs {
		if id == candidate.ID {
			replaced = true
			if len(versions) > 0 {
				candidate.Version = versions[len(versions)-1].Version + 1
			}
			if candidate.Active {
				policies = append(policies, candidate)
			}
			continue
		}
		if len(versions) == 0 {
			continue
		}
		current := versions[len(versions)-1]
		if current.Target == "java-extension" && isConfigActive(current) {
			policies = append(policies, current)
		}
	}
	state.RUnlock()
	if !replaced && candidate.Active {
		candidate.Version = 1
		policies = append(policies, candidate)
	}
	if _, _, err := encodePolicySet(policies); err != nil {
		return err
	}
	return validatePolicySetCompatibility(policies)
}

// validatePolicySetCompatibility applies the same global namespaces used by
// the extension after policies are composed. Individual policies can be valid
// in isolation while still colliding on a metric/method/event ID or eventName;
// rejecting that bundle here prevents one bad addition from making the agent
// reject every otherwise healthy policy.
func validatePolicySetCompatibility(policies []Config) error {
	merged := javaPolicy{SchemaVersion: maximumPolicySchema(policies)}
	requestHeaders := map[string]bool{}
	responseHeaders := map[string]bool{}
	for _, config := range policies {
		policy, err := decodeJavaPolicy(config.Body)
		if err != nil {
			return fmt.Errorf("policy %s: %w", config.ID, err)
		}
		merged.MetricPolicies = append(merged.MetricPolicies, policy.MetricPolicies...)
		merged.MethodPolicies = append(merged.MethodPolicies, policy.MethodPolicies...)
		merged.BodyEventPolicies = append(merged.BodyEventPolicies, policy.BodyEventPolicies...)
		merged.EventMetricPolicies = append(merged.EventMetricPolicies, policy.EventMetricPolicies...)
		merged.MessagingEventPolicies = append(merged.MessagingEventPolicies, policy.MessagingEventPolicies...)
		merged.MessagingMetricPolicies = append(merged.MessagingMetricPolicies, policy.MessagingMetricPolicies...)
		mergePolicySetHeaders(&merged.RequestHeaders, requestHeaders, policy.RequestHeaders)
		mergePolicySetHeaders(&merged.ResponseHeaders, responseHeaders, policy.ResponseHeaders)
	}
	if err := validatePolicyResourceLimits(merged); err != nil {
		return fmt.Errorf("incompatible effective policy set: %w", err)
	}
	if err := validateHeaderLists(merged); err != nil {
		return fmt.Errorf("incompatible effective policy set: %w", err)
	}
	if _, err := policyMetricDefinitions("__effective_policy_set__", merged); err != nil {
		return fmt.Errorf("incompatible effective policy set: %w", err)
	}
	return nil
}

func maximumPolicySchema(policies []Config) string {
	maximum := "1.0"
	for _, config := range policies {
		policy, err := decodeJavaPolicy(config.Body)
		if err == nil && policySchemaRank(policy.SchemaVersion) > policySchemaRank(maximum) {
			maximum = policy.SchemaVersion
		}
	}
	return maximum
}

func policySchemaRank(value string) int {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) != 2 {
		return -1
	}
	major, majorErr := strconv.Atoi(parts[0])
	minor, minorErr := strconv.Atoi(parts[1])
	if majorErr != nil || minorErr != nil || major < 0 || minor < 0 {
		return -1
	}
	return major*1000 + minor
}

func advertisedPolicySchema(agent Agent) string {
	for key, value := range agent.Attributes {
		if canonicalAttributeKey(key) == "o11y.policy.schema" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func validatePolicySchemasForAgent(policies []Config, agent Agent) error {
	required := maximumPolicySchema(policies)
	if policySchemaRank(required) <= policySchemaRank("1.3") {
		return nil
	}
	advertised := advertisedPolicySchema(agent)
	if policySchemaRank(advertised) < policySchemaRank(required) {
		if advertised == "" {
			advertised = "<not-reported>"
		}
		return fmt.Errorf(
			"uid=%s service=%s requires o11y.policy.schema >= %s, advertised=%s",
			agent.UID,
			agent.Service,
			required,
			advertised,
		)
	}
	return nil
}

func validatePolicySchemaForKnownAgents(config Config) error {
	policy, err := decodeJavaPolicy(config.Body)
	if err != nil {
		return err
	}
	if policySchemaRank(policy.SchemaVersion) <= policySchemaRank("1.3") {
		return nil
	}
	now := time.Now().UTC()
	state.RLock()
	destinations := make([]Agent, 0)
	for _, agent := range state.Agents {
		if agent.Kind == "java-extension" &&
			matches(config.Selector, agent) &&
			agentIsLiveForCoverage(agent, now) {
			destinations = append(destinations, agent)
		}
	}
	state.RUnlock()
	sort.Slice(destinations, func(i, j int) bool { return destinations[i].UID < destinations[j].UID })
	violations := []string{}
	for _, agent := range destinations {
		if err := validatePolicySchemasForAgent([]Config{config}, agent); err != nil {
			violations = append(violations, err.Error())
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf("policy schema is incompatible with known destinations: %s", strings.Join(violations, "; "))
	}
	return nil
}

func mergePolicySetHeaders(target *[]namedValue, seen map[string]bool, values []namedValue) {
	for _, value := range values {
		name := strings.ToLower(strings.TrimSpace(value.Name))
		direction := normalizedHTTPDirection(value.Direction)
		key := direction + ":" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		*target = append(*target, namedValue{Name: name, Direction: direction})
	}
}

func validateMethodPackagesForKnownAgents(config Config) error {
	policy, err := decodeJavaPolicy(config.Body)
	if err != nil {
		return err
	}
	enabledMethods := make([]methodPolicy, 0, len(policy.MethodPolicies))
	for _, method := range policy.MethodPolicies {
		if method.Enabled {
			enabledMethods = append(enabledMethods, method)
		}
	}
	if len(enabledMethods) == 0 {
		return nil
	}

	now := time.Now().UTC()
	state.RLock()
	destinations := make([]Agent, 0)
	for _, agent := range state.Agents {
		if agent.Kind == "java-extension" &&
			matches(config.Selector, agent) &&
			agentIsLiveForCoverage(agent, now) {
			destinations = append(destinations, agent)
		}
	}
	state.RUnlock()
	// A policy may be created before its first replica exists. The Java
	// extension advertises this immutable startup capability when it connects
	// and performs the same compatibility validation before applying the set.
	if len(destinations) == 0 {
		return nil
	}
	sort.Slice(destinations, func(i, j int) bool { return destinations[i].UID < destinations[j].UID })
	violations := []string{}
	for _, agent := range destinations {
		allowed := methodPackagesForAgent(agent)
		for _, method := range enabledMethods {
			if methodPackageAllowed(method.PackagePrefix, allowed) {
				continue
			}
			violations = append(violations, fmt.Sprintf(
				"uid=%s service=%s method=%s packagePrefix=%s advertised=%s",
				agent.UID,
				agent.Service,
				method.ID,
				method.PackagePrefix,
				strings.Join(allowed, ","),
			))
		}
	}
	if len(violations) > 0 {
		return fmt.Errorf(
			"method policy is incompatible with known destinations via o11y.method.packages: %s",
			strings.Join(violations, "; "),
		)
	}
	return nil
}

func methodPackagesForAgent(agent Agent) []string {
	configured := ""
	for key, value := range agent.Attributes {
		if canonicalAttributeKey(key) == "o11y.method.packages" {
			configured = value
			break
		}
	}
	seen := map[string]bool{}
	packages := []string{}
	for _, value := range strings.Split(configured, ",") {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] || !validJavaQualifiedName(value) {
			continue
		}
		seen[value] = true
		packages = append(packages, value)
	}
	sort.Strings(packages)
	return packages
}

func methodPackageAllowed(packagePrefix string, allowed []string) bool {
	for _, candidate := range allowed {
		if packagePrefix == candidate || strings.HasPrefix(packagePrefix, candidate+".") {
			return true
		}
	}
	return false
}

func pushJavaPolicySets() {
	state.RLock()
	agents := make([]Agent, 0, len(state.Agents))
	for _, agent := range state.Agents {
		if agent.Kind == "java-extension" {
			agents = append(agents, agent)
		}
	}
	state.RUnlock()
	for _, agent := range agents {
		pushJavaPolicySet(agent)
	}
}

func pushJavaPolicySet(agent Agent) {
	bundle, policies, err := effectiveJavaPolicySet(agent)
	if err != nil {
		log.Printf("compose Java policy set for %s: %v", agent.UID, err)
		return
	}
	if err := validatePolicySchemasForAgent(policies, agent); err != nil {
		log.Printf("skip incompatible Java policy set for %s: %v", agent.UID, err)
		queueJavaPolicyDeployments(bundle, policies, agent, "FAILED")
		return
	}
	if hasLatestRemoteConfig(agent, nil, bundle) && agent.ConfigStatus == "APPLIED" {
		queueJavaPolicyDeployments(bundle, policies, agent, "APPLIED")
		return
	}
	queueJavaPolicyDeployments(bundle, policies, agent, "CONFIG_PENDING")
	state.Lock()
	current := state.Agents[agent.UID]
	current.ConfigStatus = "CONFIG_PENDING"
	current.ConfigID = bundle.ID
	current.Version = 0
	state.Agents[agent.UID] = current
	state.Unlock()
	queueAgentUpdate(current)

	state.RLock()
	conn, connected := state.Conns[agent.UID]
	uid := append([]byte(nil), state.UIDs[agent.UID]...)
	state.RUnlock()
	if !connected {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := conn.Send(ctx, &protobufs.ServerToAgent{
			InstanceUid:  uid,
			Capabilities: serverCapabilities(),
			RemoteConfig: remote("java-extension", bundle),
		}); err != nil {
			return
		}
	}()
}

func queueJavaPolicyDeployments(bundle Config, policies []Config, agent Agent, status string) {
	desired := make(map[string]bool, len(policies))
	for _, policy := range policies {
		desired[policy.ID] = true
		queueDeploymentUpdateWithBundle(policy, agent, status, bundle.Hash, true)
	}

	// Record removals only for policies the agent previously acknowledged. This
	// avoids inventing REMOVED deployments when a new replica joins after an old
	// policy was already deactivated.
	state.RLock()
	removals := make([]Config, 0)
	for id := range agent.PolicyVersions {
		versions := state.Configs[id]
		if desired[id] || len(versions) == 0 {
			continue
		}
		latest := versions[len(versions)-1]
		if latest.Target != "java-extension" {
			continue
		}
		removals = append(removals, latest)
	}
	state.RUnlock()
	removalStatus := "REMOVAL_PENDING"
	if status == "APPLIED" {
		removalStatus = "REMOVED"
	} else if status != "CONFIG_PENDING" {
		removalStatus = status
	}
	for _, policy := range removals {
		queueDeploymentUpdateWithBundle(policy, agent, removalStatus, bundle.Hash, false)
	}
}

func latestForAgent(agent Agent) (Config, bool) {
	state.RLock()
	defer state.RUnlock()
	var out Config
	for _, vs := range state.Configs {
		if len(vs) > 0 {
			c := vs[len(vs)-1]
			if isConfigActive(c) && c.Target == agent.Kind && (agent.Kind != "collector" || agent.RemoteConfig) && matches(c.Selector, agent) && c.UpdatedAt.After(out.UpdatedAt) {
				out = c
			}
		}
	}
	return out, out.ID != ""
}

func validateCollectorSelectorDoesNotOverlap(candidate Config) error {
	state.RLock()
	defer state.RUnlock()
	for id, versions := range state.Configs {
		if id == candidate.ID || len(versions) == 0 {
			continue
		}
		current := versions[len(versions)-1]
		if current.Target != "collector" || !isConfigActive(current) {
			continue
		}
		if collectorSelectorsMayOverlap(candidate.Selector, current.Selector) {
			return fmt.Errorf(
				"collector selector potentially overlaps active configuration %q; update the same id or make service, instance or attributes mutually exclusive",
				current.ID,
			)
		}
	}
	return nil
}

func collectorSelectorsMayOverlap(left, right AgentSelector) bool {
	if !stringSetsMayOverlap(left.InstanceUIDs, right.InstanceUIDs) ||
		!stringSetsMayOverlap(left.Services, right.Services) {
		return false
	}
	for key, leftValue := range left.Attributes {
		if rightValue, ok := right.Attributes[key]; ok && rightValue != leftValue {
			return false
		}
	}
	return true
}

func stringSetsMayOverlap(left, right []string) bool {
	if len(left) == 0 || len(right) == 0 {
		return true
	}
	values := make(map[string]struct{}, len(left))
	for _, value := range left {
		values[value] = struct{}{}
	}
	for _, value := range right {
		if _, ok := values[value]; ok {
			return true
		}
	}
	return false
}

func desiredCollectorConfig(agent Agent) (Config, string, bool) {
	if agent.Kind != "collector" || !agent.RemoteConfig {
		return Config{}, "", false
	}
	if managed, ok := latestForAgent(agent); ok {
		return managed, collectorOriginManaged, true
	}
	if !validCollectorBaseConfig(agent.BaseConfig) {
		return Config{}, "", false
	}
	return collectorBaseRemoteConfig(agent.BaseConfig), collectorOriginBase, true
}

func collectorBaseRemoteConfig(base BaseConfig) Config {
	hashInput := base.ID + "\n" + base.Revision + "\n" + collectorBaseRemoteMarker
	hash := sha256.Sum256([]byte(hashInput))
	return Config{
		ID:      base.ID,
		Target:  "collector",
		Body:    collectorBaseRemoteMarker,
		Hash:    hex.EncodeToString(hash[:]),
		Version: collectorBaseConfigVersion,
		Active:  true,
		Action:  "BASE",
		Base:    true,
	}
}

func queueCollectorRemovalDeployments(
	desired Config,
	agent Agent,
	desiredStatus string,
	desiredApplied bool,
) {
	state.RLock()
	removals := make([]Config, 0)
	for _, versions := range state.Configs {
		if len(versions) == 0 {
			continue
		}
		latest := versions[len(versions)-1]
		previouslyManaged := latest.ID == agent.LastManagedConfigID ||
			latest.ID == agent.ConfigID
		stillSelected := isConfigActive(latest) && matches(latest.Selector, agent) &&
			desired.ID == latest.ID
		if latest.Target == "collector" && previouslyManaged && !stillSelected {
			removals = append(removals, latest)
		}
	}
	state.RUnlock()
	status := "REMOVAL_PENDING"
	if desiredApplied {
		status = "REMOVED"
	} else if desiredStatus == "FAILED" {
		status = "FAILED"
	}
	for _, removal := range removals {
		queueDeploymentUpdateWithBundle(removal, agent, status, desired.Hash, false)
	}
}

type collectorBaseConfigView struct {
	BaseConfig
	Agents       []string
	Services     []string
	CurrentUsers int
	PendingUsers int
	FailedUsers  int
}

func collectorBaseConfigs(w http.ResponseWriter, _ *http.Request) {
	byID := map[string]*collectorBaseConfigView{}
	state.RLock()
	for _, agent := range state.Agents {
		if agent.Kind != "collector" || !validCollectorBaseConfig(agent.BaseConfig) {
			continue
		}
		key := agent.BaseConfig.ID + "\x00" + agent.BaseConfig.Revision
		view := byID[key]
		if view == nil {
			view = &collectorBaseConfigView{BaseConfig: agent.BaseConfig}
			byID[key] = view
		}
		view.Agents = append(view.Agents, agent.UID)
		view.Services = append(view.Services, agent.Service)
		if agent.ConfigID == agent.BaseConfig.ID {
			switch agent.ConfigStatus {
			case "APPLIED":
				if agent.EffectiveConfigOrigin == collectorOriginBase {
					view.CurrentUsers++
				} else {
					view.PendingUsers++
				}
			case "FAILED":
				view.FailedUsers++
			default:
				view.PendingUsers++
			}
		}
	}
	state.RUnlock()
	result := make([]collectorBaseConfigView, 0, len(byID))
	for _, view := range byID {
		sort.Strings(view.Agents)
		sort.Strings(view.Services)
		view.Services = uniqueSortedStrings(view.Services)
		result = append(result, *view)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].ID == result[j].ID {
			return result[i].Revision < result[j].Revision
		}
		return result[i].ID < result[j].ID
	})
	jsonOut(w, result)
}

func uniqueSortedStrings(values []string) []string {
	if len(values) < 2 {
		return values
	}
	result := values[:1]
	for _, value := range values[1:] {
		if value != result[len(result)-1] {
			result = append(result, value)
		}
	}
	return result
}
func agents(w http.ResponseWriter, r *http.Request) {
	state.RLock()
	x := make([]Agent, 0, len(state.Agents))
	now := time.Now().UTC()
	for uid, a := range state.Agents {
		_, websocketConnected := state.Conns[uid]
		a.ConnectionStatus, a.NextExpectedAt = observedConnectionStatus(
			a,
			websocketConnected,
			now,
		)
		a.LiveStatus = agentSignalStatus(a.ConnectionStatus)
		a.InfrastructureStatus = "UNKNOWN"
		x = append(x, a)
	}
	state.RUnlock()
	sort.Slice(x, func(i, j int) bool { return x[i].LastSeen.After(x[j].LastSeen) })
	jsonOut(w, x)
}

func observedConnectionStatus(
	agent Agent,
	websocketConnected bool,
	now time.Time,
) (string, time.Time) {
	if agent.Transport != "http-poll" && !websocketConnected {
		return "DISCONNECTED", time.Time{}
	}
	return liveStatus(agent, now)
}

func agentSignalStatus(connectionStatus string) string {
	switch connectionStatus {
	case "CONNECTED", "ONLINE":
		return "CONNECTED"
	case "DEGRADED":
		return "STALE"
	case "OFFLINE", "DISCONNECTED":
		return "UNREACHABLE"
	default:
		return "UNKNOWN"
	}
}

func liveStatus(agent Agent, now time.Time) (string, time.Time) {
	if agent.Transport != "http-poll" {
		return agent.ConnectionStatus, time.Time{}
	}
	pollInterval := time.Duration(agent.PollIntervalSeconds) * time.Second
	if pollInterval <= 0 {
		pollInterval = 10 * time.Second
	}
	nextExpected := agent.LastSeen.Add(pollInterval)
	age := now.Sub(agent.LastSeen)
	switch {
	case age <= 3*pollInterval:
		return "ONLINE", nextExpected
	case age <= 6*pollInterval:
		return "DEGRADED", nextExpected
	default:
		return "OFFLINE", nextExpected
	}
}

// ensureAgentInventoryCapacityLocked admits known agents without side effects.
// For a new UID at capacity, it evicts only the oldest agent that is provably
// offline. LastSeen ties are resolved by UID so every replica makes the same
// choice from the same inventory snapshot. The caller must hold state.Lock.
func ensureAgentInventoryCapacityLocked(
	uid string,
	now time.Time,
	limit int,
) (*Agent, bool) {
	if _, exists := state.Agents[uid]; exists {
		return nil, true
	}
	if limit <= 0 || len(state.Agents) < limit {
		return nil, true
	}

	var candidate Agent
	found := false
	for candidateUID, agent := range state.Agents {
		if _, connected := state.Conns[candidateUID]; connected {
			continue
		}
		status := agent.ConnectionStatus
		if agent.Transport == "http-poll" {
			status, _ = liveStatus(agent, now)
		}
		if status != "OFFLINE" && status != "DISCONNECTED" {
			continue
		}
		if !found || agent.LastSeen.Before(candidate.LastSeen) ||
			(agent.LastSeen.Equal(candidate.LastSeen) && candidateUID < candidate.UID) {
			candidate = agent
			candidate.UID = candidateUID
			found = true
		}
	}
	if !found {
		return nil, false
	}
	delete(state.Agents, candidate.UID)
	delete(state.Conns, candidate.UID)
	delete(state.UIDs, candidate.UID)
	delete(state.PollOffers, candidate.UID)
	return &candidate, true
}

func pruneExpiredAgentMap(agents map[string]Agent, cutoff time.Time) []string {
	removed := make([]string, 0)
	for uid, agent := range agents {
		if agent.LastSeen.Before(cutoff) {
			delete(agents, uid)
			removed = append(removed, uid)
		}
	}
	sort.Strings(removed)
	return removed
}

func configs(w http.ResponseWriter, r *http.Request) {
	state.RLock()
	defer state.RUnlock()
	jsonOut(w, state.Configs)
}

func securityDenylist(w http.ResponseWriter, r *http.Request) {
	entries, err := database.securityDenylist(r.Context())
	if err != nil {
		log.Printf("load security denylist: %v", err)
		http.Error(w, "security denylist unavailable", http.StatusServiceUnavailable)
		return
	}
	jsonOut(w, entries)
}

func updateSecurityDenylist(w http.ResponseWriter, r *http.Request) {
	if !authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var entries []DenylistEntry
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&entries); err != nil {
		http.Error(w, "invalid security denylist", http.StatusUnprocessableEntity)
		return
	}
	normalized, err := normalizeSecurityDenylist(entries)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	securityPolicyMu.Lock()
	defer securityPolicyMu.Unlock()
	if err := validateActivePoliciesAgainstDenylist(normalized); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	saved, err := database.replaceSecurityDenylist(r.Context(), normalized, requestActor(r))
	if err != nil {
		log.Printf("persist security denylist: %v", err)
		http.Error(w, "security denylist could not be persisted", http.StatusInternalServerError)
		return
	}
	emitAuditLog("security.denylist.updated", requestActor(r), map[string]any{
		"security.entry.count": len(saved),
	})
	jsonOut(w, saved)
}

func saveConfig(w http.ResponseWriter, r *http.Request) {
	if !authorized(r) {
		http.Error(w, "unauthorized", 401)
		return
	}
	var c Config
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&c) != nil || c.ID == "" || (c.Target != "collector" && c.Target != "java-extension") || c.Body == "" {
		http.Error(w, "invalid config", 422)
		return
	}
	identity, ok := authenticatedIdentity(r)
	requiredPermission := "business-events.edit"
	if c.Target == "collector" {
		requiredPermission = "collectors.edit"
	}
	if !ok || !hasPermission(identity, requiredPermission) {
		http.Error(w, "permission "+requiredPermission+" required", http.StatusForbidden)
		return
	}
	if err := validateSelector(c.Selector); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	if c.Target == "collector" && strings.HasPrefix(c.ID, collectorBaseIDPrefix) {
		http.Error(w, "collector base configuration ids are reserved and read-only", http.StatusUnprocessableEntity)
		return
	}
	if c.Target == "java-extension" {
		policyLifecycleMu.Lock()
		defer policyLifecycleMu.Unlock()
		c.Active = true
		securityPolicyMu.RLock()
		defer securityPolicyMu.RUnlock()
		if err := validateJavaPolicy(c.ID, c.Body); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		denylist, err := database.securityDenylist(r.Context())
		if err != nil {
			http.Error(w, "security denylist unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := validateJavaPolicyAgainstDenylist(c.Body, denylist); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		if err := validatePolicySetCapacity(c); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		if err := validateMethodPackagesForKnownAgents(c); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		if err := validatePolicySchemaForKnownAgents(c); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	} else {
		if err := validateCollectorSelectorDoesNotOverlap(c); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		if !validateCollectorBeforeSave(w, r.Context(), c.Body) {
			return
		}
	}
	h := sha256.Sum256([]byte(c.Body))
	c.Hash = hex.EncodeToString(h[:])
	actor := requestActor(r)
	saved, err := database.saveConfig(r.Context(), c, actor, "PUBLISHED", map[string]any{
		"target":   c.Target,
		"selector": c.Selector,
	})
	if err != nil {
		log.Printf("persist configuration: %v", err)
		http.Error(w, "configuration could not be persisted", http.StatusInternalServerError)
		return
	}
	state.Lock()
	state.Configs[saved.ID] = append(state.Configs[saved.ID], saved)
	state.Unlock()
	queueMatchingDeployments(saved, "MATCHED")
	push(saved)
	emitAuditLog("configuration.published", actor, map[string]any{
		"config.id": saved.ID, "config.version": saved.Version, "config.target": saved.Target,
		"config.selector": saved.Selector,
	})
	w.WriteHeader(201)
	jsonOut(w, saved)
}

func rollbackConfig(w http.ResponseWriter, r *http.Request) {
	if !authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	configID := strings.TrimSpace(r.PathValue("id"))
	version, err := strconv.Atoi(r.PathValue("version"))
	if configID == "" || version <= 0 || err != nil {
		http.Error(w, "invalid configuration version", http.StatusUnprocessableEntity)
		return
	}
	source, err := database.configVersion(r.Context(), configID, version)
	if err != nil {
		http.Error(w, "configuration version not found", http.StatusNotFound)
		return
	}
	if err := validateVersionedRollbackTarget(source); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	identity, ok := authenticatedIdentity(r)
	requiredPermission := "collectors.edit"
	if !ok || !hasPermission(identity, requiredPermission) {
		http.Error(w, "permission "+requiredPermission+" required", http.StatusForbidden)
		return
	}
	if !validateCollectorBeforeSave(w, r.Context(), source.Body) {
		return
	}
	saved, err := database.saveConfig(
		r.Context(),
		source,
		requestActor(r),
		"ROLLBACK",
		map[string]any{"sourceVersion": version},
	)
	if err != nil {
		log.Printf("persist rollback: %v", err)
		http.Error(w, "rollback could not be persisted", http.StatusInternalServerError)
		return
	}
	state.Lock()
	state.Configs[saved.ID] = append(state.Configs[saved.ID], saved)
	state.Unlock()
	queueMatchingDeployments(saved, "MATCHED")
	push(saved)
	emitAuditLog("configuration.rollback", requestActor(r), map[string]any{
		"config.id": saved.ID, "config.version": saved.Version,
		"config.source.version": version, "config.target": saved.Target,
	})
	w.WriteHeader(http.StatusCreated)
	jsonOut(w, saved)
}

func validateVersionedRollbackTarget(source Config) error {
	if source.Target != "collector" {
		return fmt.Errorf(
			"versioned rollback is only available for Collector configurations; use POST /api/policies/{id}/rollback for Java policies",
		)
	}
	if !isConfigActive(source) {
		return fmt.Errorf("a deactivated Collector journal entry cannot be restored; select a published configuration version")
	}
	return nil
}

func deactivateCollectorConfig(w http.ResponseWriter, r *http.Request) {
	configID := strings.TrimSpace(r.PathValue("id"))
	if configID == "" || strings.HasPrefix(configID, collectorBaseIDPrefix) {
		http.Error(w, "invalid or reserved Collector configuration id", http.StatusUnprocessableEntity)
		return
	}
	policyLifecycleMu.Lock()
	defer policyLifecycleMu.Unlock()
	current, err := database.latestConfig(r.Context(), configID)
	if err != nil {
		http.Error(w, "Collector configuration not found", http.StatusNotFound)
		return
	}
	if current.Target != "collector" {
		http.Error(w, "configuration is not a Collector configuration", http.StatusUnprocessableEntity)
		return
	}
	if !isConfigActive(current) {
		http.Error(w, "Collector configuration is already inactive", http.StatusConflict)
		return
	}

	transition := current
	transition.Active = false
	actor := requestActor(r)
	saved, err := database.saveConfigExpected(
		r.Context(),
		transition,
		actor,
		"DEACTIVATED",
		map[string]any{
			"previousVersion":       current.Version,
			"previousSourceVersion": current.SourceVersion,
			"reason":                "explicit-deactivation",
			"fallback":              "supervisor-configmap-base",
		},
		current.Version,
	)
	if err != nil {
		if errors.Is(err, errConcurrentConfigUpdate) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		log.Printf("persist Collector deactivation for %s: %v", configID, err)
		http.Error(w, "Collector configuration deactivation could not be persisted", http.StatusInternalServerError)
		return
	}
	state.Lock()
	state.Configs[saved.ID] = append(state.Configs[saved.ID], saved)
	state.Unlock()
	push(saved)
	emitAuditLog("collector.configuration.deactivated", actor, map[string]any{
		"config.id":             saved.ID,
		"config.version":        saved.Version,
		"config.source.version": saved.SourceVersion,
		"config.active":         false,
		"config.target":         saved.Target,
	})
	w.WriteHeader(http.StatusCreated)
	jsonOut(w, saved)
}

// rollbackPolicy performs a semantic rollback of the currently effective Java
// policy. It walks the original PUBLISHED lineage via SourceVersion. When the
// first published revision is active there is nothing older to restore, so the
// policy is deactivated and removed from every matching extension bundle.
func rollbackPolicy(w http.ResponseWriter, r *http.Request) {
	configID := strings.TrimSpace(r.PathValue("id"))
	if configID == "" {
		http.Error(w, "invalid policy id", http.StatusUnprocessableEntity)
		return
	}
	policyLifecycleMu.Lock()
	defer policyLifecycleMu.Unlock()
	current, predecessor, err := database.policyRollbackCandidate(r.Context(), configID)
	if err != nil {
		switch {
		case errors.Is(err, errPolicyInactive):
			http.Error(w, err.Error(), http.StatusConflict)
		case errors.Is(err, pgx.ErrNoRows):
			http.Error(w, "policy not found", http.StatusNotFound)
		default:
			log.Printf("load semantic rollback for %s: %v", configID, err)
			http.Error(w, "policy unavailable", http.StatusNotFound)
		}
		return
	}

	actor := requestActor(r)
	action := "ROLLBACK"
	transition := current
	details := map[string]any{
		"previousVersion":       current.Version,
		"previousSourceVersion": current.SourceVersion,
	}
	if predecessor == nil {
		action = "DEACTIVATED"
		transition.Active = false
		details["reason"] = "rollback-before-first-version"
	} else {
		transition = *predecessor
		transition.Active = true
		transition.SourceVersion = predecessor.Version
		details["sourceVersion"] = predecessor.Version
		if err := validatePolicyTransition(r.Context(), transition); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}

	saved, err := database.saveConfigExpected(
		r.Context(),
		transition,
		actor,
		action,
		details,
		current.Version,
	)
	if err != nil {
		if errors.Is(err, errConcurrentConfigUpdate) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		log.Printf("persist semantic rollback for %s: %v", configID, err)
		http.Error(w, "policy rollback could not be persisted", http.StatusInternalServerError)
		return
	}
	publishPolicyTransition(saved, actor)
	w.WriteHeader(http.StatusCreated)
	jsonOut(w, saved)
}

func deactivatePolicy(w http.ResponseWriter, r *http.Request) {
	configID := strings.TrimSpace(r.PathValue("id"))
	if configID == "" {
		http.Error(w, "invalid policy id", http.StatusUnprocessableEntity)
		return
	}
	policyLifecycleMu.Lock()
	defer policyLifecycleMu.Unlock()
	current, err := database.latestConfig(r.Context(), configID)
	if err != nil {
		http.Error(w, "policy not found", http.StatusNotFound)
		return
	}
	if current.Target != "java-extension" {
		http.Error(w, "configuration is not a Java policy", http.StatusUnprocessableEntity)
		return
	}
	if !current.Active {
		http.Error(w, errPolicyInactive.Error(), http.StatusConflict)
		return
	}
	transition := current
	transition.Active = false
	actor := requestActor(r)
	saved, err := database.saveConfigExpected(
		r.Context(),
		transition,
		actor,
		"DEACTIVATED",
		map[string]any{
			"previousVersion":       current.Version,
			"previousSourceVersion": current.SourceVersion,
			"reason":                "explicit-deactivation",
		},
		current.Version,
	)
	if err != nil {
		if errors.Is(err, errConcurrentConfigUpdate) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		log.Printf("persist policy deactivation for %s: %v", configID, err)
		http.Error(w, "policy deactivation could not be persisted", http.StatusInternalServerError)
		return
	}
	publishPolicyTransition(saved, actor)
	w.WriteHeader(http.StatusCreated)
	jsonOut(w, saved)
}

func validatePolicyTransition(ctx context.Context, policy Config) error {
	securityPolicyMu.RLock()
	defer securityPolicyMu.RUnlock()
	if err := validateJavaPolicy(policy.ID, policy.Body); err != nil {
		return err
	}
	denylist, err := database.securityDenylist(ctx)
	if err != nil {
		return fmt.Errorf("security denylist unavailable")
	}
	if err := validateJavaPolicyAgainstDenylist(policy.Body, denylist); err != nil {
		return err
	}
	if err := validatePolicySetCapacity(policy); err != nil {
		return err
	}
	if err := validateMethodPackagesForKnownAgents(policy); err != nil {
		return err
	}
	return validatePolicySchemaForKnownAgents(policy)
}

func publishPolicyTransition(saved Config, actor string) {
	state.Lock()
	state.Configs[saved.ID] = append(state.Configs[saved.ID], saved)
	state.Unlock()
	pushJavaPolicySets()
	eventName := "policy.rollback"
	if !saved.Active {
		eventName = "policy.deactivated"
	}
	emitAuditLog(eventName, actor, map[string]any{
		"config.id":             saved.ID,
		"config.version":        saved.Version,
		"config.source.version": saved.SourceVersion,
		"config.active":         saved.Active,
		"config.target":         saved.Target,
	})
}

func authorized(r *http.Request) bool {
	_, ok := authenticatedIdentity(r)
	return ok
}

func requestActor(r *http.Request) string {
	if authenticator != nil {
		if identity, ok := authenticatedIdentity(r); ok {
			return identity.Username
		}
	}
	actor := strings.TrimSpace(r.Header.Get("X-Actor"))
	if actor == "" {
		return "local-admin"
	}
	if len(actor) > 80 {
		return actor[:80]
	}
	return actor
}

func readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := database.ping(ctx); err != nil {
		http.Error(w, "PostgreSQL unavailable", http.StatusServiceUnavailable)
		return
	}
	jsonOut(w, map[string]string{"status": "ready", "database": "PostgreSQL"})
}

func storage(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	status := "healthy"
	if err := database.ping(ctx); err != nil {
		status = "unavailable"
	}
	jsonOut(w, map[string]any{
		"driver":            "PostgreSQL",
		"status":            status,
		"versionedPolicies": true,
		"auditTrail":        true,
		"securityDenylist":  true,
	})
}

func audit(w http.ResponseWriter, r *http.Request) {
	rows, err := database.audit(r.Context(), 200)
	if err != nil {
		log.Printf("load audit: %v", err)
		http.Error(w, "audit unavailable", http.StatusServiceUnavailable)
		return
	}
	jsonOut(w, rows)
}

func deployments(w http.ResponseWriter, r *http.Request) {
	records, err := database.deployments(r.Context(), 2000)
	if err != nil {
		log.Printf("load deployments: %v", err)
		http.Error(w, "deployments unavailable", http.StatusServiceUnavailable)
		return
	}
	now := time.Now().UTC()
	state.RLock()
	agents := make(map[string]Agent, len(state.Agents))
	for uid, agent := range state.Agents {
		_, websocketConnected := state.Conns[uid]
		agent.ConnectionStatus, agent.NextExpectedAt = observedConnectionStatus(
			agent,
			websocketConnected,
			now,
		)
		agents[uid] = agent
	}
	configs := make(map[string][]Config, len(state.Configs))
	for id, versions := range state.Configs {
		configs[id] = append([]Config(nil), versions...)
	}
	state.RUnlock()
	records = deploymentRecordsWithLiveCoverage(records, agents, configs, now)
	jsonOut(w, records)
}

const (
	coverageInScope         = "IN_SCOPE"
	coverageInScopeDegraded = "IN_SCOPE_DEGRADED"
	coverageHistorical      = "HISTORICAL"
	coverageUnknown         = "UNKNOWN"
)

// deploymentRecordsWithLiveCoverage enriches persisted audit observations
// with the currently observable selector scope. A persisted agent UID is not
// an expected replica count: Kubernetes may have replaced, scaled or deleted
// it. Only agents that are presently connected over OpAMP count towards live
// coverage. DEGRADED agents and historical rows remain visible, but are kept
// out of the rollout denominator.
func deploymentRecordsWithLiveCoverage(
	records []DeploymentRecord,
	agents map[string]Agent,
	configs map[string][]Config,
	now time.Time,
) []DeploymentRecord {
	result := append([]DeploymentRecord(nil), records...)
	known := make(map[string]struct{}, len(result))
	for index := range result {
		record := &result[index]
		known[deploymentRecordKey(record.ConfigID, record.Version, record.AgentUID)] = struct{}{}
		if agent, ok := agents[record.AgentUID]; ok {
			applyDeploymentLiveState(record, agent, now)
		}
		applyDeploymentCoverageState(record, agents, now)
	}

	// Persistence is intentionally asynchronous. Include an in-memory record
	// for every live destination of the latest revision and every known removal
	// target, including UIDs excluded by an active revision whose selector was
	// narrowed. This prevents a publish or removal acknowledgement from briefly
	// disappearing while its durable row waits in the database queue.
	for _, versions := range configs {
		if len(versions) == 0 {
			continue
		}
		config := versions[len(versions)-1]
		for _, agent := range agents {
			if !agentIsLiveForCoverage(agent, now) {
				continue
			}
			desiredPresence := isConfigActive(config) &&
				agentEligibleForConfig(agent, config)
			if !desiredPresence && !knownRemovalTarget(config, agent, records) {
				continue
			}
			key := deploymentRecordKey(config.ID, config.Version, agent.UID)
			if _, ok := known[key]; ok {
				continue
			}
			var record DeploymentRecord
			if desiredPresence {
				record = liveDeploymentRecord(config, agent, now)
			} else {
				record = liveRemovalDeploymentRecord(config, agent, now)
			}
			applyDeploymentLiveState(&record, agent, now)
			applyDeploymentCoverageState(&record, agents, now)
			result = append(result, record)
			known[key] = struct{}{}
		}
	}

	sort.SliceStable(result, func(i, j int) bool {
		if result[i].LastObservedAt.Equal(result[j].LastObservedAt) {
			if result[i].ConfigID == result[j].ConfigID {
				if result[i].Version == result[j].Version {
					return result[i].AgentUID < result[j].AgentUID
				}
				return result[i].Version > result[j].Version
			}
			return result[i].ConfigID < result[j].ConfigID
		}
		return result[i].LastObservedAt.After(result[j].LastObservedAt)
	})
	return result
}

func deploymentRecordKey(configID string, version int, agentUID string) string {
	return configID + "\x00" + strconv.Itoa(version) + "\x00" + agentUID
}

func agentEligibleForConfig(agent Agent, config Config) bool {
	return agent.Kind == config.Target &&
		(agent.Kind != "collector" || agent.RemoteConfig) &&
		matches(config.Selector, agent)
}

func knownRemovalTarget(
	config Config,
	agent Agent,
	records []DeploymentRecord,
) bool {
	if agent.Kind != config.Target {
		return false
	}
	if config.Target == "java-extension" {
		if _, present := agent.PolicyVersions[config.ID]; present {
			return true
		}
	} else if config.Target == "collector" {
		if agent.ConfigID == config.ID || agent.LastManagedConfigID == config.ID {
			return true
		}
	} else {
		return false
	}
	for _, record := range records {
		if record.ConfigID == config.ID && record.AgentUID == agent.UID &&
			record.DesiredPresence {
			return true
		}
	}
	return false
}

func agentIsLiveForCoverage(agent Agent, now time.Time) bool {
	status, _ := liveStatus(agent, now)
	return status == "CONNECTED" || status == "ONLINE"
}

func liveMatchingDestinationExists(
	record DeploymentRecord,
	agents map[string]Agent,
	now time.Time,
) bool {
	for _, candidate := range agents {
		if candidate.Kind != record.Target ||
			(candidate.Kind == "collector" && !candidate.RemoteConfig) ||
			!matches(record.Selector, candidate) ||
			!agentIsLiveForCoverage(candidate, now) {
			continue
		}
		return true
	}
	return false
}

func applyDeploymentCoverageState(
	record *DeploymentRecord,
	agents map[string]Agent,
	now time.Time,
) {
	record.CountsForLiveCoverage = false
	if agent, ok := agents[record.AgentUID]; ok && agent.Kind == record.Target {
		status, _ := liveStatus(agent, now)
		switch status {
		case "CONNECTED", "ONLINE":
			// A removal is directed to an already matched UID. It remains a
			// live target even if a later policy revision narrowed the selector;
			// otherwise the pending/confirmed removal would vanish from coverage.
			// Active deployments still require current selector compatibility.
			if (!record.DesiredPresence &&
				!(record.Active && record.ObservedStatus == "REMOVED")) ||
				((agent.Kind != "collector" || agent.RemoteConfig) &&
					matches(record.Selector, agent)) {
				record.CoverageState = coverageInScope
				record.CountsForLiveCoverage = true
				return
			}
		case "DEGRADED":
			if (!record.DesiredPresence &&
				!(record.Active && record.ObservedStatus == "REMOVED")) ||
				((agent.Kind != "collector" || agent.RemoteConfig) &&
					matches(record.Selector, agent)) {
				record.CoverageState = coverageInScopeDegraded
				return
			}
		}
	}
	if !record.DesiredPresence && record.Active && record.ObservedStatus == "REMOVED" {
		// A successful removal caused by selector narrowing is no longer part of
		// the active selector denominator. Keep it as rollout history instead of
		// making the correctly narrowed policy look partially applied forever.
		record.CoverageState = coverageHistorical
		return
	}
	if liveMatchingDestinationExists(*record, agents, now) {
		// This row is no longer part of live coverage, but without an
		// authoritative Kubernetes workload source we cannot tell whether it
		// was deleted, rescheduled or merely belongs to a previous scale set.
		record.CoverageState = coverageHistorical
		return
	}
	record.CoverageState = coverageUnknown
}

func liveDeploymentRecord(config Config, agent Agent, now time.Time) DeploymentRecord {
	status := "CONFIG_PENDING"
	if agent.ConfigStatus == "FAILED" {
		status = "FAILED"
	} else if config.Target == "java-extension" {
		if agent.ConfigStatus == "APPLIED" &&
			agent.PolicyVersions[config.ID] == config.Version {
			status = "APPLIED"
		}
	} else if agent.ConfigStatus == "APPLIED" &&
		agent.ConfigID == config.ID && agent.Version == config.Version {
		status = "APPLIED"
	}
	attributes := make(map[string]string, len(agent.Attributes))
	for key, value := range agent.Attributes {
		attributes[key] = value
	}
	record := DeploymentRecord{
		ConfigID:             config.ID,
		Version:              config.Version,
		SourceVersion:        config.SourceVersion,
		Active:               config.Active,
		Target:               config.Target,
		Body:                 config.Body,
		Selector:             config.Selector,
		PublishedAt:          config.UpdatedAt,
		PublishedBy:          config.CreatedBy,
		AgentUID:             agent.UID,
		Service:              agent.Service,
		AgentAttributes:      attributes,
		FirstMatchedAt:       now,
		LastObservedAt:       agent.LastSeen,
		ObservedStatus:       status,
		BundleHash:           agent.ConfigHash,
		DesiredPresence:      true,
		ConnectionStatus:     agent.ConnectionStatus,
		CurrentConfigID:      agent.ConfigID,
		CurrentConfigVersion: agent.Version,
		CurrentConfigStatus:  agent.ConfigStatus,
	}
	setSyntheticAppliedAt(&record, agent.LastSeen)
	return record
}

func liveRemovalDeploymentRecord(config Config, agent Agent, now time.Time) DeploymentRecord {
	status := "REMOVAL_PENDING"
	bundleHash := agent.ConfigHash
	if agent.ConfigStatus == "FAILED" {
		status = "FAILED"
	} else if config.Target == "java-extension" {
		_, policyPresent := agent.PolicyVersions[config.ID]
		if !policyPresent && agent.ConfigStatus == "APPLIED" {
			status = "REMOVED"
		}
	} else if agent.ConfigStatus == "APPLIED" &&
		agent.ConfigID != "" && agent.ConfigID != config.ID &&
		agent.EffectiveConfigOrigin == collectorOriginManaged {
		// A selector change can move a Supervisor directly from one managed
		// configuration to another. The replacement acknowledgement proves the
		// former configuration is gone just as strongly as a base acknowledgement.
		status = "REMOVED"
		bundleHash = agent.ConfigHash
	} else if validCollectorBaseConfig(agent.BaseConfig) {
		base := collectorBaseRemoteConfig(agent.BaseConfig)
		bundleHash = base.Hash
		if agent.ConfigID == base.ID && agent.ConfigStatus == "APPLIED" &&
			agent.EffectiveConfigOrigin == collectorOriginBase &&
			agent.ConfigHash == base.Hash {
			status = "REMOVED"
		}
	} else {
		status = "BASE_UNAVAILABLE"
	}
	attributes := make(map[string]string, len(agent.Attributes))
	for key, value := range agent.Attributes {
		attributes[key] = value
	}
	record := DeploymentRecord{
		ConfigID:             config.ID,
		Version:              config.Version,
		SourceVersion:        config.SourceVersion,
		Active:               config.Active,
		Target:               config.Target,
		Body:                 config.Body,
		Selector:             config.Selector,
		PublishedAt:          config.UpdatedAt,
		PublishedBy:          config.CreatedBy,
		AgentUID:             agent.UID,
		Service:              agent.Service,
		AgentAttributes:      attributes,
		FirstMatchedAt:       now,
		LastObservedAt:       agent.LastSeen,
		ObservedStatus:       status,
		BundleHash:           bundleHash,
		DesiredPresence:      false,
		ConnectionStatus:     agent.ConnectionStatus,
		CurrentConfigID:      agent.ConfigID,
		CurrentConfigVersion: agent.Version,
		CurrentConfigStatus:  agent.ConfigStatus,
	}
	setSyntheticAppliedAt(&record, agent.LastSeen)
	return record
}

func setSyntheticAppliedAt(record *DeploymentRecord, confirmedAt time.Time) {
	if record.ObservedStatus != "APPLIED" && record.ObservedStatus != "REMOVED" {
		return
	}
	if confirmedAt.IsZero() {
		confirmedAt = time.Now().UTC()
	}
	confirmation := confirmedAt
	record.AppliedAt = &confirmation
}

func applyDeploymentLiveState(record *DeploymentRecord, agent Agent, now time.Time) {
	record.ConnectionStatus, _ = liveStatus(agent, now)
	record.CurrentConfigID = agent.ConfigID
	record.CurrentConfigVersion = agent.Version
	record.CurrentConfigStatus = agent.ConfigStatus
	record.CurrentConfigOrigin = agent.EffectiveConfigOrigin
	record.BaseConfig = agent.BaseConfig
	if record.Target == "collector" {
		applyCollectorDeploymentLiveState(record, agent)
		return
	}
	if record.Target != "java-extension" {
		return
	}
	record.CurrentPolicyVersion, record.PolicyPresent = agent.PolicyVersions[record.ConfigID]
	legacyCurrent := len(agent.PolicyVersions) == 0 &&
		agent.ConfigID != "" &&
		agent.ConfigID != "java-policy-set" &&
		agent.ConfigID == record.ConfigID &&
		agent.Version == record.Version &&
		agent.ConfigStatus == "APPLIED" &&
		record.ObservedStatus == "APPLIED"
	if legacyCurrent {
		record.PolicyPresent = true
		record.CurrentPolicyVersion = record.Version
		if record.ConnectionStatus == "OFFLINE" || record.ConnectionStatus == "DISCONNECTED" {
			record.LiveStatus = "APPLIED_OFFLINE"
		} else {
			// A pre-PolicySet acknowledgement cannot prove that the currently
			// connected process still holds the policy. Preserve the last-known
			// state without claiming a live APPLIED result.
			record.LiveStatus = "APPLIED_STALE"
		}
		return
	}
	switch {
	case !record.DesiredPresence && !record.PolicyPresent && record.ObservedStatus == "REMOVED":
		record.LiveStatus = "REMOVED"
	case !record.DesiredPresence && record.ObservedStatus == "FAILED":
		record.LiveStatus = "FAILED"
	case !record.DesiredPresence:
		record.LiveStatus = "REMOVAL_PENDING"
	case record.PolicyPresent && record.CurrentPolicyVersion == record.Version:
		switch record.ConnectionStatus {
		case "CONNECTED", "ONLINE":
			if agent.ConfigStatus == "APPLIED" {
				record.LiveStatus = "APPLIED"
			} else {
				record.LiveStatus = "APPLIED_PENDING_REPLACEMENT"
			}
		case "DEGRADED":
			record.LiveStatus = "APPLIED_STALE"
		default:
			record.LiveStatus = "APPLIED_OFFLINE"
		}
	case record.PolicyPresent:
		record.LiveStatus = "SUPERSEDED"
	case record.ObservedStatus == "FAILED":
		record.LiveStatus = "FAILED"
	case agent.ConfigStatus == "CONFIG_PENDING":
		record.LiveStatus = "CONFIG_PENDING"
	default:
		record.LiveStatus = "NOT_APPLIED"
	}
}

func applyCollectorDeploymentLiveState(record *DeploymentRecord, agent Agent) {
	if record.DesiredPresence {
		current := record.CurrentConfigID == record.ConfigID &&
			record.CurrentConfigVersion == record.Version
		switch {
		case !current:
			record.LiveStatus = "SUPERSEDED"
		case record.CurrentConfigStatus == "FAILED":
			record.LiveStatus = "FAILED"
		case record.CurrentConfigStatus != "APPLIED":
			record.LiveStatus = record.CurrentConfigStatus
		case record.ConnectionStatus == "CONNECTED" || record.ConnectionStatus == "ONLINE":
			record.LiveStatus = "APPLIED"
		default:
			record.LiveStatus = "APPLIED_OFFLINE"
		}
		return
	}

	baseDesired := agent.BaseConfig.ID != "" && agent.ConfigID == agent.BaseConfig.ID
	switch {
	case baseDesired && agent.ConfigStatus == "FAILED":
		record.LiveStatus = "BASE_FAILED"
	case baseDesired && agent.ConfigStatus != "APPLIED":
		record.LiveStatus = "BASE_PENDING"
	case baseDesired && agent.EffectiveConfigOrigin == collectorOriginBase &&
		agent.ConfigHash == record.BundleHash:
		record.LiveStatus = "BASE_APPLIED"
	case agent.ConfigStatus == "FAILED":
		record.LiveStatus = "FAILED"
	case record.ObservedStatus == "BASE_UNAVAILABLE":
		record.LiveStatus = "BASE_UNAVAILABLE"
	case record.ObservedStatus == "REMOVED":
		record.LiveStatus = "REMOVED"
	default:
		record.LiveStatus = "REMOVAL_PENDING"
	}
}

func persistAgentUpdates(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case update := <-agentUpdates:
			if database == nil {
				continue
			}
			if update.DeleteUID != "" {
				if err := database.deleteAgentSeenAtOrBefore(
					ctx,
					update.DeleteUID,
					update.DeleteAtOrBefore,
				); err != nil && ctx.Err() == nil {
					log.Printf("delete evicted agent %s: %v", update.DeleteUID, err)
				}
				continue
			}
			if update.Agent == nil {
				continue
			}
			agent := *update.Agent
			state.RLock()
			current, exists := state.Agents[agent.UID]
			stale := !exists || current.LastSeen.After(agent.LastSeen)
			state.RUnlock()
			if stale {
				continue
			}
			err := database.upsertAgent(ctx, agent)
			if err != nil && ctx.Err() == nil {
				log.Printf("persist agent %s: %v", agent.UID, err)
			}
		case deployment := <-deploymentUpdates:
			if err := database.recordDeployment(
				ctx,
				deployment.Config,
				deployment.Agent,
				deployment.Status,
				deployment.BundleHash,
				deployment.DesiredPresence,
			); err != nil && ctx.Err() == nil {
				log.Printf(
					"persist deployment %s v%d for %s: %v",
					deployment.Config.ID,
					deployment.Config.Version,
					deployment.Agent.UID,
					err,
				)
			}
		}
	}
}

func queueAgentUpdate(agent Agent) {
	if agentUpdates == nil {
		return
	}
	copy := agent
	select {
	case agentUpdates <- agentPersistenceUpdate{Agent: &copy}:
	default:
		log.Printf("agent persistence queue full; dropping stale update for %s", agent.UID)
	}
}

func queueAgentDeletion(uid string, lastSeen time.Time) bool {
	if agentUpdates == nil || uid == "" {
		return true
	}
	select {
	case agentUpdates <- agentPersistenceUpdate{
		DeleteUID:        uid,
		DeleteAtOrBefore: lastSeen,
	}:
		return true
	default:
		log.Printf("agent persistence queue full; rejecting eviction of %s", uid)
		return false
	}
}

func queueDeploymentUpdate(config Config, agent Agent, status string) {
	queueDeploymentUpdateWithBundle(config, agent, status, "", true)
}

func queueDeploymentUpdateWithBundle(
	config Config,
	agent Agent,
	status string,
	bundleHash string,
	desiredPresence bool,
) {
	if deploymentUpdates == nil {
		return
	}
	select {
	case deploymentUpdates <- DeploymentUpdate{
		Config:          config,
		Agent:           agent,
		Status:          status,
		BundleHash:      bundleHash,
		DesiredPresence: desiredPresence,
	}:
	default:
		log.Printf(
			"deployment persistence queue full; dropping %s v%d for %s",
			config.ID,
			config.Version,
			agent.UID,
		)
	}
}

func queueMatchingDeployments(config Config, status string) {
	state.RLock()
	agents := make([]Agent, 0, len(state.Agents))
	for _, agent := range state.Agents {
		if agent.Kind == config.Target &&
			(agent.Kind != "collector" || agent.RemoteConfig) &&
			matches(config.Selector, agent) {
			agents = append(agents, agent)
		}
	}
	state.RUnlock()
	for _, agent := range agents {
		queueDeploymentUpdate(config, agent, status)
	}
}

func emitAuditLog(action string, actor string, fields map[string]any) {
	record := map[string]any{
		"timestamp":     time.Now().UTC().Format(time.RFC3339Nano),
		"severity_text": "INFO",
		"event.domain":  "control-plane.audit",
		"event.name":    action,
		"audit.action":  action,
		"user.name":     actor,
	}
	for key, value := range fields {
		record[key] = value
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		log.Printf("encode audit log: %v", err)
		return
	}
	auditLogger.Print(string(encoded))
}

type javaPolicy struct {
	SchemaVersion           string                  `json:"schemaVersion"`
	RequestHeaders          []namedValue            `json:"requestHeaders"`
	ResponseHeaders         []namedValue            `json:"responseHeaders"`
	DeniedHeaders           []namedValue            `json:"deniedHeaders"`
	DeniedBodyPaths         []namedValue            `json:"deniedBodyPaths"`
	MetricPolicies          []httpMetricPolicy      `json:"metricPolicies"`
	MethodPolicies          []methodPolicy          `json:"methodPolicies"`
	BodyEventPolicies       []bodyEventPolicy       `json:"bodyEventPolicies"`
	EventMetricPolicies     []eventMetricPolicy     `json:"eventMetricPolicies"`
	MessagingEventPolicies  []messagingEventPolicy  `json:"messagingEventPolicies"`
	MessagingMetricPolicies []messagingMetricPolicy `json:"messagingMetricPolicies"`
}
type namedValue struct {
	Name      string `json:"name"`
	Direction string `json:"direction,omitempty"`
}
type httpMetricPolicy struct {
	ID                 string            `json:"id"`
	Enabled            bool              `json:"enabled"`
	Direction          string            `json:"direction"`
	Value              valueSource       `json:"value"`
	Name               string            `json:"name"`
	Instrument         string            `json:"instrument"`
	Unit               string            `json:"unit"`
	Description        string            `json:"description"`
	StandardAttributes []string          `json:"standardAttributes"`
	CustomAttributes   []attributeSource `json:"customAttributes"`
	Buckets            []float64         `json:"buckets"`
}
type valueSource struct {
	Source        string  `json:"source"`
	ArgumentIndex int     `json:"argumentIndex"`
	Path          string  `json:"path"`
	Constant      float64 `json:"constant"`
}
type attributeSource struct {
	valueSource
	Header       string      `json:"header"`
	Attribute    string      `json:"attribute"`
	Destinations []string    `json:"destinations"`
	ValuePolicy  valuePolicy `json:"valuePolicy"`
}
type valuePolicy struct {
	Type     string       `json:"type"`
	Allowed  []string     `json:"allowed"`
	Fallback string       `json:"fallback"`
	Ranges   []valueRange `json:"ranges"`
}
type valueRange struct {
	Max   *float64 `json:"max"`
	Label string   `json:"label"`
}
type methodPolicy struct {
	ID            string         `json:"id"`
	Enabled       bool           `json:"enabled"`
	PackagePrefix string         `json:"packagePrefix"`
	ClassName     string         `json:"className"`
	MethodName    string         `json:"methodName"`
	Captures      []capture      `json:"captures"`
	Metrics       []methodMetric `json:"metrics"`
	Log           logPolicy      `json:"log"`
}
type capture struct {
	valueSource
	Attribute    string      `json:"attribute"`
	Type         string      `json:"type"`
	Destinations []string    `json:"destinations"`
	ValuePolicy  valuePolicy `json:"valuePolicy"`
}
type methodMetric struct {
	Name        string      `json:"name"`
	Instrument  string      `json:"instrument"`
	Unit        string      `json:"unit"`
	Description string      `json:"description"`
	Value       valueSource `json:"value"`
	Buckets     []float64   `json:"buckets"`
}
type logPolicy struct {
	Enabled  bool   `json:"enabled"`
	Severity string `json:"severity"`
	Body     string `json:"body"`
}
type bodyEventPolicy struct {
	ID                  string            `json:"id"`
	Enabled             bool              `json:"enabled"`
	RuleName            string            `json:"ruleName"`
	Direction           string            `json:"direction"`
	RequestContentType  string            `json:"requestContentType"`
	ResponseContentType string            `json:"responseContentType"`
	Conditions          []httpCondition   `json:"conditions"`
	EventName           string            `json:"eventName"`
	StaticAttributes    []staticAttribute `json:"staticAttributes"`
	MaxBodyBytes        int               `json:"maxBodyBytes"`
	Fields              []bodyField       `json:"fields"`
	DerivedFields       []derivedField    `json:"derivedFields"`
	Log                 logPolicy         `json:"log"`
}
type staticAttribute struct {
	Attribute    string   `json:"attribute"`
	Value        string   `json:"value"`
	Type         string   `json:"type"`
	Destinations []string `json:"destinations"`
}
type httpCondition struct {
	Source   string   `json:"source"`
	Path     string   `json:"path"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}
type bodyField struct {
	Attribute    string      `json:"attribute"`
	Source       string      `json:"source"`
	Path         string      `json:"path"`
	Type         string      `json:"type"`
	Destinations []string    `json:"destinations"`
	ValuePolicy  valuePolicy `json:"valuePolicy"`
}
type derivedField struct {
	Attribute    string      `json:"attribute"`
	Expression   string      `json:"expression"`
	Type         string      `json:"type"`
	Destinations []string    `json:"destinations"`
	ValuePolicy  valuePolicy `json:"valuePolicy"`
}
type eventFieldDefinition struct {
	Type         string
	Destinations []string
	ValuePolicy  valuePolicy
}
type eventMetricPolicy struct {
	ID                 string    `json:"id"`
	Enabled            bool      `json:"enabled"`
	EventName          string    `json:"eventName"`
	Name               string    `json:"name"`
	Instrument         string    `json:"instrument"`
	Unit               string    `json:"unit"`
	Description        string    `json:"description"`
	ValueField         string    `json:"valueField"`
	Dimensions         []string  `json:"dimensions"`
	StandardAttributes []string  `json:"standardAttributes"`
	Buckets            []float64 `json:"buckets"`
}
type messagingEventPolicy struct {
	ID               string               `json:"id"`
	Enabled          bool                 `json:"enabled"`
	RuleName         string               `json:"ruleName"`
	Scope            string               `json:"scope"`
	Conditions       []messagingCondition `json:"conditions"`
	EventName        string               `json:"eventName"`
	StaticAttributes []staticAttribute    `json:"staticAttributes"`
	MaxPayloadBytes  int                  `json:"maxPayloadBytes"`
	Fields           []messagingField     `json:"fields"`
	Log              logPolicy            `json:"log"`
}
type messagingCondition struct {
	Source   string   `json:"source"`
	Path     string   `json:"path"`
	Operator string   `json:"operator"`
	Values   []string `json:"values"`
}
type messagingField struct {
	Attribute    string      `json:"attribute"`
	Source       string      `json:"source"`
	Path         string      `json:"path"`
	Type         string      `json:"type"`
	Destinations []string    `json:"destinations"`
	ValuePolicy  valuePolicy `json:"valuePolicy"`
}
type messagingMetricPolicy struct {
	ID          string    `json:"id"`
	Enabled     bool      `json:"enabled"`
	EventName   string    `json:"eventName"`
	Name        string    `json:"name"`
	Instrument  string    `json:"instrument"`
	Unit        string    `json:"unit"`
	Description string    `json:"description"`
	ValueField  string    `json:"valueField"`
	Dimensions  []string  `json:"dimensions"`
	Buckets     []float64 `json:"buckets"`
}
type metricDefinition struct {
	Name, Instrument, Unit, Owner, Identity string
	Buckets                                 []float64
}

func normalizeSecurityDenylist(entries []DenylistEntry) ([]DenylistEntry, error) {
	if len(entries) > 256 {
		return nil, fmt.Errorf("security denylist exceeds its limit of 256 entries")
	}
	seen := map[string]bool{}
	normalized := make([]DenylistEntry, 0, len(entries))
	for _, entry := range entries {
		entry.Kind = strings.ToUpper(strings.TrimSpace(entry.Kind))
		entry.Value = strings.TrimSpace(entry.Value)
		switch entry.Kind {
		case "HEADER":
			entry.Value = strings.ToLower(entry.Value)
			if !validHeaderName(entry.Value) {
				return nil, fmt.Errorf("invalid denied header %q", entry.Value)
			}
		case "BODY_PATH":
			if !validJSONPath(entry.Value) {
				return nil, fmt.Errorf("invalid denied JSON path %q", entry.Value)
			}
			entry.Value = normalizeJSONPath(entry.Value)
		case "QUERY_PARAM":
			if !validQueryParameterName(entry.Value) {
				return nil, fmt.Errorf("invalid denied query parameter %q", entry.Value)
			}
		case "PATH_PARAM":
			if !validPathParameterName(entry.Value) {
				return nil, fmt.Errorf("invalid denied path parameter %q", entry.Value)
			}
		case "MESSAGE_PROPERTY":
			if !validMessagePropertyName(entry.Value) {
				return nil, fmt.Errorf("invalid denied message property %q", entry.Value)
			}
		case "METHOD_PATH":
			if len(entry.Value) > 256 || !validJavaQualifiedName(entry.Value) {
				return nil, fmt.Errorf("invalid denied method object path %q", entry.Value)
			}
		default:
			return nil, fmt.Errorf("unsupported denylist kind %q", entry.Kind)
		}
		key := entry.Kind + "\x00" + entry.Value
		if seen[key] {
			return nil, fmt.Errorf("duplicated denylist entry %s:%s", entry.Kind, entry.Value)
		}
		seen[key] = true
		entry.UpdatedAt = time.Time{}
		entry.UpdatedBy = ""
		normalized = append(normalized, entry)
	}
	sort.Slice(normalized, func(i, j int) bool {
		if normalized[i].Kind == normalized[j].Kind {
			return normalized[i].Value < normalized[j].Value
		}
		return normalized[i].Kind < normalized[j].Kind
	})
	return normalized, nil
}

func validateActivePoliciesAgainstDenylist(entries []DenylistEntry) error {
	state.RLock()
	latest := []Config{}
	for _, versions := range state.Configs {
		if len(versions) > 0 && versions[len(versions)-1].Target == "java-extension" && isConfigActive(versions[len(versions)-1]) {
			latest = append(latest, versions[len(versions)-1])
		}
	}
	state.RUnlock()
	for _, config := range latest {
		if err := validateJavaPolicyAgainstDenylist(config.Body, entries); err != nil {
			return fmt.Errorf(
				"active policy %s v%d violates the proposed denylist: %w",
				config.ID,
				config.Version,
				err,
			)
		}
	}
	return nil
}

func validateJavaPolicyAgainstDenylist(body string, entries []DenylistEntry) error {
	policy, err := decodeJavaPolicy(body)
	if err != nil {
		return err
	}
	denied := map[string][]string{}
	for _, entry := range entries {
		denied[entry.Kind] = append(denied[entry.Kind], entry.Value)
	}
	checkHeader := func(owner, value string) error {
		normalized := strings.ToLower(strings.TrimSpace(value))
		for _, blocked := range denied["HEADER"] {
			if normalized == blocked {
				return fmt.Errorf("%s attempts to capture denied header %s", owner, normalized)
			}
		}
		return nil
	}
	checkPath := func(kind, owner, value string) error {
		normalized := strings.TrimSpace(value)
		if kind == "BODY_PATH" {
			normalized = normalizeJSONPath(normalized)
		}
		for _, blocked := range denied[kind] {
			blocked = strings.TrimSpace(blocked)
			if kind == "BODY_PATH" {
				blocked = normalizeJSONPath(blocked)
			}
			exact := kind == "QUERY_PARAM" || kind == "PATH_PARAM" || kind == "MESSAGE_PROPERTY"
			blockedCapture := exact && normalized == blocked ||
				!exact && governedPathsIntersect(normalized, blocked)
			if blockedCapture {
				displayPath := normalized
				if displayPath == "" {
					displayPath = "<root>"
				}
				return fmt.Errorf("%s attempts to capture denied %s %s", owner, strings.ToLower(kind), displayPath)
			}
		}
		return nil
	}
	for _, header := range policy.RequestHeaders {
		if err := checkHeader("requestHeaders", header.Name); err != nil {
			return err
		}
	}
	for _, header := range policy.ResponseHeaders {
		if err := checkHeader("responseHeaders", header.Name); err != nil {
			return err
		}
	}
	for _, metric := range policy.MetricPolicies {
		if !metric.Enabled {
			continue
		}
		for _, attribute := range metric.CustomAttributes {
			if err := checkHeader(metric.Name, attribute.Header); err != nil {
				return err
			}
		}
	}
	for _, event := range policy.BodyEventPolicies {
		if !event.Enabled {
			continue
		}
		for _, condition := range event.Conditions {
			switch condition.Source {
			case "REQUEST_BODY", "RESPONSE_BODY":
				if err := checkPath("BODY_PATH", event.ID+" condition", condition.Path); err != nil {
					return err
				}
			case "REQUEST_HEADER", "RESPONSE_HEADER":
				if err := checkHeader(event.ID+" condition", condition.Path); err != nil {
					return err
				}
			case "REQUEST_QUERY":
				if err := checkPath("QUERY_PARAM", event.ID+" condition", condition.Path); err != nil {
					return err
				}
			case "REQUEST_PATH_PARAM":
				if err := checkPath("PATH_PARAM", event.ID+" condition", condition.Path); err != nil {
					return err
				}
			}
		}
		for _, field := range event.Fields {
			switch field.Source {
			case "REQUEST_BODY", "RESPONSE_BODY":
				if err := checkPath("BODY_PATH", event.ID+" field "+field.Attribute, field.Path); err != nil {
					return err
				}
			case "REQUEST_HEADER", "RESPONSE_HEADER":
				if err := checkHeader(event.ID+" field "+field.Attribute, field.Path); err != nil {
					return err
				}
			case "REQUEST_QUERY":
				if err := checkPath("QUERY_PARAM", event.ID+" field "+field.Attribute, field.Path); err != nil {
					return err
				}
			case "REQUEST_PATH_PARAM":
				if err := checkPath("PATH_PARAM", event.ID+" field "+field.Attribute, field.Path); err != nil {
					return err
				}
			}
		}
	}
	for _, event := range policy.MessagingEventPolicies {
		if !event.Enabled {
			continue
		}
		for _, condition := range event.Conditions {
			if err := validateMessagingSelectorAgainstDenylist(event.ID+" condition", condition.Source, condition.Path, checkHeader, checkPath); err != nil {
				return err
			}
		}
		for _, field := range event.Fields {
			if err := validateMessagingSelectorAgainstDenylist(event.ID+" field "+field.Attribute, field.Source, field.Path, checkHeader, checkPath); err != nil {
				return err
			}
		}
	}
	for _, method := range policy.MethodPolicies {
		if !method.Enabled {
			continue
		}
		for _, item := range method.Captures {
			if item.Source == "ARGUMENT" || item.Source == "RETURN" {
				if err := checkPath("METHOD_PATH", method.ID+" capture "+item.Attribute, item.Path); err != nil {
					return err
				}
			}
		}
		for _, metric := range method.Metrics {
			if metric.Value.Source == "ARGUMENT" || metric.Value.Source == "RETURN" {
				if err := checkPath("METHOD_PATH", method.ID+" metric "+metric.Name, metric.Value.Path); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// governedPathsIntersect treats both paths as projections over the same object
// tree. Capturing either an ancestor or a descendant of a denied projection can
// expose the denied value, so both directions are rejected. An empty path is the
// object root and intersects every non-empty path.
func governedPathsIntersect(left, right string) bool {
	if left == "" || right == "" {
		return true
	}
	return pathIsWithin(left, right) || pathIsWithin(right, left)
}

func pathIsWithin(candidate, ancestor string) bool {
	if candidate == ancestor {
		return true
	}
	if !strings.HasPrefix(candidate, ancestor) || len(candidate) == len(ancestor) {
		return false
	}
	separator := candidate[len(ancestor)]
	return separator == '.' || separator == '['
}

var standardHTTPAttributes = map[string]bool{
	"http.request.method":       true,
	"url.scheme":                true,
	"error.type":                true,
	"http.response.status_code": true,
	"http.route":                true,
	"network.protocol.name":     true,
	"network.protocol.version":  true,
	"server.address":            true,
	"server.port":               true,
	"user_agent.synthetic.type": true,
}

var eventHTTPAttributes = map[string]bool{
	"http.request.method":       true,
	"error.type":                true,
	"http.response.status_code": true,
	"http.route":                true,
}
var numericHTTPAttributes = map[string]bool{
	"http.response.status_code": true,
	"server.port":               true,
}
var builtInMetrics = map[string]bool{
	"http.server.request.duration":   true,
	"http.server.active_requests":    true,
	"http.server.request.body.size":  true,
	"http.server.response.body.size": true,
	"http.client.request.duration":   true,
	"http.client.request.body.size":  true,
	"http.client.response.body.size": true,
}

func decodeJavaPolicy(body string) (javaPolicy, error) {
	var policy javaPolicy
	decoder := json.NewDecoder(strings.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&policy); err != nil {
		return policy, fmt.Errorf("invalid policy JSON: %w", err)
	}
	if decoder.Decode(&struct{}{}) == nil {
		return policy, fmt.Errorf("policy contains trailing JSON")
	}
	if err := validatePolicyRequiredFields([]byte(body)); err != nil {
		return policy, fmt.Errorf("invalid policy JSON: %w", err)
	}
	return policy, nil
}

func validateJavaPolicy(configID, body string) error {
	if !policyIDPattern.MatchString(configID) {
		return fmt.Errorf("policy id must match [a-z][a-z0-9._-]{0,127}")
	}
	policy, err := decodeJavaPolicy(body)
	if err != nil {
		return err
	}
	if err := validatePolicyResourceLimits(policy); err != nil {
		return err
	}
	if !contains([]string{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6"}, policy.SchemaVersion) {
		return fmt.Errorf("schemaVersion must be 1.0, 1.1, 1.2, 1.3, 1.4, 1.5 or 1.6")
	}
	if len(policy.MetricPolicies) > 0 && !contains([]string{"1.3", "1.4", "1.5", "1.6"}, policy.SchemaVersion) {
		return fmt.Errorf("dynamic HTTP metric value sources require schemaVersion 1.3 or newer")
	}
	if (len(policy.BodyEventPolicies) > 0 || len(policy.EventMetricPolicies) > 0) && !contains([]string{"1.3", "1.4", "1.5", "1.6"}, policy.SchemaVersion) {
		return fmt.Errorf("policy-driven HTTP events require schemaVersion 1.3 or newer")
	}
	for _, event := range policy.BodyEventPolicies {
		if len(event.DerivedFields) > 0 && !contains([]string{"1.2", "1.3", "1.4", "1.5", "1.6"}, policy.SchemaVersion) {
			return fmt.Errorf("derived body fields require schemaVersion 1.2 or newer")
		}
		if httpEventUsesExtendedSources(event) && !contains([]string{"1.4", "1.5", "1.6"}, policy.SchemaVersion) {
			return fmt.Errorf("HTTP event header and query sources require schemaVersion 1.4")
		}
	}
	if httpEventUsesPathParameters(policy) && !contains([]string{"1.5", "1.6"}, policy.SchemaVersion) {
		return fmt.Errorf("REQUEST_PATH_PARAM requires schemaVersion 1.5")
	}
	if (len(policy.MessagingEventPolicies) > 0 || len(policy.MessagingMetricPolicies) > 0) && !contains([]string{"1.5", "1.6"}, policy.SchemaVersion) {
		return fmt.Errorf("messaging policy events require schemaVersion 1.5")
	}
	for _, metric := range policy.EventMetricPolicies {
		if len(metric.StandardAttributes) > 0 && policy.SchemaVersion != "1.6" {
			return fmt.Errorf("HTTP event metric standard attributes require schemaVersion 1.6")
		}
	}
	if len(policy.DeniedHeaders) > 0 || len(policy.DeniedBodyPaths) > 0 {
		return fmt.Errorf("policy-level deniedHeaders and deniedBodyPaths are not supported; configure the Control Plane security denylist")
	}
	if err := validateHeaderLists(policy); err != nil {
		return err
	}
	if err := validateDeniedBodyPaths(policy.DeniedBodyPaths); err != nil {
		return err
	}
	definitions, err := policyMetricDefinitions(configID, policy)
	if err != nil {
		return err
	}
	if err := validateExistingMetricNames(configID, definitions); err != nil {
		return err
	}
	return nil
}

func httpEventUsesExtendedSources(event bodyEventPolicy) bool {
	for _, condition := range event.Conditions {
		if contains([]string{"REQUEST_HEADER", "RESPONSE_HEADER", "REQUEST_QUERY"}, condition.Source) {
			return true
		}
	}
	for _, field := range event.Fields {
		if contains([]string{"REQUEST_HEADER", "RESPONSE_HEADER", "REQUEST_QUERY"}, field.Source) {
			return true
		}
	}
	return false
}

func httpEventUsesPathParameters(policy javaPolicy) bool {
	for _, event := range policy.BodyEventPolicies {
		if !event.Enabled {
			continue
		}
		for _, condition := range event.Conditions {
			if condition.Source == "REQUEST_PATH_PARAM" {
				return true
			}
		}
		for _, field := range event.Fields {
			if field.Source == "REQUEST_PATH_PARAM" {
				return true
			}
		}
	}
	return false
}

// validatePolicyResourceLimits mirrors the Java extension's hard safety
// limits. Keeping the same contract here prevents a policy from being stored
// and published only to be rejected by every matching agent.
func validatePolicyResourceLimits(policy javaPolicy) error {
	if len(policy.MetricPolicies) > maxHTTPMetricPolicies {
		return fmt.Errorf("metricPolicies exceeds its limit of %d", maxHTTPMetricPolicies)
	}
	if len(policy.MethodPolicies) > maxMethodPolicies {
		return fmt.Errorf("methodPolicies exceeds its limit of %d", maxMethodPolicies)
	}
	for index, method := range policy.MethodPolicies {
		if len(method.Captures) > maxMethodCaptures {
			return fmt.Errorf(
				"methodPolicies[%d].captures exceeds its limit of %d",
				index,
				maxMethodCaptures,
			)
		}
		if len(method.Metrics) > maxMethodMetrics {
			return fmt.Errorf(
				"methodPolicies[%d].metrics exceeds its limit of %d",
				index,
				maxMethodMetrics,
			)
		}
	}
	return nil
}

func validateHeaderLists(policy javaPolicy) error {
	for section, values := range map[string][]namedValue{
		"requestHeaders":  policy.RequestHeaders,
		"responseHeaders": policy.ResponseHeaders,
		"deniedHeaders":   policy.DeniedHeaders,
	} {
		limit := 16
		if section == "deniedHeaders" {
			limit = 64
		}
		if len(values) > limit {
			return fmt.Errorf("%s exceeds its limit of %d", section, limit)
		}
		seen := map[string]bool{}
		for _, item := range values {
			name := strings.ToLower(strings.TrimSpace(item.Name))
			identity := name
			if section != "deniedHeaders" {
				direction := normalizedHTTPDirection(item.Direction)
				if direction != "INCOMING" && direction != "OUTGOING" {
					return fmt.Errorf("%s direction must be INCOMING or OUTGOING", section)
				}
				identity = direction + ":" + name
			}
			if !validHeaderName(name) || seen[identity] {
				return fmt.Errorf("%s contains an invalid or duplicated header", section)
			}
			seen[identity] = true
		}
	}
	return nil
}

func normalizedHTTPDirection(direction string) string {
	normalized := strings.ToUpper(strings.TrimSpace(direction))
	if normalized == "" {
		return "INCOMING"
	}
	return normalized
}

func validateDeniedBodyPaths(values []namedValue) error {
	if len(values) > 64 {
		return fmt.Errorf("deniedBodyPaths exceeds its limit of 64")
	}
	seen := map[string]bool{}
	for _, item := range values {
		path := normalizeJSONPath(item.Name)
		if !validJSONPath(item.Name) || seen[path] {
			return fmt.Errorf("deniedBodyPaths contains an invalid or duplicated JSON path")
		}
		seen[path] = true
	}
	return nil
}

func validateHTTPConditions(event bodyEventPolicy) error {
	if len(event.Conditions) < 2 || len(event.Conditions) > 16 {
		return fmt.Errorf("%s conditions requires between 2 and 16 AND conditions", event.ID)
	}
	hasPath, hasMethod := false, false
	for _, condition := range event.Conditions {
		if !contains([]string{
			"REQUEST_PATH",
			"REQUEST_METHOD",
			"REQUEST_HEADER",
			"REQUEST_QUERY",
			"REQUEST_PATH_PARAM",
			"REQUEST_BODY",
			"RESPONSE_STATUS",
			"RESPONSE_HEADER",
			"RESPONSE_BODY",
		}, condition.Source) {
			return fmt.Errorf("%s has unsupported condition source %s", event.ID, condition.Source)
		}
		if condition.Operator != "EQUALS" && condition.Operator != "IN" {
			return fmt.Errorf("%s condition operator must be EQUALS or IN", event.ID)
		}
		if len(condition.Values) == 0 || len(condition.Values) > 16 || condition.Operator == "EQUALS" && len(condition.Values) != 1 {
			return fmt.Errorf("%s EQUALS needs one value and IN supports at most 16 values", event.ID)
		}
		for _, value := range condition.Values {
			if isPolicyBlank(value) || len(value) > 128 {
				return fmt.Errorf("%s condition values are required and limited to 128 characters", event.ID)
			}
		}
		switch condition.Source {
		case "REQUEST_PATH":
			hasPath = true
			if !isPolicyBlank(condition.Path) {
				return fmt.Errorf("%s REQUEST_PATH does not use a JSON path", event.ID)
			}
			for _, value := range condition.Values {
				if !strings.HasPrefix(value, "/") || len(value) > 256 || strings.ContainsAny(value, "*?") || !validRequestPathTemplate(value) {
					return fmt.Errorf("%s request paths must be exact paths or named-segment templates", event.ID)
				}
			}
		case "REQUEST_METHOD":
			hasMethod = true
			if !isPolicyBlank(condition.Path) {
				return fmt.Errorf("%s REQUEST_METHOD does not use a JSON path", event.ID)
			}
			for _, value := range condition.Values {
				if !contains([]string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}, value) {
					return fmt.Errorf("%s has unsupported request method %s", event.ID, value)
				}
			}
		case "RESPONSE_STATUS":
			if !isPolicyBlank(condition.Path) {
				return fmt.Errorf("%s RESPONSE_STATUS does not use a JSON path", event.ID)
			}
			for _, value := range condition.Values {
				status, err := strconv.Atoi(value)
				if err != nil || status < 100 || status > 599 {
					return fmt.Errorf("%s response status must be between 100 and 599", event.ID)
				}
			}
		case "REQUEST_BODY", "RESPONSE_BODY":
			if !validJSONPath(condition.Path) {
				return fmt.Errorf("%s has invalid condition JSON path %s", event.ID, condition.Path)
			}
		case "REQUEST_HEADER", "RESPONSE_HEADER":
			if !validHeaderName(strings.ToLower(strings.TrimSpace(condition.Path))) {
				return fmt.Errorf("%s has invalid condition header name %s", event.ID, condition.Path)
			}
		case "REQUEST_QUERY":
			if !validQueryParameterName(condition.Path) {
				return fmt.Errorf("%s has invalid condition query parameter %s", event.ID, condition.Path)
			}
		case "REQUEST_PATH_PARAM":
			if !validPathParameterName(condition.Path) {
				return fmt.Errorf("%s has invalid path parameter name %s", event.ID, condition.Path)
			}
		}
	}
	if !hasPath || !hasMethod {
		return fmt.Errorf("%s REQUEST_PATH and REQUEST_METHOD conditions are mandatory", event.ID)
	}
	return nil
}

func policyMetricDefinitions(owner string, policy javaPolicy) ([]metricDefinition, error) {
	definitions := []metricDefinition{}
	seenNames := map[string]bool{}
	seenPrometheus := map[string]bool{}
	seenPolicyIDs := map[string]bool{}
	for _, metric := range policy.MetricPolicies {
		if !metric.Enabled {
			continue
		}
		if isPolicyBlank(metric.ID) || seenPolicyIDs[metric.ID] {
			return nil, fmt.Errorf("HTTP metric policies require unique IDs")
		}
		seenPolicyIDs[metric.ID] = true
		direction := metric.Direction
		if direction != "INCOMING" && direction != "OUTGOING" {
			return nil, fmt.Errorf("%s direction must be INCOMING or OUTGOING", metric.ID)
		}
		if err := validateHTTPMetricValue(metric); err != nil {
			return nil, err
		}
		seenStandardAttributes := map[string]bool{}
		for _, attribute := range metric.StandardAttributes {
			if !standardHTTPAttributes[attribute] {
				return nil, fmt.Errorf("%s has unsupported standard attribute %s", metric.Name, attribute)
			}
			if seenStandardAttributes[attribute] {
				return nil, fmt.Errorf("%s has duplicated standard attribute %s", metric.Name, attribute)
			}
			seenStandardAttributes[attribute] = true
		}
		if len(metric.CustomAttributes) > maxMetricDimensions {
			return nil, fmt.Errorf("%s customAttributes exceeds its limit of %d", metric.Name, maxMetricDimensions)
		}
		seenCustomAttributes := map[string]bool{}
		customCardinality := 1
		for _, attribute := range metric.CustomAttributes {
			if attribute.Source != "REQUEST_HEADER" {
				return nil, fmt.Errorf("%s supports only REQUEST_HEADER custom attributes", metric.Name)
			}
			if !validHeaderName(strings.ToLower(attribute.Header)) || !validAttributeName(attribute.Attribute) {
				return nil, fmt.Errorf("%s contains an invalid custom attribute", metric.Name)
			}
			if seenCustomAttributes[attribute.Attribute] {
				return nil, fmt.Errorf("%s has duplicated custom attribute %s", metric.Name, attribute.Attribute)
			}
			seenCustomAttributes[attribute.Attribute] = true
			for _, destination := range attribute.Destinations {
				if destination != "SPAN" {
					return nil, fmt.Errorf("%s HTTP custom attributes support only SPAN destination", metric.Name)
				}
			}
			if err := validateBoundedPolicy(attribute.ValuePolicy); err != nil {
				return nil, fmt.Errorf("%s/%s: %w", metric.Name, attribute.Attribute, err)
			}
			customCardinality = boundedCardinalityProduct(
				customCardinality,
				boundedValueCardinality(attribute.ValuePolicy),
			)
		}
		if customCardinality > maxMetricCardinality {
			return nil, fmt.Errorf(
				"%s custom attribute cardinality exceeds its limit of %d",
				metric.Name,
				maxMetricCardinality,
			)
		}
		definition, err := validateMetricDefinition(owner, metric.Name, metric.Instrument, metric.Unit, metric.Buckets, seenNames, seenPrometheus)
		if err != nil {
			return nil, err
		}
		definitions = append(definitions, definition)
	}
	for _, method := range policy.MethodPolicies {
		if !method.Enabled {
			continue
		}
		if !validJavaQualifiedName(method.PackagePrefix) || !validJavaQualifiedName(method.ClassName) || !strings.HasPrefix(method.ClassName, method.PackagePrefix+".") || !validJavaIdentifier(method.MethodName) {
			return nil, fmt.Errorf("%s has an invalid package, class or method", method.ID)
		}
		if isPolicyBlank(method.ID) || seenPolicyIDs[method.ID] {
			return nil, fmt.Errorf("method policies require unique IDs")
		}
		seenPolicyIDs[method.ID] = true
		seenCaptureAttributes := map[string]bool{}
		metricDimensions := 0
		metricCardinality := 1
		for _, item := range method.Captures {
			if err := validateValueSource(item.valueSource); err != nil {
				return nil, fmt.Errorf("%s capture %s: %w", method.ID, item.Attribute, err)
			}
			if !validAttributeName(item.Attribute) {
				return nil, fmt.Errorf("%s has invalid capture %s", method.ID, item.Attribute)
			}
			if seenCaptureAttributes[item.Attribute] {
				return nil, fmt.Errorf("%s has duplicated capture attribute %s", method.ID, item.Attribute)
			}
			seenCaptureAttributes[item.Attribute] = true
			if !contains([]string{"STRING", "DOUBLE", "LONG", "BOOLEAN"}, item.Type) {
				return nil, fmt.Errorf("%s has unsupported capture type %s", method.ID, item.Type)
			}
			for _, destination := range item.Destinations {
				if destination != "SPAN" && destination != "LOG" && destination != "METRIC" {
					return nil, fmt.Errorf("%s has unsupported destination %s", method.ID, destination)
				}
			}
			if contains(item.Destinations, "METRIC") {
				metricDimensions++
				if err := validateBoundedPolicy(item.ValuePolicy); err != nil {
					return nil, fmt.Errorf("%s metric label %s: %w", method.ID, item.Attribute, err)
				}
				metricCardinality = boundedCardinalityProduct(
					metricCardinality,
					boundedValueCardinality(item.ValuePolicy),
				)
			}
		}
		if metricDimensions > maxMetricDimensions {
			return nil, fmt.Errorf("%s metric dimensions exceeds its limit of %d", method.ID, maxMetricDimensions)
		}
		if metricCardinality > maxMetricCardinality {
			return nil, fmt.Errorf(
				"%s metric dimension cardinality exceeds its limit of %d",
				method.ID,
				maxMetricCardinality,
			)
		}
		for _, metric := range method.Metrics {
			if err := validateValueSource(metric.Value); err != nil {
				return nil, fmt.Errorf("%s/%s: %w", method.ID, metric.Name, err)
			}
			definition, err := validateMetricDefinition(owner, metric.Name, metric.Instrument, metric.Unit, metric.Buckets, seenNames, seenPrometheus)
			if err != nil {
				return nil, err
			}
			definitions = append(definitions, definition)
		}
		if method.Log.Enabled {
			if !contains([]string{"TRACE", "DEBUG", "INFO", "WARN", "ERROR"}, method.Log.Severity) || isPolicyBlank(method.Log.Body) || len(method.Log.Body) > 256 {
				return nil, fmt.Errorf("%s has invalid log severity or body", method.ID)
			}
		}
	}
	bodyDefinitions, err := validateBodyEventPolicies(
		owner,
		policy,
		seenNames,
		seenPrometheus,
		seenPolicyIDs,
	)
	if err != nil {
		return nil, err
	}
	definitions = append(definitions, bodyDefinitions...)
	messagingDefinitions, err := validateMessagingEventPolicies(
		owner,
		policy,
		seenNames,
		seenPrometheus,
		seenPolicyIDs,
	)
	if err != nil {
		return nil, err
	}
	definitions = append(definitions, messagingDefinitions...)
	return definitions, nil
}

func validateHTTPMetricValue(metric httpMetricPolicy) error {
	switch metric.Value.Source {
	case "DURATION":
		if !isPolicyBlank(metric.Value.Path) {
			return fmt.Errorf("%s DURATION does not use path", metric.Name)
		}
	case "CONSTANT":
		if math.IsNaN(metric.Value.Constant) || math.IsInf(metric.Value.Constant, 0) || !isPolicyBlank(metric.Value.Path) {
			return fmt.Errorf("%s CONSTANT requires a finite value and no path", metric.Name)
		}
	case "ATTRIBUTE":
		if !numericHTTPAttributes[metric.Value.Path] {
			return fmt.Errorf("%s ATTRIBUTE must reference a numeric HTTP attribute", metric.Name)
		}
	default:
		return fmt.Errorf("%s has unsupported HTTP value source %s", metric.Name, metric.Value.Source)
	}
	return nil
}

func validateStaticAttributes(event bodyEventPolicy) error {
	if len(event.StaticAttributes) > 16 {
		return fmt.Errorf("%s staticAttributes exceeds its limit of 16", event.ID)
	}
	seen := map[string]bool{}
	for _, attribute := range event.StaticAttributes {
		if !validAttributeName(attribute.Attribute) || seen[attribute.Attribute] {
			return fmt.Errorf("%s has an invalid or duplicated static attribute %s", event.ID, attribute.Attribute)
		}
		seen[attribute.Attribute] = true
		if err := validateStaticAttributeValue(attribute); err != nil {
			return fmt.Errorf("%s: %w", event.ID, err)
		}
		if len(attribute.Destinations) == 0 {
			return fmt.Errorf("%s static attributes require at least one destination", event.ID)
		}
		for _, destination := range attribute.Destinations {
			if destination != "SPAN" && destination != "LOG" {
				return fmt.Errorf("%s static attributes support SPAN or LOG destination", event.ID)
			}
		}
	}
	return nil
}

func validateStaticAttributeValue(attribute staticAttribute) error {
	if isPolicyBlank(attribute.Value) || len(attribute.Value) > 256 || !contains([]string{"STRING", "DOUBLE", "LONG", "BOOLEAN"}, attribute.Type) {
		return fmt.Errorf("invalid static attribute value or type for %s", attribute.Attribute)
	}
	switch attribute.Type {
	case "DOUBLE":
		value, err := strconv.ParseFloat(attribute.Value, 64)
		if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
			return fmt.Errorf("invalid DOUBLE value for %s", attribute.Attribute)
		}
	case "LONG":
		if _, err := strconv.ParseInt(attribute.Value, 10, 64); err != nil {
			return fmt.Errorf("invalid LONG value for %s", attribute.Attribute)
		}
	case "BOOLEAN":
		if attribute.Value != "true" && attribute.Value != "false" {
			return fmt.Errorf("invalid BOOLEAN value for %s", attribute.Attribute)
		}
	}
	return nil
}

func validateBodyEventPolicies(
	owner string,
	policy javaPolicy,
	seenNames map[string]bool,
	seenPrometheus map[string]bool,
	seenPolicyIDs map[string]bool,
) ([]metricDefinition, error) {
	if len(policy.BodyEventPolicies) > 16 {
		return nil, fmt.Errorf("bodyEventPolicies exceeds its limit of 16")
	}
	if len(policy.EventMetricPolicies) > 32 {
		return nil, fmt.Errorf("eventMetricPolicies exceeds its limit of 32")
	}

	eventFields := map[string]map[string]eventFieldDefinition{}
	eventSelectors := map[string]map[string]bool{
		"REQUEST_HEADER":     {},
		"RESPONSE_HEADER":    {},
		"REQUEST_QUERY":      {},
		"REQUEST_PATH_PARAM": {},
	}
	eventNames := map[string]string{}
	eventDirections := map[string]string{}
	enabledMetricEvents := map[string]bool{}
	for _, metric := range policy.EventMetricPolicies {
		if metric.Enabled {
			enabledMetricEvents[metric.EventName] = true
		}
	}
	for _, event := range policy.BodyEventPolicies {
		if isPolicyBlank(event.EventName) {
			continue
		}
		if previousID, duplicated := eventNames[event.EventName]; duplicated {
			return nil, fmt.Errorf(
				"%s eventName %s duplicates %s; eventName must be unique across all HTTP event rules",
				event.ID,
				event.EventName,
				previousID,
			)
		}
		eventNames[event.EventName] = event.ID
	}
	for _, event := range policy.BodyEventPolicies {
		if !event.Enabled {
			continue
		}
		if isPolicyBlank(event.ID) || seenPolicyIDs[event.ID] {
			return nil, fmt.Errorf("HTTP event policies require unique IDs")
		}
		seenPolicyIDs[event.ID] = true
		if isPolicyBlank(event.RuleName) || len(event.RuleName) > 128 {
			return nil, fmt.Errorf("%s ruleName is required and limited to 128 characters", event.ID)
		}
		if event.Direction != "INCOMING" && event.Direction != "OUTGOING" {
			return nil, fmt.Errorf("%s direction must be INCOMING or OUTGOING", event.ID)
		}
		if event.Direction == "OUTGOING" && bodyEventUsesSource(event, "REQUEST_PATH_PARAM") {
			return nil, fmt.Errorf("%s REQUEST_PATH_PARAM is supported only for INCOMING HTTP", event.ID)
		}
		if !validJSONContentType(event.RequestContentType) || !validJSONContentType(event.ResponseContentType) {
			return nil, fmt.Errorf("%s supports only application/json or application/*+json", event.ID)
		}
		if !validEventValue(event.EventName) {
			return nil, fmt.Errorf("%s eventName must be a stable identifier", event.ID)
		}
		if err := validateStaticAttributes(event); err != nil {
			return nil, err
		}
		if event.MaxBodyBytes < 1024 || event.MaxBodyBytes > 262144 {
			return nil, fmt.Errorf("%s maxBodyBytes must be between 1024 and 262144", event.ID)
		}
		if err := validateHTTPConditions(event); err != nil {
			return nil, err
		}
		if err := validatePathParameterSelectors(event); err != nil {
			return nil, err
		}
		for _, condition := range event.Conditions {
			collectHTTPEventSelector(eventSelectors, condition.Source, condition.Path)
		}
		if len(event.Fields) > 32 {
			return nil, fmt.Errorf("%s fields exceeds its limit of 32 entries", event.ID)
		}
		fields := map[string]eventFieldDefinition{}
		selectors := map[string]bool{}
		for _, field := range event.Fields {
			if !validAttributeName(field.Attribute) {
				return nil, fmt.Errorf("%s has invalid body attribute %s", event.ID, field.Attribute)
			}
			if _, duplicated := fields[field.Attribute]; duplicated {
				return nil, fmt.Errorf("%s has duplicated body field %s", event.ID, field.Attribute)
			}
			selector, err := normalizedHTTPEventSelector(field.Source, field.Path)
			if err != nil {
				return nil, fmt.Errorf("%s field %s: %w", event.ID, field.Attribute, err)
			}
			identity := field.Source + "|" + selector
			if selectors[identity] {
				if field.Source == "REQUEST_BODY" || field.Source == "RESPONSE_BODY" {
					return nil, fmt.Errorf("%s has invalid or duplicated JSON path %s", event.ID, field.Path)
				}
				return nil, fmt.Errorf("%s has duplicated %s selector %s", event.ID, field.Source, field.Path)
			}
			selectors[identity] = true
			collectHTTPEventSelector(eventSelectors, field.Source, field.Path)
			if !contains([]string{"STRING", "DOUBLE", "LONG", "BOOLEAN"}, field.Type) {
				return nil, fmt.Errorf("%s has unsupported body field type %s", event.ID, field.Type)
			}
			if len(field.Destinations) == 0 {
				return nil, fmt.Errorf("%s body fields require at least one destination", event.ID)
			}
			for _, destination := range field.Destinations {
				if !contains([]string{"SPAN", "LOG", "METRIC"}, destination) {
					return nil, fmt.Errorf("%s has unsupported body destination %s", event.ID, destination)
				}
			}
			if contains(field.Destinations, "METRIC") {
				if err := validateBoundedPolicy(field.ValuePolicy); err != nil {
					return nil, fmt.Errorf("%s metric dimension %s: %w", event.ID, field.Attribute, err)
				}
			}
			fields[field.Attribute] = eventFieldDefinition{
				Type:         field.Type,
				Destinations: field.Destinations,
				ValuePolicy:  field.ValuePolicy,
			}
		}
		if len(event.DerivedFields) > 16 {
			return nil, fmt.Errorf("%s derivedFields exceeds its limit of 16", event.ID)
		}
		numericFields := map[string]bool{}
		for attribute, definition := range fields {
			if definition.Type == "DOUBLE" || definition.Type == "LONG" {
				numericFields[attribute] = true
			}
		}
		for _, field := range event.DerivedFields {
			if !validAttributeName(field.Attribute) {
				return nil, fmt.Errorf("%s has invalid derived attribute %s", event.ID, field.Attribute)
			}
			if _, duplicated := fields[field.Attribute]; duplicated {
				return nil, fmt.Errorf("%s has duplicated extracted or derived field %s", event.ID, field.Attribute)
			}
			if field.Type != "DOUBLE" {
				return nil, fmt.Errorf("%s derived fields support only DOUBLE", event.ID)
			}
			if len(field.Destinations) == 0 {
				return nil, fmt.Errorf("%s derived fields require at least one destination", event.ID)
			}
			for _, destination := range field.Destinations {
				if !contains([]string{"SPAN", "LOG", "METRIC"}, destination) {
					return nil, fmt.Errorf("%s has unsupported derived destination %s", event.ID, destination)
				}
			}
			if contains(field.Destinations, "METRIC") {
				if err := validateBoundedPolicy(field.ValuePolicy); err != nil {
					return nil, fmt.Errorf("%s metric dimension %s: %w", event.ID, field.Attribute, err)
				}
			}
			if err := validateNumericExpression(field.Expression, numericFields); err != nil {
				return nil, fmt.Errorf("%s/%s: %w", event.ID, field.Attribute, err)
			}
			fields[field.Attribute] = eventFieldDefinition{
				Type:         field.Type,
				Destinations: field.Destinations,
				ValuePolicy:  field.ValuePolicy,
			}
			numericFields[field.Attribute] = true
		}
		if event.Log.Enabled && (!contains([]string{"TRACE", "DEBUG", "INFO", "WARN", "ERROR"}, event.Log.Severity) || isPolicyBlank(event.Log.Body) || len(event.Log.Body) > 256) {
			return nil, fmt.Errorf("%s has invalid log severity or body", event.ID)
		}
		if !bodyEventHasEffectiveOutput(event, enabledMetricEvents) {
			return nil, fmt.Errorf(
				"%s must define at least one effective output: SPAN, enabled log, or enabled event metric",
				event.ID,
			)
		}
		eventFields[event.EventName] = fields
		eventDirections[event.EventName] = event.Direction
	}
	for _, source := range []string{"REQUEST_HEADER", "RESPONSE_HEADER", "REQUEST_QUERY", "REQUEST_PATH_PARAM"} {
		if len(eventSelectors[source]) > 16 {
			return nil, fmt.Errorf("%s selectors exceed their limit of 16 unique names", source)
		}
	}

	definitions := []metricDefinition{}
	for _, metric := range policy.EventMetricPolicies {
		if !metric.Enabled {
			continue
		}
		if isPolicyBlank(metric.ID) || seenPolicyIDs[metric.ID] {
			return nil, fmt.Errorf("event metric policies require unique IDs")
		}
		seenPolicyIDs[metric.ID] = true
		if metric.Instrument != "COUNTER" && metric.Instrument != "HISTOGRAM" {
			return nil, fmt.Errorf("%s HTTP event metrics support COUNTER or HISTOGRAM", metric.Name)
		}
		definition, err := validateMetricDefinition(
			owner,
			metric.Name,
			metric.Instrument,
			metric.Unit,
			metric.Buckets,
			seenNames,
			seenPrometheus,
		)
		if err != nil {
			return nil, err
		}
		fields, exists := eventFields[metric.EventName]
		if !exists {
			return nil, fmt.Errorf("%s eventName does not reference an enabled HTTP event", metric.Name)
		}
		if isPolicyBlank(metric.ValueField) {
			if metric.Instrument != "COUNTER" {
				return nil, fmt.Errorf("%s requires a valueField for a value metric", metric.Name)
			}
		} else {
			field, exists := fields[metric.ValueField]
			if !exists || (field.Type != "DOUBLE" && field.Type != "LONG") {
				return nil, fmt.Errorf("%s valueField must reference a numeric extracted or derived field", metric.Name)
			}
		}
		if len(metric.Dimensions) > maxMetricDimensions {
			return nil, fmt.Errorf("%s dimensions exceeds its limit of %d", metric.Name, maxMetricDimensions)
		}
		if len(metric.StandardAttributes) > len(eventHTTPAttributes) {
			return nil, fmt.Errorf(
				"%s standardAttributes exceeds its limit of %d",
				metric.Name,
				len(eventHTTPAttributes),
			)
		}
		seenStandardAttributes := map[string]bool{}
		for _, attribute := range metric.StandardAttributes {
			if !eventHTTPAttributes[attribute] {
				return nil, fmt.Errorf(
					"%s has unsupported HTTP event standard attribute %s",
					metric.Name,
					attribute,
				)
			}
			if seenStandardAttributes[attribute] {
				return nil, fmt.Errorf("%s has duplicated standard attribute %s", metric.Name, attribute)
			}
			if attribute == "http.route" && eventDirections[metric.EventName] != "INCOMING" {
				return nil, fmt.Errorf("%s supports http.route only for INCOMING HTTP events", metric.Name)
			}
			seenStandardAttributes[attribute] = true
		}
		seenDimensions := map[string]bool{}
		metricCardinality := 1
		for _, dimension := range metric.Dimensions {
			field, exists := fields[dimension]
			if seenDimensions[dimension] || !exists || !contains(field.Destinations, "METRIC") {
				return nil, fmt.Errorf("%s dimension must reference a unique bounded extracted or derived field: %s", metric.Name, dimension)
			}
			seenDimensions[dimension] = true
			metricCardinality = boundedCardinalityProduct(
				metricCardinality,
				boundedValueCardinality(field.ValuePolicy),
			)
		}
		if metricCardinality > maxMetricCardinality {
			return nil, fmt.Errorf(
				"%s dimension cardinality exceeds its limit of %d",
				metric.Name,
				maxMetricCardinality,
			)
		}
		definitions = append(definitions, definition)
	}
	return definitions, nil
}

func bodyEventHasEffectiveOutput(
	event bodyEventPolicy,
	enabledMetricEvents map[string]bool,
) bool {
	if event.Log.Enabled || enabledMetricEvents[event.EventName] {
		return true
	}
	for _, attribute := range event.StaticAttributes {
		if contains(attribute.Destinations, "SPAN") {
			return true
		}
	}
	for _, field := range event.Fields {
		if contains(field.Destinations, "SPAN") {
			return true
		}
	}
	for _, field := range event.DerivedFields {
		if contains(field.Destinations, "SPAN") {
			return true
		}
	}
	return false
}

func collectHTTPEventSelector(
	selectors map[string]map[string]bool,
	source string,
	path string,
) {
	bySource, selected := selectors[source]
	if !selected {
		return
	}
	bySource[path] = true
}

func validateNumericExpression(source string, allowed map[string]bool) error {
	if strings.TrimSpace(source) == "" || len(source) > 256 {
		return fmt.Errorf("expression must contain between 1 and 256 characters")
	}
	expression, err := parser.ParseExpr(source)
	if err != nil {
		return fmt.Errorf("invalid arithmetic expression: %w", err)
	}
	nodes := 0
	var validate func(ast.Expr) error
	validate = func(node ast.Expr) error {
		nodes++
		if nodes > 64 {
			return fmt.Errorf("expression exceeds 64 operations and values")
		}
		switch current := node.(type) {
		case *ast.BinaryExpr:
			if current.Op != token.ADD && current.Op != token.SUB && current.Op != token.MUL && current.Op != token.QUO {
				return fmt.Errorf("only +, -, * and / operators are supported")
			}
			if err := validate(current.X); err != nil {
				return err
			}
			return validate(current.Y)
		case *ast.UnaryExpr:
			if current.Op != token.ADD && current.Op != token.SUB {
				return fmt.Errorf("only unary + and - are supported")
			}
			return validate(current.X)
		case *ast.ParenExpr:
			return validate(current.X)
		case *ast.BasicLit:
			if current.Kind != token.INT && current.Kind != token.FLOAT {
				return fmt.Errorf("only numeric constants are supported")
			}
			value, parseErr := strconv.ParseFloat(current.Value, 64)
			if parseErr != nil || math.IsInf(value, 0) || math.IsNaN(value) {
				return fmt.Errorf("numeric constant must be finite")
			}
			return nil
		case *ast.Ident, *ast.SelectorExpr:
			name, ok := numericFieldReference(current)
			if !ok || !allowed[name] {
				return fmt.Errorf("unknown or non-numeric field %s", name)
			}
			return nil
		default:
			return fmt.Errorf("unsupported expression element %T", node)
		}
	}
	return validate(expression)
}

func numericFieldReference(expression ast.Expr) (string, bool) {
	switch current := expression.(type) {
	case *ast.Ident:
		return current.Name, true
	case *ast.SelectorExpr:
		prefix, ok := numericFieldReference(current.X)
		if !ok {
			return "", false
		}
		return prefix + "." + current.Sel.Name, true
	default:
		return "", false
	}
}

func validateMetricDefinition(owner, name, instrument, unit string, buckets []float64, seenNames, seenPrometheus map[string]bool) (metricDefinition, error) {
	if !validMetricName(name) || builtInMetrics[name] {
		return metricDefinition{}, fmt.Errorf("invalid or reserved metric name: %s", name)
	}
	if instrument != "HISTOGRAM" && instrument != "COUNTER" && instrument != "UP_DOWN_COUNTER" {
		return metricDefinition{}, fmt.Errorf("%s has unsupported instrument %s", name, instrument)
	}
	if isPolicyBlank(unit) || len(unit) > 32 {
		return metricDefinition{}, fmt.Errorf("%s has invalid unit", name)
	}
	if instrument == "HISTOGRAM" {
		if len(buckets) == 0 {
			return metricDefinition{}, fmt.Errorf("%s histogram requires explicit buckets", name)
		}
		if len(buckets) > maxExplicitBuckets {
			return metricDefinition{}, fmt.Errorf(
				"%s buckets exceeds its limit of %d",
				name,
				maxExplicitBuckets,
			)
		}
		for index, bucket := range buckets {
			if index > 0 && bucket <= buckets[index-1] {
				return metricDefinition{}, fmt.Errorf("%s buckets must be strictly increasing", name)
			}
		}
	} else if len(buckets) > 0 {
		return metricDefinition{}, fmt.Errorf("%s buckets are valid only for histograms", name)
	}
	if seenNames[name] {
		return metricDefinition{}, fmt.Errorf("duplicated metric name: %s", name)
	}
	seenNames[name] = true
	prometheusBase := prometheusMetricBase(name)
	if seenPrometheus[prometheusBase] {
		return metricDefinition{}, fmt.Errorf("Prometheus name collision generated by %s", name)
	}
	seenPrometheus[prometheusBase] = true
	identity := instrument + "|" + unit + "|" + fmt.Sprint(buckets)
	return metricDefinition{Name: name, Instrument: instrument, Unit: unit, Owner: owner, Identity: identity, Buckets: buckets}, nil
}

func validateExistingMetricNames(configID string, proposed []metricDefinition) error {
	existing := allMetricDefinitions()
	if err := validateLifetimeMetricCapacity(existing, proposed); err != nil {
		return err
	}
	for _, candidate := range proposed {
		candidatePrometheusBase := prometheusMetricBase(candidate.Name)
		for _, current := range existing {
			if current.Owner == configID {
				if current.Name == candidate.Name && current.Identity != candidate.Identity {
					return fmt.Errorf("metric identity is immutable after creation: %s", candidate.Name)
				}
				if current.Name != candidate.Name && candidatePrometheusBase == prometheusMetricBase(current.Name) {
					return fmt.Errorf("metric name collides with a previous version: %s", candidate.Name)
				}
				continue
			}
			if candidatePrometheusBase == prometheusMetricBase(current.Name) {
				return fmt.Errorf("metric name already exists or collides in Prometheus: %s (owner %s)", candidate.Name, current.Owner)
			}
		}
	}
	return nil
}

func validateLifetimeMetricCapacity(existing, proposed []metricDefinition) error {
	locked := make(map[string]bool, len(existing)+len(proposed))
	for _, definition := range existing {
		locked[definition.Name] = true
	}
	for _, definition := range proposed {
		locked[definition.Name] = true
	}
	if len(locked) > maxLifetimeMetricNames {
		return fmt.Errorf(
			"metric instrument names exceed the lifetime limit of %d",
			maxLifetimeMetricNames,
		)
	}
	return nil
}

func allMetricDefinitions() []metricDefinition {
	state.RLock()
	configsCopy := make(map[string][]Config, len(state.Configs))
	for id, versions := range state.Configs {
		configsCopy[id] = append([]Config(nil), versions...)
	}
	state.RUnlock()
	result := []metricDefinition{}
	seen := map[string]bool{}
	for id, versions := range configsCopy {
		for _, config := range versions {
			if config.Target != "java-extension" {
				continue
			}
			policy, err := decodeJavaPolicy(config.Body)
			if err != nil {
				continue
			}
			definitions, err := policyMetricDefinitions(id, policy)
			if err != nil {
				continue
			}
			for _, definition := range definitions {
				key := definition.Owner + "|" + definition.Name + "|" + definition.Identity
				if !seen[key] {
					seen[key] = true
					result = append(result, definition)
				}
			}
		}
	}
	return result
}

func validateValueSource(source valueSource) error {
	if source.Source != "ARGUMENT" && source.Source != "RETURN" && source.Source != "DURATION" && source.Source != "CONSTANT" {
		return fmt.Errorf("unsupported source %s", source.Source)
	}
	if source.Source == "ARGUMENT" && source.ArgumentIndex < 0 {
		return fmt.Errorf("ARGUMENT requires argumentIndex >= 0")
	}
	path := strings.TrimSpace(source.Path)
	if path != "" && !validJavaQualifiedName(path) {
		return fmt.Errorf("invalid object path %s", source.Path)
	}
	return nil
}

func validateBoundedPolicy(policy valuePolicy) error {
	if isPolicyBlank(policy.Fallback) || len(policy.Fallback) > 64 {
		return fmt.Errorf("bounded value policy requires a fallback of at most 64 characters")
	}
	switch policy.Type {
	case "ENUM":
		if len(policy.Allowed) == 0 || len(policy.Allowed) > 32 {
			return fmt.Errorf("ENUM requires between 1 and 32 allowed values")
		}
		seen := map[string]bool{}
		for _, value := range policy.Allowed {
			normalized := strings.ToLower(strings.TrimSpace(value))
			if normalized == "" || len(value) > 64 || seen[normalized] {
				return fmt.Errorf("ENUM values must be unique and at most 64 characters")
			}
			seen[normalized] = true
		}
		return nil
	case "RANGE":
		if len(policy.Ranges) == 0 || len(policy.Ranges) > 20 {
			return fmt.Errorf("RANGE requires between 1 and 20 ranges")
		}
		var previous float64
		hasPrevious := false
		for index, item := range policy.Ranges {
			if isPolicyBlank(item.Label) || len(item.Label) > 64 {
				return fmt.Errorf("RANGE labels are required and limited to 64 characters")
			}
			if item.Max == nil {
				if index != len(policy.Ranges)-1 {
					return fmt.Errorf("only the last RANGE boundary may be open")
				}
				continue
			}
			if hasPrevious && *item.Max <= previous {
				return fmt.Errorf("RANGE boundaries must be strictly increasing")
			}
			previous, hasPrevious = *item.Max, true
		}
		return nil
	case "BOOLEAN":
		if policy.Fallback != "true" && policy.Fallback != "false" {
			return fmt.Errorf("BOOLEAN fallback must be true or false")
		}
		return nil
	default:
		return fmt.Errorf("metric labels require bounded ENUM, RANGE or BOOLEAN")
	}
}

func boundedValueCardinality(policy valuePolicy) int {
	switch policy.Type {
	case "ENUM":
		return min(len(policy.Allowed)+1, maxMetricCardinality+1)
	case "RANGE":
		return min(len(policy.Ranges)+1, maxMetricCardinality+1)
	case "BOOLEAN":
		return 2
	default:
		return maxMetricCardinality + 1
	}
}

func boundedCardinalityProduct(current, factor int) int {
	if current > maxMetricCardinality || factor <= 0 ||
		current > maxMetricCardinality/factor {
		return maxMetricCardinality + 1
	}
	return current * factor
}

func prometheusSeries(name, instrument string) []string {
	base := prometheusMetricBase(name)
	switch instrument {
	case "HISTOGRAM":
		return []string{base + "_bucket", base + "_sum", base + "_count"}
	case "COUNTER":
		return []string{base + "_total"}
	default:
		return []string{base}
	}
}

func prometheusMetricBase(name string) string {
	var normalized strings.Builder
	for _, character := range name {
		if isASCIILetter(character) || character >= '0' && character <= '9' || character == '_' || character == ':' {
			normalized.WriteRune(character)
		} else {
			normalized.WriteByte('_')
		}
	}
	base := normalized.String()
	return strings.TrimSuffix(base, "_total")
}

func validMetricName(value string) bool {
	if len(value) < 3 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func validAttributeName(value string) bool {
	if len(value) < 2 || len(value) > 96 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func validHeaderName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') &&
			!(character >= '0' && character <= '9') &&
			!strings.ContainsRune("!#$%&'*+.^_`|~-", character) {
			return false
		}
	}
	return true
}

func validQueryParameterName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !isASCIIAlphaNumeric(character) && !strings.ContainsRune("._~-", character) {
			return false
		}
	}
	return true
}

func validPathParameterName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if index == 0 {
			if !isASCIILetter(character) && character != '_' {
				return false
			}
			continue
		}
		if !isASCIIAlphaNumeric(character) && !strings.ContainsRune("_.-", character) {
			return false
		}
	}
	return true
}

func validRequestPathTemplate(value string) bool {
	seen := map[string]bool{}
	for _, segment := range strings.Split(value, "/") {
		if !strings.ContainsAny(segment, "{}") {
			continue
		}
		if len(segment) < 3 || segment[0] != '{' || segment[len(segment)-1] != '}' {
			return false
		}
		name := segment[1 : len(segment)-1]
		if !validPathParameterName(name) || seen[name] {
			return false
		}
		seen[name] = true
	}
	return true
}

func validatePathParameterSelectors(event bodyEventPolicy) error {
	declared := map[string]bool{}
	for _, condition := range event.Conditions {
		if condition.Source != "REQUEST_PATH" {
			continue
		}
		for _, template := range condition.Values {
			for _, name := range requestPathParameterNames(template) {
				declared[name] = true
			}
		}
	}
	validate := func(selector string) error {
		if validPathParameterName(selector) && !declared[selector] {
			return fmt.Errorf(
				"%s REQUEST_PATH_PARAM selector %s must appear as {%s} in a REQUEST_PATH condition",
				event.ID,
				selector,
				selector,
			)
		}
		return nil
	}
	for _, condition := range event.Conditions {
		if condition.Source == "REQUEST_PATH_PARAM" {
			if err := validate(condition.Path); err != nil {
				return err
			}
		}
	}
	for _, field := range event.Fields {
		if field.Source == "REQUEST_PATH_PARAM" {
			if err := validate(field.Path); err != nil {
				return err
			}
		}
	}
	return nil
}

func requestPathParameterNames(template string) []string {
	if !validRequestPathTemplate(template) {
		return nil
	}
	names := []string{}
	for _, segment := range strings.Split(template, "/") {
		if len(segment) >= 3 && segment[0] == '{' && segment[len(segment)-1] == '}' {
			names = append(names, segment[1:len(segment)-1])
		}
	}
	return names
}

func normalizedHTTPEventSelector(source, value string) (string, error) {
	value = strings.TrimSpace(value)
	switch source {
	case "REQUEST_BODY", "RESPONSE_BODY":
		if !validJSONPath(value) {
			return "", fmt.Errorf("invalid JSON path %s", value)
		}
		return normalizeJSONPath(value), nil
	case "REQUEST_HEADER", "RESPONSE_HEADER":
		value = strings.ToLower(value)
		if !validHeaderName(value) {
			return "", fmt.Errorf("invalid header name %s", value)
		}
		return value, nil
	case "REQUEST_QUERY":
		if !validQueryParameterName(value) {
			return "", fmt.Errorf("invalid query parameter %s", value)
		}
		return value, nil
	case "REQUEST_PATH_PARAM":
		if !validPathParameterName(value) {
			return "", fmt.Errorf("invalid path parameter name %s", value)
		}
		return value, nil
	default:
		return "", fmt.Errorf("unsupported HTTP event field source %s", source)
	}
}

func bodyEventUsesSource(event bodyEventPolicy, source string) bool {
	for _, condition := range event.Conditions {
		if condition.Source == source {
			return true
		}
	}
	for _, field := range event.Fields {
		if field.Source == source {
			return true
		}
	}
	return false
}

func validJSONContentType(value string) bool {
	contentType := strings.ToLower(strings.TrimSpace(value))
	return contentType == "application/json" || strings.HasPrefix(contentType, "application/") && strings.HasSuffix(contentType, "+json")
}

func validEventValue(value string) bool {
	if len(value) < 2 || len(value) > 128 || !isASCIIAlphaNumeric(rune(value[0])) {
		return false
	}
	for _, character := range value[1:] {
		if !isASCIIAlphaNumeric(character) && character != '_' && character != '.' && character != '-' {
			return false
		}
	}
	return true
}

func validJSONPath(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	path := normalizeJSONPath(value)
	if path == "" {
		return false
	}
	depth := 0
	for index := 0; index < len(path); {
		if depth >= 16 {
			return false
		}
		if path[index] == '.' {
			index++
			if index >= len(path) {
				return false
			}
		}
		if path[index] == '[' {
			end := strings.IndexByte(path[index:], ']')
			if end < 2 || end > 5 {
				return false
			}
			for _, character := range path[index+1 : index+end] {
				if character < '0' || character > '9' {
					return false
				}
			}
			index += end + 1
			depth++
			continue
		}
		if !(isASCIILetter(rune(path[index])) || path[index] == '_') {
			return false
		}
		index++
		for index < len(path) && path[index] != '.' && path[index] != '[' {
			character := rune(path[index])
			if !isASCIIAlphaNumeric(character) && character != '_' && character != '-' {
				return false
			}
			index++
		}
		depth++
	}
	return true
}

func normalizeJSONPath(value string) string {
	normalized := strings.TrimSpace(value)
	normalized = strings.TrimPrefix(normalized, "$")
	normalized = strings.TrimPrefix(normalized, ".")
	return normalized
}

func validJavaQualifiedName(value string) bool {
	if value == "" {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if !validJavaIdentifier(part) {
			return false
		}
	}
	return true
}

func validJavaIdentifier(value string) bool {
	if value == "" || !(isASCIILetter(rune(value[0])) || value[0] == '_' || value[0] == '$') {
		return false
	}
	for _, character := range value[1:] {
		if !(isASCIILetter(character) || character >= '0' && character <= '9' || character == '_' || character == '$') {
			return false
		}
	}
	return true
}

func isASCIILetter(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
}

func isASCIIAlphaNumeric(character rune) bool {
	return isASCIILetter(character) || character >= '0' && character <= '9'
}

func contains(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func isPolicyBlank(value string) bool {
	return strings.TrimSpace(value) == ""
}

func intersects(left, right []string) bool {
	values := map[string]bool{}
	for _, value := range left {
		values[value] = true
	}
	for _, value := range right {
		if values[value] {
			return true
		}
	}
	return false
}

func validateSelector(selector AgentSelector) error {
	if len(selector.InstanceUIDs) > 100 || len(selector.Services) > 100 || len(selector.Attributes) > 20 {
		return fmt.Errorf("selector is too large")
	}
	for key, value := range selector.Attributes {
		if !validAttributeName(key) || value == "" || len(value) > 128 {
			return fmt.Errorf("invalid selector attribute %s", key)
		}
	}
	return nil
}

func matches(selector AgentSelector, agent Agent) bool {
	if len(selector.InstanceUIDs) > 0 && !contains(selector.InstanceUIDs, agent.UID) {
		return false
	}
	if len(selector.Services) > 0 && !contains(selector.Services, agent.Service) {
		return false
	}
	for key, expected := range selector.Attributes {
		if agent.Attributes[key] != expected {
			return false
		}
	}
	return true
}

func policyMetadata(w http.ResponseWriter, _ *http.Request) {
	jsonOut(w, map[string]any{
		"schemaVersion": "1.6",
		"httpValueSources": []map[string]string{
			{"id": "DURATION", "label": "Duración del request HTTP", "help": "Segundos transcurridos entre inicio y fin."},
			{"id": "ATTRIBUTE", "label": "Atributo HTTP numérico", "help": "Convierte un atributo OTel disponible a número."},
			{"id": "CONSTANT", "label": "Constante", "help": "Registra el valor configurado por cada request."},
		},
		"httpAttributes": []map[string]any{
			{"name": "http.request.method", "type": "STRING", "level": "required", "help": "Método HTTP conocido."},
			{"name": "url.scheme", "type": "STRING", "level": "required", "help": "Esquema HTTP o HTTPS."},
			{"name": "http.response.status_code", "type": "LONG", "level": "conditional", "help": "Código de respuesta disponible."},
			{"name": "http.route", "type": "STRING", "level": "conditional", "help": "Plantilla de ruta de baja cardinalidad."},
			{"name": "error.type", "type": "STRING", "level": "conditional", "help": "Tipo estable de error."},
			{"name": "network.protocol.name", "type": "STRING", "level": "conditional", "help": "Nombre del protocolo."},
			{"name": "network.protocol.version", "type": "STRING", "level": "recommended", "help": "Versión del protocolo."},
			{"name": "server.address", "type": "STRING", "level": "opt-in", "help": "Puede aumentar cardinalidad."},
			{"name": "server.port", "type": "LONG", "level": "opt-in", "help": "Puede aumentar cardinalidad."},
		},
		"instruments":          []string{"HISTOGRAM", "COUNTER", "UP_DOWN_COUNTER"},
		"eventInstruments":     []string{"COUNTER", "HISTOGRAM"},
		"eventHTTPAttributes":  []string{"http.request.method", "http.route", "http.response.status_code", "error.type"},
		"eventFieldSources":    []string{"REQUEST_HEADER", "REQUEST_QUERY", "REQUEST_PATH_PARAM", "REQUEST_BODY", "RESPONSE_HEADER", "RESPONSE_BODY"},
		"bodySources":          []string{"REQUEST_BODY", "RESPONSE_BODY"},
		"conditionSources":     []string{"REQUEST_PATH", "REQUEST_METHOD", "REQUEST_HEADER", "REQUEST_QUERY", "REQUEST_PATH_PARAM", "REQUEST_BODY", "RESPONSE_STATUS", "RESPONSE_HEADER", "RESPONSE_BODY"},
		"conditionOperators":   []string{"EQUALS", "IN"},
		"methodValueSources":   []string{"ARGUMENT", "RETURN", "DURATION", "CONSTANT"},
		"messagingScopes":      messagingScopes,
		"messagingSources":     messagingSources,
		"destinations":         []string{"SPAN", "METRIC", "LOG"},
		"boundedValuePolicies": []string{"ENUM", "RANGE", "BOOLEAN"},
	})
}

func metricNames(w http.ResponseWriter, _ *http.Request) {
	definitions := allMetricDefinitions()
	rows := make([]map[string]any, 0, len(definitions)+len(builtInMetrics))
	for name := range builtInMetrics {
		rows = append(rows, map[string]any{"name": name, "owner": "opentelemetry", "reserved": true})
	}
	for _, definition := range definitions {
		rows = append(rows, map[string]any{
			"name": definition.Name, "owner": definition.Owner, "instrument": definition.Instrument,
			"unit": definition.Unit, "reserved": true,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return fmt.Sprint(rows[i]["name"]) < fmt.Sprint(rows[j]["name"]) })
	jsonOut(w, rows)
}

func jsonOut(w http.ResponseWriter, v any) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
