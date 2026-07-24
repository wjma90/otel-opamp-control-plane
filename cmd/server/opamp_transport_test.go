package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
)

func TestOpAMPTLSConfigurationIsOptInAndValidatesKeyPair(t *testing.T) {
	disabled, err := loadOpAMPTLSConfiguration(mapEnvironment(nil))
	if err != nil || disabled.Enabled {
		t.Fatalf("TLS must be disabled by default: %#v, %v", disabled, err)
	}
	if _, err := loadOpAMPTLSConfiguration(mapEnvironment(map[string]string{
		"OPAMP_TLS_ENABLED": "sometimes",
	})); err == nil {
		t.Fatal("invalid TLS boolean was accepted")
	}
	if _, err := loadOpAMPTLSConfiguration(mapEnvironment(map[string]string{
		"OPAMP_TLS_CERT_FILE": "/unused/tls.crt",
	})); err == nil {
		t.Fatal("TLS paths must not be silently ignored while TLS is disabled")
	}
	if _, err := loadOpAMPTLSConfiguration(mapEnvironment(map[string]string{
		"OPAMP_TLS_ENABLED": "true",
	})); err == nil {
		t.Fatal("TLS without a certificate and private key was accepted")
	}

	certFile, keyFile := writeTestTLSKeyPair(t)
	enabled, err := loadOpAMPTLSConfiguration(mapEnvironment(map[string]string{
		"OPAMP_TLS_ENABLED":   "true",
		"OPAMP_TLS_CERT_FILE": certFile,
		"OPAMP_TLS_KEY_FILE":  keyFile,
	}))
	if err != nil || !enabled.Enabled || enabled.CertFile != certFile || enabled.KeyFile != keyFile {
		t.Fatalf("valid TLS key pair was rejected: %#v, %v", enabled, err)
	}
	if got := opampServerTLSConfiguration().MinVersion; got != tls.VersionTLS12 {
		t.Fatalf("unexpected minimum TLS version: %d", got)
	}
}

func writeTestTLSKeyPair(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "opamp.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"opamp.test"},
	}
	certificate, err := x509.CreateCertificate(
		rand.Reader, template, template, &privateKey.PublicKey, privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certFile := filepath.Join(directory, "tls.crt")
	keyFile := filepath.Join(directory, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certificate,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyDER,
	}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestOpAMPRequestMiddlewareRejectsBeforeCallingHandler(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		token      string
		encoding   string
		upgrade    string
		body       []byte
		wantStatus int
	}{
		{name: "missing token", method: http.MethodPost, wantStatus: http.StatusUnauthorized},
		{name: "wrong token", method: http.MethodPost, token: "Bearer wrong", wantStatus: http.StatusUnauthorized},
		{name: "websocket", method: http.MethodGet, token: "Bearer test-token", upgrade: "websocket", wantStatus: http.StatusMethodNotAllowed},
		{name: "gzip", method: http.MethodPost, token: "Bearer test-token", encoding: "gzip", wantStatus: http.StatusUnsupportedMediaType},
		{name: "oversized", method: http.MethodPost, token: "Bearer test-token", body: bytes.Repeat([]byte{'x'}, maxOpAMPRequestBytes+1), wantStatus: http.StatusRequestEntityTooLarge},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			called := false
			handler := opampRequestMiddleware(opampAuthentication{Mode: opampAuthModeToken, Token: "test-token"}, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}))
			request := httptest.NewRequest(test.method, "/v1/opamp", bytes.NewReader(test.body))
			request.Header.Set("Authorization", test.token)
			request.Header.Set("Content-Encoding", test.encoding)
			request.Header.Set("Upgrade", test.upgrade)
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, request)

			if recorder.Code != test.wantStatus {
				t.Fatalf("expected %d, got %d", test.wantStatus, recorder.Code)
			}
			if called {
				t.Fatal("rejected request reached OpAMP handler")
			}
		})
	}
}

func TestOpAMPRequestMiddlewareForwardsBoundedHTTPPoll(t *testing.T) {
	handler := opampRequestMiddleware(opampAuthentication{Mode: opampAuthModeToken, Token: "test-token"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, 4)
		if _, err := r.Body.Read(body); err != nil {
			t.Fatalf("read forwarded body: %v", err)
		}
		if string(body) != "test" {
			t.Fatalf("unexpected forwarded body: %q", body)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "/v1/opamp", strings.NewReader("test"))
	request.Header.Set("Authorization", "Bearer test-token")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}
}

func TestOpAMPHTTPServerHasResourceLimits(t *testing.T) {
	server := newOpAMPHTTPServer(
		http.NotFoundHandler(),
		func(ctx context.Context, _ net.Conn) context.Context { return ctx },
	)
	if server.ReadHeaderTimeout != 5*time.Second ||
		server.ReadTimeout != 20*time.Second ||
		server.WriteTimeout != 30*time.Second ||
		server.IdleTimeout != 60*time.Second ||
		server.MaxHeaderBytes != 16<<10 {
		t.Fatalf("unexpected OpAMP server limits: %#v", server)
	}
}

func TestOpAMPAuthenticationModes(t *testing.T) {
	t.Setenv("OPAMP_AUTH_MODE", "")
	t.Setenv("CONTROL_TOKEN", "")
	authentication, err := opampAuthenticationFromEnvironment()
	if err != nil || authentication.Mode != opampAuthModeDisabled || !authentication.authorized("") {
		t.Fatalf("disabled must be the tokenless default: %#v, %v", authentication, err)
	}

	t.Setenv("OPAMP_AUTH_MODE", "token")
	if _, err = opampAuthenticationFromEnvironment(); err == nil {
		t.Fatal("token mode must reject an empty token")
	}
	t.Setenv("CONTROL_TOKEN", "valid-token")
	authentication, err = opampAuthenticationFromEnvironment()
	if err != nil || !authentication.authorized("Bearer valid-token") || authentication.authorized("") {
		t.Fatalf("unexpected token mode result: %#v, %v", authentication, err)
	}

	t.Setenv("OPAMP_AUTH_MODE", "unknown")
	if _, err = opampAuthenticationFromEnvironment(); err == nil {
		t.Fatal("unknown auth mode must be rejected")
	}
}

func TestOpAMPRequestMiddlewareAllowsTokenlessDisabledMode(t *testing.T) {
	called := false
	handler := opampRequestMiddleware(opampAuthentication{Mode: opampAuthModeDisabled}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/opamp", nil))
	if recorder.Code != http.StatusNoContent || !called {
		t.Fatalf("disabled mode must forward tokenless polling: %d, called=%t", recorder.Code, called)
	}
}

func TestOpAMPRejectsInvalidUIDWithoutGrowingInventory(t *testing.T) {
	resetState(t)
	response := onMessage(
		context.Background(),
		nil,
		&protobufs.AgentToServer{InstanceUid: bytes.Repeat([]byte{1}, 17)},
		connectionHints{transport: "http-poll"},
	)
	if response.ErrorResponse == nil || len(state.Agents) != 0 {
		t.Fatalf("invalid UID must fail without state growth: %#v", response)
	}
}

func TestOpAMPRejectsNewAgentAfterInventoryLimit(t *testing.T) {
	resetState(t)
	for index := 0; index < maxKnownOpAMPAgents; index++ {
		state.Agents[string(rune(index))] = Agent{UID: string(rune(index))}
	}
	uid := bytes.Repeat([]byte{42}, 16)
	response := onMessage(
		context.Background(),
		nil,
		&protobufs.AgentToServer{InstanceUid: uid},
		connectionHints{transport: "http-poll"},
	)
	if response.ErrorResponse == nil || len(state.Agents) != maxKnownOpAMPAgents {
		t.Fatalf("agent over inventory limit was admitted: %#v", response)
	}
}

func TestReportedAttributeLimits(t *testing.T) {
	stringValue := func(value string) *protobufs.AnyValue {
		return &protobufs.AnyValue{Value: &protobufs.AnyValue_StringValue{StringValue: value}}
	}
	attribute := func(key string, value string) *protobufs.KeyValue {
		return &protobufs.KeyValue{Key: key, Value: stringValue(value)}
	}

	tests := []struct {
		name       string
		attributes []*protobufs.KeyValue
	}{
		{
			name: "count",
			attributes: func() []*protobufs.KeyValue {
				values := make([]*protobufs.KeyValue, maxReportedAttributes+1)
				for index := range values {
					values[index] = attribute("key-"+strconv.Itoa(index), "value")
				}
				return values
			}(),
		},
		{name: "key", attributes: []*protobufs.KeyValue{
			attribute(strings.Repeat("k", maxReportedAttributeKeyBytes+1), "value"),
		}},
		{name: "value", attributes: []*protobufs.KeyValue{
			attribute("key", strings.Repeat("v", maxReportedAttributeValueBytes+1)),
		}},
		{
			name: "total",
			attributes: func() []*protobufs.KeyValue {
				values := make([]*protobufs.KeyValue, 17)
				for index := range values {
					values[index] = attribute(
						"key-"+strconv.Itoa(index),
						strings.Repeat("v", maxReportedAttributeValueBytes-16),
					)
				}
				return values
			}(),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateReportedAttributes(test.attributes); err == nil {
				t.Fatal("expected reported attributes to exceed their bound")
			}
		})
	}
	if err := validateReportedAttributes([]*protobufs.KeyValue{
		attribute("service.name", "exchange-service"),
	}); err != nil {
		t.Fatalf("ordinary resource attribute was rejected: %v", err)
	}
}

func TestReportedEffectiveConfigLimits(t *testing.T) {
	files := map[string]*protobufs.AgentConfigFile{}
	for index := 0; index <= maxEffectiveConfigFiles; index++ {
		files["config-"+strconv.Itoa(index)+".yaml"] = &protobufs.AgentConfigFile{}
	}
	if err := validateReportedEffectiveConfig(&protobufs.AgentConfigMap{ConfigMap: files}); err == nil {
		t.Fatal("expected effective config file-count limit")
	}
	if err := validateReportedEffectiveConfig(&protobufs.AgentConfigMap{ConfigMap: map[string]*protobufs.AgentConfigFile{
		strings.Repeat("n", maxEffectiveConfigNameBytes+1): {},
	}}); err == nil {
		t.Fatal("expected effective config filename limit")
	}
	if err := validateReportedEffectiveConfig(&protobufs.AgentConfigMap{ConfigMap: map[string]*protobufs.AgentConfigFile{
		"config.yaml": {Body: bytes.Repeat([]byte{'x'}, maxEffectiveConfigFileBytes+1)},
	}}); err == nil {
		t.Fatal("expected effective config per-file limit")
	}
	if err := validateReportedEffectiveConfig(&protobufs.AgentConfigMap{ConfigMap: map[string]*protobufs.AgentConfigFile{
		"first.yaml":  {Body: bytes.Repeat([]byte{'x'}, 700<<10)},
		"second.yaml": {Body: bytes.Repeat([]byte{'x'}, 700<<10)},
		"third.yaml":  {Body: bytes.Repeat([]byte{'x'}, 700<<10)},
	}}); err == nil {
		t.Fatal("expected effective config aggregate limit")
	}
}

func TestInvalidReportedPayloadDoesNotMutateAgentState(t *testing.T) {
	resetState(t)
	uidBytes := bytes.Repeat([]byte{7}, 16)
	uid := "07070707070707070707070707070707"
	before := Agent{
		UID:              uid,
		Service:          "original",
		ConnectionStatus: "OFFLINE",
		ConfigStatus:     "APPLIED",
		LastSeen:         time.Unix(100, 0).UTC(),
		Attributes:       map[string]string{"service.name": "original"},
	}
	state.Agents[uid] = before
	response := onMessage(context.Background(), nil, &protobufs.AgentToServer{
		InstanceUid: uidBytes,
		EffectiveConfig: &protobufs.EffectiveConfig{ConfigMap: &protobufs.AgentConfigMap{
			ConfigMap: map[string]*protobufs.AgentConfigFile{
				"config.yaml": {Body: bytes.Repeat([]byte{'x'}, maxEffectiveConfigFileBytes+1)},
			},
		}},
	}, connectionHints{service: "mutated", transport: "http-poll"})
	if response.ErrorResponse == nil {
		t.Fatal("oversized effective config must be rejected")
	}
	if after := state.Agents[uid]; !reflect.DeepEqual(after, before) {
		t.Fatalf("rejected payload mutated state: before=%#v after=%#v", before, after)
	}
}

func TestInventoryEvictsOldestOfflineAgentDeterministically(t *testing.T) {
	resetState(t)
	now := time.Unix(10_000, 0).UTC()
	oldest := now.Add(-time.Hour)
	state.Agents = map[string]Agent{
		"b-offline": {
			UID: "b-offline", ConnectionStatus: "DISCONNECTED", LastSeen: oldest,
		},
		"a-offline": {
			UID: "a-offline", ConnectionStatus: "DISCONNECTED", LastSeen: oldest,
		},
		"live-http": {
			UID: "live-http", Transport: "http-poll", PollIntervalSeconds: 10,
			ConnectionStatus: "ONLINE", LastSeen: now,
		},
	}

	evicted, admitted := ensureAgentInventoryCapacityLocked("new", now, len(state.Agents))
	if !admitted || evicted == nil || evicted.UID != "a-offline" {
		t.Fatalf("expected deterministic eviction of a-offline, got %#v, admitted=%v", evicted, admitted)
	}
	if _, exists := state.Agents["live-http"]; !exists {
		t.Fatal("live agent was evicted")
	}
}

func TestInventoryNeverEvictsLiveAgent(t *testing.T) {
	resetState(t)
	now := time.Unix(10_000, 0).UTC()
	state.Agents["live-http"] = Agent{
		UID: "live-http", Transport: "http-poll", PollIntervalSeconds: 10,
		ConnectionStatus: "ONLINE", LastSeen: now,
	}
	state.Agents["live-websocket"] = Agent{
		UID: "live-websocket", Transport: "websocket",
		ConnectionStatus: "CONNECTED", LastSeen: now,
	}
	state.Conns["live-websocket"] = nil

	if evicted, admitted := ensureAgentInventoryCapacityLocked("new", now, 2); admitted || evicted != nil {
		t.Fatalf("full live inventory must reject admission, got %#v, admitted=%v", evicted, admitted)
	}
	if len(state.Agents) != 2 {
		t.Fatal("rejected admission mutated live inventory")
	}
}

func TestAgentInventoryTTLPrunesOnlyExpiredEntries(t *testing.T) {
	cutoff := time.Unix(10_000, 0).UTC()
	agents := map[string]Agent{
		"expired-b": {UID: "expired-b", LastSeen: cutoff.Add(-time.Second)},
		"current":   {UID: "current", LastSeen: cutoff},
		"expired-a": {UID: "expired-a", LastSeen: cutoff.Add(-time.Hour)},
	}
	removed := pruneExpiredAgentMap(agents, cutoff)
	if !reflect.DeepEqual(removed, []string{"expired-a", "expired-b"}) {
		t.Fatalf("unexpected deterministic prune result: %#v", removed)
	}
	if len(agents) != 1 || agents["current"].UID != "current" {
		t.Fatalf("TTL prune retained the wrong inventory: %#v", agents)
	}

	var nilStore *PostgresStore
	if count, err := nilStore.pruneAgentsSeenBefore(context.Background(), cutoff); err != nil || count != 0 {
		t.Fatalf("nil store prune must be unit-test safe, count=%d err=%v", count, err)
	}
	if err := nilStore.deleteAgentSeenAtOrBefore(context.Background(), "expired", cutoff); err != nil {
		t.Fatalf("nil store delete must be unit-test safe: %v", err)
	}
}
