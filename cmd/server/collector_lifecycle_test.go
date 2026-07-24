package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
)

func testCollectorBase() BaseConfig {
	return BaseConfig{
		ID:        "collector-base.o11y-infra.gateway",
		Source:    "ConfigMap/o11y/otel-gateway-config:base.yaml",
		Revision:  "1",
		Immutable: true,
		Behavior:  collectorBaseBehavior,
	}
}

func TestAgentHintsExposeCompleteImmutableCollectorBase(t *testing.T) {
	header := http.Header{}
	header.Set("X-O11y-Base-Config-ID", "collector-base.o11y-infra.gateway")
	header.Set("X-O11y-Base-Config-Source", "ConfigMap/o11y/otel-gateway-config:base.yaml")
	header.Set("X-O11y-Base-Config-Revision", "1")
	header.Set("X-O11y-Collector-Version", "0.156.0")
	header.Set("X-O11y-Supervisor-Version", "0.4.1")

	hints := agentHints(&http.Request{Header: header})
	base := hints.baseConfig
	if base != testCollectorBase() {
		t.Fatalf("unexpected base metadata: %#v", base)
	}
	if hints.attributes["o11y.collector.version"] != "0.156.0" ||
		hints.attributes["o11y.supervisor.version"] != "0.4.1" {
		t.Fatalf("reported versions must remain agent attributes: %#v", hints.attributes)
	}

	header.Del("X-O11y-Base-Config-Revision")
	if incomplete := agentHints(&http.Request{Header: header}).baseConfig; incomplete.ID != "" {
		t.Fatalf("incomplete base metadata must be ignored: %#v", incomplete)
	}

	header.Set("X-O11y-Base-Config-Revision", "1")
	header.Set("X-O11y-Base-Config-ID", "user-managed-id")
	if unreserved := agentHints(&http.Request{Header: header}).baseConfig; unreserved.ID != "" {
		t.Fatalf("base id outside reserved namespace must be ignored: %#v", unreserved)
	}
}

func TestDesiredCollectorConfigUsesManagedThenImmutableBase(t *testing.T) {
	resetState(t)
	agent := Agent{
		Kind:         "collector",
		Service:      "gateway-supervisor",
		RemoteConfig: true,
		BaseConfig:   testCollectorBase(),
	}

	base, origin, ok := desiredCollectorConfig(agent)
	if !ok || origin != collectorOriginBase || !base.Base || base.Body != collectorBaseRemoteMarker {
		t.Fatalf("unexpected base desired state: %#v %q %v", base, origin, ok)
	}
	if file := remote("collector", base).Config.ConfigMap[""]; file == nil || string(file.Body) != "service: {}\n" {
		t.Fatalf("base reset must be a non-empty remote config map: %#v", file)
	}

	managed := Config{
		ID:        "gateway-managed",
		Target:    "collector",
		Body:      "receivers: {}\n",
		Hash:      "managed-hash",
		Version:   3,
		Active:    true,
		Action:    "PUBLISHED",
		UpdatedAt: time.Now().UTC(),
		Selector:  AgentSelector{Services: []string{"gateway-supervisor"}},
	}
	state.Configs[managed.ID] = []Config{managed}
	desired, origin, ok := desiredCollectorConfig(agent)
	if !ok || origin != collectorOriginManaged || desired.ID != managed.ID {
		t.Fatalf("managed configuration must take precedence: %#v %q", desired, origin)
	}

	managed.Active = false
	managed.Action = "DEACTIVATED"
	state.Configs[managed.ID] = append(state.Configs[managed.ID], managed)
	desired, origin, ok = desiredCollectorConfig(agent)
	if !ok || origin != collectorOriginBase || desired.ID != agent.BaseConfig.ID {
		t.Fatalf("deactivated managed config must fall back to base: %#v %q", desired, origin)
	}
}

func TestCollectorWithoutBaseMetadataDoesNotReceiveDangerousReset(t *testing.T) {
	resetState(t)
	_, _, ok := desiredCollectorConfig(Agent{Kind: "collector", RemoteConfig: true})
	if ok {
		t.Fatal("legacy Supervisor without base metadata must preserve its current configuration")
	}
}

func TestCollectorBaseHashIsDeterministicForIDRevisionAndMarker(t *testing.T) {
	base := testCollectorBase()
	config := collectorBaseRemoteConfig(base)
	wantInput := base.ID + "\n" + base.Revision + "\n" + collectorBaseRemoteMarker
	wantHash := sha256.Sum256([]byte(wantInput))
	if config.Hash != hex.EncodeToString(wantHash[:]) {
		t.Fatalf("unexpected base hash: %s", config.Hash)
	}
	if config.Hash != collectorBaseRemoteConfig(base).Hash {
		t.Fatal("same base identity must always produce the same hash")
	}
	base.Revision = "2"
	if config.Hash == collectorBaseRemoteConfig(base).Hash {
		t.Fatal("changing the ConfigMap revision must change the remote hash")
	}
	if hasLatestRemoteConfig(Agent{ConfigID: config.ID, Version: 0}, nil, config) {
		t.Fatal("base version zero without an acknowledged hash must remain pending")
	}
}

func TestCollectorRemovalDeploymentIsOnlyCreatedForPreviouslyManagedAgent(t *testing.T) {
	resetState(t)
	previousUpdates := deploymentUpdates
	deploymentUpdates = make(chan DeploymentUpdate, 2)
	t.Cleanup(func() { deploymentUpdates = previousUpdates })
	inactive := Config{
		ID:      "gateway-managed",
		Target:  "collector",
		Version: 2,
		Active:  false,
		Action:  "DEACTIVATED",
	}
	state.Configs[inactive.ID] = []Config{inactive}
	desired := collectorBaseRemoteConfig(testCollectorBase())

	queueCollectorRemovalDeployments(desired, Agent{UID: "new-replica"}, "APPLIED", true)
	if len(deploymentUpdates) != 0 {
		t.Fatal("a replica that never applied the managed config must not get a fabricated removal")
	}
	queueCollectorRemovalDeployments(desired, Agent{
		UID:                 "old-replica",
		LastManagedConfigID: inactive.ID,
	}, "APPLIED", true)
	if len(deploymentUpdates) != 1 {
		t.Fatal("the previously managed replica must record the acknowledged removal")
	}
	update := <-deploymentUpdates
	if update.Config.ID != inactive.ID || update.Status != "REMOVED" || update.DesiredPresence {
		t.Fatalf("unexpected removal update: %#v", update)
	}
}

func TestCollectorSelectorNarrowingQueuesAndConfirmsFallback(t *testing.T) {
	resetState(t)
	previousUpdates := deploymentUpdates
	deploymentUpdates = make(chan DeploymentUpdate, 4)
	t.Cleanup(func() { deploymentUpdates = previousUpdates })

	base := testCollectorBase()
	baseConfig := collectorBaseRemoteConfig(base)
	config := Config{
		ID:      "gateway-managed",
		Target:  "collector",
		Version: 2,
		Active:  true,
		Action:  "PUBLISHED",
		Selector: AgentSelector{Attributes: map[string]string{
			"deployment.environment.name": "canary",
		}},
	}
	agent := Agent{
		UID:                      "production-gateway",
		Kind:                     "collector",
		Service:                  "gateway-supervisor",
		RemoteConfig:             true,
		ConfigID:                 config.ID,
		Version:                  1,
		ConfigStatus:             "APPLIED",
		LastManagedConfigID:      config.ID,
		LastManagedConfigVersion: 1,
		BaseConfig:               base,
		Attributes: map[string]string{
			"deployment.environment.name": "production",
		},
	}
	state.Configs[config.ID] = []Config{config}
	state.Agents[agent.UID] = agent

	pushCollectorDesired(config)
	if len(deploymentUpdates) != 1 {
		t.Fatalf("active selector narrowing must queue a fallback removal, got %d", len(deploymentUpdates))
	}
	pending := <-deploymentUpdates
	if pending.Config.Version != config.Version || pending.DesiredPresence ||
		pending.Status != "REMOVAL_PENDING" || pending.BundleHash != baseConfig.Hash {
		t.Fatalf("unexpected narrowed-selector fallback update: %#v", pending)
	}

	queueCollectorRemovalDeployments(baseConfig, agent, "APPLIED", true)
	if len(deploymentUpdates) != 1 {
		t.Fatalf("fallback acknowledgement was not queued, got %d", len(deploymentUpdates))
	}
	confirmed := <-deploymentUpdates
	if confirmed.Config.Version != config.Version || confirmed.DesiredPresence ||
		confirmed.Status != "REMOVED" || confirmed.BundleHash != baseConfig.Hash {
		t.Fatalf("unexpected confirmed narrowed-selector fallback: %#v", confirmed)
	}
}

func TestHydrateLastManagedCollectorFromAppliedHashSkipsDeactivationJournal(t *testing.T) {
	resetState(t)
	published := Config{
		ID:      "gateway-managed",
		Target:  "collector",
		Hash:    "managed-hash",
		Version: 1,
		Active:  true,
		Action:  "PUBLISHED",
	}
	deactivated := published
	deactivated.Version = 2
	deactivated.Active = false
	deactivated.Action = "DEACTIVATED"
	state.Configs[published.ID] = []Config{published, deactivated}
	agent := Agent{Kind: "collector"}
	hydrateLastManagedCollectorConfig(&agent, &protobufs.RemoteConfigStatus{
		LastRemoteConfigHash: []byte(published.Hash),
		Status:               protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED,
	})
	if agent.LastManagedConfigID != published.ID || agent.LastManagedConfigVersion != published.Version {
		t.Fatalf("unexpected hydrated managed identity: %#v", agent)
	}

	failed := Agent{Kind: "collector"}
	hydrateLastManagedCollectorConfig(&failed, &protobufs.RemoteConfigStatus{
		LastRemoteConfigHash: []byte(published.Hash),
		Status:               protobufs.RemoteConfigStatuses_RemoteConfigStatuses_FAILED,
	})
	if failed.LastManagedConfigID != "" {
		t.Fatalf("a failed candidate must not be treated as previously applied: %#v", failed)
	}
}

func TestCollectorSelectorOverlapDetectionIsConservative(t *testing.T) {
	base := AgentSelector{
		Services: []string{"gateway"},
		Attributes: map[string]string{
			"k8s.cluster.name": "o11y-infra",
		},
	}
	if !collectorSelectorsMayOverlap(base, AgentSelector{Services: []string{"gateway"}}) {
		t.Fatal("an unconstrained attribute set can overlap")
	}
	if collectorSelectorsMayOverlap(base, AgentSelector{Services: []string{"monitoring"}}) {
		t.Fatal("disjoint services cannot overlap")
	}
	if collectorSelectorsMayOverlap(base, AgentSelector{Attributes: map[string]string{
		"k8s.cluster.name": "another-cluster",
	}}) {
		t.Fatal("conflicting equality attributes cannot overlap")
	}
}

func TestCollectorBaseAcknowledgementPersistsHashAndOrigin(t *testing.T) {
	resetState(t)
	base := testCollectorBase()
	hints := connectionHints{
		service:    "o11y-infra-gateway-supervisor",
		transport:  "http-poll",
		baseConfig: base,
	}
	uid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	capabilities := uint64(protobufs.AgentCapabilities_AgentCapabilities_AcceptsRemoteConfig)

	response := onMessage(nil, nil, &protobufs.AgentToServer{
		InstanceUid:  uid,
		Capabilities: capabilities,
	}, hints)
	desired := collectorBaseRemoteConfig(base)
	if response.RemoteConfig == nil || string(response.RemoteConfig.ConfigHash) != desired.Hash {
		t.Fatalf("first poll did not offer the immutable base: %#v", response.RemoteConfig)
	}

	onMessage(nil, nil, &protobufs.AgentToServer{
		InstanceUid:  uid,
		Capabilities: capabilities,
		RemoteConfigStatus: &protobufs.RemoteConfigStatus{
			LastRemoteConfigHash: []byte(desired.Hash),
			Status:               protobufs.RemoteConfigStatuses_RemoteConfigStatuses_APPLIED,
		},
	}, hints)
	agent := state.Agents[hex.EncodeToString(uid)]
	if agent.ConfigHash != desired.Hash || agent.EffectiveConfigOrigin != collectorOriginBase ||
		agent.ConfigID != base.ID || agent.ConfigStatus != "APPLIED" {
		t.Fatalf("base acknowledgement was not persisted in memory: %#v", agent)
	}
}

func TestCollectorRemovalLiveStatuses(t *testing.T) {
	base := testCollectorBase()
	desired := collectorBaseRemoteConfig(base)
	record := DeploymentRecord{
		Target:          "collector",
		DesiredPresence: false,
		BundleHash:      desired.Hash,
	}
	agent := Agent{
		ConfigID:              base.ID,
		ConfigHash:            desired.Hash,
		ConfigStatus:          "CONFIG_PENDING",
		BaseConfig:            base,
		EffectiveConfigOrigin: collectorOriginManaged,
	}
	applyCollectorDeploymentLiveState(&record, agent)
	if record.LiveStatus != "BASE_PENDING" {
		t.Fatalf("unexpected pending state: %s", record.LiveStatus)
	}
	agent.ConfigStatus = "APPLIED"
	agent.EffectiveConfigOrigin = collectorOriginBase
	applyCollectorDeploymentLiveState(&record, agent)
	if record.LiveStatus != "BASE_APPLIED" {
		t.Fatalf("unexpected applied state: %s", record.LiveStatus)
	}
	agent.ConfigStatus = "FAILED"
	applyCollectorDeploymentLiveState(&record, agent)
	if record.LiveStatus != "BASE_FAILED" {
		t.Fatalf("unexpected failure state: %s", record.LiveStatus)
	}
}

func TestCollectorBaseInventoryIsReadOnlyAgentDerivedData(t *testing.T) {
	resetState(t)
	base := testCollectorBase()
	desired := collectorBaseRemoteConfig(base)
	state.Agents["collector-a"] = Agent{
		UID:                   "collector-a",
		Kind:                  "collector",
		Service:               "gateway-supervisor",
		ConfigID:              base.ID,
		ConfigHash:            desired.Hash,
		ConfigStatus:          "APPLIED",
		EffectiveConfigOrigin: collectorOriginBase,
		BaseConfig:            base,
		Attributes: map[string]string{
			"o11y.collector.version":  "0.156.0",
			"o11y.supervisor.version": "0.4.1",
		},
	}
	recorder := httptest.NewRecorder()
	collectorBaseConfigs(recorder, httptest.NewRequest(http.MethodGet, "/api/collector-base-configs", nil))
	var result []collectorBaseConfigView
	if err := json.NewDecoder(recorder.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].ID != base.ID || !result[0].Immutable ||
		result[0].Behavior != collectorBaseBehavior || result[0].CurrentUsers != 1 {
		t.Fatalf("unexpected base inventory: %#v", result)
	}
}
