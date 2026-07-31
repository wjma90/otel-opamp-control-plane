package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDeploymentCoverageEmptyStateEncodesAsJSONArray(t *testing.T) {
	records := deploymentRecordsWithLiveCoverage(
		nil,
		map[string]Agent{},
		map[string][]Config{},
		time.Now().UTC(),
	)
	if records == nil {
		t.Fatal("empty deployment coverage must be a non-nil slice")
	}
	body, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("encode empty deployment coverage: %v", err)
	}
	if string(body) != "[]" {
		t.Fatalf("empty deployment coverage encoded as %s, want []", body)
	}
}

func TestDeploymentCoverageIgnoresHistoricalUIDWhenLiveReplicaMatches(t *testing.T) {
	now := time.Now().UTC()
	config := Config{
		ID:        "exchange-policy",
		Target:    "java-extension",
		Version:   3,
		Active:    true,
		Action:    "PUBLISHED",
		UpdatedAt: now.Add(-time.Minute),
		Selector: AgentSelector{
			Services: []string{"exchange-service"},
			Attributes: map[string]string{
				"k8s.cluster.name": "o11y-infra",
			},
		},
	}
	offline := Agent{
		UID:              "old-pod",
		Kind:             "java-extension",
		Service:          "exchange-service",
		ConnectionStatus: "OFFLINE",
		ConfigStatus:     "APPLIED",
		ConfigID:         "java-policy-set",
		PolicyVersions:   map[string]int{config.ID: config.Version},
		LastSeen:         now.Add(-time.Hour),
		Attributes: map[string]string{
			"k8s.cluster.name": "o11y-infra",
		},
	}
	live := offline
	live.UID = "new-pod"
	live.ConnectionStatus = "ONLINE"
	live.Transport = "http-poll"
	live.PollIntervalSeconds = 10
	live.LastSeen = now

	records := deploymentRecordsWithLiveCoverage(
		[]DeploymentRecord{{
			ConfigID:        config.ID,
			Version:         config.Version,
			Target:          config.Target,
			Selector:        config.Selector,
			AgentUID:        offline.UID,
			Service:         offline.Service,
			ObservedStatus:  "APPLIED",
			DesiredPresence: true,
			LastObservedAt:  offline.LastSeen,
		}},
		map[string]Agent{offline.UID: offline, live.UID: live},
		map[string][]Config{config.ID: {config}},
		now,
	)

	if len(records) != 2 {
		t.Fatalf("expected historical and synthetic live records, got %#v", records)
	}
	byUID := recordsByAgentUID(records)
	if old := byUID[offline.UID]; old.CoverageState != coverageHistorical || old.CountsForLiveCoverage {
		t.Fatalf("old UID must remain audit-only, got %#v", old)
	}
	if current := byUID[live.UID]; current.CoverageState != coverageInScope ||
		!current.CountsForLiveCoverage || current.LiveStatus != "APPLIED" {
		t.Fatalf("live replica must define current coverage, got %#v", current)
	}
}

func TestDeploymentCoverageIncludesLivePendingReplica(t *testing.T) {
	now := time.Now().UTC()
	config := Config{
		ID:      "exchange-policy",
		Target:  "java-extension",
		Version: 1,
		Active:  true,
		Action:  "PUBLISHED",
		Selector: AgentSelector{
			Services: []string{"exchange-service"},
		},
	}
	agents := map[string]Agent{
		"applied": {
			UID:                 "applied",
			Kind:                "java-extension",
			Service:             "exchange-service",
			ConnectionStatus:    "ONLINE",
			Transport:           "http-poll",
			PollIntervalSeconds: 10,
			LastSeen:            now,
			ConfigStatus:        "APPLIED",
			ConfigID:            "java-policy-set",
			PolicyVersions:      map[string]int{config.ID: config.Version},
		},
		"pending": {
			UID:                 "pending",
			Kind:                "java-extension",
			Service:             "exchange-service",
			ConnectionStatus:    "ONLINE",
			Transport:           "http-poll",
			PollIntervalSeconds: 10,
			LastSeen:            now,
			ConfigStatus:        "CONFIG_PENDING",
			ConfigID:            "java-policy-set",
			PolicyVersions:      map[string]int{},
		},
	}
	records := deploymentRecordsWithLiveCoverage(
		nil,
		agents,
		map[string][]Config{config.ID: {config}},
		now,
	)
	if len(records) != 2 {
		t.Fatalf("both current replicas must be represented, got %#v", records)
	}
	for _, record := range records {
		if !record.CountsForLiveCoverage || record.CoverageState != coverageInScope {
			t.Fatalf("live replica missing from coverage: %#v", record)
		}
	}
	if recordsByAgentUID(records)["pending"].LiveStatus != "CONFIG_PENDING" {
		t.Fatalf("pending replica was not exposed: %#v", recordsByAgentUID(records)["pending"])
	}
}

func TestDeploymentCoverageDoesNotInferDeletionOrReplacement(t *testing.T) {
	now := time.Now().UTC()
	record := DeploymentRecord{
		ConfigID:        "policy",
		Version:         1,
		Target:          "java-extension",
		Selector:        AgentSelector{Services: []string{"exchange-service"}},
		AgentUID:        "last-known-uid",
		Service:         "exchange-service",
		ObservedStatus:  "APPLIED",
		DesiredPresence: true,
	}
	applyDeploymentCoverageState(&record, map[string]Agent{}, now)
	if record.CoverageState != coverageUnknown || record.CountsForLiveCoverage {
		t.Fatalf("absence of OpAMP traffic cannot prove deletion: %#v", record)
	}
}

func TestRemovalTargetRemainsInCoverageAfterSelectorNarrows(t *testing.T) {
	now := time.Now().UTC()
	agent := Agent{
		UID:                 "previously-targeted",
		Kind:                "java-extension",
		Service:             "exchange-service",
		ConnectionStatus:    "ONLINE",
		Transport:           "http-poll",
		PollIntervalSeconds: 10,
		LastSeen:            now,
		Attributes: map[string]string{
			"deployment.environment.name": "production",
		},
	}
	record := DeploymentRecord{
		ConfigID: "policy",
		Version:  2,
		Target:   "java-extension",
		Active:   true,
		// The latest selector was narrowed after this UID had already received
		// the policy. Removal remains directed to the UID, not re-evaluated as
		// a new publication.
		Selector: AgentSelector{Attributes: map[string]string{
			"deployment.environment.name": "canary",
		}},
		AgentUID:        agent.UID,
		ObservedStatus:  "REMOVAL_PENDING",
		DesiredPresence: false,
	}
	applyDeploymentCoverageState(&record, map[string]Agent{agent.UID: agent}, now)
	if record.CoverageState != coverageInScope || !record.CountsForLiveCoverage {
		t.Fatalf("directed removal disappeared after selector change: %#v", record)
	}

	record.ObservedStatus = "REMOVED"
	applyDeploymentCoverageState(&record, map[string]Agent{agent.UID: agent}, now)
	if record.CoverageState != coverageHistorical || record.CountsForLiveCoverage {
		t.Fatalf("successful narrowed-selector removal must leave active coverage: %#v", record)
	}

	record.ObservedStatus = "FAILED"
	applyDeploymentCoverageState(&record, map[string]Agent{agent.UID: agent}, now)
	if record.CoverageState != coverageInScope || !record.CountsForLiveCoverage {
		t.Fatalf("failed removal must remain visible while UID is live: %#v", record)
	}
}

func TestDeploymentCoverageSynthesizesActiveJavaSelectorNarrowing(t *testing.T) {
	now := time.Now().UTC()
	config := Config{
		ID:      "exchange-policy",
		Target:  "java-extension",
		Version: 2,
		Active:  true,
		Action:  "PUBLISHED",
		Selector: AgentSelector{Attributes: map[string]string{
			"deployment.environment.name": "canary",
		}},
	}
	agent := Agent{
		UID:                 "production-pod",
		Kind:                "java-extension",
		Service:             "exchange-service",
		ConnectionStatus:    "ONLINE",
		Transport:           "http-poll",
		PollIntervalSeconds: 10,
		LastSeen:            now,
		ConfigStatus:        "CONFIG_PENDING",
		ConfigID:            "java-policy-set",
		PolicyVersions:      map[string]int{config.ID: 1},
		Attributes: map[string]string{
			"deployment.environment.name": "production",
		},
	}
	records := deploymentRecordsWithLiveCoverage(
		nil,
		map[string]Agent{agent.UID: agent},
		map[string][]Config{config.ID: {config}},
		now,
	)
	if len(records) != 1 || records[0].DesiredPresence ||
		records[0].ObservedStatus != "REMOVAL_PENDING" ||
		!records[0].CountsForLiveCoverage {
		t.Fatalf("selector narrowing must synthesize the directed policy removal: %#v", records)
	}

	agent.ConfigStatus = "APPLIED"
	agent.PolicyVersions = map[string]int{}
	history := []DeploymentRecord{{
		ConfigID:        config.ID,
		Version:         1,
		Target:          config.Target,
		AgentUID:        agent.UID,
		DesiredPresence: true,
		ObservedStatus:  "APPLIED",
		LastObservedAt:  now.Add(-time.Minute),
	}}
	records = deploymentRecordsWithLiveCoverage(
		history,
		map[string]Agent{agent.UID: agent},
		map[string][]Config{config.ID: {config}},
		now,
	)
	removed := recordsByVersion(records)[config.Version]
	if removed.DesiredPresence || removed.ObservedStatus != "REMOVED" ||
		removed.CountsForLiveCoverage || removed.CoverageState != coverageHistorical ||
		removed.AppliedAt == nil {
		t.Fatalf("confirmed narrowing removal must become history: %#v", removed)
	}

	newReplica := agent
	newReplica.UID = "unmatched-new-replica"
	records = deploymentRecordsWithLiveCoverage(
		nil,
		map[string]Agent{newReplica.UID: newReplica},
		map[string][]Config{config.ID: {config}},
		now,
	)
	if len(records) != 0 {
		t.Fatalf("unmatched replica with no prior targeting must not get a removal: %#v", records)
	}
}

func TestDeploymentCoverageSynthesizesJavaPolicyRemoval(t *testing.T) {
	now := time.Now().UTC()
	config := Config{
		ID:        "exchange-policy",
		Target:    "java-extension",
		Version:   2,
		Active:    false,
		Action:    "DEACTIVATED",
		UpdatedAt: now.Add(-time.Second),
		Selector:  AgentSelector{Services: []string{"exchange-service"}},
	}
	agent := Agent{
		UID:                 "exchange-pod",
		Kind:                "java-extension",
		Service:             "exchange-service",
		ConnectionStatus:    "ONLINE",
		Transport:           "http-poll",
		PollIntervalSeconds: 10,
		LastSeen:            now,
		ConfigStatus:        "CONFIG_PENDING",
		ConfigID:            "java-policy-set",
		PolicyVersions:      map[string]int{config.ID: 1},
	}
	records := deploymentRecordsWithLiveCoverage(
		nil,
		map[string]Agent{agent.UID: agent},
		map[string][]Config{config.ID: {config}},
		now,
	)
	if len(records) != 1 {
		t.Fatalf("pending policy removal must be synthesized: %#v", records)
	}
	pending := records[0]
	if pending.DesiredPresence || pending.ObservedStatus != "REMOVAL_PENDING" ||
		pending.LiveStatus != "REMOVAL_PENDING" || pending.AppliedAt != nil ||
		!pending.CountsForLiveCoverage {
		t.Fatalf("unexpected pending synthetic removal: %#v", pending)
	}

	// Once the extension acknowledges the new bundle, the policy is absent.
	// The prior desired row proves this UID was a real removal target; a newly
	// started replica after deactivation would have no such evidence.
	agent.ConfigStatus = "APPLIED"
	agent.PolicyVersions = map[string]int{}
	history := []DeploymentRecord{{
		ConfigID:        config.ID,
		Version:         1,
		Target:          config.Target,
		AgentUID:        agent.UID,
		DesiredPresence: true,
		ObservedStatus:  "APPLIED",
		LastObservedAt:  now.Add(-time.Minute),
	}}
	records = deploymentRecordsWithLiveCoverage(
		history,
		map[string]Agent{agent.UID: agent},
		map[string][]Config{config.ID: {config}},
		now,
	)
	byVersion := recordsByVersion(records)
	removed := byVersion[config.Version]
	if removed.DesiredPresence || removed.ObservedStatus != "REMOVED" ||
		removed.LiveStatus != "REMOVED" || removed.AppliedAt == nil ||
		!removed.AppliedAt.Equal(agent.LastSeen) || !removed.CountsForLiveCoverage {
		t.Fatalf("unexpected confirmed synthetic removal: %#v", removed)
	}

	newReplica := agent
	newReplica.UID = "joined-after-deactivation"
	records = deploymentRecordsWithLiveCoverage(
		nil,
		map[string]Agent{newReplica.UID: newReplica},
		map[string][]Config{config.ID: {config}},
		now,
	)
	if len(records) != 0 {
		t.Fatalf("a new replica that never held the policy is not a removal target: %#v", records)
	}
}

func TestDeploymentCoverageSynthesizesCollectorFallback(t *testing.T) {
	now := time.Now().UTC()
	base := testCollectorBase()
	baseConfig := collectorBaseRemoteConfig(base)
	config := Config{
		ID:        "gateway-managed",
		Target:    "collector",
		Version:   4,
		Active:    false,
		Action:    "DEACTIVATED",
		UpdatedAt: now.Add(-time.Second),
		Selector:  AgentSelector{Services: []string{"gateway-supervisor"}},
	}
	agent := Agent{
		UID:                      "gateway-pod",
		Kind:                     "collector",
		Service:                  "gateway-supervisor",
		RemoteConfig:             true,
		ConnectionStatus:         "ONLINE",
		Transport:                "http-poll",
		PollIntervalSeconds:      10,
		LastSeen:                 now,
		ConfigStatus:             "APPLIED",
		ConfigID:                 base.ID,
		ConfigHash:               baseConfig.Hash,
		EffectiveConfigOrigin:    collectorOriginBase,
		LastManagedConfigID:      config.ID,
		LastManagedConfigVersion: 3,
		BaseConfig:               base,
	}
	records := deploymentRecordsWithLiveCoverage(
		nil,
		map[string]Agent{agent.UID: agent},
		map[string][]Config{config.ID: {config}},
		now,
	)
	if len(records) != 1 {
		t.Fatalf("collector fallback acknowledgement must be synthesized: %#v", records)
	}
	removed := records[0]
	if removed.DesiredPresence || removed.ObservedStatus != "REMOVED" ||
		removed.LiveStatus != "BASE_APPLIED" || removed.BundleHash != baseConfig.Hash ||
		removed.AppliedAt == nil || !removed.AppliedAt.Equal(agent.LastSeen) ||
		!removed.CountsForLiveCoverage {
		t.Fatalf("unexpected synthetic Collector fallback: %#v", removed)
	}
}

func TestDeploymentCoverageSynthesizesActiveCollectorSelectorNarrowing(t *testing.T) {
	now := time.Now().UTC()
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
		ConnectionStatus:         "ONLINE",
		Transport:                "http-poll",
		PollIntervalSeconds:      10,
		LastSeen:                 now,
		ConfigStatus:             "APPLIED",
		ConfigID:                 base.ID,
		ConfigHash:               baseConfig.Hash,
		EffectiveConfigOrigin:    collectorOriginBase,
		LastManagedConfigID:      config.ID,
		LastManagedConfigVersion: 1,
		BaseConfig:               base,
		Attributes: map[string]string{
			"deployment.environment.name": "production",
		},
	}
	records := deploymentRecordsWithLiveCoverage(
		nil,
		map[string]Agent{agent.UID: agent},
		map[string][]Config{config.ID: {config}},
		now,
	)
	if len(records) != 1 {
		t.Fatalf("selector narrowing must synthesize Collector fallback: %#v", records)
	}
	removed := records[0]
	if removed.DesiredPresence || removed.ObservedStatus != "REMOVED" ||
		removed.LiveStatus != "BASE_APPLIED" || removed.CountsForLiveCoverage ||
		removed.CoverageState != coverageHistorical || removed.AppliedAt == nil {
		t.Fatalf("confirmed narrowed Collector fallback must become history: %#v", removed)
	}

	newReplica := agent
	newReplica.UID = "unmatched-new-gateway"
	newReplica.LastManagedConfigID = ""
	newReplica.LastManagedConfigVersion = 0
	records = deploymentRecordsWithLiveCoverage(
		nil,
		map[string]Agent{newReplica.UID: newReplica},
		map[string][]Config{config.ID: {config}},
		now,
	)
	if len(records) != 0 {
		t.Fatalf("unmatched new Collector must not get a fabricated fallback: %#v", records)
	}
}

func TestDeploymentCoverageSynthesizesManagedCollectorReplacement(t *testing.T) {
	now := time.Now().UTC()
	former := Config{
		ID:      "gateway-former",
		Target:  "collector",
		Version: 2,
		Active:  true,
		Action:  "PUBLISHED",
		Selector: AgentSelector{Attributes: map[string]string{
			"collector.role": "former",
		}},
	}
	agent := Agent{
		UID:                      "gateway",
		Kind:                     "collector",
		Service:                  "gateway-supervisor",
		RemoteConfig:             true,
		ConnectionStatus:         "ONLINE",
		Transport:                "http-poll",
		PollIntervalSeconds:      10,
		LastSeen:                 now,
		ConfigStatus:             "APPLIED",
		ConfigID:                 "gateway-replacement",
		ConfigHash:               "replacement-hash",
		Version:                  5,
		EffectiveConfigOrigin:    collectorOriginManaged,
		LastManagedConfigID:      "gateway-replacement",
		LastManagedConfigVersion: 5,
		BaseConfig:               testCollectorBase(),
		Attributes: map[string]string{
			"collector.role": "replacement",
		},
	}
	history := []DeploymentRecord{{
		ConfigID:        former.ID,
		Version:         1,
		Target:          former.Target,
		AgentUID:        agent.UID,
		DesiredPresence: true,
		ObservedStatus:  "APPLIED",
		LastObservedAt:  now.Add(-time.Minute),
	}}
	records := deploymentRecordsWithLiveCoverage(
		history,
		map[string]Agent{agent.UID: agent},
		map[string][]Config{former.ID: {former}},
		now,
	)
	replacement := recordsByVersion(records)[former.Version]
	if replacement.DesiredPresence || replacement.ObservedStatus != "REMOVED" ||
		replacement.LiveStatus != "REMOVED" ||
		replacement.BundleHash != agent.ConfigHash || replacement.AppliedAt == nil ||
		replacement.CountsForLiveCoverage || replacement.CoverageState != coverageHistorical {
		t.Fatalf("managed replacement did not confirm former config removal: %#v", replacement)
	}
}

func TestSyntheticAppliedDeploymentHasConfirmationTimestamp(t *testing.T) {
	now := time.Now().UTC()
	config := Config{
		ID:       "policy",
		Target:   "java-extension",
		Version:  1,
		Active:   true,
		Action:   "PUBLISHED",
		Selector: AgentSelector{Services: []string{"exchange-service"}},
	}
	agent := Agent{
		UID:                 "exchange-pod",
		Kind:                "java-extension",
		Service:             "exchange-service",
		Transport:           "http-poll",
		PollIntervalSeconds: 10,
		ConnectionStatus:    "ONLINE",
		LastSeen:            now,
		ConfigStatus:        "APPLIED",
		ConfigID:            "java-policy-set",
		PolicyVersions:      map[string]int{config.ID: config.Version},
	}
	records := deploymentRecordsWithLiveCoverage(
		nil,
		map[string]Agent{agent.UID: agent},
		map[string][]Config{config.ID: {config}},
		now,
	)
	if len(records) != 1 || records[0].AppliedAt == nil ||
		!records[0].AppliedAt.Equal(agent.LastSeen) {
		t.Fatalf("synthetic APPLIED record lacks confirmation time: %#v", records)
	}
}

func TestDeploymentCoverageDegradedPollIsVisibleButNotCounted(t *testing.T) {
	now := time.Now().UTC()
	agent := Agent{
		UID:                 "degraded",
		Kind:                "collector",
		Service:             "gateway-supervisor",
		RemoteConfig:        true,
		Transport:           "http-poll",
		PollIntervalSeconds: 10,
		ConnectionStatus:    "ONLINE",
		LastSeen:            now.Add(-45 * time.Second),
	}
	record := DeploymentRecord{
		Target:   "collector",
		AgentUID: agent.UID,
		Selector: AgentSelector{Services: []string{agent.Service}},
	}
	applyDeploymentCoverageState(&record, map[string]Agent{agent.UID: agent}, now)
	if record.CoverageState != coverageInScopeDegraded || record.CountsForLiveCoverage {
		t.Fatalf("degraded agent must not distort live rollout coverage: %#v", record)
	}
}

func TestAgentSignalStatusDoesNotClaimInfrastructurePresence(t *testing.T) {
	tests := map[string]string{
		"CONNECTED":    "CONNECTED",
		"ONLINE":       "CONNECTED",
		"DEGRADED":     "STALE",
		"OFFLINE":      "UNREACHABLE",
		"DISCONNECTED": "UNREACHABLE",
		"":             "UNKNOWN",
	}
	for input, expected := range tests {
		if actual := agentSignalStatus(input); actual != expected {
			t.Fatalf("agentSignalStatus(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestObservedConnectionStatusRequiresCurrentWebsocketConnection(t *testing.T) {
	now := time.Now().UTC()
	agent := Agent{
		Transport:        "websocket",
		ConnectionStatus: "CONNECTED",
		LastSeen:         now,
	}
	status, _ := observedConnectionStatus(agent, false, now)
	if status != "DISCONNECTED" {
		t.Fatalf("persisted websocket state must not survive a server restart: %s", status)
	}
	status, _ = observedConnectionStatus(agent, true, now)
	if status != "CONNECTED" {
		t.Fatalf("active websocket connection was not preserved: %s", status)
	}
}

func recordsByAgentUID(records []DeploymentRecord) map[string]DeploymentRecord {
	result := make(map[string]DeploymentRecord, len(records))
	for _, record := range records {
		result[record.AgentUID] = record
	}
	return result
}

func recordsByVersion(records []DeploymentRecord) map[int]DeploymentRecord {
	result := make(map[int]DeploymentRecord, len(records))
	for _, record := range records {
		result[record.Version] = record
	}
	return result
}
