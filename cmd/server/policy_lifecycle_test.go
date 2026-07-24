package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestEffectiveJavaPolicySetCombinesMatchingPoliciesDeterministically(t *testing.T) {
	resetState(t)
	now := time.Now().UTC()
	agent := Agent{
		UID:     "java-1",
		Kind:    "java-extension",
		Service: "exchange-service",
		Attributes: map[string]string{
			"deployment.environment.name": "local",
		},
	}
	state.Configs["z-policy"] = []Config{{
		ID:        "z-policy",
		Target:    "java-extension",
		Body:      `{"schemaVersion":"1.3","requestHeaders":[]}`,
		Version:   2,
		Active:    true,
		Action:    "PUBLISHED",
		UpdatedAt: now,
		Selector:  AgentSelector{Services: []string{"exchange-service"}},
	}}
	state.Configs["a-policy"] = []Config{{
		ID:      "a-policy",
		Target:  "java-extension",
		Body:    `{"schemaVersion":"1.3","responseHeaders":[]}`,
		Version: 4,
		Active:  true,
		Action:  "PUBLISHED",
		Selector: AgentSelector{Attributes: map[string]string{
			"deployment.environment.name": "local",
		}},
	}}
	state.Configs["other-service"] = []Config{{
		ID:       "other-service",
		Target:   "java-extension",
		Body:     `{"schemaVersion":"1.3"}`,
		Version:  1,
		Active:   true,
		Action:   "PUBLISHED",
		Selector: AgentSelector{Services: []string{"rates-service"}},
	}}

	bundle, policies, err := effectiveJavaPolicySet(agent)
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 2 || policies[0].ID != "a-policy" || policies[1].ID != "z-policy" {
		t.Fatalf("unexpected effective policies: %#v", policies)
	}
	var envelope policySetEnvelope
	if err := json.Unmarshal([]byte(bundle.Body), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.APIVersion != "o11y.dev/v1" || envelope.Kind != "PolicySet" || envelope.Revision == "" {
		t.Fatalf("unexpected envelope metadata: %#v", envelope)
	}
	if len(envelope.Policies) != 2 || envelope.Policies[0].ID != "a-policy" || envelope.Policies[1].ID != "z-policy" {
		t.Fatalf("policy set is not ordered by id: %#v", envelope.Policies)
	}

	again, _, err := effectiveJavaPolicySet(agent)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.Body != again.Body || bundle.Hash != again.Hash {
		t.Fatal("the same active policy set must produce a stable body and hash")
	}
	file := remote("java-extension", bundle).Config.ConfigMap["dev.o11y/http-headers.json"]
	if file == nil || string(file.Body) != bundle.Body || file.ContentType != "application/json" {
		t.Fatalf("unexpected OpAMP policy set file: %#v", file)
	}
}

func TestEffectiveJavaPolicySetCanBeEmptyToRemoveLastPolicy(t *testing.T) {
	resetState(t)
	state.Configs["only-policy"] = []Config{
		{ID: "only-policy", Target: "java-extension", Body: `{}`, Version: 1, Active: true, Action: "PUBLISHED"},
		{ID: "only-policy", Target: "java-extension", Body: `{}`, Version: 2, SourceVersion: 1, Active: false, Action: "DEACTIVATED"},
	}
	bundle, policies, err := effectiveJavaPolicySet(Agent{Kind: "java-extension"})
	if err != nil {
		t.Fatal(err)
	}
	if len(policies) != 0 {
		t.Fatalf("deactivated policy remained effective: %#v", policies)
	}
	var envelope policySetEnvelope
	if err := json.Unmarshal([]byte(bundle.Body), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Policies == nil || len(envelope.Policies) != 0 {
		t.Fatalf("empty policy set must use an empty JSON array: %s", bundle.Body)
	}
}

func TestSemanticRollbackLineageDoesNotOscillate(t *testing.T) {
	versions := []Config{
		{ID: "policy", Target: "java-extension", Version: 1, SourceVersion: 1, Action: "PUBLISHED"},
		{ID: "policy", Target: "java-extension", Version: 2, SourceVersion: 2, Action: "PUBLISHED"},
	}
	predecessor, ok := previousPublishedPolicy(versions, 2)
	if !ok || predecessor.Version != 1 {
		t.Fatalf("v2 must roll back to v1, got %#v", predecessor)
	}

	// A journal v3 copied from v1 has SourceVersion=1. Another rollback must
	// deactivate instead of returning to the discarded v2 content.
	versions = append(versions, Config{
		ID: "policy", Target: "java-extension", Version: 3, SourceVersion: 1, Action: "ROLLBACK",
	})
	if predecessor, ok := previousPublishedPolicy(versions, versions[2].SourceVersion); ok {
		t.Fatalf("rollback from the first effective source must deactivate, got %#v", predecessor)
	}
}

func TestPolicySetLimitsProtectFutureReplicas(t *testing.T) {
	policies := make([]Config, 0, maxPoliciesPerSet+1)
	for index := 0; index <= maxPoliciesPerSet; index++ {
		policies = append(policies, Config{
			ID:      fmt.Sprintf("policy-%02d", index),
			Body:    `{}`,
			Version: 1,
		})
	}
	if _, _, err := encodePolicySet(policies); err == nil {
		t.Fatalf("expected more than %d policies to be rejected", maxPoliciesPerSet)
	}
}

func TestPolicySetRejectsCrossPolicyInternalIDCollisions(t *testing.T) {
	first := testPolicy("test.first.events", "COUNTER")
	second := testPolicy("test.second.events", "COUNTER")
	// Keep metric series distinct so this test isolates the internal policy-ID
	// namespace shared by the effective PolicySet.
	second.MetricPolicies[0].Name = "test.second.http.duration"
	second.MethodPolicies[0].Metrics[0].Name = "test.second.events"
	policies := []Config{
		{ID: "first", Target: "java-extension", Body: encodePolicy(t, first), Version: 1},
		{ID: "second", Target: "java-extension", Body: encodePolicy(t, second), Version: 1},
	}
	if err := validatePolicySetCompatibility(policies); err == nil {
		t.Fatal("duplicate internal IDs across policies must be rejected before publication")
	}
	second.MetricPolicies[0].ID = "second-http-v1"
	second.MethodPolicies[0].ID = "second-method-v1"
	policies[1].Body = encodePolicy(t, second)
	if err := validatePolicySetCompatibility(policies); err != nil {
		t.Fatalf("distinct policy namespaces should compose: %v", err)
	}
}

func TestPolicySetDeduplicatesSharedHeadersAndLimitsUniqueUnion(t *testing.T) {
	first := javaPolicy{SchemaVersion: "1.3"}
	second := javaPolicy{SchemaVersion: "1.3"}
	for index := 0; index < 10; index++ {
		first.RequestHeaders = append(first.RequestHeaders, namedValue{Name: fmt.Sprintf("x-first-%02d", index)})
		second.RequestHeaders = append(second.RequestHeaders, namedValue{Name: fmt.Sprintf("x-second-%02d", index)})
	}
	policies := []Config{
		{ID: "first", Target: "java-extension", Body: encodePolicy(t, first), Version: 1},
		{ID: "second", Target: "java-extension", Body: encodePolicy(t, second), Version: 1},
	}
	if err := validatePolicySetCompatibility(policies); err == nil {
		t.Fatal("more than 16 unique request headers across the PolicySet must be rejected")
	}

	second.RequestHeaders = append([]namedValue(nil), first.RequestHeaders...)
	policies[1].Body = encodePolicy(t, second)
	if err := validatePolicySetCompatibility(policies); err != nil {
		t.Fatalf("shared header names must be deduplicated before enforcing the limit: %v", err)
	}
}

func TestPolicySetKeepsTheSameHeaderInBothDirections(t *testing.T) {
	first := javaPolicy{
		SchemaVersion:  "1.3",
		RequestHeaders: []namedValue{{Name: "X-Correlation-ID"}},
	}
	second := javaPolicy{
		SchemaVersion:  "1.3",
		RequestHeaders: []namedValue{{Name: "x-correlation-id", Direction: "OUTGOING"}},
	}
	merged := javaPolicy{SchemaVersion: "1.3"}
	seen := map[string]bool{}
	mergePolicySetHeaders(&merged.RequestHeaders, seen, first.RequestHeaders)
	mergePolicySetHeaders(&merged.RequestHeaders, seen, second.RequestHeaders)

	if len(merged.RequestHeaders) != 2 {
		t.Fatalf("expected an isolated header per direction, got %#v", merged.RequestHeaders)
	}
	if merged.RequestHeaders[0].Direction != "INCOMING" || merged.RequestHeaders[1].Direction != "OUTGOING" {
		t.Fatalf("directions were not normalized and preserved: %#v", merged.RequestHeaders)
	}
	if err := validateHeaderLists(merged); err != nil {
		t.Fatalf("effective directional headers should be valid: %v", err)
	}
}

func TestPolicyIDMustBeCompatibleWithPolicySetEnvelope(t *testing.T) {
	resetState(t)
	body := encodePolicy(t, testPolicy("test.policy.id", "COUNTER"))
	if err := validateJavaPolicy("valid-policy.v1", body); err != nil {
		t.Fatalf("valid policy id was rejected: %v", err)
	}
	if err := validateJavaPolicy("Invalid Policy", body); err == nil {
		t.Fatal("expected invalid policy id to be rejected")
	}
}

func TestJavaPolicyRemovalDeploymentUsesAcknowledgedPolicyMap(t *testing.T) {
	resetState(t)
	previousQueue := deploymentUpdates
	deploymentUpdates = make(chan DeploymentUpdate, 4)
	t.Cleanup(func() { deploymentUpdates = previousQueue })
	state.Configs["only-policy"] = []Config{
		{ID: "only-policy", Target: "java-extension", Body: `{}`, Version: 1, Active: true, Action: "PUBLISHED"},
		{ID: "only-policy", Target: "java-extension", Body: `{}`, Version: 2, SourceVersion: 1, Active: false, Action: "DEACTIVATED"},
	}
	agent := Agent{
		UID:              "java-1",
		Kind:             "java-extension",
		ConnectionStatus: "CONNECTED",
		PolicyVersions:   map[string]int{"only-policy": 1},
	}
	bundle, policies, err := effectiveJavaPolicySet(agent)
	if err != nil {
		t.Fatal(err)
	}
	queueJavaPolicyDeployments(bundle, policies, agent, "APPLIED")
	update := <-deploymentUpdates
	if update.Config.Version != 2 || update.DesiredPresence || update.Status != "REMOVED" || update.BundleHash != bundle.Hash {
		t.Fatalf("unexpected removal deployment: %#v", update)
	}
}

func TestPolicySetHashIsUsedAcrossHeartbeat(t *testing.T) {
	bundle := Config{ID: "java-policy-set", Target: "java-extension", Hash: "bundle-hash"}
	agent := Agent{ConfigHash: bundle.Hash, ConfigID: bundle.ID, ConfigStatus: "APPLIED"}
	if !hasLatestRemoteConfig(agent, nil, bundle) {
		t.Fatal("persisted PolicySet hash must avoid resending an unchanged bundle")
	}
	pendingFirstPoll := Agent{ConfigID: bundle.ID, Version: 0, ConfigStatus: "CONFIG_PENDING"}
	if hasLatestRemoteConfig(pendingFirstPoll, nil, bundle) {
		t.Fatal("PolicySet ID/version without an acknowledged hash must not be considered applied")
	}
}

func TestDeploymentLiveStatusTracksCurrentVersionAndConfirmedRemoval(t *testing.T) {
	now := time.Now().UTC()
	agent := Agent{
		UID:              "java-1",
		Kind:             "java-extension",
		ConnectionStatus: "CONNECTED",
		ConfigID:         "java-policy-set",
		ConfigStatus:     "APPLIED",
		PolicyVersions:   map[string]int{"policy": 2},
		LastSeen:         now,
	}
	v1 := DeploymentRecord{
		ConfigID:        "policy",
		Version:         1,
		Target:          "java-extension",
		DesiredPresence: true,
		ObservedStatus:  "APPLIED",
	}
	applyDeploymentLiveState(&v1, agent, now)
	if v1.LiveStatus != "SUPERSEDED" || !v1.PolicyPresent || v1.CurrentPolicyVersion != 2 {
		t.Fatalf("unexpected historical version state: %#v", v1)
	}
	v2 := v1
	v2.Version = 2
	applyDeploymentLiveState(&v2, agent, now)
	if v2.LiveStatus != "APPLIED" {
		t.Fatalf("current policy version is not live: %#v", v2)
	}
	offlineAgent := agent
	offlineAgent.ConnectionStatus = "DISCONNECTED"
	applyDeploymentLiveState(&v2, offlineAgent, now)
	if v2.LiveStatus != "APPLIED_OFFLINE" {
		t.Fatalf("offline last-known state must not be reported as live APPLIED: %#v", v2)
	}

	removedAgent := agent
	removedAgent.PolicyVersions = map[string]int{}
	removal := DeploymentRecord{
		ConfigID:        "policy",
		Version:         3,
		Target:          "java-extension",
		DesiredPresence: false,
		ObservedStatus:  "REMOVED",
	}
	applyDeploymentLiveState(&removal, removedAgent, now)
	if removal.LiveStatus != "REMOVED" || removal.PolicyPresent {
		t.Fatalf("confirmed removal is not reflected as live: %#v", removal)
	}
}

func TestValidateJavaPolicyRejectsUnsupportedMethodCaptureType(t *testing.T) {
	resetState(t)
	policy := testPolicy("test.capture.type", "COUNTER")
	policy.MethodPolicies[0].Captures[0].Type = "DECIMAL"
	err := validateJavaPolicy("capture-type-policy", encodePolicy(t, policy))
	if err == nil || !strings.Contains(err.Error(), "unsupported capture type DECIMAL") {
		t.Fatalf("expected capture type validation aligned with Java, got %v", err)
	}
}

func TestMethodPackageCompatibilityUsesMatchingKnownDestinations(t *testing.T) {
	resetState(t)
	policy := testPolicy("test.method.packages", "COUNTER")
	config := Config{
		ID:       "method-package-policy",
		Target:   "java-extension",
		Body:     encodePolicy(t, policy),
		Active:   true,
		Selector: AgentSelector{Services: []string{"exchange-service"}},
	}

	// Creating a policy before its first replica exists is supported.
	if err := validateMethodPackagesForKnownAgents(config); err != nil {
		t.Fatalf("no known destination must defer compatibility to connect time: %v", err)
	}
	state.Agents["allowed"] = Agent{
		UID:              "allowed",
		Kind:             "java-extension",
		Service:          "exchange-service",
		ConnectionStatus: "CONNECTED",
		Attributes: map[string]string{
			// Exercise canonicalization of an older mixed-case resource key.
			"O11y.method.packages": "dev.o11y.rates, dev.o11y.exchange.service",
		},
	}
	state.Agents["unrelated"] = Agent{
		UID:              "unrelated",
		Kind:             "java-extension",
		Service:          "rates-service",
		ConnectionStatus: "CONNECTED",
		Attributes: map[string]string{
			"o11y.method.packages": "dev.unrelated",
		},
	}
	if err := validateMethodPackagesForKnownAgents(config); err != nil {
		t.Fatalf("parent package advertised by the matching destination must allow the policy: %v", err)
	}

	state.Agents["blocked"] = Agent{
		UID:              "blocked",
		Kind:             "java-extension",
		Service:          "exchange-service",
		ConnectionStatus: "CONNECTED",
		Attributes: map[string]string{
			"o11y.method.packages": "dev.o11y.exchange.service",
		},
	}
	err := validateMethodPackagesForKnownAgents(config)
	if err == nil ||
		!strings.Contains(err.Error(), "uid=blocked service=exchange-service") ||
		!strings.Contains(err.Error(), "packagePrefix=dev.o11y.rates.service") {
		t.Fatalf("mixed destination compatibility must identify the blocked target: %v", err)
	}

	historical := state.Agents["blocked"]
	historical.ConnectionStatus = "OFFLINE"
	state.Agents["blocked"] = historical
	if err := validateMethodPackagesForKnownAgents(config); err != nil {
		t.Fatalf("a historical incompatible destination must not block publication: %v", err)
	}
}

func TestHTTPAndDisabledMethodPoliciesDoNotRequireMethodAllowlist(t *testing.T) {
	resetState(t)
	state.Agents["no-method-capability"] = Agent{
		UID:        "no-method-capability",
		Kind:       "java-extension",
		Service:    "exchange-service",
		Attributes: map[string]string{},
	}
	policy := testPolicy("test.http.only", "COUNTER")
	policy.MethodPolicies = nil
	config := Config{
		ID:       "http-only-policy",
		Target:   "java-extension",
		Body:     encodePolicy(t, policy),
		Selector: AgentSelector{Services: []string{"exchange-service"}},
	}
	if err := validateMethodPackagesForKnownAgents(config); err != nil {
		t.Fatalf("HTTP-only policy must not depend on method package capability: %v", err)
	}

	policy.MethodPolicies = testPolicy("test.disabled.method", "COUNTER").MethodPolicies
	policy.MethodPolicies[0].Enabled = false
	config.Body = encodePolicy(t, policy)
	if err := validateMethodPackagesForKnownAgents(config); err != nil {
		t.Fatalf("disabled method policy must not depend on method package capability: %v", err)
	}
}

func TestPolicySchemaCompatibilityUsesMatchingKnownDestinations(t *testing.T) {
	resetState(t)
	policy := bodyEventTestPolicy()
	policy.SchemaVersion = "1.4"
	policy.BodyEventPolicies[0].Fields = append(
		policy.BodyEventPolicies[0].Fields,
		bodyField{
			Attribute: "campaign.id", Source: "REQUEST_QUERY", Path: "campaign_id",
			Type: "STRING", Destinations: []string{"SPAN"},
		},
	)
	config := Config{
		ID:       "schema-14-policy",
		Target:   "java-extension",
		Body:     encodePolicy(t, policy),
		Active:   true,
		Selector: AgentSelector{Services: []string{"exchange-service"}},
	}
	if err := validatePolicySchemaForKnownAgents(config); err != nil {
		t.Fatalf("a policy may be authored before its first destination exists: %v", err)
	}
	state.Agents["legacy"] = Agent{
		UID:              "legacy",
		Kind:             "java-extension",
		Service:          "exchange-service",
		ConnectionStatus: "CONNECTED",
		Attributes: map[string]string{
			"o11y.policy.schema": "1.3",
		},
	}
	err := validatePolicySchemaForKnownAgents(config)
	if err == nil || !strings.Contains(err.Error(), "requires o11y.policy.schema >= 1.4") {
		t.Fatalf("expected schema 1.3 destination to be rejected, got %v", err)
	}
	historical := state.Agents["legacy"]
	historical.ConnectionStatus = "OFFLINE"
	state.Agents["legacy"] = historical
	if err := validatePolicySchemaForKnownAgents(config); err != nil {
		t.Fatalf("a historical schema 1.3 destination must not block publication: %v", err)
	}
	state.Agents["modern"] = Agent{
		UID:              "modern",
		Kind:             "java-extension",
		Service:          "exchange-service",
		ConnectionStatus: "CONNECTED",
		Attributes: map[string]string{
			"O11y.policy.schema": "1.4",
		},
	}
	if err := validatePolicySchemaForKnownAgents(config); err != nil {
		t.Fatalf("canonicalized schema 1.4 capability must be accepted: %v", err)
	}
}

func TestEffectivePolicyValidationUsesMaximumSchema(t *testing.T) {
	classic := bodyEventTestPolicy()
	extended := bodyEventTestPolicy()
	extended.SchemaVersion = "1.4"
	extended.BodyEventPolicies[0].ID = "extended-event"
	extended.BodyEventPolicies[0].EventName = "extended-event"
	extended.BodyEventPolicies[0].Fields[0].Source = "REQUEST_HEADER"
	extended.BodyEventPolicies[0].Fields[0].Path = "x-client-type"
	extended.EventMetricPolicies = nil
	policies := []Config{
		{ID: "classic", Body: encodePolicy(t, classic)},
		{ID: "extended", Body: encodePolicy(t, extended)},
	}
	if got := maximumPolicySchema(policies); got != "1.4" {
		t.Fatalf("expected maximum policy schema 1.4, got %s", got)
	}
	if err := validatePolicySetCompatibility(policies); err != nil {
		t.Fatalf("1.3 and 1.4 policies must compose using the maximum schema: %v", err)
	}
}

func TestDeploymentLiveStatusPreservesLegacyLastAcknowledgement(t *testing.T) {
	now := time.Now().UTC()
	record := DeploymentRecord{
		ConfigID:        "legacy-policy",
		Version:         1,
		Target:          "java-extension",
		DesiredPresence: true,
		ObservedStatus:  "APPLIED",
	}
	legacy := Agent{
		UID:              "legacy-agent",
		Kind:             "java-extension",
		ConnectionStatus: "DISCONNECTED",
		ConfigID:         "legacy-policy",
		Version:          1,
		ConfigStatus:     "APPLIED",
		PolicyVersions:   map[string]int{},
		LastSeen:         now.Add(-time.Hour),
	}
	applyDeploymentLiveState(&record, legacy, now)
	if record.LiveStatus != "APPLIED_OFFLINE" || !record.PolicyPresent || record.CurrentPolicyVersion != 1 {
		t.Fatalf("legacy acknowledgement was not preserved as last-known offline state: %#v", record)
	}

	legacy.ConnectionStatus = "CONNECTED"
	applyDeploymentLiveState(&record, legacy, now)
	if record.LiveStatus != "APPLIED_STALE" {
		t.Fatalf("legacy acknowledgement must not be promoted to live APPLIED: %#v", record)
	}

	newAgent := legacy
	newAgent.ConfigID = "java-policy-set"
	newAgent.Version = 0
	applyDeploymentLiveState(&record, newAgent, now)
	if record.PolicyPresent || record.LiveStatus == "APPLIED_OFFLINE" || record.LiveStatus == "APPLIED_STALE" {
		t.Fatalf("legacy fallback leaked into a PolicySet agent: %#v", record)
	}

	otherVersion := record
	otherVersion.Version = 2
	legacy.ConnectionStatus = "DISCONNECTED"
	applyDeploymentLiveState(&otherVersion, legacy, now)
	if otherVersion.PolicyPresent || otherVersion.LiveStatus == "APPLIED_OFFLINE" {
		t.Fatalf("legacy fallback must require an exact policy version match: %#v", otherVersion)
	}
}

func TestVersionedRollbackIsCollectorOnly(t *testing.T) {
	if err := validateVersionedRollbackTarget(Config{Target: "collector"}); err != nil {
		t.Fatalf("Collector historical rollback must remain supported: %v", err)
	}
	err := validateVersionedRollbackTarget(Config{Target: "java-extension"})
	if err == nil || !strings.Contains(err.Error(), "/api/policies/{id}/rollback") {
		t.Fatalf("Java historical rollback must direct callers to semantic lifecycle endpoint: %v", err)
	}
}
