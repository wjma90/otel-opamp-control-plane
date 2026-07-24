package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-telemetry/opamp-go/protobufs"
	"github.com/open-telemetry/opamp-go/server/types"
)

func TestAgentHintsExposeSupervisorIdentityForSelectors(t *testing.T) {
	header := http.Header{}
	header.Set("X-Service-Name", "o11y-infra-monitoring-supervisor")
	header.Set("X-O11y-Cluster", "o11y-infra")
	header.Set("X-O11y-Collector-Role", "cluster-monitoring")
	header.Set("X-O11y-Managed-By", "opamp-supervisor")

	hints := agentHints(&http.Request{Method: http.MethodGet, Header: header})

	if hints.service != "o11y-infra-monitoring-supervisor" {
		t.Fatalf("unexpected service hint: %s", hints.service)
	}
	if hints.attributes["k8s.cluster.name"] != "o11y-infra" ||
		hints.attributes["collector.role"] != "cluster-monitoring" ||
		hints.attributes["managed_by"] != "opamp-supervisor" ||
		hints.transport != "websocket" {
		t.Fatalf("unexpected connection hints: %#v", hints)
	}
}

func TestCanonicalAttributeKeyNormalizesO11yNamespace(t *testing.T) {
	tests := map[string]string{
		"o11y.opamp.transport":       "o11y.opamp.transport",
		"O11yLegacy.opamp.transport": "o11y.opamp.transport",
		"service.name":               "service.name",
	}
	for input, expected := range tests {
		if actual := canonicalAttributeKey(input); actual != expected {
			t.Fatalf("canonicalAttributeKey(%q) = %q, want %q", input, actual, expected)
		}
	}
}

func TestHTTPPollingStatusAllowsThreeMissedPolls(t *testing.T) {
	now := time.Now().UTC()
	agent := Agent{
		Transport:           "http-poll",
		PollIntervalSeconds: 10,
		LastSeen:            now.Add(-20 * time.Second),
	}
	status, next := liveStatus(agent, now)
	if status != "ONLINE" || !next.Equal(agent.LastSeen.Add(10*time.Second)) {
		t.Fatalf("expected ONLINE with next poll timestamp, got %s %s", status, next)
	}
	agent.LastSeen = now.Add(-45 * time.Second)
	status, _ = liveStatus(agent, now)
	if status != "DEGRADED" {
		t.Fatalf("expected DEGRADED, got %s", status)
	}
	agent.LastSeen = now.Add(-70 * time.Second)
	status, _ = liveStatus(agent, now)
	if status != "OFFLINE" {
		t.Fatalf("expected OFFLINE, got %s", status)
	}
}

func TestNewReplicaReceivesLatestDynamicSelectorPolicy(t *testing.T) {
	resetState(t)
	now := time.Now().UTC()
	state.Configs["exchange-policy"] = []Config{{
		ID:        "exchange-policy",
		Target:    "java-extension",
		Version:   4,
		UpdatedAt: now,
		Selector: AgentSelector{
			Services: []string{"exchange-service"},
			Attributes: map[string]string{
				"deployment.environment.name": "local",
			},
		},
	}}

	newReplica := Agent{
		UID:     "brand-new-instance-uid",
		Kind:    "java-extension",
		Service: "exchange-service",
		Attributes: map[string]string{
			"deployment.environment.name": "local",
		},
		RemoteConfig: true,
	}
	selected, ok := latestForAgent(newReplica)
	if !ok || selected.ID != "exchange-policy" || selected.Version != 4 {
		t.Fatalf("new matching replica did not receive latest policy: %#v", selected)
	}

	state.Configs["exact-canary"] = []Config{{
		ID:        "exact-canary",
		Target:    "java-extension",
		Version:   1,
		UpdatedAt: now.Add(time.Second),
		Selector:  AgentSelector{InstanceUIDs: []string{"old-instance-uid"}},
	}}
	selected, ok = latestForAgent(newReplica)
	if !ok || selected.ID != "exchange-policy" {
		t.Fatalf("an exact selector for another UID must not capture the replica: %#v", selected)
	}
}

func TestHTTPCollectorReceivesTenSecondPollingOffer(t *testing.T) {
	resetState(t)
	hints := connectionHints{
		transport:           "http-poll",
		pollIntervalSeconds: 10,
		opampEndpoint:       "http://control-plane.o11y.svc.cluster.local:4320/v1/opamp",
	}
	capabilities := uint64(
		protobufs.AgentCapabilities_AgentCapabilities_ReportsHeartbeat,
	)

	offer := pollingConnectionSettings("collector", capabilities, hints)
	if offer == nil || offer.Opamp == nil {
		t.Fatal("expected HTTP Collector polling settings")
	}
	if offer.Opamp.HeartbeatIntervalSeconds != 10 {
		t.Fatalf("expected a 10 second polling interval, got %d", offer.Opamp.HeartbeatIntervalSeconds)
	}
	if offer.Opamp.DestinationEndpoint != hints.opampEndpoint {
		t.Fatalf("unexpected endpoint: %s", offer.Opamp.DestinationEndpoint)
	}
	if len(offer.Hash) == 0 {
		t.Fatal("connection settings must have a stable hash")
	}
	if pollingConnectionSettings("java-extension", capabilities, hints) != nil {
		t.Fatal("Java extensions manage their own HTTP polling interval")
	}

	first := pollingConnectionSettingsForAgent("collector-1", "collector", capabilities, hints)
	second := pollingConnectionSettingsForAgent("collector-1", "collector", capabilities, hints)
	if first == nil || second != nil {
		t.Fatal("the same polling offer must be sent only once per Collector instance")
	}
}

func TestHasLatestRemoteConfigPreservesAppliedStatusAcrossHeartbeat(t *testing.T) {
	config := Config{ID: "app-collector", Version: 3, Hash: "abc123"}
	agent := Agent{
		ConfigID:     config.ID,
		Version:      config.Version,
		ConfigStatus: "APPLIED",
	}

	if !hasLatestRemoteConfig(agent, nil, config) {
		t.Fatal("a heartbeat without RemoteConfigStatus must preserve the known applied version")
	}

	newVersion := config
	newVersion.Version++
	if hasLatestRemoteConfig(agent, nil, newVersion) {
		t.Fatal("a new policy version must be sent even when the previous version was applied")
	}

	reported := &protobufs.RemoteConfigStatus{LastRemoteConfigHash: []byte(config.Hash)}
	if !hasLatestRemoteConfig(Agent{}, reported, config) {
		t.Fatal("the agent-reported hash must be authoritative")
	}
}

func TestServerAcceptsAndPersistsReportedEffectiveConfig(t *testing.T) {
	capabilities := serverCapabilities()
	if capabilities&uint64(protobufs.ServerCapabilities_ServerCapabilities_OffersRemoteConfig) == 0 {
		t.Fatal("server must offer remote config")
	}
	if capabilities&uint64(protobufs.ServerCapabilities_ServerCapabilities_AcceptsEffectiveConfig) == 0 {
		t.Fatal("server must advertise effective config support")
	}
	if capabilities&uint64(protobufs.ServerCapabilities_ServerCapabilities_OffersConnectionSettings) == 0 {
		t.Fatal("server must advertise connection settings for HTTP polling")
	}

	reported := reportedEffectiveConfig(&protobufs.AgentConfigMap{ConfigMap: map[string]*protobufs.AgentConfigFile{
		"collector.yaml": {
			Body:        []byte("receivers:\n  otlp: {}\n"),
			ContentType: "text/yaml",
		},
	}})
	if reported["collector.yaml"].Body != "receivers:\n  otlp: {}\n" ||
		reported["collector.yaml"].ContentType != "text/yaml" {
		t.Fatalf("unexpected effective config: %#v", reported)
	}
}

func TestFullStateIsRequestedUntilJavaResourceAttributesArrive(t *testing.T) {
	partial := Agent{
		Kind:       "java-extension",
		Attributes: map[string]string{"o11y.opamp.transport": "http-poll"},
	}
	if !needsFullStateReport(partial, false) {
		t.Fatal("connection hints alone are not enough for resource-attribute selectors")
	}
	partial.Attributes["agent.type"] = "java-extension"
	if needsFullStateReport(partial, false) {
		t.Fatal("a complete Java Agent description must not be requested repeatedly")
	}
}

func TestValidateJavaPolicyAcceptsGovernedHTTPAndMethodMetrics(t *testing.T) {
	resetState(t)
	body := encodePolicy(t, testPolicy("test.business.events", "COUNTER"))

	if err := validateJavaPolicy("test-policy", body); err != nil {
		t.Fatalf("expected policy to be valid: %v", err)
	}
}

func TestPolicyLevelDenylistIsRejectedInFavorOfControlPlaneSecurity(t *testing.T) {
	resetState(t)
	policy := testPolicy("test.global.denylist", "COUNTER")
	policy.DeniedHeaders = []namedValue{{Name: "authorization"}}

	err := validateJavaPolicy("legacy-denylist", encodePolicy(t, policy))
	if err == nil || !strings.Contains(err.Error(), "Control Plane security denylist") {
		t.Fatalf("expected legacy policy denylist rejection, got %v", err)
	}
}

func TestNormalizeSecurityDenylistValidatesAndCanonicalizesEntries(t *testing.T) {
	entries, err := normalizeSecurityDenylist([]DenylistEntry{
		{Kind: " header ", Value: " Authorization "},
		{Kind: "body_path", Value: " $.customer.email "},
		{Kind: "query_param", Value: "access_token"},
		{Kind: "method_path", Value: "customer.accountNumber"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if entries[1].Kind != "HEADER" || entries[1].Value != "authorization" {
		t.Fatalf("unexpected normalized entries: %#v", entries)
	}
	if entries[3].Kind != "QUERY_PARAM" || entries[3].Value != "access_token" {
		t.Fatalf("unexpected normalized query parameter: %#v", entries)
	}
	if _, err := normalizeSecurityDenylist([]DenylistEntry{
		{Kind: "HEADER", Value: "authorization"},
		{Kind: "header", Value: "Authorization"},
	}); err == nil {
		t.Fatal("expected duplicate denylist entry to be rejected")
	}
}

func TestMetricIdentityRemainsLockedAcrossRemovedVersions(t *testing.T) {
	resetState(t)
	first := encodePolicy(t, testPolicy("test.immutable.events", "COUNTER"))
	removedPolicy := testPolicy("test.temporary.events", "COUNTER")
	removedPolicy.MethodPolicies = nil
	removed := encodePolicy(t, removedPolicy)
	state.Configs["immutable-policy"] = []Config{
		{ID: "immutable-policy", Target: "java-extension", Body: first, Version: 1},
		{ID: "immutable-policy", Target: "java-extension", Body: removed, Version: 2},
	}

	changed := encodePolicy(t, testPolicy("test.immutable.events", "UP_DOWN_COUNTER"))
	err := validateJavaPolicy("immutable-policy", changed)

	if err == nil || !strings.Contains(err.Error(), "identity is immutable") {
		t.Fatalf("expected immutable identity error, got %v", err)
	}
}

func TestAcceptsPolicyDefinedNamesAndRejectsInvalidBoundaries(t *testing.T) {
	resetState(t)
	policy := testPolicy("test.policy.names", "COUNTER")
	policy.RequestHeaders = []namedValue{{Name: "authorization"}}
	policy.MethodPolicies[0].Captures[0].Path = "password"
	if err := validateJavaPolicy("policy-defined-names", encodePolicy(t, policy)); err != nil {
		t.Fatalf("expected names to be governed by policy, got %v", err)
	}
	if err := validateJavaPolicyAgainstDenylist(
		encodePolicy(t, policy),
		[]DenylistEntry{{Kind: "HEADER", Value: "authorization"}},
	); err == nil || !strings.Contains(err.Error(), "denied header authorization") {
		t.Fatalf("expected Control Plane denylist rejection, got %v", err)
	}
	policy.RequestHeaders = nil
	if err := validateJavaPolicyAgainstDenylist(
		encodePolicy(t, policy),
		[]DenylistEntry{{Kind: "METHOD_PATH", Value: "password"}},
	); err == nil || !strings.Contains(err.Error(), "denied method_path password") {
		t.Fatalf("expected Control Plane method denylist rejection, got %v", err)
	}

	policy = testPolicy("test.invalid.ranges", "COUNTER")
	policy.MethodPolicies[0].Captures[0].ValuePolicy = valuePolicy{
		Type:     "RANGE",
		Fallback: "OTHER",
		Ranges: []valueRange{
			{Max: floatPointer(3000), Label: "large"},
			{Max: floatPointer(1000), Label: "small"},
		},
	}
	if err := validateJavaPolicy("invalid-range", encodePolicy(t, policy)); err == nil {
		t.Fatal("expected unordered ranges to be rejected")
	}

	policy = testPolicy("test.invalid.header", "COUNTER")
	policy.RequestHeaders = []namedValue{{Name: "invalid header"}}
	if err := validateJavaPolicy("invalid-header", encodePolicy(t, policy)); err == nil {
		t.Fatal("expected syntactically invalid header to be rejected")
	}

	directional := testPolicy("test.directional.header", "COUNTER")
	directional.RequestHeaders = []namedValue{
		{Name: "X-Correlation-ID"},
		{Name: "x-correlation-id", Direction: "OUTGOING"},
	}
	if err := validateJavaPolicy("directional-header", encodePolicy(t, directional)); err != nil {
		t.Fatalf("same header in different directions must be accepted: %v", err)
	}
	directional.RequestHeaders[1].Direction = "INCOMING"
	if err := validateJavaPolicy("duplicate-directional-header", encodePolicy(t, directional)); err == nil ||
		!strings.Contains(err.Error(), "duplicated header") {
		t.Fatalf("same header in the same direction must be rejected: %v", err)
	}
	directional.RequestHeaders[1].Direction = "SIDEWAYS"
	if err := validateJavaPolicy("invalid-directional-header", encodePolicy(t, directional)); err == nil ||
		!strings.Contains(err.Error(), "direction must be INCOMING or OUTGOING") {
		t.Fatalf("invalid generic header direction must be rejected: %v", err)
	}
}

func TestHTTPMetricValueIsPolicyDriven(t *testing.T) {
	resetState(t)
	constant := testPolicy("test.constant.events", "COUNTER")
	constant.MetricPolicies[0].Value = valueSource{Source: "CONSTANT", ArgumentIndex: -1, Constant: 1}
	constant.MetricPolicies[0].Instrument = "COUNTER"
	constant.MetricPolicies[0].Unit = "1"
	constant.MetricPolicies[0].Buckets = nil
	if err := validateJavaPolicy("constant-http-value", encodePolicy(t, constant)); err != nil {
		t.Fatalf("expected a generic constant HTTP value to be valid: %v", err)
	}

	outgoing := testPolicy("test.outgoing.events", "COUNTER")
	outgoing.MetricPolicies[0].Direction = "OUTGOING"
	if err := validateJavaPolicy("outgoing-http-value", encodePolicy(t, outgoing)); err != nil {
		t.Fatalf("expected an OUTGOING HTTP metric to be valid: %v", err)
	}

	invalidDirection := testPolicy("test.invalid.direction", "COUNTER")
	invalidDirection.MetricPolicies[0].Direction = "SIDEWAYS"
	if err := validateJavaPolicy("invalid-http-direction", encodePolicy(t, invalidDirection)); err == nil ||
		!strings.Contains(err.Error(), "direction must be INCOMING or OUTGOING") {
		t.Fatalf("expected an invalid HTTP direction to be rejected: %v", err)
	}

	unknown := testPolicy("test.unknown.events", "COUNTER")
	unknown.MetricPolicies[0].Value.Source = "NAMED_METRIC"
	if err := validateJavaPolicy("unknown-http-value", encodePolicy(t, unknown)); err == nil ||
		!strings.Contains(err.Error(), "unsupported HTTP value source") {
		t.Fatalf("expected an unknown HTTP value source to be rejected: %v", err)
	}

	stringAttribute := testPolicy("test.string.attribute.events", "COUNTER")
	stringAttribute.MetricPolicies[0].Value = valueSource{
		Source: "ATTRIBUTE", ArgumentIndex: -1, Path: "http.request.method",
	}
	if err := validateJavaPolicy("string-http-attribute", encodePolicy(t, stringAttribute)); err == nil ||
		!strings.Contains(err.Error(), "numeric HTTP attribute") {
		t.Fatalf("expected a string HTTP attribute value to be rejected: %v", err)
	}

	reservedClientMetric := testPolicy("test.reserved.client.events", "COUNTER")
	reservedClientMetric.MetricPolicies[0].Name = "http.client.request.duration"
	if err := validateJavaPolicy("reserved-client-metric", encodePolicy(t, reservedClientMetric)); err == nil ||
		!strings.Contains(err.Error(), "invalid or reserved metric name") {
		t.Fatalf("expected a standard HTTP client metric name to be reserved: %v", err)
	}
}

func TestPolicyMetadataMarksOnlyNumericHTTPMetricValueAttributes(t *testing.T) {
	recorder := httptest.NewRecorder()
	policyMetadata(recorder, httptest.NewRequest(http.MethodGet, "/api/policy-metadata", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected metadata status: %d", recorder.Code)
	}
	var payload struct {
		SchemaVersion       string   `json:"schemaVersion"`
		EventFieldSources   []string `json:"eventFieldSources"`
		ConditionSources    []string `json:"conditionSources"`
		MessagingScopes     []string `json:"messagingScopes"`
		MessagingSources    []string `json:"messagingSources"`
		EventHTTPAttributes []string `json:"eventHTTPAttributes"`
		HTTPAttributes      []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"httpAttributes"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.SchemaVersion != "1.6" ||
		!contains(payload.EventFieldSources, "REQUEST_HEADER") ||
		!contains(payload.EventFieldSources, "REQUEST_QUERY") ||
		!contains(payload.EventFieldSources, "REQUEST_PATH_PARAM") ||
		!contains(payload.EventFieldSources, "RESPONSE_HEADER") ||
		!contains(payload.ConditionSources, "RESPONSE_BODY") ||
		!contains(payload.MessagingScopes, "KAFKA_PRODUCER") ||
		!contains(payload.MessagingScopes, "JMS_CONSUMER") ||
		!contains(payload.MessagingSources, "PAYLOAD") ||
		!contains(payload.EventHTTPAttributes, "http.route") ||
		!contains(payload.EventHTTPAttributes, "error.type") {
		t.Fatalf("policy metadata does not expose schema 1.6 sources: %#v", payload)
	}
	types := map[string]string{}
	for _, attribute := range payload.HTTPAttributes {
		types[attribute.Name] = attribute.Type
	}
	if types["http.response.status_code"] != "LONG" || types["server.port"] != "LONG" {
		t.Fatalf("numeric HTTP attributes are not typed: %#v", types)
	}
	if types["http.request.method"] != "STRING" {
		t.Fatalf("string HTTP attributes must not be offered as numeric: %#v", types)
	}
}

func TestValidateJavaPolicyCombinesRequestAndResponseBusinessEvent(t *testing.T) {
	resetState(t)
	policy := bodyEventTestPolicy()
	if err := validateJavaPolicy("transfer-policy", encodePolicy(t, policy)); err != nil {
		t.Fatalf("expected request and response body event to be valid: %v", err)
	}

	policy.SchemaVersion = "1.2"
	if err := validateJavaPolicy("old-transfer-policy", encodePolicy(t, policy)); err == nil ||
		!strings.Contains(err.Error(), "schemaVersion 1.3") {
		t.Fatalf("expected schema 1.3 requirement, got %v", err)
	}

	policy = bodyEventTestPolicy()
	policy.BodyEventPolicies[0].Conditions[3].Path = "password"
	if err := validateJavaPolicy("policy-defined-transfer", encodePolicy(t, policy)); err != nil {
		t.Fatalf("expected response path to be governed by policy, got %v", err)
	}
	if err := validateJavaPolicyAgainstDenylist(
		encodePolicy(t, policy),
		[]DenylistEntry{{Kind: "BODY_PATH", Value: "password"}},
	); err == nil || !strings.Contains(err.Error(), "denied body_path password") {
		t.Fatalf("expected Control Plane body denylist rejection, got %v", err)
	}
}

func TestValidateJavaPolicyAcceptsCounterEventWithoutExtractedFields(t *testing.T) {
	resetState(t)
	policy := bodyEventTestPolicy()
	policy.BodyEventPolicies[0].Fields = nil
	policy.EventMetricPolicies = policy.EventMetricPolicies[:1]
	policy.EventMetricPolicies[0].Dimensions = nil

	if err := validateJavaPolicy("count-only-http-event", encodePolicy(t, policy)); err != nil {
		t.Fatalf("expected a Counter event without fields or valueField to be valid: %v", err)
	}

	overLimit := bodyEventTestPolicy()
	overLimit.EventMetricPolicies = nil
	overLimit.BodyEventPolicies[0].Fields = make([]bodyField, 33)
	for index := range overLimit.BodyEventPolicies[0].Fields {
		overLimit.BodyEventPolicies[0].Fields[index] = bodyField{
			Attribute:    fmt.Sprintf("event.field.%d", index),
			Source:       "REQUEST_BODY",
			Path:         fmt.Sprintf("field%d", index),
			Type:         "STRING",
			Destinations: []string{"SPAN"},
		}
	}
	if err := validateJavaPolicy("http-event-fields-over-limit", encodePolicy(t, overLimit)); err == nil ||
		!strings.Contains(err.Error(), "fields exceeds its limit of 32 entries") {
		t.Fatalf("expected 33 HTTP event fields to be rejected: %v", err)
	}
}

func TestValidateJavaPolicyRejectsHTTPEventWithoutAnEffectiveOutput(t *testing.T) {
	resetState(t)
	withoutOutputPolicy := func() javaPolicy {
		policy := bodyEventTestPolicy()
		policy.BodyEventPolicies[0].StaticAttributes = nil
		policy.BodyEventPolicies[0].Fields = nil
		policy.BodyEventPolicies[0].Log.Enabled = false
		policy.EventMetricPolicies = nil
		return policy
	}
	withoutOutput := withoutOutputPolicy()

	if err := validateJavaPolicy("http-event-without-output", encodePolicy(t, withoutOutput)); err == nil ||
		!strings.Contains(err.Error(), "must define at least one effective output") {
		t.Fatalf("expected a no-op HTTP event to be rejected: %v", err)
	}

	staticSpan := withoutOutputPolicy()
	staticSpan.BodyEventPolicies[0].StaticAttributes = []staticAttribute{{
		Attribute: "event.result", Value: "matched", Type: "STRING", Destinations: []string{"SPAN"},
	}}
	if err := validateJavaPolicy("http-event-static-span", encodePolicy(t, staticSpan)); err != nil {
		t.Fatalf("expected a static SPAN attribute to be an effective output: %v", err)
	}

	logOnly := withoutOutputPolicy()
	logOnly.BodyEventPolicies[0].Log = logPolicy{
		Enabled: true, Severity: "INFO", Body: "HTTP event matched",
	}
	if err := validateJavaPolicy("http-event-log-only", encodePolicy(t, logOnly)); err != nil {
		t.Fatalf("expected an enabled event log to be an effective output: %v", err)
	}

	metricDestinationOnly := withoutOutputPolicy()
	metricDestinationOnly.BodyEventPolicies[0].Fields = []bodyField{{
		Attribute:    "event.channel",
		Source:       "REQUEST_BODY",
		Path:         "channel",
		Type:         "STRING",
		Destinations: []string{"METRIC"},
		ValuePolicy: valuePolicy{
			Type: "ENUM", Allowed: []string{"WEB"}, Fallback: "OTHER",
		},
	}}
	if err := validateJavaPolicy("http-event-metric-destination-only", encodePolicy(t, metricDestinationOnly)); err == nil ||
		!strings.Contains(err.Error(), "must define at least one effective output") {
		t.Fatalf("expected METRIC destination without an event metric to be rejected: %v", err)
	}
}

func TestValidateJavaPolicyAcceptsCorrelatedHTTPHeaderAndQuerySources(t *testing.T) {
	resetState(t)
	policy := bodyEventTestPolicy()
	policy.SchemaVersion = "1.4"
	event := &policy.BodyEventPolicies[0]
	event.Conditions = append(event.Conditions,
		httpCondition{Source: "REQUEST_HEADER", Path: "X-Client-Type", Operator: "IN", Values: []string{"PREMIUM", "STANDARD"}},
		httpCondition{Source: "REQUEST_QUERY", Path: "campaign_id", Operator: "EQUALS", Values: []string{"winter"}},
		httpCondition{Source: "RESPONSE_HEADER", Path: "X-Rate-Type", Operator: "EQUALS", Values: []string{"PREFERRED"}},
	)
	event.Fields = append(event.Fields,
		bodyField{
			Attribute: "client.type", Source: "REQUEST_HEADER", Path: "X-Client-Type", Type: "STRING",
			Destinations: []string{"SPAN", "LOG", "METRIC"},
			ValuePolicy:  valuePolicy{Type: "ENUM", Allowed: []string{"PREMIUM", "STANDARD"}, Fallback: "OTHER"},
		},
		bodyField{
			Attribute: "campaign.id", Source: "REQUEST_QUERY", Path: "campaign_id", Type: "STRING",
			Destinations: []string{"SPAN", "LOG"},
		},
		bodyField{
			Attribute: "exchange.rate", Source: "RESPONSE_HEADER", Path: "X-Exchange-Rate", Type: "DOUBLE",
			Destinations: []string{"SPAN", "LOG"},
		},
	)
	policy.EventMetricPolicies[0].Dimensions = append(policy.EventMetricPolicies[0].Dimensions, "client.type")
	policy.EventMetricPolicies[1].ValueField = "exchange.rate"

	if err := validateJavaPolicy("http-telemetry-event", encodePolicy(t, policy)); err != nil {
		t.Fatalf("expected headers and query sources to be accepted: %v", err)
	}
	policy.SchemaVersion = "1.3"
	if err := validateJavaPolicy("old-http-telemetry-event", encodePolicy(t, policy)); err == nil ||
		!strings.Contains(err.Error(), "require schemaVersion 1.4") {
		t.Fatalf("expected extended HTTP sources to require schema 1.4, got %v", err)
	}
	policy.SchemaVersion = "1.4"
	if err := validateJavaPolicyAgainstDenylist(
		encodePolicy(t, policy),
		[]DenylistEntry{{Kind: "HEADER", Value: "x-client-type"}},
	); err == nil || !strings.Contains(err.Error(), "denied header x-client-type") {
		t.Fatalf("expected event header denylist rejection, got %v", err)
	}
	if err := validateJavaPolicyAgainstDenylist(
		encodePolicy(t, policy),
		[]DenylistEntry{{Kind: "QUERY_PARAM", Value: "campaign_id"}},
	); err == nil || !strings.Contains(err.Error(), "denied query_param campaign_id") {
		t.Fatalf("expected event query denylist rejection, got %v", err)
	}
}

func TestHTTPEventNameMustBeUniqueAcrossDisabledAndEnabledRules(t *testing.T) {
	for _, test := range []struct {
		name          string
		firstEnabled  bool
		secondEnabled bool
	}{
		{name: "enabled and disabled", firstEnabled: true, secondEnabled: false},
		{name: "two disabled", firstEnabled: false, secondEnabled: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy := bodyEventTestPolicy()
			policy.EventMetricPolicies = nil
			first := policy.BodyEventPolicies[0]
			first.Enabled = test.firstEnabled
			second := first
			second.ID = "duplicate-event"
			second.Enabled = test.secondEnabled
			policy.BodyEventPolicies = []bodyEventPolicy{first, second}

			err := validateJavaPolicy("duplicate-event-name", encodePolicy(t, policy))
			if err == nil || !strings.Contains(
				err.Error(),
				"eventName must be unique across all HTTP event rules",
			) {
				t.Fatalf("expected duplicate eventName rejection, got %v", err)
			}
		})
	}

	valid := bodyEventTestPolicy()
	valid.EventMetricPolicies = nil
	first := valid.BodyEventPolicies[0]
	first.Enabled = false
	second := first
	second.ID = "other-disabled-event"
	second.EventName = "other-disabled-event"
	valid.BodyEventPolicies = []bodyEventPolicy{first, second}
	if err := validateJavaPolicy("unique-disabled-events", encodePolicy(t, valid)); err != nil {
		t.Fatalf("distinct disabled event names must remain valid: %v", err)
	}
}

func TestValidateJavaPolicyRejectsInvalidHTTPEventSelectors(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
		path   string
		want   string
	}{
		{name: "header", source: "REQUEST_HEADER", path: "bad header", want: "invalid header name"},
		{name: "query", source: "REQUEST_QUERY", path: "access token", want: "invalid query parameter"},
		{name: "unsupported", source: "REQUEST_COOKIE", path: "session", want: "unsupported HTTP event field source"},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetState(t)
			policy := bodyEventTestPolicy()
			policy.SchemaVersion = "1.4"
			policy.BodyEventPolicies[0].Fields[0].Source = test.source
			policy.BodyEventPolicies[0].Fields[0].Path = test.path
			err := validateJavaPolicy("invalid-http-event-selector", encodePolicy(t, policy))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
}

func TestValidateJavaPolicyLimitsUniqueHTTPEventSelectorsPerSource(t *testing.T) {
	for _, test := range []struct {
		source string
		prefix string
	}{
		{source: "REQUEST_HEADER", prefix: "x-request-selector-"},
		{source: "RESPONSE_HEADER", prefix: "x-response-selector-"},
		{source: "REQUEST_QUERY", prefix: "query_selector_"},
	} {
		t.Run(test.source, func(t *testing.T) {
			atLimit := bodyEventTestPolicy()
			atLimit.SchemaVersion = "1.4"
			atLimit.EventMetricPolicies = nil
			appendHTTPEventSelectorFields(&atLimit, test.source, test.prefix, 16)
			if err := validateJavaPolicy("selectors-at-limit", encodePolicy(t, atLimit)); err != nil {
				t.Fatalf("16 unique %s selectors must be accepted: %v", test.source, err)
			}

			overLimit := bodyEventTestPolicy()
			overLimit.SchemaVersion = "1.4"
			overLimit.EventMetricPolicies = nil
			appendHTTPEventSelectorFields(&overLimit, test.source, test.prefix, 17)
			err := validateJavaPolicy("selectors-over-limit", encodePolicy(t, overLimit))
			if err == nil || !strings.Contains(
				err.Error(),
				test.source+" selectors exceed their limit of 16 unique names",
			) {
				t.Fatalf("expected %s selector limit rejection, got %v", test.source, err)
			}
		})
	}
}

func TestEffectivePolicySetLimitsHTTPEventSelectorsAcrossPolicies(t *testing.T) {
	first := bodyEventTestPolicy()
	first.SchemaVersion = "1.4"
	first.BodyEventPolicies[0].ID = "event-a"
	first.BodyEventPolicies[0].EventName = "event-a"
	first.EventMetricPolicies = nil
	appendHTTPEventSelectorFields(&first, "REQUEST_HEADER", "x-policy-a-", 9)

	second := bodyEventTestPolicy()
	second.SchemaVersion = "1.4"
	second.BodyEventPolicies[0].ID = "event-b"
	second.BodyEventPolicies[0].EventName = "event-b"
	second.EventMetricPolicies = nil
	appendHTTPEventSelectorFields(&second, "REQUEST_HEADER", "x-policy-b-", 9)

	for id, policy := range map[string]javaPolicy{"policy-a": first, "policy-b": second} {
		if err := validateJavaPolicy(id, encodePolicy(t, policy)); err != nil {
			t.Fatalf("%s must be valid in isolation: %v", id, err)
		}
	}
	err := validatePolicySetCompatibility([]Config{
		{ID: "policy-a", Body: encodePolicy(t, first)},
		{ID: "policy-b", Body: encodePolicy(t, second)},
	})
	if err == nil || !strings.Contains(
		err.Error(),
		"REQUEST_HEADER selectors exceed their limit of 16 unique names",
	) {
		t.Fatalf("expected effective PolicySet selector limit rejection, got %v", err)
	}
}

func appendHTTPEventSelectorFields(
	policy *javaPolicy,
	source string,
	prefix string,
	count int,
) {
	for index := 0; index < count; index++ {
		policy.BodyEventPolicies[0].Fields = append(
			policy.BodyEventPolicies[0].Fields,
			bodyField{
				Attribute:    fmt.Sprintf("event.field_%02d", index),
				Source:       source,
				Path:         fmt.Sprintf("%s%02d", prefix, index),
				Type:         "STRING",
				Destinations: []string{"SPAN"},
			},
		)
	}
}

func TestBodyFieldsMayReuseAJSONPathAcrossRequestAndResponseOnly(t *testing.T) {
	resetState(t)
	requestAndResponse := bodyEventTestPolicy()
	requestAndResponse.BodyEventPolicies[0].Fields = append(
		requestAndResponse.BodyEventPolicies[0].Fields,
		bodyField{
			Attribute: "response.amount", Source: "RESPONSE_BODY", Path: "amount",
			Type: "DOUBLE", Destinations: []string{"SPAN"},
		},
	)
	if err := validateJavaPolicy("request-response-same-path", encodePolicy(t, requestAndResponse)); err != nil {
		t.Fatalf("request and response bodies are distinct JSON scopes: %v", err)
	}

	duplicateRequest := bodyEventTestPolicy()
	duplicateRequest.BodyEventPolicies[0].Fields = append(
		duplicateRequest.BodyEventPolicies[0].Fields,
		bodyField{
			Attribute: "duplicate.request.amount", Source: "REQUEST_BODY", Path: "amount",
			Type: "DOUBLE", Destinations: []string{"SPAN"},
		},
	)
	if err := validateJavaPolicy("duplicate-request-path", encodePolicy(t, duplicateRequest)); err == nil ||
		!strings.Contains(err.Error(), "duplicated JSON path") {
		t.Fatalf("expected a duplicate path within the request body to be rejected: %v", err)
	}
}

func TestValidateJavaPolicyAcceptsCalculatedBusinessField(t *testing.T) {
	resetState(t)
	policy := bodyEventTestPolicy()
	policy.BodyEventPolicies[0].DerivedFields = []derivedField{{
		Attribute:    "transaction.total",
		Expression:   "transaction.amount * 1.02",
		Type:         "DOUBLE",
		Destinations: []string{"SPAN", "LOG"},
	}}
	policy.EventMetricPolicies[1].ValueField = "transaction.total"

	if err := validateJavaPolicy("calculated-transfer-policy", encodePolicy(t, policy)); err != nil {
		t.Fatalf("expected calculated field to be valid: %v", err)
	}

	policy.BodyEventPolicies[0].DerivedFields[0].Expression = "transaction.unknown * 1.02"
	if err := validateJavaPolicy("invalid-calculated-transfer-policy", encodePolicy(t, policy)); err == nil ||
		!strings.Contains(err.Error(), "unknown or non-numeric field") {
		t.Fatalf("expected unknown expression field to be rejected, got %v", err)
	}

	policy = bodyEventTestPolicy()
	policy.SchemaVersion = "1.2"
	policy.BodyEventPolicies[0].DerivedFields = []derivedField{{
		Attribute:    "transaction.total",
		Expression:   "transaction.amount * 1.02",
		Type:         "DOUBLE",
		Destinations: []string{"SPAN"},
	}}
	if err := validateJavaPolicy("old-calculated-transfer-policy", encodePolicy(t, policy)); err == nil ||
		!strings.Contains(err.Error(), "schemaVersion 1.3") {
		t.Fatalf("expected schema 1.3 requirement, got %v", err)
	}
}

func TestSelectorRequiresEveryConfiguredConstraint(t *testing.T) {
	agent := Agent{
		UID:     "agent-1",
		Service: "rates-service",
		Attributes: map[string]string{
			"deployment.environment.name": "local",
			"service.namespace":           "payments",
		},
	}
	selector := AgentSelector{
		InstanceUIDs: []string{"agent-1"},
		Services:     []string{"rates-service"},
		Attributes: map[string]string{
			"deployment.environment.name": "local",
		},
	}

	if !matches(selector, agent) {
		t.Fatal("expected selector to match")
	}
	selector.Attributes["deployment.environment.name"] = "production"
	if matches(selector, agent) {
		t.Fatal("expected selector mismatch")
	}
}

func testPolicy(metricName, instrument string) javaPolicy {
	return javaPolicy{
		SchemaVersion:   "1.3",
		RequestHeaders:  []namedValue{{Name: "x-request-id"}},
		ResponseHeaders: []namedValue{{Name: "x-rate-type"}},
		MetricPolicies: []httpMetricPolicy{{
			ID:                 "http-v1",
			Enabled:            true,
			Direction:          "INCOMING",
			Value:              valueSource{Source: "DURATION", ArgumentIndex: -1},
			Name:               "test.http.duration",
			Instrument:         "HISTOGRAM",
			Unit:               "s",
			StandardAttributes: []string{"http.request.method", "http.route"},
			CustomAttributes: []attributeSource{{
				valueSource: valueSource{Source: "REQUEST_HEADER", ArgumentIndex: -1},
				Header:      "x-client-channel",
				Attribute:   "client.channel",
				Destinations: []string{
					"SPAN",
				},
				ValuePolicy: valuePolicy{
					Type:     "ENUM",
					Allowed:  []string{"WEB", "API"},
					Fallback: "OTHER",
				},
			}},
			Buckets: []float64{0.01, 0.1, 1},
		}},
		MethodPolicies: []methodPolicy{{
			ID:            "method-v1",
			Enabled:       true,
			PackagePrefix: "dev.o11y.rates.service",
			ClassName:     "dev.o11y.rates.service.ExchangeRateCalculator",
			MethodName:    "calculate",
			Captures: []capture{{
				valueSource:  valueSource{Source: "ARGUMENT", ArgumentIndex: 0, Path: "customerType"},
				Attribute:    "customer.type",
				Type:         "STRING",
				Destinations: []string{"SPAN", "METRIC", "LOG"},
				ValuePolicy: valuePolicy{
					Type:     "ENUM",
					Allowed:  []string{"SALARY_ACCOUNT", "STANDARD"},
					Fallback: "OTHER",
				},
			}},
			Metrics: []methodMetric{{
				Name:        metricName,
				Instrument:  instrument,
				Unit:        "1",
				Description: "Business events",
				Value:       valueSource{Source: "CONSTANT", ArgumentIndex: -1, Constant: 1},
			}},
			Log: logPolicy{Enabled: true, Severity: "INFO", Body: "Business method completed"},
		}},
	}
}

func bodyEventTestPolicy() javaPolicy {
	return javaPolicy{
		SchemaVersion: "1.3",
		BodyEventPolicies: []bodyEventPolicy{{
			ID:                  "transfer-approved-v1",
			Enabled:             true,
			RuleName:            "Approved transfer",
			Direction:           "INCOMING",
			RequestContentType:  "application/json",
			ResponseContentType: "application/json",
			Conditions: []httpCondition{
				{Source: "REQUEST_PATH", Operator: "EQUALS", Values: []string{"/api/transfer"}},
				{Source: "REQUEST_METHOD", Operator: "EQUALS", Values: []string{"POST"}},
				{Source: "RESPONSE_STATUS", Operator: "IN", Values: []string{"200", "201"}},
				{Source: "RESPONSE_BODY", Path: "status", Operator: "EQUALS", Values: []string{"APPROVED"}},
			},
			EventName: "transfer-approved",
			StaticAttributes: []staticAttribute{{
				Attribute: "event.type", Value: "transfer-approved", Type: "STRING", Destinations: []string{"SPAN", "LOG"},
			}},
			MaxBodyBytes: 65536,
			Fields: []bodyField{
				{
					Attribute:    "business.channel",
					Source:       "REQUEST_BODY",
					Path:         "channel",
					Type:         "STRING",
					Destinations: []string{"SPAN", "LOG", "METRIC"},
					ValuePolicy: valuePolicy{
						Type:     "ENUM",
						Allowed:  []string{"MOBILE", "WEB"},
						Fallback: "OTHER",
					},
				},
				{
					Attribute:    "transaction.amount",
					Source:       "REQUEST_BODY",
					Path:         "amount",
					Type:         "DOUBLE",
					Destinations: []string{"SPAN", "LOG"},
				},
				{
					Attribute:    "business.result",
					Source:       "RESPONSE_BODY",
					Path:         "status",
					Type:         "STRING",
					Destinations: []string{"SPAN", "LOG"},
				},
			},
			Log: logPolicy{Enabled: true, Severity: "INFO", Body: "Transfer approved"},
		}},
		EventMetricPolicies: []eventMetricPolicy{
			{
				ID:          "transfer-count-v1",
				Enabled:     true,
				EventName:   "transfer-approved",
				Name:        "biz.transfer.count",
				Instrument:  "COUNTER",
				Unit:        "1",
				Description: "Approved transfer count",
				Dimensions:  []string{"business.channel"},
			},
			{
				ID:          "transfer-amount-v1",
				Enabled:     true,
				EventName:   "transfer-approved",
				Name:        "biz.transfer.amount",
				Instrument:  "HISTOGRAM",
				Unit:        "1",
				Description: "Approved transfer amount",
				ValueField:  "transaction.amount",
				Dimensions:  []string{"business.channel"},
				Buckets:     []float64{100, 500, 1000, 3000, 10000},
			},
		},
	}
}

func encodePolicy(t *testing.T, policy javaPolicy) string {
	t.Helper()
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func floatPointer(value float64) *float64 {
	return &value
}

func resetState(t *testing.T) {
	t.Helper()
	previous := state
	state = &State{
		Configs:    map[string][]Config{},
		Agents:     map[string]Agent{},
		Conns:      map[string]types.Connection{},
		UIDs:       map[string][]byte{},
		PollOffers: map[string]string{},
	}
	t.Cleanup(func() { state = previous })
}
