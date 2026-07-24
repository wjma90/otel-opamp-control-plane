package main

import (
	"strings"
	"testing"
)

func TestSchema16ValidatesHTTPEventMetricStandardAttributes(t *testing.T) {
	resetState(t)
	policy := bodyEventTestPolicy()
	policy.SchemaVersion = "1.6"
	policy.EventMetricPolicies[0].StandardAttributes = []string{
		"http.request.method",
		"http.route",
		"http.response.status_code",
		"error.type",
	}
	if err := validateJavaPolicy("event-context-policy", encodePolicy(t, policy)); err != nil {
		t.Fatalf("schema 1.6 contextual HTTP attributes must be accepted: %v", err)
	}

	policy.SchemaVersion = "1.5"
	if err := validateJavaPolicy("event-context-policy", encodePolicy(t, policy)); err == nil ||
		!strings.Contains(err.Error(), "require schemaVersion 1.6") {
		t.Fatalf("contextual HTTP attributes must require schema 1.6, got %v", err)
	}

	policy.SchemaVersion = "1.6"
	policy.BodyEventPolicies[0].Direction = "OUTGOING"
	if err := validateJavaPolicy("event-context-policy", encodePolicy(t, policy)); err == nil ||
		!strings.Contains(err.Error(), "http.route only for INCOMING") {
		t.Fatalf("outgoing HTTP events must reject http.route, got %v", err)
	}
}

func TestSchema16RejectsUnknownOrDuplicatedHTTPEventMetricAttributes(t *testing.T) {
	for _, attributes := range [][]string{
		{"url.path"},
		{"http.request.method", "http.request.method"},
	} {
		policy := bodyEventTestPolicy()
		policy.SchemaVersion = "1.6"
		policy.EventMetricPolicies[0].StandardAttributes = attributes
		if err := validateJavaPolicy("invalid-event-context-policy", encodePolicy(t, policy)); err == nil {
			t.Fatalf("invalid contextual attributes must be rejected: %#v", attributes)
		}
	}
}
