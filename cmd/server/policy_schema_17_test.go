package main

import (
	"strings"
	"testing"
)

func TestSchema17AllowsExplicitlyUncontrolledMetricLabels(t *testing.T) {
	resetState(t)
	policy := testPolicy("test.schema17.events", "COUNTER")
	policy.MetricPolicies[0].CustomAttributes[0].ValuePolicy = valuePolicy{
		Type: "PASSTHROUGH",
	}

	policy.SchemaVersion = "1.6"
	if err := validateJavaPolicy("schema17-uncontrolled", encodePolicy(t, policy)); err == nil ||
		!strings.Contains(err.Error(), "requires schemaVersion 1.7") {
		t.Fatalf("PASSTHROUGH must require schema 1.7, got %v", err)
	}

	policy.SchemaVersion = "1.7"
	if err := validateJavaPolicy("schema17-uncontrolled", encodePolicy(t, policy)); err != nil {
		t.Fatalf("schema 1.7 PASSTHROUGH label must be accepted: %v", err)
	}

	policy.MetricPolicies[0].CustomAttributes[0].ValuePolicy.Fallback = "OTHER"
	if err := validateJavaPolicy("schema17-invalid", encodePolicy(t, policy)); err == nil ||
		!strings.Contains(err.Error(), "PASSTHROUGH does not accept") {
		t.Fatalf("PASSTHROUGH options must remain empty, got %v", err)
	}
}
