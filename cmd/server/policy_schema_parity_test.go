package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPolicyValidationRejectsWhitespaceOnlyRequiredValues(t *testing.T) {
	tests := []struct {
		name   string
		policy func() javaPolicy
	}{
		{
			name: "HTTP metric id",
			policy: func() javaPolicy {
				policy := testPolicy("test.method.events", "COUNTER")
				policy.MetricPolicies[0].ID = " \t"
				return policy
			},
		},
		{
			name: "metric unit",
			policy: func() javaPolicy {
				policy := testPolicy("test.method.events", "COUNTER")
				policy.MetricPolicies[0].Unit = " \n"
				return policy
			},
		},
		{
			name: "method id",
			policy: func() javaPolicy {
				policy := testPolicy("test.method.events", "COUNTER")
				policy.MethodPolicies[0].ID = "  "
				return policy
			},
		},
		{
			name: "method log body",
			policy: func() javaPolicy {
				policy := testPolicy("test.method.events", "COUNTER")
				policy.MethodPolicies[0].Log.Body = " \t"
				return policy
			},
		},
		{
			name: "bounded fallback",
			policy: func() javaPolicy {
				policy := testPolicy("test.method.events", "COUNTER")
				policy.MethodPolicies[0].Captures[0].ValuePolicy.Fallback = " \n"
				return policy
			},
		},
		{
			name: "range label",
			policy: func() javaPolicy {
				policy := testPolicy("test.method.events", "COUNTER")
				policy.MethodPolicies[0].Captures[0].ValuePolicy = valuePolicy{
					Type:     "RANGE",
					Fallback: "OTHER",
					Ranges:   []valueRange{{Label: " \t"}},
				}
				return policy
			},
		},
		{
			name: "HTTP rule name",
			policy: func() javaPolicy {
				policy := bodyEventTestPolicy()
				policy.BodyEventPolicies[0].RuleName = " \t"
				return policy
			},
		},
		{
			name: "HTTP condition value",
			policy: func() javaPolicy {
				policy := bodyEventTestPolicy()
				policy.BodyEventPolicies[0].Conditions[3].Values = []string{" \n"}
				return policy
			},
		},
		{
			name: "static attribute value",
			policy: func() javaPolicy {
				policy := bodyEventTestPolicy()
				policy.BodyEventPolicies[0].StaticAttributes[0].Value = "  "
				return policy
			},
		},
		{
			name: "HTTP log body",
			policy: func() javaPolicy {
				policy := bodyEventTestPolicy()
				policy.BodyEventPolicies[0].Log.Body = " \t"
				return policy
			},
		},
		{
			name: "messaging rule name",
			policy: func() javaPolicy {
				policy := messagingTestPolicy("KAFKA_PRODUCER")
				policy.MessagingEventPolicies[0].RuleName = " \t"
				return policy
			},
		},
		{
			name: "messaging condition value",
			policy: func() javaPolicy {
				policy := messagingTestPolicy("KAFKA_PRODUCER")
				policy.MessagingEventPolicies[0].Conditions[0].Values = []string{" \n"}
				return policy
			},
		},
		{
			name: "messaging log body",
			policy: func() javaPolicy {
				policy := messagingTestPolicy("KAFKA_PRODUCER")
				policy.MessagingEventPolicies[0].Log.Enabled = true
				policy.MessagingEventPolicies[0].Log.Body = " \t"
				return policy
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resetState(t)
			if err := validateJavaPolicy("schema-parity-policy", encodePolicy(t, test.policy())); err == nil {
				t.Fatal("whitespace-only required value must be rejected")
			}
		})
	}
}

func TestPolicyValidationTreatsWhitespaceOnlyOptionalPathsAsAbsent(t *testing.T) {
	resetState(t)
	policy := testPolicy("test.method.events", "COUNTER")
	policy.MetricPolicies[0].Value.Path = " \t"
	policy.MethodPolicies[0].Captures[0].Path = " \n"
	if err := validateJavaPolicy("blank-optional-paths", encodePolicy(t, policy)); err != nil {
		t.Fatalf("optional paths that Java treats as blank must be accepted: %v", err)
	}

	httpPolicy := bodyEventTestPolicy()
	httpPolicy.BodyEventPolicies[0].Conditions[0].Path = " \t"
	httpPolicy.BodyEventPolicies[0].Conditions[1].Path = " \n"
	httpPolicy.BodyEventPolicies[0].Conditions[2].Path = "  "
	if err := validateJavaPolicy("blank-http-condition-paths", encodePolicy(t, httpPolicy)); err != nil {
		t.Fatalf("selector-free HTTP condition paths that Java treats as blank must be accepted: %v", err)
	}
}

func TestHTTPMetricDirectionMustBeExplicitAndSupported(t *testing.T) {
	resetState(t)
	policy := testPolicy("test.method.events", "COUNTER")
	policy.MetricPolicies[0].Direction = ""

	err := validateJavaPolicy("explicit-http-direction", encodePolicy(t, policy))
	if err == nil || !strings.Contains(err.Error(), "direction must be INCOMING or OUTGOING") {
		t.Fatalf("empty HTTP metric direction must be rejected, got %v", err)
	}
}

func TestDecodeJavaPolicyRejectsExplicitNullMethodObjects(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*testing.T, map[string]json.RawMessage)
		expected string
	}{
		{
			name: "method log",
			mutate: func(_ *testing.T, method map[string]json.RawMessage) {
				method["log"] = json.RawMessage("null")
			},
			expected: "methodPolicies[0].log must not be null",
		},
		{
			name: "capture value policy",
			mutate: func(t *testing.T, method map[string]json.RawMessage) {
				captures := rawPolicyObjectArray(t, method["captures"], "methodPolicies[0].captures")
				captures[0]["valuePolicy"] = json.RawMessage("null")
				method["captures"] = marshalRawPolicyValue(t, captures)
			},
			expected: "methodPolicies[0].captures[0].valuePolicy must not be null",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := rewritePolicySection(
				t,
				encodePolicy(t, testPolicy("test.method.events", "COUNTER")),
				"methodPolicies",
				func(method map[string]json.RawMessage) {
					test.mutate(t, method)
				},
			)
			_, err := decodeJavaPolicy(body)
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("expected %q, got %v", test.expected, err)
			}
		})
	}
}

func TestMetricNamesCollideOnNormalizedPrometheusBaseAcrossInstruments(t *testing.T) {
	resetState(t)
	policy := testPolicy("foo-bar", "HISTOGRAM")
	policy.MetricPolicies[0].Name = "foo.bar"
	policy.MetricPolicies[0].Instrument = "COUNTER"
	policy.MetricPolicies[0].Buckets = nil
	policy.MethodPolicies[0].Metrics[0].Buckets = []float64{1, 10}

	err := validateJavaPolicy("normalized-prometheus-collision", encodePolicy(t, policy))
	if err == nil || !strings.Contains(err.Error(), "Prometheus name collision") {
		t.Fatalf("foo.bar and foo-bar must collide on the Prometheus base foo_bar, got %v", err)
	}
}
