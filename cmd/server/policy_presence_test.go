package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDecodeJavaPolicyRequiresExplicitRuleEnabled(t *testing.T) {
	for _, section := range []string{
		"metricPolicies",
		"methodPolicies",
		"bodyEventPolicies",
		"eventMetricPolicies",
		"messagingEventPolicies",
		"messagingMetricPolicies",
	} {
		t.Run(section+" omitted", func(t *testing.T) {
			body := rewritePolicySection(t, encodePolicy(t, policyWithAllRuleTypes()), section, func(object map[string]json.RawMessage) {
				delete(object, "enabled")
			})
			_, err := decodeJavaPolicy(body)
			if err == nil || !strings.Contains(err.Error(), section+"[0].enabled is required") {
				t.Fatalf("expected explicit enabled requirement for %s, got %v", section, err)
			}
		})

		t.Run(section+" null", func(t *testing.T) {
			body := rewritePolicySection(t, encodePolicy(t, policyWithAllRuleTypes()), section, func(object map[string]json.RawMessage) {
				object["enabled"] = json.RawMessage("null")
			})
			_, err := decodeJavaPolicy(body)
			if err == nil || !strings.Contains(err.Error(), section+"[0].enabled must be a boolean") {
				t.Fatalf("expected boolean enabled requirement for %s, got %v", section, err)
			}
		})
	}
}

func TestDecodeJavaPolicyPreservesExplicitRuleDisabled(t *testing.T) {
	policy := policyWithAllRuleTypes()
	policy.MetricPolicies[0].Enabled = false
	policy.MethodPolicies[0].Enabled = false
	policy.BodyEventPolicies[0].Enabled = false
	policy.EventMetricPolicies[0].Enabled = false
	policy.MessagingEventPolicies[0].Enabled = false
	policy.MessagingMetricPolicies[0].Enabled = false

	decoded, err := decodeJavaPolicy(encodePolicy(t, policy))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.MetricPolicies[0].Enabled || decoded.MethodPolicies[0].Enabled ||
		decoded.BodyEventPolicies[0].Enabled || decoded.EventMetricPolicies[0].Enabled ||
		decoded.MessagingEventPolicies[0].Enabled || decoded.MessagingMetricPolicies[0].Enabled {
		t.Fatal("an explicit enabled=false must remain disabled")
	}
}

func TestOmittedEnabledCannotBypassDenylistOrInventory(t *testing.T) {
	tests := []struct {
		name    string
		section string
		policy  func() javaPolicy
		entry   DenylistEntry
	}{
		{
			name:    "HTTP metric header",
			section: "metricPolicies",
			policy: func() javaPolicy {
				policy := testPolicy("test.required.enabled.http", "COUNTER")
				policy.MetricPolicies[0].CustomAttributes[0].Header = "authorization"
				return policy
			},
			entry: DenylistEntry{Kind: "HEADER", Value: "authorization"},
		},
		{
			name:    "method object",
			section: "methodPolicies",
			policy: func() javaPolicy {
				policy := testPolicy("test.required.enabled.method", "COUNTER")
				policy.MethodPolicies[0].Captures[0].Path = "customer"
				return policy
			},
			entry: DenylistEntry{Kind: "METHOD_PATH", Value: "customer.secret"},
		},
		{
			name:    "body object",
			section: "bodyEventPolicies",
			policy: func() javaPolicy {
				policy := bodyEventTestPolicy()
				policy.BodyEventPolicies[0].Fields[0].Path = "customer"
				return policy
			},
			entry: DenylistEntry{Kind: "BODY_PATH", Value: "customer.secret"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := rewritePolicySection(t, encodePolicy(t, test.policy()), test.section, func(object map[string]json.RawMessage) {
				delete(object, "enabled")
			})

			err := validateJavaPolicyAgainstDenylist(body, []DenylistEntry{test.entry})
			if err == nil || !strings.Contains(err.Error(), test.section+"[0].enabled is required") {
				t.Fatalf("denylist path must reject ambiguous disabled semantics, got %v", err)
			}

		})
	}
}

func TestDecodeJavaPolicyRequiresValueSourceOperands(t *testing.T) {
	tests := []struct {
		name string
		body func(*testing.T) string
		want string
	}{
		{
			name: "HTTP constant",
			body: func(t *testing.T) string {
				policy := testPolicy("test.required.http.constant", "COUNTER")
				policy.MetricPolicies[0].Value.Source = "CONSTANT"
				return rewritePolicySection(t, encodePolicy(t, policy), "metricPolicies", func(metric map[string]json.RawMessage) {
					value := rawPolicyObject(t, metric["value"], "metricPolicies[0].value")
					delete(value, "constant")
					metric["value"] = marshalRawPolicyValue(t, value)
				})
			},
			want: "metricPolicies[0].value.constant is required when source is CONSTANT",
		},
		{
			name: "HTTP argument",
			body: func(t *testing.T) string {
				policy := testPolicy("test.required.http.argument", "COUNTER")
				policy.MetricPolicies[0].Value.Source = "ARGUMENT"
				return rewritePolicySection(t, encodePolicy(t, policy), "metricPolicies", func(metric map[string]json.RawMessage) {
					value := rawPolicyObject(t, metric["value"], "metricPolicies[0].value")
					delete(value, "argumentIndex")
					metric["value"] = marshalRawPolicyValue(t, value)
				})
			},
			want: "metricPolicies[0].value.argumentIndex is required when source is ARGUMENT",
		},
		{
			name: "method capture argument",
			body: func(t *testing.T) string {
				policy := testPolicy("test.required.capture.argument", "COUNTER")
				return rewritePolicySection(t, encodePolicy(t, policy), "methodPolicies", func(method map[string]json.RawMessage) {
					captures := rawPolicyObjectArray(t, method["captures"], "methodPolicies[0].captures")
					delete(captures[0], "argumentIndex")
					method["captures"] = marshalRawPolicyValue(t, captures)
				})
			},
			want: "methodPolicies[0].captures[0].argumentIndex is required when source is ARGUMENT",
		},
		{
			name: "method capture constant",
			body: func(t *testing.T) string {
				policy := testPolicy("test.required.capture.constant", "COUNTER")
				policy.MethodPolicies[0].Captures[0].Source = "CONSTANT"
				return rewritePolicySection(t, encodePolicy(t, policy), "methodPolicies", func(method map[string]json.RawMessage) {
					captures := rawPolicyObjectArray(t, method["captures"], "methodPolicies[0].captures")
					delete(captures[0], "constant")
					method["captures"] = marshalRawPolicyValue(t, captures)
				})
			},
			want: "methodPolicies[0].captures[0].constant is required when source is CONSTANT",
		},
		{
			name: "method metric argument",
			body: func(t *testing.T) string {
				policy := testPolicy("test.required.metric.argument", "COUNTER")
				policy.MethodPolicies[0].Metrics[0].Value.Source = "ARGUMENT"
				return rewritePolicySection(t, encodePolicy(t, policy), "methodPolicies", func(method map[string]json.RawMessage) {
					metrics := rawPolicyObjectArray(t, method["metrics"], "methodPolicies[0].metrics")
					value := rawPolicyObject(t, metrics[0]["value"], "methodPolicies[0].metrics[0].value")
					delete(value, "argumentIndex")
					metrics[0]["value"] = marshalRawPolicyValue(t, value)
					method["metrics"] = marshalRawPolicyValue(t, metrics)
				})
			},
			want: "methodPolicies[0].metrics[0].value.argumentIndex is required when source is ARGUMENT",
		},
		{
			name: "method metric constant",
			body: func(t *testing.T) string {
				policy := testPolicy("test.required.metric.constant", "COUNTER")
				return rewritePolicySection(t, encodePolicy(t, policy), "methodPolicies", func(method map[string]json.RawMessage) {
					metrics := rawPolicyObjectArray(t, method["metrics"], "methodPolicies[0].metrics")
					value := rawPolicyObject(t, metrics[0]["value"], "methodPolicies[0].metrics[0].value")
					delete(value, "constant")
					metrics[0]["value"] = marshalRawPolicyValue(t, value)
					method["metrics"] = marshalRawPolicyValue(t, metrics)
				})
			},
			want: "methodPolicies[0].metrics[0].value.constant is required when source is CONSTANT",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := decodeJavaPolicy(test.body(t))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("expected %q, got %v", test.want, err)
			}
		})
	}
}

func TestDecodeJavaPolicyAcceptsExplicitZeroValueSourceOperands(t *testing.T) {
	policy := testPolicy("test.explicit.zero.values", "COUNTER")
	policy.MetricPolicies[0].Value = valueSource{
		Source:        "CONSTANT",
		ArgumentIndex: -1,
		Constant:      0,
	}
	policy.MethodPolicies[0].Captures[0].valueSource = valueSource{
		Source:        "ARGUMENT",
		ArgumentIndex: 0,
	}
	policy.MethodPolicies[0].Metrics[0].Value = valueSource{
		Source:        "CONSTANT",
		ArgumentIndex: -1,
		Constant:      0,
	}

	if _, err := decodeJavaPolicy(encodePolicy(t, policy)); err != nil {
		t.Fatalf("explicit argumentIndex=0 and constant=0 must be accepted: %v", err)
	}
}

func TestOmittedEventMetricEnabledIsRejectedBeforeBehaviorCanDiverge(t *testing.T) {
	resetState(t)
	policy := bodyEventTestPolicy()
	policy.EventMetricPolicies[0].EventName = "event-that-does-not-exist"
	body := rewritePolicySection(t, encodePolicy(t, policy), "eventMetricPolicies", func(metric map[string]json.RawMessage) {
		delete(metric, "enabled")
	})

	err := validateJavaPolicy("required-enabled-event-metric", body)
	if err == nil || !strings.Contains(err.Error(), "eventMetricPolicies[0].enabled is required") {
		t.Fatalf("event metric omission must be rejected instead of treated as disabled, got %v", err)
	}

	policy.EventMetricPolicies[0].Enabled = false
	if err := validateJavaPolicy("explicit-disabled-event-metric", encodePolicy(t, policy)); err != nil {
		t.Fatalf("explicit enabled=false must retain disabled event metric behavior, got %v", err)
	}
}

func TestRequiredPresenceValidationKeepsUnknownFieldRejection(t *testing.T) {
	for _, section := range []string{
		"metricPolicies",
		"methodPolicies",
		"bodyEventPolicies",
		"eventMetricPolicies",
		"messagingEventPolicies",
		"messagingMetricPolicies",
	} {
		t.Run(section, func(t *testing.T) {
			body := rewritePolicySection(t, encodePolicy(t, policyWithAllRuleTypes()), section, func(object map[string]json.RawMessage) {
				object["unexpected"] = json.RawMessage("true")
			})
			_, err := decodeJavaPolicy(body)
			if err == nil || !strings.Contains(err.Error(), `unknown field "unexpected"`) {
				t.Fatalf("expected strict unknown-field rejection for %s, got %v", section, err)
			}
		})
	}
}

func policyWithAllRuleTypes() javaPolicy {
	policy := testPolicy("test.required.fields.method.metric", "COUNTER")
	bodyPolicy := bodyEventTestPolicy()
	policy.BodyEventPolicies = bodyPolicy.BodyEventPolicies
	policy.EventMetricPolicies = bodyPolicy.EventMetricPolicies
	messagingPolicy := messagingTestPolicy("KAFKA_PRODUCER")
	policy.MessagingEventPolicies = messagingPolicy.MessagingEventPolicies
	policy.MessagingMetricPolicies = messagingPolicy.MessagingMetricPolicies
	return policy
}

func rewritePolicySection(
	t *testing.T,
	body, section string,
	mutate func(map[string]json.RawMessage),
) string {
	t.Helper()
	var document map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatal(err)
	}
	objects := rawPolicyObjectArray(t, document[section], section)
	if len(objects) == 0 {
		t.Fatalf("section %s must contain at least one object", section)
	}
	for _, object := range objects {
		mutate(object)
	}
	document[section] = marshalRawPolicyValue(t, objects)
	return string(marshalRawPolicyValue(t, document))
}

func rawPolicyObject(t *testing.T, raw json.RawMessage, location string) map[string]json.RawMessage {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || object == nil {
		t.Fatalf("decode %s as object: %v", location, err)
	}
	return object
}

func rawPolicyObjectArray(t *testing.T, raw json.RawMessage, location string) []map[string]json.RawMessage {
	t.Helper()
	var objects []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &objects); err != nil {
		t.Fatalf("decode %s as object array: %v", location, err)
	}
	return objects
}

func marshalRawPolicyValue(t *testing.T, value any) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
