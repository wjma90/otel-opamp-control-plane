package main

import (
	"strings"
	"testing"
)

func messagingTestPolicy(scope string) javaPolicy {
	return javaPolicy{
		SchemaVersion: "1.5",
		MessagingEventPolicies: []messagingEventPolicy{{
			ID:              "message-event",
			Enabled:         true,
			RuleName:        "Approved exchange message",
			Scope:           scope,
			Conditions:      []messagingCondition{{Source: "DESTINATION", Operator: "EQUALS", Values: []string{"cambistapp.exchange.completed"}}},
			EventName:       "exchange-message-approved",
			MaxPayloadBytes: 65536,
			Fields: []messagingField{
				{
					Attribute: "client.channel", Source: "MESSAGE_HEADER", Path: "x-client-channel",
					Type: "STRING", Destinations: []string{"SPAN", "METRIC"},
					ValuePolicy: valuePolicy{Type: "ENUM", Allowed: []string{"WEB", "API"}, Fallback: "OTHER"},
				},
				{
					Attribute: "exchange.amount", Source: "PAYLOAD", Path: "sourceAmount",
					Type: "DOUBLE", Destinations: []string{"SPAN"},
				},
			},
			Log: logPolicy{Enabled: false, Severity: "INFO", Body: "Exchange message matched"},
		}},
		MessagingMetricPolicies: []messagingMetricPolicy{{
			ID: "message-amount", Enabled: true, EventName: "exchange-message-approved",
			Name: "cambistapp.messaging.exchange.amount", Instrument: "HISTOGRAM",
			Unit: "{PEN}", ValueField: "exchange.amount", Dimensions: []string{"client.channel"},
			Buckets: []float64{100, 500, 1000, 5000},
		}},
	}
}

func TestSchema15AcceptsNamedHTTPPathParameters(t *testing.T) {
	resetState(t)
	policy := bodyEventTestPolicy()
	policy.SchemaVersion = "1.5"
	policy.BodyEventPolicies[0].Conditions[0].Values = []string{"/api/customers/{customerId}/exchanges/{exchangeId}"}
	policy.BodyEventPolicies[0].Fields = append(policy.BodyEventPolicies[0].Fields, bodyField{
		Attribute: "customer.id", Source: "REQUEST_PATH_PARAM", Path: "customerId",
		Type: "STRING", Destinations: []string{"SPAN"},
	})
	if err := validateJavaPolicy("path-parameter-policy", encodePolicy(t, policy)); err != nil {
		t.Fatalf("schema 1.5 path parameter policy must be accepted: %v", err)
	}

	policy.SchemaVersion = "1.4"
	if err := validateJavaPolicy("path-parameter-policy", encodePolicy(t, policy)); err == nil ||
		!strings.Contains(err.Error(), "REQUEST_PATH_PARAM requires schemaVersion 1.5") {
		t.Fatalf("path parameter source must require schema 1.5, got %v", err)
	}

	policy.SchemaVersion = "1.5"
	policy.BodyEventPolicies[0].Direction = "OUTGOING"
	if err := validateJavaPolicy("path-parameter-policy", encodePolicy(t, policy)); err == nil ||
		!strings.Contains(err.Error(), "supported only for INCOMING") {
		t.Fatalf("outgoing path parameters must be rejected, got %v", err)
	}
}

func TestSchema15RequiresPathParameterSelectorsInTheRequestPathTemplate(t *testing.T) {
	for _, test := range []struct {
		name      string
		condition bool
	}{
		{name: "field"},
		{name: "condition", condition: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			resetState(t)
			policy := bodyEventTestPolicy()
			policy.SchemaVersion = "1.5"
			policy.BodyEventPolicies[0].Conditions[0].Values = []string{"/api/customers/{customerId}/exchanges"}
			if test.condition {
				policy.BodyEventPolicies[0].Conditions = append(
					policy.BodyEventPolicies[0].Conditions,
					httpCondition{
						Source: "REQUEST_PATH_PARAM", Path: "exchangeId",
						Operator: "EQUALS", Values: []string{"exchange-1"},
					},
				)
			} else {
				policy.BodyEventPolicies[0].Fields = append(
					policy.BodyEventPolicies[0].Fields,
					bodyField{
						Attribute: "exchange.id", Source: "REQUEST_PATH_PARAM", Path: "exchangeId",
						Type: "STRING", Destinations: []string{"SPAN"},
					},
				)
			}

			err := validateJavaPolicy("path-parameter-policy", encodePolicy(t, policy))
			if err == nil || !strings.Contains(err.Error(), "must appear as {exchangeId}") {
				t.Fatalf("orphan path parameter selector must be rejected, got %v", err)
			}
		})
	}
}

func TestSchema15ValidatesMessagingEventsAndMetrics(t *testing.T) {
	resetState(t)
	policy := messagingTestPolicy("KAFKA_PRODUCER")
	if err := validateJavaPolicy("kafka-exchange-policy", encodePolicy(t, policy)); err != nil {
		t.Fatalf("valid Kafka policy must be accepted: %v", err)
	}

	policy.SchemaVersion = "1.4"
	if err := validateJavaPolicy("kafka-exchange-policy", encodePolicy(t, policy)); err == nil ||
		!strings.Contains(err.Error(), "messaging policy events require schemaVersion 1.5") {
		t.Fatalf("messaging must require schema 1.5, got %v", err)
	}

	policy = messagingTestPolicy("KAFKA_CONSUMER")
	policy.MessagingEventPolicies[0].Fields[0].Source = "MESSAGE_PROPERTY"
	policy.MessagingEventPolicies[0].Fields[0].Path = "clientChannel"
	if err := validateJavaPolicy("kafka-property-policy", encodePolicy(t, policy)); err == nil ||
		!strings.Contains(err.Error(), "available only for JMS") {
		t.Fatalf("Kafka must reject JMS properties, got %v", err)
	}

	policy = messagingTestPolicy("JMS_CONSUMER")
	policy.MessagingEventPolicies[0].Fields[0].Source = "MESSAGE_PROPERTY"
	policy.MessagingEventPolicies[0].Fields[0].Path = "clientChannel"
	if err := validateJavaPolicy("jms-property-policy", encodePolicy(t, policy)); err != nil {
		t.Fatalf("JMS message property policy must be accepted: %v", err)
	}
}

func TestSchema15DenylistGovernsPathAndMessagingSelectors(t *testing.T) {
	pathPolicy := bodyEventTestPolicy()
	pathPolicy.SchemaVersion = "1.5"
	pathPolicy.BodyEventPolicies[0].Conditions[0].Values = []string{"/customers/{customerId}/exchange"}
	pathPolicy.BodyEventPolicies[0].Fields = append(pathPolicy.BodyEventPolicies[0].Fields, bodyField{
		Attribute: "customer.id", Source: "REQUEST_PATH_PARAM", Path: "customerId",
		Type: "STRING", Destinations: []string{"SPAN"},
	})
	if err := validateJavaPolicyAgainstDenylist(
		encodePolicy(t, pathPolicy),
		[]DenylistEntry{{Kind: "PATH_PARAM", Value: "customerId"}},
	); err == nil || !strings.Contains(err.Error(), "denied path_param customerId") {
		t.Fatalf("path parameter denylist must reject the capture, got %v", err)
	}

	messaging := messagingTestPolicy("KAFKA_PRODUCER")
	for _, test := range []struct {
		name  string
		entry DenylistEntry
	}{
		{name: "message header", entry: DenylistEntry{Kind: "HEADER", Value: "x-client-channel"}},
		{name: "payload path", entry: DenylistEntry{Kind: "BODY_PATH", Value: "sourceAmount"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateJavaPolicyAgainstDenylist(encodePolicy(t, messaging), []DenylistEntry{test.entry}); err == nil {
				t.Fatalf("denylist entry %#v must reject messaging policy", test.entry)
			}
		})
	}

	jms := messagingTestPolicy("JMS_PRODUCER")
	jms.MessagingEventPolicies[0].Fields[0].Source = "MESSAGE_PROPERTY"
	jms.MessagingEventPolicies[0].Fields[0].Path = "clientChannel"
	if err := validateJavaPolicyAgainstDenylist(
		encodePolicy(t, jms),
		[]DenylistEntry{{Kind: "MESSAGE_PROPERTY", Value: "clientChannel"}},
	); err == nil || !strings.Contains(err.Error(), "denied message_property clientChannel") {
		t.Fatalf("JMS property denylist must reject the capture, got %v", err)
	}
}

func TestSchema15MessagingParticipatesInEffectiveSetCollisions(t *testing.T) {
	first := messagingTestPolicy("KAFKA_PRODUCER")
	second := messagingTestPolicy("KAFKA_CONSUMER")
	second.MessagingEventPolicies[0].ID = "second-message-event"
	second.MessagingEventPolicies[0].EventName = "second-message-event"
	second.MessagingMetricPolicies[0].ID = "second-message-metric"
	second.MessagingMetricPolicies[0].EventName = "second-message-event"

	err := validatePolicySetCompatibility([]Config{
		{ID: "first-messaging", Body: encodePolicy(t, first)},
		{ID: "second-messaging", Body: encodePolicy(t, second)},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicated metric name") {
		t.Fatalf("effective set must reject messaging metric collisions, got %v", err)
	}
}

func TestSchema15RejectsUnknownMessagingJSONFields(t *testing.T) {
	body := `{
		"schemaVersion":"1.5",
		"messagingEventPolicies":[{
			"id":"message","enabled":true,"ruleName":"message","scope":"KAFKA_PRODUCER",
			"conditions":[],"eventName":"message-event","staticAttributes":[],
			"maxPayloadBytes":65536,"fields":[],"log":{"enabled":false,"severity":"INFO","body":"message"},
			"unexpected":true
		}],
		"messagingMetricPolicies":[]
	}`
	if _, err := decodeJavaPolicy(body); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("strict decoder must reject unknown messaging fields, got %v", err)
	}
}
