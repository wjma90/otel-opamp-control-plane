package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestBoundedValueCardinalityFactors(t *testing.T) {
	tests := []struct {
		name   string
		policy valuePolicy
		want   int
	}{
		{name: "ENUM includes fallback", policy: enumValuePolicy(3), want: 4},
		{
			name: "RANGE includes fallback",
			policy: valuePolicy{
				Type: "RANGE", Fallback: "OTHER",
				Ranges: []valueRange{
					{Max: floatPointer(100), Label: "LOW"},
					{Max: nil, Label: "HIGH"},
				},
			},
			want: 3,
		},
		{name: "BOOLEAN", policy: booleanValuePolicy(), want: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := boundedValueCardinality(test.policy); got != test.want {
				t.Fatalf("expected factor %d, got %d", test.want, got)
			}
		})
	}
	if got := boundedCardinalityProduct(4096, 2); got != maxMetricCardinality+1 {
		t.Fatalf("overflow must saturate above the limit, got %d", got)
	}
}

func TestHTTPMetricDimensionAndCardinalityLimitsMirrorJava(t *testing.T) {
	t.Run("eight bounded dimensions", func(t *testing.T) {
		resetState(t)
		policy := httpCardinalityPolicy(8, booleanValuePolicy())
		if err := validateJavaPolicy("http-eight-dimensions", encodePolicy(t, policy)); err != nil {
			t.Fatalf("eight bounded HTTP dimensions were rejected: %v", err)
		}
	})

	t.Run("nine dimensions", func(t *testing.T) {
		resetState(t)
		policy := httpCardinalityPolicy(9, booleanValuePolicy())
		err := validateJavaPolicy("http-nine-dimensions", encodePolicy(t, policy))
		if err == nil || !strings.Contains(err.Error(), "customAttributes exceeds") {
			t.Fatalf("expected HTTP dimension limit, got %v", err)
		}
	})

	t.Run("product at 4096", func(t *testing.T) {
		resetState(t)
		policy := httpCardinalityPolicy(4, enumValuePolicy(7))
		if err := validateJavaPolicy("http-cardinality-limit", encodePolicy(t, policy)); err != nil {
			t.Fatalf("HTTP cardinality at 4096 was rejected: %v", err)
		}
	})

	t.Run("product above 4096", func(t *testing.T) {
		resetState(t)
		policy := httpCardinalityPolicy(5, enumValuePolicy(7))
		err := validateJavaPolicy("http-cardinality-overflow", encodePolicy(t, policy))
		if err == nil || !strings.Contains(err.Error(), "cardinality exceeds") {
			t.Fatalf("expected HTTP cardinality rejection, got %v", err)
		}
	})

	t.Run("duplicate custom and standard dimensions", func(t *testing.T) {
		resetState(t)
		policy := httpCardinalityPolicy(2, booleanValuePolicy())
		policy.MetricPolicies[0].CustomAttributes[1].Attribute =
			policy.MetricPolicies[0].CustomAttributes[0].Attribute
		err := validateJavaPolicy("http-duplicate-custom", encodePolicy(t, policy))
		if err == nil || !strings.Contains(err.Error(), "duplicated custom attribute") {
			t.Fatalf("expected duplicate HTTP custom dimension rejection, got %v", err)
		}

		policy = httpCardinalityPolicy(1, booleanValuePolicy())
		policy.MetricPolicies[0].StandardAttributes = []string{
			"http.request.method",
			"http.request.method",
		}
		err = validateJavaPolicy("http-duplicate-standard", encodePolicy(t, policy))
		if err == nil || !strings.Contains(err.Error(), "duplicated standard attribute") {
			t.Fatalf("expected duplicate HTTP standard dimension rejection, got %v", err)
		}
	})
}

func TestMethodMetricDimensionAndCardinalityLimitsMirrorJava(t *testing.T) {
	t.Run("eight bounded captures", func(t *testing.T) {
		resetState(t)
		policy := methodCardinalityPolicy(8, booleanValuePolicy())
		if err := validateJavaPolicy("method-eight-dimensions", encodePolicy(t, policy)); err != nil {
			t.Fatalf("eight method metric dimensions were rejected: %v", err)
		}
	})

	t.Run("nine metric captures", func(t *testing.T) {
		resetState(t)
		policy := methodCardinalityPolicy(9, booleanValuePolicy())
		err := validateJavaPolicy("method-nine-dimensions", encodePolicy(t, policy))
		if err == nil || !strings.Contains(err.Error(), "metric dimensions exceeds") {
			t.Fatalf("expected method dimension limit, got %v", err)
		}
	})

	t.Run("product boundary", func(t *testing.T) {
		resetState(t)
		atLimit := methodCardinalityPolicy(4, enumValuePolicy(7))
		if err := validateJavaPolicy("method-cardinality-limit", encodePolicy(t, atLimit)); err != nil {
			t.Fatalf("method cardinality at 4096 was rejected: %v", err)
		}

		aboveLimit := methodCardinalityPolicy(5, enumValuePolicy(7))
		err := validateJavaPolicy("method-cardinality-overflow", encodePolicy(t, aboveLimit))
		if err == nil || !strings.Contains(err.Error(), "cardinality exceeds") {
			t.Fatalf("expected method cardinality rejection, got %v", err)
		}
	})

	t.Run("duplicate capture", func(t *testing.T) {
		resetState(t)
		policy := methodCardinalityPolicy(2, booleanValuePolicy())
		policy.MethodPolicies[0].Captures[1].Attribute =
			policy.MethodPolicies[0].Captures[0].Attribute
		err := validateJavaPolicy("method-duplicate-capture", encodePolicy(t, policy))
		if err == nil || !strings.Contains(err.Error(), "duplicated capture attribute") {
			t.Fatalf("expected duplicate method capture rejection, got %v", err)
		}
	})
}

func TestBusinessEventDimensionAndCardinalityLimitsMirrorJava(t *testing.T) {
	t.Run("eight bounded dimensions", func(t *testing.T) {
		resetState(t)
		policy := businessCardinalityPolicy(8, booleanValuePolicy())
		if err := validateJavaPolicy("business-eight-dimensions", encodePolicy(t, policy)); err != nil {
			t.Fatalf("eight business event dimensions were rejected: %v", err)
		}
	})

	t.Run("nine dimensions", func(t *testing.T) {
		resetState(t)
		policy := businessCardinalityPolicy(9, booleanValuePolicy())
		err := validateJavaPolicy("business-nine-dimensions", encodePolicy(t, policy))
		if err == nil || !strings.Contains(err.Error(), "dimensions exceeds") {
			t.Fatalf("expected business dimension limit, got %v", err)
		}
	})

	t.Run("product boundary", func(t *testing.T) {
		resetState(t)
		atLimit := businessCardinalityPolicy(4, enumValuePolicy(7))
		if err := validateJavaPolicy("business-cardinality-limit", encodePolicy(t, atLimit)); err != nil {
			t.Fatalf("business cardinality at 4096 was rejected: %v", err)
		}

		aboveLimit := businessCardinalityPolicy(5, enumValuePolicy(7))
		err := validateJavaPolicy("business-cardinality-overflow", encodePolicy(t, aboveLimit))
		if err == nil || !strings.Contains(err.Error(), "cardinality exceeds") {
			t.Fatalf("expected business cardinality rejection, got %v", err)
		}
	})

	t.Run("duplicate dimension", func(t *testing.T) {
		resetState(t)
		policy := businessCardinalityPolicy(2, booleanValuePolicy())
		policy.EventMetricPolicies[0].Dimensions[1] =
			policy.EventMetricPolicies[0].Dimensions[0]
		err := validateJavaPolicy("business-duplicate-dimension", encodePolicy(t, policy))
		if err == nil || !strings.Contains(err.Error(), "unique bounded") {
			t.Fatalf("expected duplicate business dimension rejection, got %v", err)
		}
	})
}

func httpCardinalityPolicy(dimensions int, valuePolicy valuePolicy) javaPolicy {
	policy := testPolicy("test.method.unused", "COUNTER")
	policy.MethodPolicies = nil
	metric := &policy.MetricPolicies[0]
	metric.CustomAttributes = make([]attributeSource, dimensions)
	for index := range metric.CustomAttributes {
		metric.CustomAttributes[index] = attributeSource{
			valueSource:  valueSource{Source: "REQUEST_HEADER", ArgumentIndex: -1},
			Header:       fmt.Sprintf("x-dimension-%d", index),
			Attribute:    fmt.Sprintf("test.dimension.%d", index),
			Destinations: []string{"SPAN"},
			ValuePolicy:  valuePolicy,
		}
	}
	return policy
}

func methodCardinalityPolicy(dimensions int, valuePolicy valuePolicy) javaPolicy {
	policy := testPolicy("test.method.cardinality", "COUNTER")
	policy.MetricPolicies = nil
	method := &policy.MethodPolicies[0]
	method.Captures = make([]capture, dimensions)
	for index := range method.Captures {
		method.Captures[index] = capture{
			valueSource: valueSource{Source: "ARGUMENT", ArgumentIndex: index},
			Attribute:   fmt.Sprintf("test.dimension.%d", index),
			Type:        "STRING",
			Destinations: []string{
				"METRIC",
			},
			ValuePolicy: valuePolicy,
		}
	}
	return policy
}

func businessCardinalityPolicy(dimensions int, valuePolicy valuePolicy) javaPolicy {
	policy := bodyEventTestPolicy()
	event := &policy.BodyEventPolicies[0]
	event.Fields = make([]bodyField, dimensions)
	dimensionNames := make([]string, dimensions)
	for index := range event.Fields {
		name := fmt.Sprintf("test.dimension.%d", index)
		dimensionNames[index] = name
		event.Fields[index] = bodyField{
			Attribute:    name,
			Source:       "REQUEST_BODY",
			Path:         fmt.Sprintf("dimension%d", index),
			Type:         "STRING",
			Destinations: []string{"METRIC"},
			ValuePolicy:  valuePolicy,
		}
	}
	policy.EventMetricPolicies = []eventMetricPolicy{{
		ID:          "test-business-count-v1",
		Enabled:     true,
		EventName:   event.EventName,
		Name:        "test.business.count",
		Instrument:  "COUNTER",
		Unit:        "{event}",
		Description: "Test business event count",
		Dimensions:  dimensionNames,
	}}
	return policy
}

func enumValuePolicy(allowed int) valuePolicy {
	values := make([]string, allowed)
	for index := range values {
		values[index] = fmt.Sprintf("VALUE_%d", index)
	}
	return valuePolicy{Type: "ENUM", Allowed: values, Fallback: "OTHER"}
}

func booleanValuePolicy() valuePolicy {
	return valuePolicy{Type: "BOOLEAN", Fallback: "false"}
}
