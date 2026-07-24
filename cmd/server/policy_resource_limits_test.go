package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestPolicyResourceLimitsMirrorJavaExtension(t *testing.T) {
	atLimit := javaPolicy{
		MetricPolicies: make([]httpMetricPolicy, maxHTTPMetricPolicies),
		MethodPolicies: make([]methodPolicy, maxMethodPolicies),
	}
	for index := range atLimit.MethodPolicies {
		atLimit.MethodPolicies[index].Captures = make([]capture, maxMethodCaptures)
		atLimit.MethodPolicies[index].Metrics = make([]methodMetric, maxMethodMetrics)
	}
	if err := validatePolicyResourceLimits(atLimit); err != nil {
		t.Fatalf("policy at the Java limits was rejected: %v", err)
	}

	tests := map[string]javaPolicy{
		"HTTP metrics": {MetricPolicies: make([]httpMetricPolicy, maxHTTPMetricPolicies+1)},
		"methods":      {MethodPolicies: make([]methodPolicy, maxMethodPolicies+1)},
		"captures": {
			MethodPolicies: []methodPolicy{{Captures: make([]capture, maxMethodCaptures+1)}},
		},
		"method metrics": {
			MethodPolicies: []methodPolicy{{Metrics: make([]methodMetric, maxMethodMetrics+1)}},
		},
	}
	for name, policy := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validatePolicyResourceLimits(policy); err == nil {
				t.Fatal("policy above the Java limit was accepted")
			}
		})
	}
}

func TestEffectivePolicySetUsesAggregateResourceLimits(t *testing.T) {
	policies := make([]Config, 0, maxHTTPMetricPolicies+1)
	for index := 0; index < maxHTTPMetricPolicies+1; index++ {
		policy := javaPolicy{
			SchemaVersion: "1.3",
			MetricPolicies: []httpMetricPolicy{{
				ID:         fmt.Sprintf("metric-%d", index),
				Enabled:    true,
				Value:      valueSource{Source: "CONSTANT", ArgumentIndex: -1, Constant: 1},
				Name:       fmt.Sprintf("test.aggregate.metric.%d", index),
				Instrument: "COUNTER",
				Unit:       "{operation}",
			}},
		}
		policies = append(policies, Config{
			ID:     fmt.Sprintf("aggregate-policy-%d", index),
			Target: "java-extension",
			Body:   encodePolicy(t, policy),
			Active: true,
		})
	}
	err := validatePolicySetCompatibility(policies)
	if err == nil || !strings.Contains(err.Error(), "metricPolicies exceeds") {
		t.Fatalf("aggregate HTTP metric limit was not enforced: %v", err)
	}
}

func TestMetricBucketAndLifetimeLimitsMirrorJavaExtension(t *testing.T) {
	buckets := make([]float64, maxExplicitBuckets)
	for index := range buckets {
		buckets[index] = float64(index + 1)
	}
	if _, err := validateMetricDefinition(
		"test",
		"test.bucket.limit",
		"HISTOGRAM",
		"1",
		buckets,
		map[string]bool{},
		map[string]bool{},
	); err != nil {
		t.Fatalf("histogram at bucket limit was rejected: %v", err)
	}
	buckets = append(buckets, float64(maxExplicitBuckets+1))
	if _, err := validateMetricDefinition(
		"test",
		"test.bucket.overflow",
		"HISTOGRAM",
		"1",
		buckets,
		map[string]bool{},
		map[string]bool{},
	); err == nil {
		t.Fatal("histogram above bucket limit was accepted")
	}

	existing := make([]metricDefinition, maxLifetimeMetricNames)
	for index := range existing {
		existing[index] = metricDefinition{Name: fmt.Sprintf("test.metric.%d", index)}
	}
	if err := validateLifetimeMetricCapacity(existing, []metricDefinition{{Name: existing[0].Name}}); err != nil {
		t.Fatalf("existing instrument name should not consume another slot: %v", err)
	}
	if err := validateLifetimeMetricCapacity(
		existing,
		[]metricDefinition{{Name: "test.metric.overflow"}},
	); err == nil {
		t.Fatal("lifetime instrument limit was not enforced")
	}
}
