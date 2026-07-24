package main

import (
	"strings"
	"testing"
)

func TestGovernedPathsIntersectOnlyForSameTreeBranch(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		left      string
		right     string
		intersect bool
	}{
		{name: "exact", left: "customer.email", right: "customer.email", intersect: true},
		{name: "candidate descendant", left: "customer.email.value", right: "customer.email", intersect: true},
		{name: "candidate ancestor", left: "customer", right: "customer.email", intersect: true},
		{name: "array descendant", left: "items[0].card.number", right: "items[0].card", intersect: true},
		{name: "array ancestor", left: "items", right: "items[0].card", intersect: true},
		{name: "empty candidate root", left: "", right: "customer.email", intersect: true},
		{name: "empty denied root", left: "customer.email", right: "", intersect: true},
		{name: "object siblings", left: "customer.name", right: "customer.email", intersect: false},
		{name: "lexical prefix is not ancestor", left: "customer.emailAddress", right: "customer.email", intersect: false},
		{name: "array siblings", left: "items[1].card", right: "items[0].card", intersect: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := governedPathsIntersect(test.left, test.right); got != test.intersect {
				t.Fatalf("governedPathsIntersect(%q, %q) = %t; want %t", test.left, test.right, got, test.intersect)
			}
		})
	}
}

func TestBodyPathDenylistRejectsAncestorsDescendantsAndRoot(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*javaPolicy)
		denied      string
		wantBlocked bool
	}{
		{
			name: "field ancestor",
			mutate: func(policy *javaPolicy) {
				policy.BodyEventPolicies[0].Fields[0].Path = "customer"
			},
			denied:      "customer.email",
			wantBlocked: true,
		},
		{
			name: "field descendant",
			mutate: func(policy *javaPolicy) {
				policy.BodyEventPolicies[0].Fields[0].Path = "customer.email.value"
			},
			denied:      "customer.email",
			wantBlocked: true,
		},
		{
			name: "field root",
			mutate: func(policy *javaPolicy) {
				policy.BodyEventPolicies[0].Fields[0].Path = ""
			},
			denied:      "customer.email",
			wantBlocked: true,
		},
		{
			name: "condition ancestor",
			mutate: func(policy *javaPolicy) {
				policy.BodyEventPolicies[0].Conditions[3].Path = "result"
			},
			denied:      "result.customer.email",
			wantBlocked: true,
		},
		{
			name: "condition dollar root",
			mutate: func(policy *javaPolicy) {
				policy.BodyEventPolicies[0].Conditions[3].Path = "$"
			},
			denied:      "result.customer.email",
			wantBlocked: true,
		},
		{
			name: "object sibling",
			mutate: func(policy *javaPolicy) {
				policy.BodyEventPolicies[0].Fields[0].Path = "customer.name"
			},
			denied: "customer.email",
		},
		{
			name: "lexical sibling",
			mutate: func(policy *javaPolicy) {
				policy.BodyEventPolicies[0].Fields[0].Path = "customer.emailAddress"
			},
			denied: "customer.email",
		},
		{
			name: "array sibling",
			mutate: func(policy *javaPolicy) {
				policy.BodyEventPolicies[0].Fields[0].Path = "items[1].sku"
			},
			denied: "items[0].card.number",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := bodyEventTestPolicy()
			test.mutate(&policy)
			err := validateJavaPolicyAgainstDenylist(
				encodePolicy(t, policy),
				[]DenylistEntry{{Kind: "BODY_PATH", Value: test.denied}},
			)
			assertDenylistResult(t, err, test.wantBlocked, "body_path")
		})
	}
}

func TestMethodPathDenylistRejectsAncestorsDescendantsAndObjectRoot(t *testing.T) {
	tests := []struct {
		name        string
		mutate      func(*javaPolicy)
		denied      string
		wantBlocked bool
	}{
		{
			name: "argument capture ancestor",
			mutate: func(policy *javaPolicy) {
				policy.MethodPolicies[0].Captures[0].Path = "customer"
			},
			denied:      "customer.accountNumber",
			wantBlocked: true,
		},
		{
			name: "return capture descendant",
			mutate: func(policy *javaPolicy) {
				policy.MethodPolicies[0].Captures[0].Source = "RETURN"
				policy.MethodPolicies[0].Captures[0].ArgumentIndex = -1
				policy.MethodPolicies[0].Captures[0].Path = "customer.accountNumber.value"
			},
			denied:      "customer.accountNumber",
			wantBlocked: true,
		},
		{
			name: "argument capture root",
			mutate: func(policy *javaPolicy) {
				policy.MethodPolicies[0].Captures[0].Path = ""
			},
			denied:      "password",
			wantBlocked: true,
		},
		{
			name: "return capture root",
			mutate: func(policy *javaPolicy) {
				policy.MethodPolicies[0].Captures[0].Source = "RETURN"
				policy.MethodPolicies[0].Captures[0].ArgumentIndex = -1
				policy.MethodPolicies[0].Captures[0].Path = ""
			},
			denied:      "secret.value",
			wantBlocked: true,
		},
		{
			name: "metric argument ancestor",
			mutate: func(policy *javaPolicy) {
				policy.MethodPolicies[0].Metrics[0].Value = valueSource{
					Source:        "ARGUMENT",
					ArgumentIndex: 0,
					Path:          "payment",
				}
			},
			denied:      "payment.card.number",
			wantBlocked: true,
		},
		{
			name: "metric return root",
			mutate: func(policy *javaPolicy) {
				policy.MethodPolicies[0].Metrics[0].Value = valueSource{
					Source:        "RETURN",
					ArgumentIndex: -1,
				}
			},
			denied:      "customer.accountNumber",
			wantBlocked: true,
		},
		{
			name: "object sibling",
			mutate: func(policy *javaPolicy) {
				policy.MethodPolicies[0].Captures[0].Path = "customer.name"
			},
			denied: "customer.email",
		},
		{
			name: "lexical sibling",
			mutate: func(policy *javaPolicy) {
				policy.MethodPolicies[0].Captures[0].Path = "customer.emailAddress"
			},
			denied: "customer.email",
		},
		{
			name: "constant metric is not an object capture",
			mutate: func(policy *javaPolicy) {
				policy.MethodPolicies[0].Captures = nil
				policy.MethodPolicies[0].Metrics[0].Value = valueSource{
					Source:        "CONSTANT",
					ArgumentIndex: -1,
					Constant:      1,
				}
			},
			denied: "customer.accountNumber",
		},
		{
			name: "duration metric is not an object capture",
			mutate: func(policy *javaPolicy) {
				policy.MethodPolicies[0].Captures = nil
				policy.MethodPolicies[0].Metrics[0].Value = valueSource{
					Source:        "DURATION",
					ArgumentIndex: -1,
				}
			},
			denied: "customer.accountNumber",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := testPolicy("test.method.path.denylist", "COUNTER")
			test.mutate(&policy)
			err := validateJavaPolicyAgainstDenylist(
				encodePolicy(t, policy),
				[]DenylistEntry{{Kind: "METHOD_PATH", Value: test.denied}},
			)
			assertDenylistResult(t, err, test.wantBlocked, "method_path")
		})
	}
}

func assertDenylistResult(t *testing.T, err error, wantBlocked bool, kind string) {
	t.Helper()
	if wantBlocked {
		if err == nil || !strings.Contains(err.Error(), "denied "+kind) {
			t.Fatalf("expected %s denylist rejection, got %v", kind, err)
		}
		return
	}
	if err != nil {
		t.Fatalf("expected non-intersecting %s paths to remain allowed, got %v", kind, err)
	}
}
