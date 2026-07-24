//go:build integration

package main

import (
	"context"
	"testing"
	"time"
)

func TestPostgresSemanticPolicyLifecycle(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := newPostgresStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.close)

	const policyID = "integration-policy-lifecycle"
	_, _ = store.pool.Exec(ctx, "DELETE FROM config_deployments WHERE config_id = $1", policyID)
	_, _ = store.pool.Exec(ctx, "DELETE FROM policy_audit WHERE config_id = $1", policyID)
	_, _ = store.pool.Exec(ctx, "DELETE FROM control_plane_configs WHERE config_id = $1", policyID)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = store.pool.Exec(cleanupContext, "DELETE FROM config_deployments WHERE config_id = $1", policyID)
		_, _ = store.pool.Exec(cleanupContext, "DELETE FROM policy_audit WHERE config_id = $1", policyID)
		_, _ = store.pool.Exec(cleanupContext, "DELETE FROM control_plane_configs WHERE config_id = $1", policyID)
	})

	v1, err := store.saveConfig(ctx, Config{
		ID:       policyID,
		Target:   "java-extension",
		Body:     `{"schemaVersion":"1.3"}`,
		Hash:     "v1",
		Selector: AgentSelector{Services: []string{"exchange-service"}},
	}, "test", "PUBLISHED", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if v1.Version != 1 || v1.SourceVersion != 1 || !v1.Active {
		t.Fatalf("unexpected first revision: %#v", v1)
	}
	v2, err := store.saveConfig(ctx, Config{
		ID:       policyID,
		Target:   "java-extension",
		Body:     `{"schemaVersion":"1.3","requestHeaders":[]}`,
		Hash:     "v2",
		Selector: v1.Selector,
	}, "test", "PUBLISHED", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	current, predecessor, err := store.policyRollbackCandidate(ctx, policyID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != v2.Version || predecessor == nil || predecessor.Version != v1.Version {
		t.Fatalf("unexpected rollback candidate: current=%#v predecessor=%#v", current, predecessor)
	}

	rollback := *predecessor
	rollback.Active = true
	rollback.SourceVersion = predecessor.Version
	v3, err := store.saveConfigExpected(
		ctx,
		rollback,
		"test",
		"ROLLBACK",
		map[string]any{"sourceVersion": predecessor.Version},
		current.Version,
	)
	if err != nil {
		t.Fatal(err)
	}
	if v3.Version != 3 || v3.SourceVersion != 1 || !v3.Active || v3.Action != "ROLLBACK" {
		t.Fatalf("unexpected rollback journal row: %#v", v3)
	}

	current, predecessor, err = store.policyRollbackCandidate(ctx, policyID)
	if err != nil {
		t.Fatal(err)
	}
	if predecessor != nil {
		t.Fatalf("a second rollback must deactivate instead of oscillating: %#v", predecessor)
	}
	current.Active = false
	v4, err := store.saveConfigExpected(
		ctx,
		current,
		"test",
		"DEACTIVATED",
		map[string]any{"reason": "rollback-before-first-version"},
		current.Version,
	)
	if err != nil {
		t.Fatal(err)
	}
	if v4.Version != 4 || v4.Active || v4.SourceVersion != 1 || v4.Action != "DEACTIVATED" {
		t.Fatalf("unexpected deactivation journal row: %#v", v4)
	}
}
