//go:build integration

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresMigrationRemovesCollectorBootstrapCatalog(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	legacyPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"collector_bootstrap_profiles",
		"collector_bootstrap_audit",
	} {
		if _, err := legacyPool.Exec(
			ctx,
			"CREATE TABLE IF NOT EXISTS "+table+" (legacy_marker INTEGER)",
		); err != nil {
			legacyPool.Close()
			t.Fatal(err)
		}
	}
	legacyPool.Close()

	store, err := newPostgresStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.close)

	for _, table := range []string{
		"collector_bootstrap_profiles",
		"collector_bootstrap_audit",
	} {
		var absent bool
		if err := store.pool.QueryRow(
			ctx,
			"SELECT to_regclass($1) IS NULL",
			"public."+table,
		).Scan(&absent); err != nil {
			t.Fatal(err)
		}
		if !absent {
			t.Fatalf("obsolete table %s still exists", table)
		}
	}
}

func TestPostgresCollectorDeactivationCreatesImmutableJournalEntry(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := newPostgresStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.close)

	const configID = "integration-collector-lifecycle"
	_, _ = store.pool.Exec(ctx, "DELETE FROM config_deployments WHERE config_id = $1", configID)
	_, _ = store.pool.Exec(ctx, "DELETE FROM policy_audit WHERE config_id = $1", configID)
	_, _ = store.pool.Exec(ctx, "DELETE FROM control_plane_configs WHERE config_id = $1", configID)
	t.Cleanup(func() {
		cleanupContext, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = store.pool.Exec(cleanupContext, "DELETE FROM config_deployments WHERE config_id = $1", configID)
		_, _ = store.pool.Exec(cleanupContext, "DELETE FROM policy_audit WHERE config_id = $1", configID)
		_, _ = store.pool.Exec(cleanupContext, "DELETE FROM control_plane_configs WHERE config_id = $1", configID)
	})

	v1, err := store.saveConfig(ctx, Config{
		ID:       configID,
		Target:   "collector",
		Body:     "receivers:\n  nop: {}\nexporters:\n  nop: {}\nservice:\n  pipelines:\n    traces:\n      receivers: [nop]\n      exporters: [nop]\n",
		Hash:     "collector-v1",
		Selector: AgentSelector{Services: []string{"integration-supervisor"}},
	}, "test", "PUBLISHED", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}

	previousDatabase := database
	database = store
	t.Cleanup(func() { database = previousDatabase })
	resetState(t)
	state.Configs[v1.ID] = []Config{v1}

	request := httptest.NewRequest(http.MethodPost, "/api/collector-configs/"+configID+"/deactivate", nil)
	request.SetPathValue("id", configID)
	recorder := httptest.NewRecorder()
	deactivateCollectorConfig(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", recorder.Code, recorder.Body.String())
	}

	latest, err := store.latestConfig(ctx, configID)
	if err != nil {
		t.Fatal(err)
	}
	if latest.Version != 2 || latest.Active || latest.Action != "DEACTIVATED" ||
		latest.Body != v1.Body || latest.Hash != v1.Hash || latest.SourceVersion != v1.SourceVersion {
		t.Fatalf("unexpected deactivation journal entry: %#v", latest)
	}
	if len(state.Configs[configID]) != 2 {
		t.Fatalf("in-memory history was not updated: %#v", state.Configs[configID])
	}
}
