package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	errConcurrentConfigUpdate       = errors.New("configuration changed concurrently")
	errConcurrentAuthProviderUpdate = errors.New("identity provider changed concurrently")
	errPolicyInactive               = errors.New("policy is already inactive")
)

type PostgresStore struct {
	pool *pgxpool.Pool
}

type AuditEvent struct {
	AuditID   int64
	ConfigID  string
	Version   int
	Action    string
	Actor     string
	CreatedAt time.Time
	Details   map[string]any
}

type DeploymentRecord struct {
	ConfigID             string
	Version              int
	Target               string
	Body                 string
	Selector             AgentSelector
	PublishedAt          time.Time
	PublishedBy          string
	AgentUID             string
	Service              string
	AgentAttributes      map[string]string
	FirstMatchedAt       time.Time
	LastObservedAt       time.Time
	AppliedAt            *time.Time
	ObservedStatus       string
	ConnectionStatus     string
	CurrentConfigID      string
	CurrentConfigVersion int
	CurrentConfigStatus  string
	CurrentConfigOrigin  string
	BaseConfig           BaseConfig
	BundleHash           string
	DesiredPresence      bool
	CurrentPolicyVersion int
	PolicyPresent        bool
	LiveStatus           string
	// CoverageState separates an OpAMP deployment observation from the set of
	// destinations that can be evaluated live right now. Historical agent UIDs
	// remain useful audit evidence, but must not make a selector-scoped rollout
	// look partial after a pod has disappeared or changed UID.
	CoverageState         string
	CountsForLiveCoverage bool
	SourceVersion         int
	Active                bool
}

type DenylistEntry struct {
	Kind      string
	Value     string
	UpdatedAt time.Time
	UpdatedBy string
}

// AuthProviderRecord is the persistence model shared by OIDC and SAML. Public
// configuration lives in Config; credentials remain encrypted in SecretCipher.
type AuthProviderRecord struct {
	ProviderID        string
	Protocol          string
	Label             string
	Config            map[string]string
	SecretCipher      string
	Status            string
	ValidationMessage string
	ValidatedAt       *time.Time
	UpdatedAt         time.Time
	UpdatedBy         string
	RoleMappings      map[string]string
}

func newPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("configure PostgreSQL pool: %w", err)
	}
	store := &PostgresStore{pool: pool}
	if err := store.ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := store.migrate(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := store.migrateLocalIdentity(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

func (s *PostgresStore) close() {
	s.pool.Close()
}

func (s *PostgresStore) ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("PostgreSQL unavailable: %w", err)
	}
	return nil
}

func (s *PostgresStore) authProviders(ctx context.Context) ([]AuthProviderRecord, error) {
	rows, err := s.pool.Query(ctx, `
SELECT
    provider_id,
    protocol,
    label,
    config,
    secret_cipher,
    status,
    validation_message,
    validated_at,
    updated_at,
    updated_by
FROM auth_providers
ORDER BY provider_id`)
	if err != nil {
		return nil, fmt.Errorf("query auth providers: %w", err)
	}
	defer rows.Close()
	records := []AuthProviderRecord{}
	for rows.Next() {
		var record AuthProviderRecord
		var configJSON []byte
		if err := rows.Scan(
			&record.ProviderID,
			&record.Protocol,
			&record.Label,
			&configJSON,
			&record.SecretCipher,
			&record.Status,
			&record.ValidationMessage,
			&record.ValidatedAt,
			&record.UpdatedAt,
			&record.UpdatedBy,
		); err != nil {
			return nil, fmt.Errorf("scan auth provider: %w", err)
		}
		if err := json.Unmarshal(configJSON, &record.Config); err != nil {
			return nil, fmt.Errorf("decode auth provider %s config: %w", record.ProviderID, err)
		}
		record.RoleMappings, err = s.authProviderRoleMappings(ctx, record.ProviderID)
		if err != nil {
			return nil, err
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (s *PostgresStore) saveAuthProvider(ctx context.Context, record AuthProviderRecord) error {
	configJSON, err := json.Marshal(record.Config)
	if err != nil {
		return fmt.Errorf("encode auth provider config: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO auth_providers (
    provider_id,
    protocol,
    label,
    config,
    secret_cipher,
    status,
    validation_message,
    validated_at,
    updated_at,
    updated_by
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (provider_id) DO UPDATE SET
    protocol = EXCLUDED.protocol,
    label = EXCLUDED.label,
    config = EXCLUDED.config,
    secret_cipher = EXCLUDED.secret_cipher,
    status = EXCLUDED.status,
    validation_message = EXCLUDED.validation_message,
    validated_at = EXCLUDED.validated_at,
    updated_at = EXCLUDED.updated_at,
    updated_by = EXCLUDED.updated_by`,
		record.ProviderID,
		record.Protocol,
		record.Label,
		configJSON,
		record.SecretCipher,
		record.Status,
		record.ValidationMessage,
		record.ValidatedAt,
		record.UpdatedAt,
		record.UpdatedBy,
	)
	if err != nil {
		return fmt.Errorf("save auth provider: %w", err)
	}
	return nil
}

// saveAuthProviderWithRoleMappings persists the provider revision and its
// authorization boundary as one unit. A provider must never become visible
// with stale or partially replaced role mappings.
func (s *PostgresStore) saveAuthProviderWithRoleMappings(
	ctx context.Context,
	record AuthProviderRecord,
	expectedUpdatedAt *time.Time,
) error {
	configJSON, err := json.Marshal(record.Config)
	if err != nil {
		return fmt.Errorf("encode auth provider config: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin auth provider update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var storedUpdatedAt time.Time
	lookupErr := tx.QueryRow(ctx, `
SELECT updated_at
FROM auth_providers
WHERE provider_id = $1
FOR UPDATE`, record.ProviderID).Scan(&storedUpdatedAt)
	switch {
	case errors.Is(lookupErr, pgx.ErrNoRows) && expectedUpdatedAt != nil:
		return errConcurrentAuthProviderUpdate
	case lookupErr != nil && !errors.Is(lookupErr, pgx.ErrNoRows):
		return fmt.Errorf("lock auth provider: %w", lookupErr)
	case lookupErr == nil && expectedUpdatedAt == nil:
		return errConcurrentAuthProviderUpdate
	case lookupErr == nil && !storedUpdatedAt.Equal(expectedUpdatedAt.UTC().Truncate(time.Microsecond)):
		return errConcurrentAuthProviderUpdate
	}
	if _, err = tx.Exec(ctx, `
INSERT INTO auth_providers (
    provider_id,
    protocol,
    label,
    config,
    secret_cipher,
    status,
    validation_message,
    validated_at,
    updated_at,
    updated_by
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (provider_id) DO UPDATE SET
    protocol = EXCLUDED.protocol,
    label = EXCLUDED.label,
    config = EXCLUDED.config,
    secret_cipher = EXCLUDED.secret_cipher,
    status = EXCLUDED.status,
    validation_message = EXCLUDED.validation_message,
    validated_at = EXCLUDED.validated_at,
    updated_at = EXCLUDED.updated_at,
    updated_by = EXCLUDED.updated_by`,
		record.ProviderID,
		record.Protocol,
		record.Label,
		configJSON,
		record.SecretCipher,
		record.Status,
		record.ValidationMessage,
		record.ValidatedAt,
		record.UpdatedAt,
		record.UpdatedBy,
	); err != nil {
		return fmt.Errorf("save auth provider: %w", err)
	}
	if _, err = tx.Exec(
		ctx,
		"DELETE FROM auth_provider_role_mappings WHERE provider_id = $1",
		record.ProviderID,
	); err != nil {
		return fmt.Errorf("clear auth role mappings: %w", err)
	}
	for externalRole, localRole := range record.RoleMappings {
		if _, err = tx.Exec(ctx, `
INSERT INTO auth_provider_role_mappings (provider_id, external_role, local_role)
VALUES ($1, $2, $3)`, record.ProviderID, externalRole, localRole); err != nil {
			return fmt.Errorf("save auth role mapping: %w", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit auth provider update: %w", err)
	}
	return nil
}

func (s *PostgresStore) updateAuthProviderValidation(
	ctx context.Context,
	providerID string,
	status string,
	message string,
	validatedAt *time.Time,
	actor string,
) error {
	_, err := s.pool.Exec(ctx, `
UPDATE auth_providers
SET status = $2,
    validation_message = $3,
    validated_at = $4,
    updated_at = NOW(),
    updated_by = $5
WHERE provider_id = $1`, providerID, status, message, validatedAt, actor)
	if err != nil {
		return fmt.Errorf("update auth provider validation: %w", err)
	}
	return nil
}

func (s *PostgresStore) deleteAuthProvider(ctx context.Context, providerID string) error {
	if _, err := s.pool.Exec(ctx, "DELETE FROM auth_providers WHERE provider_id = $1", providerID); err != nil {
		return fmt.Errorf("delete auth provider: %w", err)
	}
	return nil
}

func (s *PostgresStore) authProviderRoleMappings(
	ctx context.Context,
	providerID string,
) (map[string]string, error) {
	rows, err := s.pool.Query(ctx, `
SELECT external_role, local_role
FROM auth_provider_role_mappings
WHERE provider_id = $1
ORDER BY external_role`, providerID)
	if err != nil {
		return nil, fmt.Errorf("query auth provider role mappings: %w", err)
	}
	defer rows.Close()
	mappings := map[string]string{}
	for rows.Next() {
		var externalRole, localRole string
		if err := rows.Scan(&externalRole, &localRole); err != nil {
			return nil, fmt.Errorf("scan auth provider role mapping: %w", err)
		}
		mappings[externalRole] = localRole
	}
	return mappings, rows.Err()
}

func (s *PostgresStore) saveAuthProviderRoleMappings(
	ctx context.Context,
	providerID string,
	mappings map[string]string,
) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin auth role mappings update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(
		ctx,
		"DELETE FROM auth_provider_role_mappings WHERE provider_id = $1",
		providerID,
	); err != nil {
		return fmt.Errorf("clear auth role mappings: %w", err)
	}
	for externalRole, localRole := range mappings {
		if _, err := tx.Exec(ctx, `
INSERT INTO auth_provider_role_mappings (provider_id, external_role, local_role)
VALUES ($1, $2, $3)`, providerID, externalRole, localRole); err != nil {
			return fmt.Errorf("save auth role mapping: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit auth role mappings update: %w", err)
	}
	return nil
}

func (s *PostgresStore) saveSAMLFlow(
	ctx context.Context,
	relayState string,
	providerID string,
	requestID string,
	browserHash string,
	expiresAt time.Time,
) error {
	_, err := s.pool.Exec(ctx, `
WITH expired AS (
    DELETE FROM auth_saml_flows
    WHERE expires_at <= NOW()
)
INSERT INTO auth_saml_flows (relay_state, provider_id, request_id, browser_hash, expires_at)
VALUES ($1, $2, $3, $4, $5)`, relayState, providerID, requestID, browserHash, expiresAt)
	if err != nil {
		return fmt.Errorf("save SAML flow: %w", err)
	}
	return nil
}

// consumeSAMLFlow atomically deletes the RelayState. A valid response can
// therefore establish at most one session, including across replicas.
func (s *PostgresStore) consumeSAMLFlow(
	ctx context.Context,
	relayState string,
	providerID string,
	browserHash string,
) (string, bool, error) {
	var requestID string
	err := s.pool.QueryRow(ctx, `
DELETE FROM auth_saml_flows
WHERE relay_state = $1
  AND provider_id = $2
  AND browser_hash = $3
  AND expires_at > NOW()
RETURNING request_id`, relayState, providerID, browserHash).Scan(&requestID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("consume SAML flow: %w", err)
	}
	return requestID, true, nil
}

func (s *PostgresStore) migrate(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS control_plane_configs (
    config_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    target TEXT NOT NULL CHECK (target IN ('collector', 'java-extension')),
    body TEXT NOT NULL,
    hash TEXT NOT NULL,
    selector JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    created_by TEXT NOT NULL,
    action TEXT NOT NULL CHECK (action IN ('PUBLISHED', 'ROLLBACK', 'DEACTIVATED')),
	active BOOLEAN NOT NULL DEFAULT TRUE,
	source_version INTEGER NOT NULL DEFAULT 0 CHECK (source_version >= 0),
    PRIMARY KEY (config_id, version)
);

CREATE INDEX IF NOT EXISTS control_plane_configs_created_at_idx
    ON control_plane_configs (created_at DESC);

ALTER TABLE control_plane_configs
    ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE control_plane_configs
    ADD COLUMN IF NOT EXISTS source_version INTEGER NOT NULL DEFAULT 0;

UPDATE control_plane_configs
SET source_version = version
WHERE source_version = 0;

ALTER TABLE control_plane_configs
    DROP CONSTRAINT IF EXISTS control_plane_configs_action_check;

ALTER TABLE control_plane_configs
    ADD CONSTRAINT control_plane_configs_action_check
    CHECK (action IN ('PUBLISHED', 'ROLLBACK', 'DEACTIVATED'));

CREATE TABLE IF NOT EXISTS policy_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    config_id TEXT NOT NULL,
    version INTEGER NOT NULL,
	action TEXT NOT NULL CHECK (action IN ('PUBLISHED', 'ROLLBACK', 'DEACTIVATED')),
    actor TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    FOREIGN KEY (config_id, version)
        REFERENCES control_plane_configs (config_id, version)
);

CREATE INDEX IF NOT EXISTS policy_audit_created_at_idx
    ON policy_audit (created_at DESC);

ALTER TABLE policy_audit
    DROP CONSTRAINT IF EXISTS policy_audit_action_check;

ALTER TABLE policy_audit
    ADD CONSTRAINT policy_audit_action_check
    CHECK (action IN ('PUBLISHED', 'ROLLBACK', 'DEACTIVATED'));

CREATE TABLE IF NOT EXISTS config_deployments (
    config_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    agent_uid TEXT NOT NULL,
    service TEXT NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    first_matched_at TIMESTAMPTZ NOT NULL,
    last_observed_at TIMESTAMPTZ NOT NULL,
    applied_at TIMESTAMPTZ,
    observed_status TEXT NOT NULL,
	bundle_hash TEXT NOT NULL DEFAULT '',
	desired_presence BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (config_id, version, agent_uid),
    FOREIGN KEY (config_id, version)
        REFERENCES control_plane_configs (config_id, version)
);

CREATE INDEX IF NOT EXISTS config_deployments_observed_idx
    ON config_deployments (last_observed_at DESC);

ALTER TABLE config_deployments
    ADD COLUMN IF NOT EXISTS bundle_hash TEXT NOT NULL DEFAULT '';

ALTER TABLE config_deployments
    ADD COLUMN IF NOT EXISTS desired_presence BOOLEAN NOT NULL DEFAULT TRUE;

CREATE INDEX IF NOT EXISTS config_deployments_agent_idx
    ON config_deployments (agent_uid, last_observed_at DESC);

CREATE TABLE IF NOT EXISTS opamp_agents (
    uid TEXT PRIMARY KEY,
    kind TEXT NOT NULL,
    service TEXT NOT NULL,
    transport TEXT NOT NULL,
    poll_interval_seconds INTEGER NOT NULL DEFAULT 0,
    connection_status TEXT NOT NULL,
    config_status TEXT NOT NULL,
    config_id TEXT NOT NULL DEFAULT '',
    config_version INTEGER NOT NULL DEFAULT 0,
    remote_config BOOLEAN NOT NULL DEFAULT FALSE,
    last_seen TIMESTAMPTZ NOT NULL,
    attributes JSONB NOT NULL DEFAULT '{}'::jsonb,
    effective_config JSONB NOT NULL DEFAULT '{}'::jsonb
);

ALTER TABLE opamp_agents
    ADD COLUMN IF NOT EXISTS effective_config JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE opamp_agents
    ADD COLUMN IF NOT EXISTS config_hash TEXT NOT NULL DEFAULT '';

ALTER TABLE opamp_agents
    ADD COLUMN IF NOT EXISTS policy_versions JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE opamp_agents
    ADD COLUMN IF NOT EXISTS base_config JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE opamp_agents
    ADD COLUMN IF NOT EXISTS effective_config_origin TEXT NOT NULL DEFAULT '';

ALTER TABLE opamp_agents
    ADD COLUMN IF NOT EXISTS last_managed_config_id TEXT NOT NULL DEFAULT '';

ALTER TABLE opamp_agents
    ADD COLUMN IF NOT EXISTS last_managed_config_version INTEGER NOT NULL DEFAULT 0;

CREATE INDEX IF NOT EXISTS opamp_agents_last_seen_idx
    ON opamp_agents (last_seen DESC);

-- Collector binaries and immutable base configuration belong to each
-- Supervisor. Remove the short-lived Control Plane bootstrap catalog on
-- upgrade; remote configuration history remains untouched.
DROP TABLE IF EXISTS collector_bootstrap_audit;
DROP TABLE IF EXISTS collector_bootstrap_profiles;

-- Capture inventory is derived from policy revisions. Remove the former
-- mutable catalog without touching control_plane_configs or policy history.
DROP TABLE IF EXISTS capture_catalog;

CREATE TABLE IF NOT EXISTS security_denylist (
    kind TEXT NOT NULL CHECK (kind IN ('HEADER', 'BODY_PATH', 'QUERY_PARAM', 'PATH_PARAM', 'METHOD_PATH', 'MESSAGE_PROPERTY')),
    value TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by TEXT NOT NULL,
    PRIMARY KEY (kind, value)
);

ALTER TABLE security_denylist
    DROP CONSTRAINT IF EXISTS security_denylist_kind_check;

ALTER TABLE security_denylist
    ADD CONSTRAINT security_denylist_kind_check
    CHECK (kind IN ('HEADER', 'BODY_PATH', 'QUERY_PARAM', 'PATH_PARAM', 'METHOD_PATH', 'MESSAGE_PROPERTY'));

CREATE TABLE IF NOT EXISTS security_denylist_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    entries JSONB NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_oidc_providers (
    provider_id TEXT PRIMARY KEY CHECK (provider_id IN ('microsoft', 'google', 'corporate')),
    label TEXT NOT NULL,
    issuer TEXT NOT NULL,
    client_id TEXT NOT NULL,
    client_secret_cipher TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_providers (
    provider_id TEXT PRIMARY KEY CHECK (provider_id ~ '^[a-z0-9][a-z0-9-]{0,62}$'),
    protocol TEXT NOT NULL CHECK (protocol IN ('OIDC', 'SAML')),
    label TEXT NOT NULL,
    config JSONB NOT NULL DEFAULT '{}'::jsonb,
    secret_cipher TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'CONFIGURED'
        CHECK (status IN ('INACTIVE', 'CONFIGURED', 'VALIDATED', 'ERROR')),
    validation_message TEXT NOT NULL DEFAULT '',
    validated_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_provider_role_mappings (
    provider_id TEXT NOT NULL REFERENCES auth_providers(provider_id) ON DELETE CASCADE,
    external_role TEXT NOT NULL,
    local_role TEXT NOT NULL
        CHECK (local_role IN ('viewer', 'business-editor', 'collector-editor', 'security-admin', 'admin')),
    PRIMARY KEY (provider_id, external_role)
);

CREATE TABLE IF NOT EXISTS auth_saml_flows (
    relay_state TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL REFERENCES auth_providers(provider_id) ON DELETE CASCADE,
    request_id TEXT NOT NULL,
	browser_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE auth_saml_flows
    ADD COLUMN IF NOT EXISTS browser_hash TEXT;

DELETE FROM auth_saml_flows
WHERE browser_hash IS NULL;

ALTER TABLE auth_saml_flows
    ALTER COLUMN browser_hash SET NOT NULL;

CREATE INDEX IF NOT EXISTS auth_saml_flows_expires_idx
    ON auth_saml_flows (expires_at);

INSERT INTO auth_providers (
    provider_id,
    protocol,
    label,
    config,
    secret_cipher,
    status,
    validation_message,
    updated_at,
    updated_by
)
SELECT
    provider_id,
    'OIDC',
    label,
    jsonb_build_object(
        'issuer', issuer,
        'clientId', client_id,
        'userClaim', 'preferred_username',
        'roleClaim', 'roles'
    ),
    client_secret_cipher,
    'CONFIGURED',
    'Debe ejecutar la validación OIDC antes de habilitar el acceso.',
    updated_at,
    updated_by
FROM auth_oidc_providers
ON CONFLICT (provider_id) DO NOTHING;

CREATE TABLE IF NOT EXISTS control_plane_migrations (
    migration_key TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL
);

WITH new_seed AS (
    INSERT INTO control_plane_migrations (migration_key, applied_at)
    VALUES ('security-denylist-v1', NOW())
    ON CONFLICT (migration_key) DO NOTHING
    RETURNING migration_key
)
INSERT INTO security_denylist (kind, value, updated_at, updated_by)
SELECT seed.kind, seed.value, NOW(), 'system-bootstrap'
FROM (
    VALUES
        ('HEADER', 'authorization'),
        ('HEADER', 'proxy-authorization'),
        ('HEADER', 'cookie'),
        ('HEADER', 'set-cookie'),
        ('HEADER', 'x-api-key'),
        ('HEADER', 'x-auth-token'),
        ('HEADER', 'x-user-id'),
        ('HEADER', 'x-account-number'),
        ('BODY_PATH', 'authorization'),
        ('BODY_PATH', 'password'),
        ('BODY_PATH', 'token'),
        ('BODY_PATH', 'secret'),
        ('BODY_PATH', 'customer.email'),
        ('BODY_PATH', 'customer.accountNumber'),
        ('BODY_PATH', 'card'),
        ('METHOD_PATH', 'password'),
        ('METHOD_PATH', 'token'),
        ('METHOD_PATH', 'secret'),
        ('METHOD_PATH', 'customer.email'),
        ('METHOD_PATH', 'customer.accountNumber'),
        ('METHOD_PATH', 'card')
) AS seed(kind, value)
CROSS JOIN new_seed;

WITH new_seed AS (
    INSERT INTO control_plane_migrations (migration_key, applied_at)
    VALUES ('security-denylist-query-params-v1', NOW())
    ON CONFLICT (migration_key) DO NOTHING
    RETURNING migration_key
)
INSERT INTO security_denylist (kind, value, updated_at, updated_by)
SELECT 'QUERY_PARAM', seed.value, NOW(), 'system-bootstrap'
FROM (
    VALUES
        ('access_token'),
        ('api_key'),
        ('password'),
        ('token')
) AS seed(value)
CROSS JOIN new_seed;`
	if _, err := s.pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("migrate PostgreSQL schema: %w", err)
	}
	return nil
}

func (s *PostgresStore) loadConfigs(ctx context.Context) (map[string][]Config, error) {
	rows, err := s.pool.Query(ctx, `
SELECT config_id, target, body, hash, version, source_version, active,
       created_at, selector, created_by, action
FROM control_plane_configs
ORDER BY config_id, version`)
	if err != nil {
		return nil, fmt.Errorf("query configurations: %w", err)
	}
	defer rows.Close()

	result := map[string][]Config{}
	for rows.Next() {
		var c Config
		var selector []byte
		if err := rows.Scan(
			&c.ID,
			&c.Target,
			&c.Body,
			&c.Hash,
			&c.Version,
			&c.SourceVersion,
			&c.Active,
			&c.UpdatedAt,
			&selector,
			&c.CreatedBy,
			&c.Action,
		); err != nil {
			return nil, fmt.Errorf("scan configuration: %w", err)
		}
		if err := json.Unmarshal(selector, &c.Selector); err != nil {
			return nil, fmt.Errorf("decode selector for %s v%d: %w", c.ID, c.Version, err)
		}
		result[c.ID] = append(result[c.ID], c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate configurations: %w", err)
	}
	return result, nil
}

func (s *PostgresStore) saveConfig(
	ctx context.Context,
	c Config,
	actor string,
	action string,
	details map[string]any,
) (Config, error) {
	return s.saveConfigExpected(ctx, c, actor, action, details, 0)
}

func (s *PostgresStore) saveConfigExpected(
	ctx context.Context,
	c Config,
	actor string,
	action string,
	details map[string]any,
	expectedLatestVersion int,
) (Config, error) {
	selector, err := json.Marshal(c.Selector)
	if err != nil {
		return Config{}, fmt.Errorf("encode selector: %w", err)
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return Config{}, fmt.Errorf("encode audit details: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Config{}, fmt.Errorf("begin configuration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext($1))", c.ID); err != nil {
		return Config{}, fmt.Errorf("lock configuration: %w", err)
	}
	var latestVersion int
	if err := tx.QueryRow(
		ctx,
		"SELECT COALESCE(MAX(version), 0) FROM control_plane_configs WHERE config_id = $1",
		c.ID,
	).Scan(&latestVersion); err != nil {
		return Config{}, fmt.Errorf("allocate configuration version: %w", err)
	}
	if expectedLatestVersion > 0 && latestVersion != expectedLatestVersion {
		return Config{}, errConcurrentConfigUpdate
	}
	c.Version = latestVersion + 1
	c.UpdatedAt = time.Now().UTC()
	c.CreatedBy = actor
	c.Action = action
	if action == "PUBLISHED" {
		c.SourceVersion = c.Version
		c.Active = true
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO control_plane_configs (
    config_id, version, target, body, hash, selector, created_at, created_by, action,
    active, source_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		c.ID,
		c.Version,
		c.Target,
		c.Body,
		c.Hash,
		selector,
		c.UpdatedAt,
		c.CreatedBy,
		c.Action,
		c.Active,
		c.SourceVersion,
	); err != nil {
		return Config{}, fmt.Errorf("insert configuration: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO policy_audit (config_id, version, action, actor, created_at, details)
VALUES ($1, $2, $3, $4, $5, $6)`,
		c.ID,
		c.Version,
		c.Action,
		c.CreatedBy,
		c.UpdatedAt,
		detailsJSON,
	); err != nil {
		return Config{}, fmt.Errorf("insert configuration audit: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Config{}, fmt.Errorf("commit configuration: %w", err)
	}
	return c, nil
}

// policyRollbackCandidate returns the current journal entry and the preceding
// original PUBLISHED revision in its semantic lineage. A rollback entry points
// at SourceVersion, so repeated rollbacks keep moving backwards and never
// oscillate to content that was already rolled back.
func (s *PostgresStore) policyRollbackCandidate(
	ctx context.Context,
	configID string,
) (Config, *Config, error) {
	current, err := s.latestConfig(ctx, configID)
	if err != nil {
		return Config{}, nil, err
	}
	if current.Target != "java-extension" {
		return Config{}, nil, fmt.Errorf("configuration %s is not a Java policy", configID)
	}
	if !current.Active {
		return Config{}, nil, errPolicyInactive
	}
	sourceVersion := current.SourceVersion
	if sourceVersion <= 0 {
		sourceVersion = current.Version
	}

	rows, err := s.pool.Query(ctx, `
SELECT config_id, target, body, hash, version, source_version, active,
       created_at, selector, created_by, action
FROM control_plane_configs
WHERE config_id = $1
  AND target = 'java-extension'
  AND action = 'PUBLISHED'
  AND version < $2
ORDER BY version`, configID, sourceVersion)
	if err != nil {
		return Config{}, nil, fmt.Errorf("load policy predecessor: %w", err)
	}
	defer rows.Close()
	versions := []Config{}
	for rows.Next() {
		var candidate Config
		var selector []byte
		if err := rows.Scan(
			&candidate.ID,
			&candidate.Target,
			&candidate.Body,
			&candidate.Hash,
			&candidate.Version,
			&candidate.SourceVersion,
			&candidate.Active,
			&candidate.UpdatedAt,
			&selector,
			&candidate.CreatedBy,
			&candidate.Action,
		); err != nil {
			return Config{}, nil, fmt.Errorf("scan policy predecessor: %w", err)
		}
		if err := json.Unmarshal(selector, &candidate.Selector); err != nil {
			return Config{}, nil, fmt.Errorf("decode predecessor selector: %w", err)
		}
		versions = append(versions, candidate)
	}
	if err := rows.Err(); err != nil {
		return Config{}, nil, fmt.Errorf("iterate policy predecessors: %w", err)
	}
	predecessor, ok := previousPublishedPolicy(versions, sourceVersion)
	if !ok {
		return current, nil, nil
	}
	return current, &predecessor, nil
}

func previousPublishedPolicy(versions []Config, sourceVersion int) (Config, bool) {
	var predecessor Config
	for _, candidate := range versions {
		if candidate.Target != "java-extension" ||
			candidate.Action != "PUBLISHED" ||
			candidate.Version >= sourceVersion ||
			candidate.Version <= predecessor.Version {
			continue
		}
		predecessor = candidate
	}
	return predecessor, predecessor.Version > 0
}

func (s *PostgresStore) latestConfig(ctx context.Context, configID string) (Config, error) {
	var c Config
	var selector []byte
	err := s.pool.QueryRow(ctx, `
SELECT config_id, target, body, hash, version, source_version, active,
       created_at, selector, created_by, action
FROM control_plane_configs
WHERE config_id = $1
ORDER BY version DESC
LIMIT 1`, configID).Scan(
		&c.ID,
		&c.Target,
		&c.Body,
		&c.Hash,
		&c.Version,
		&c.SourceVersion,
		&c.Active,
		&c.UpdatedAt,
		&selector,
		&c.CreatedBy,
		&c.Action,
	)
	if err != nil {
		return Config{}, fmt.Errorf("load latest configuration %s: %w", configID, err)
	}
	if err := json.Unmarshal(selector, &c.Selector); err != nil {
		return Config{}, fmt.Errorf("decode selector: %w", err)
	}
	return c, nil
}

func (s *PostgresStore) configVersion(
	ctx context.Context,
	configID string,
	version int,
) (Config, error) {
	var c Config
	var selector []byte
	err := s.pool.QueryRow(ctx, `
SELECT config_id, target, body, hash, version, source_version, active,
       created_at, selector, created_by, action
FROM control_plane_configs
WHERE config_id = $1 AND version = $2`, configID, version).Scan(
		&c.ID,
		&c.Target,
		&c.Body,
		&c.Hash,
		&c.Version,
		&c.SourceVersion,
		&c.Active,
		&c.UpdatedAt,
		&selector,
		&c.CreatedBy,
		&c.Action,
	)
	if err != nil {
		return Config{}, fmt.Errorf("load configuration %s v%d: %w", configID, version, err)
	}
	if err := json.Unmarshal(selector, &c.Selector); err != nil {
		return Config{}, fmt.Errorf("decode selector: %w", err)
	}
	return c, nil
}

func (s *PostgresStore) audit(ctx context.Context, limit int) ([]AuditEvent, error) {
	rows, err := s.pool.Query(ctx, `
SELECT audit_id, config_id, version, action, actor, created_at, details
FROM policy_audit
ORDER BY created_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("query audit: %w", err)
	}
	defer rows.Close()

	result := []AuditEvent{}
	for rows.Next() {
		var event AuditEvent
		var details []byte
		if err := rows.Scan(
			&event.AuditID,
			&event.ConfigID,
			&event.Version,
			&event.Action,
			&event.Actor,
			&event.CreatedAt,
			&details,
		); err != nil {
			return nil, fmt.Errorf("scan audit: %w", err)
		}
		if err := json.Unmarshal(details, &event.Details); err != nil {
			return nil, fmt.Errorf("decode audit details: %w", err)
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *PostgresStore) recordDeployment(
	ctx context.Context,
	c Config,
	a Agent,
	status string,
	bundleHash string,
	desiredPresence bool,
) error {
	attributes, err := json.Marshal(a.Attributes)
	if err != nil {
		return fmt.Errorf("encode deployment attributes: %w", err)
	}
	now := time.Now().UTC()
	_, err = s.pool.Exec(ctx, `
INSERT INTO config_deployments (
    config_id, version, agent_uid, service, attributes,
    first_matched_at, last_observed_at, applied_at, observed_status,
    bundle_hash, desired_presence
) VALUES (
    $1, $2, $3, $4, $5, $6::timestamptz, $6::timestamptz,
    CASE WHEN $7::text IN ('APPLIED', 'REMOVED') THEN $6::timestamptz ELSE NULL END,
    $7::text, $8::text, $9::boolean
)
ON CONFLICT (config_id, version, agent_uid) DO UPDATE SET
    service = EXCLUDED.service,
    attributes = EXCLUDED.attributes,
    last_observed_at = EXCLUDED.last_observed_at,
    applied_at = CASE
        WHEN EXCLUDED.observed_status IN ('APPLIED', 'REMOVED')
            THEN COALESCE(config_deployments.applied_at, EXCLUDED.last_observed_at)
        ELSE config_deployments.applied_at
    END,
    observed_status = EXCLUDED.observed_status,
    bundle_hash = EXCLUDED.bundle_hash,
    desired_presence = EXCLUDED.desired_presence`,
		c.ID,
		c.Version,
		a.UID,
		a.Service,
		attributes,
		now,
		status,
		bundleHash,
		desiredPresence,
	)
	if err != nil {
		return fmt.Errorf("upsert configuration deployment: %w", err)
	}
	return nil
}

func (s *PostgresStore) deployments(ctx context.Context, limit int) ([]DeploymentRecord, error) {
	rows, err := s.pool.Query(ctx, `
SELECT c.config_id, c.version, c.source_version, c.active, c.target, c.body, c.selector, c.created_at,
       c.created_by, d.agent_uid, d.service, d.attributes,
       d.first_matched_at, d.last_observed_at, d.applied_at, d.observed_status,
       COALESCE(a.connection_status, 'OFFLINE'),
       COALESCE(a.config_id, ''), COALESCE(a.config_version, 0),
       COALESCE(a.config_status, 'NOT_REPORTED'), d.bundle_hash,
       d.desired_presence
FROM config_deployments d
JOIN control_plane_configs c
  ON c.config_id = d.config_id AND c.version = d.version
LEFT JOIN opamp_agents a ON a.uid = d.agent_uid
ORDER BY d.last_observed_at DESC
LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("query deployments: %w", err)
	}
	defer rows.Close()

	result := []DeploymentRecord{}
	for rows.Next() {
		var record DeploymentRecord
		var selector []byte
		var attributes []byte
		if err := rows.Scan(
			&record.ConfigID,
			&record.Version,
			&record.SourceVersion,
			&record.Active,
			&record.Target,
			&record.Body,
			&selector,
			&record.PublishedAt,
			&record.PublishedBy,
			&record.AgentUID,
			&record.Service,
			&attributes,
			&record.FirstMatchedAt,
			&record.LastObservedAt,
			&record.AppliedAt,
			&record.ObservedStatus,
			&record.ConnectionStatus,
			&record.CurrentConfigID,
			&record.CurrentConfigVersion,
			&record.CurrentConfigStatus,
			&record.BundleHash,
			&record.DesiredPresence,
		); err != nil {
			return nil, fmt.Errorf("scan deployment: %w", err)
		}
		if err := json.Unmarshal(selector, &record.Selector); err != nil {
			return nil, fmt.Errorf("decode deployment selector: %w", err)
		}
		if err := json.Unmarshal(attributes, &record.AgentAttributes); err != nil {
			return nil, fmt.Errorf("decode deployment attributes: %w", err)
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (s *PostgresStore) loadAgents(ctx context.Context) (map[string]Agent, error) {
	rows, err := s.pool.Query(ctx, `
SELECT uid, kind, service, transport, poll_interval_seconds, connection_status,
       config_status, config_id, config_version, config_hash, remote_config, last_seen, attributes,
	   effective_config, policy_versions, base_config, effective_config_origin,
	   last_managed_config_id, last_managed_config_version
FROM opamp_agents`)
	if err != nil {
		return nil, fmt.Errorf("query agents: %w", err)
	}
	defer rows.Close()

	result := map[string]Agent{}
	for rows.Next() {
		var a Agent
		var attributes []byte
		var effectiveConfig []byte
		var policyVersions []byte
		var baseConfig []byte
		if err := rows.Scan(
			&a.UID,
			&a.Kind,
			&a.Service,
			&a.Transport,
			&a.PollIntervalSeconds,
			&a.ConnectionStatus,
			&a.ConfigStatus,
			&a.ConfigID,
			&a.Version,
			&a.ConfigHash,
			&a.RemoteConfig,
			&a.LastSeen,
			&attributes,
			&effectiveConfig,
			&policyVersions,
			&baseConfig,
			&a.EffectiveConfigOrigin,
			&a.LastManagedConfigID,
			&a.LastManagedConfigVersion,
		); err != nil {
			return nil, fmt.Errorf("scan agent: %w", err)
		}
		if err := json.Unmarshal(attributes, &a.Attributes); err != nil {
			return nil, fmt.Errorf("decode agent attributes: %w", err)
		}
		if err := json.Unmarshal(effectiveConfig, &a.EffectiveConfig); err != nil {
			return nil, fmt.Errorf("decode agent effective config: %w", err)
		}
		if err := json.Unmarshal(policyVersions, &a.PolicyVersions); err != nil {
			return nil, fmt.Errorf("decode agent policy versions: %w", err)
		}
		if err := json.Unmarshal(baseConfig, &a.BaseConfig); err != nil {
			return nil, fmt.Errorf("decode agent base configuration: %w", err)
		}
		if a.Transport == "http-poll" {
			a.ConnectionStatus = "OFFLINE"
		} else {
			a.ConnectionStatus = "DISCONNECTED"
		}
		if a.ConfigStatus == "UNSET" {
			a.ConfigStatus = "NOT_REPORTED"
		}
		result[a.UID] = a
	}
	return result, rows.Err()
}

// pruneAgentsSeenBefore removes only the mutable inventory projection. The
// deployment table intentionally has no foreign key to opamp_agents, so policy
// and Collector deployment/audit history survives inventory retention.
func (s *PostgresStore) pruneAgentsSeenBefore(
	ctx context.Context,
	cutoff time.Time,
) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, nil
	}
	result, err := s.pool.Exec(ctx, `
DELETE FROM opamp_agents
WHERE last_seen < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune expired agents: %w", err)
	}
	return result.RowsAffected(), nil
}

func (s *PostgresStore) deleteAgentSeenAtOrBefore(
	ctx context.Context,
	uid string,
	lastSeen time.Time,
) error {
	if s == nil || s.pool == nil || uid == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx, `
DELETE FROM opamp_agents
WHERE uid = $1 AND last_seen <= $2`, uid, lastSeen)
	if err != nil {
		return fmt.Errorf("delete evicted agent: %w", err)
	}
	return nil
}

func (s *PostgresStore) upsertAgent(ctx context.Context, a Agent) error {
	attributes, err := json.Marshal(a.Attributes)
	if err != nil {
		return fmt.Errorf("encode agent attributes: %w", err)
	}
	effectiveConfig, err := json.Marshal(a.EffectiveConfig)
	if err != nil {
		return fmt.Errorf("encode agent effective config: %w", err)
	}
	policyVersions, err := json.Marshal(a.PolicyVersions)
	if err != nil {
		return fmt.Errorf("encode agent policy versions: %w", err)
	}
	baseConfig, err := json.Marshal(a.BaseConfig)
	if err != nil {
		return fmt.Errorf("encode agent base configuration: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO opamp_agents (
    uid, kind, service, transport, poll_interval_seconds, connection_status,
    config_status, config_id, config_version, config_hash, remote_config, last_seen, attributes,
	effective_config, policy_versions, base_config, effective_config_origin,
	last_managed_config_id, last_managed_config_version
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
ON CONFLICT (uid) DO UPDATE SET
    kind = EXCLUDED.kind,
    service = EXCLUDED.service,
    transport = EXCLUDED.transport,
    poll_interval_seconds = EXCLUDED.poll_interval_seconds,
    connection_status = EXCLUDED.connection_status,
    config_status = EXCLUDED.config_status,
    config_id = EXCLUDED.config_id,
    config_version = EXCLUDED.config_version,
    config_hash = EXCLUDED.config_hash,
    remote_config = EXCLUDED.remote_config,
    last_seen = EXCLUDED.last_seen,
    attributes = EXCLUDED.attributes,
	effective_config = EXCLUDED.effective_config,
	policy_versions = EXCLUDED.policy_versions,
	base_config = EXCLUDED.base_config,
	effective_config_origin = EXCLUDED.effective_config_origin,
	last_managed_config_id = EXCLUDED.last_managed_config_id,
	last_managed_config_version = EXCLUDED.last_managed_config_version
WHERE opamp_agents.last_seen <= EXCLUDED.last_seen`,
		a.UID,
		a.Kind,
		a.Service,
		a.Transport,
		a.PollIntervalSeconds,
		a.ConnectionStatus,
		a.ConfigStatus,
		a.ConfigID,
		a.Version,
		a.ConfigHash,
		a.RemoteConfig,
		a.LastSeen,
		attributes,
		effectiveConfig,
		policyVersions,
		baseConfig,
		a.EffectiveConfigOrigin,
		a.LastManagedConfigID,
		a.LastManagedConfigVersion,
	)
	if err != nil {
		return fmt.Errorf("upsert agent: %w", err)
	}
	return nil
}

func (s *PostgresStore) securityDenylist(ctx context.Context) ([]DenylistEntry, error) {
	rows, err := s.pool.Query(ctx, `
SELECT kind, value, updated_at, updated_by
FROM security_denylist
ORDER BY kind, value`)
	if err != nil {
		return nil, fmt.Errorf("query security denylist: %w", err)
	}
	defer rows.Close()

	entries := []DenylistEntry{}
	for rows.Next() {
		var entry DenylistEntry
		if err := rows.Scan(&entry.Kind, &entry.Value, &entry.UpdatedAt, &entry.UpdatedBy); err != nil {
			return nil, fmt.Errorf("scan security denylist: %w", err)
		}
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}

func (s *PostgresStore) replaceSecurityDenylist(
	ctx context.Context,
	entries []DenylistEntry,
	actor string,
) ([]DenylistEntry, error) {
	entriesJSON, err := json.Marshal(entries)
	if err != nil {
		return nil, fmt.Errorf("encode security denylist audit: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin security denylist transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtext('security_denylist'))"); err != nil {
		return nil, fmt.Errorf("lock security denylist: %w", err)
	}
	if _, err := tx.Exec(ctx, "DELETE FROM security_denylist"); err != nil {
		return nil, fmt.Errorf("clear security denylist: %w", err)
	}
	now := time.Now().UTC()
	for index := range entries {
		entries[index].UpdatedAt = now
		entries[index].UpdatedBy = actor
		if _, err := tx.Exec(ctx, `
INSERT INTO security_denylist (kind, value, updated_at, updated_by)
VALUES ($1, $2, $3, $4)`, entries[index].Kind, entries[index].Value, now, actor); err != nil {
			return nil, fmt.Errorf("insert security denylist entry: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO security_denylist_audit (actor, created_at, entries)
VALUES ($1, $2, $3)`, actor, now, entriesJSON); err != nil {
		return nil, fmt.Errorf("insert security denylist audit: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit security denylist: %w", err)
	}
	return entries, nil
}
