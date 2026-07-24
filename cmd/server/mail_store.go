package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const emailSettingsKey = "default"

// EmailSettingsRecord deliberately separates the public configuration from
// the encrypted credential envelope. Secret values must never be copied into
// PublicConfig or the audit table.
type EmailSettingsRecord struct {
	PublicConfig map[string]any
	SecretCipher string
	UpdatedAt    time.Time
	UpdatedBy    string
}

// migrateEmailSettings owns its schema independently from the core store
// migration. This keeps the mail module reusable and makes its integration a
// single startup call.
func (s *PostgresStore) migrateEmailSettings(ctx context.Context) error {
	const schema = `
CREATE TABLE IF NOT EXISTS email_delivery_settings (
    settings_key TEXT PRIMARY KEY CHECK (settings_key = 'default'),
    public_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    secret_cipher TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS email_delivery_settings_audit (
    audit_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    action TEXT NOT NULL CHECK (action IN ('UPDATED', 'TEST_SENT')),
    provider TEXT NOT NULL DEFAULT '',
    actor TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    public_config JSONB NOT NULL DEFAULT '{}'::jsonb,
    details JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS email_delivery_settings_audit_created_idx
    ON email_delivery_settings_audit (created_at DESC);`
	if _, err := s.pool.Exec(ctx, schema); err != nil {
		return fmt.Errorf("migrate email delivery settings: %w", err)
	}
	return nil
}

func (s *PostgresStore) loadEmailSettings(ctx context.Context) (EmailSettingsRecord, bool, error) {
	var record EmailSettingsRecord
	var publicJSON []byte
	err := s.pool.QueryRow(ctx, `
SELECT public_config, secret_cipher, updated_at, updated_by
FROM email_delivery_settings
WHERE settings_key = $1`, emailSettingsKey).Scan(
		&publicJSON,
		&record.SecretCipher,
		&record.UpdatedAt,
		&record.UpdatedBy,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return EmailSettingsRecord{}, false, nil
	}
	if err != nil {
		return EmailSettingsRecord{}, false, fmt.Errorf("load email delivery settings: %w", err)
	}
	if err := json.Unmarshal(publicJSON, &record.PublicConfig); err != nil {
		return EmailSettingsRecord{}, false, fmt.Errorf("decode email delivery settings: %w", err)
	}
	return record, true, nil
}

func (s *PostgresStore) saveEmailSettings(
	ctx context.Context,
	record EmailSettingsRecord,
	provider string,
	expectedUpdatedAt *time.Time,
) error {
	publicJSON, err := json.Marshal(record.PublicConfig)
	if err != nil {
		return fmt.Errorf("encode email delivery settings: %w", err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin email settings transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var storedUpdatedAt time.Time
	lookupErr := tx.QueryRow(ctx, `
SELECT updated_at
FROM email_delivery_settings
WHERE settings_key = $1
FOR UPDATE`, emailSettingsKey).Scan(&storedUpdatedAt)
	switch {
	case errors.Is(lookupErr, pgx.ErrNoRows) && expectedUpdatedAt != nil:
		return errConcurrentEmailSettingsUpdate
	case lookupErr != nil && !errors.Is(lookupErr, pgx.ErrNoRows):
		return fmt.Errorf("lock email delivery settings: %w", lookupErr)
	case lookupErr == nil && expectedUpdatedAt == nil:
		return errConcurrentEmailSettingsUpdate
	case lookupErr == nil && !storedUpdatedAt.Equal(expectedUpdatedAt.UTC().Truncate(time.Microsecond)):
		return errConcurrentEmailSettingsUpdate
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO email_delivery_settings (
    settings_key,
    public_config,
    secret_cipher,
    updated_at,
    updated_by
) VALUES ($1, $2, $3, $4, $5)
ON CONFLICT (settings_key) DO UPDATE SET
    public_config = EXCLUDED.public_config,
    secret_cipher = EXCLUDED.secret_cipher,
    updated_at = EXCLUDED.updated_at,
    updated_by = EXCLUDED.updated_by`,
		emailSettingsKey,
		publicJSON,
		record.SecretCipher,
		record.UpdatedAt,
		record.UpdatedBy,
	); err != nil {
		return fmt.Errorf("save email delivery settings: %w", err)
	}
	if _, err := tx.Exec(ctx, `
INSERT INTO email_delivery_settings_audit (
    action,
    provider,
    actor,
    created_at,
    public_config,
    details
) VALUES ('UPDATED', $1, $2, $3, $4, '{}'::jsonb)`,
		provider,
		record.UpdatedBy,
		record.UpdatedAt,
		publicJSON,
	); err != nil {
		return fmt.Errorf("audit email delivery settings: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit email settings transaction: %w", err)
	}
	return nil
}

func (s *PostgresStore) auditEmailTest(
	ctx context.Context,
	provider string,
	actor string,
	recipientDomain string,
) error {
	details, err := json.Marshal(map[string]string{"recipientDomain": recipientDomain})
	if err != nil {
		return fmt.Errorf("encode email test audit: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
INSERT INTO email_delivery_settings_audit (
    action,
    provider,
    actor,
    created_at,
    public_config,
    details
) VALUES ('TEST_SENT', $1, $2, NOW(), '{}'::jsonb, $3)`, provider, actor, details)
	if err != nil {
		return fmt.Errorf("audit email delivery test: %w", err)
	}
	return nil
}
