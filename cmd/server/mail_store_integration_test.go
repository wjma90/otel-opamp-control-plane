//go:build integration

package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestPostgresEmailSettingsNeverAuditSecrets(t *testing.T) {
	databaseURL := integrationDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	store, err := newPostgresStore(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.close)
	if err := store.migrateEmailSettings(ctx); err != nil {
		t.Fatal(err)
	}
	previous, hadPrevious, err := store.loadEmailSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	actor := "mail-integration-test"
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = store.pool.Exec(cleanupCtx,
			"DELETE FROM email_delivery_settings_audit WHERE actor = $1", actor)
		if hadPrevious {
			_, _ = store.pool.Exec(cleanupCtx, `
UPDATE email_delivery_settings
SET public_config = $1, secret_cipher = $2, updated_at = $3, updated_by = $4
WHERE settings_key = $5`, previous.PublicConfig, previous.SecretCipher,
				previous.UpdatedAt, previous.UpdatedBy, emailSettingsKey)
		} else {
			_, _ = store.pool.Exec(cleanupCtx,
				"DELETE FROM email_delivery_settings WHERE settings_key = $1", emailSettingsKey)
		}
	})

	service := newEmailDeliveryService(
		store,
		&Authenticator{signingKey: []byte("integration-encryption-key")},
		&recordingEmailSender{},
	)
	input := validSMTPSettings()
	input.SMTP.Password = "must-never-appear-in-audit"
	if hadPrevious {
		expected := previous.UpdatedAt
		input.ExpectedUpdatedAt = &expected
	}
	if _, err := service.Save(ctx, input, actor); err != nil {
		t.Fatal(err)
	}
	var settingsPublic, auditPublic, auditDetails string
	if err := store.pool.QueryRow(ctx, `
SELECT s.public_config::text, a.public_config::text, a.details::text
FROM email_delivery_settings s
JOIN email_delivery_settings_audit a ON a.actor = $1 AND a.action = 'UPDATED'
WHERE s.settings_key = $2
ORDER BY a.audit_id DESC
LIMIT 1`, actor, emailSettingsKey).Scan(&settingsPublic, &auditPublic, &auditDetails); err != nil {
		t.Fatal(err)
	}
	combined := settingsPublic + auditPublic + auditDetails
	if strings.Contains(combined, input.SMTP.Password) || strings.Contains(combined, "smtpPassword") {
		t.Fatalf("plaintext secret leaked into public persistence or audit: %s", combined)
	}
}
