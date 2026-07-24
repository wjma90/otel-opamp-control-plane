package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type memoryEmailStore struct {
	record        EmailSettingsRecord
	found         bool
	savedProvider string
	testProvider  string
	testActor     string
	testDomain    string
}

func (s *memoryEmailStore) loadEmailSettings(context.Context) (EmailSettingsRecord, bool, error) {
	return s.record, s.found, nil
}

func (s *memoryEmailStore) saveEmailSettings(
	_ context.Context,
	record EmailSettingsRecord,
	provider string,
	expectedUpdatedAt *time.Time,
) error {
	if s.found {
		if expectedUpdatedAt == nil || !s.record.UpdatedAt.Equal(*expectedUpdatedAt) {
			return errConcurrentEmailSettingsUpdate
		}
	} else if expectedUpdatedAt != nil {
		return errConcurrentEmailSettingsUpdate
	}
	s.record = record
	s.found = true
	s.savedProvider = provider
	return nil
}

func (s *memoryEmailStore) auditEmailTest(_ context.Context, provider, actor, domain string) error {
	s.testProvider, s.testActor, s.testDomain = provider, actor, domain
	return nil
}

type recordingEmailSender struct {
	settings emailPublicConfig
	secrets  emailSecretEnvelope
	message  OutboundEmail
	calls    int
}

func (s *recordingEmailSender) Send(
	_ context.Context,
	settings emailPublicConfig,
	secrets emailSecretEnvelope,
	message OutboundEmail,
) error {
	s.settings, s.secrets, s.message = settings, secrets, message
	s.calls++
	return nil
}

func newTestEmailService(store *memoryEmailStore, sender outboundEmailSender) *EmailDeliveryService {
	auth := &Authenticator{signingKey: []byte("mail-test-signing-key")}
	service := newEmailDeliveryService(store, auth, sender)
	service.now = func() time.Time { return time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC) }
	return service
}

func validSMTPSettings() EmailDeliverySettings {
	return EmailDeliverySettings{
		Enabled: true, Provider: emailProviderSMTP,
		FromName: "O11y", FromAddress: "no-reply@example.test",
		SMTP: SMTPEmailConfig{
			Host: "smtp.example.test", Port: 587, Username: "smtp-user",
			Password: "smtp-password", TLSMode: "STARTTLS",
		},
	}
}

func TestEmailSettingsEncryptAndRedactCredentials(t *testing.T) {
	store := &memoryEmailStore{}
	service := newTestEmailService(store, &recordingEmailSender{})
	response, err := service.Save(context.Background(), validSMTPSettings(), "security-admin")
	if err != nil {
		t.Fatalf("save settings: %v", err)
	}
	if response.SMTP.Password != "" || !response.Secrets.SMTPPassword {
		t.Fatalf("response exposed or lost SMTP secret state: %#v", response)
	}
	responseJSON, _ := json.Marshal(response)
	if strings.Contains(string(responseJSON), "smtp-password") || strings.Contains(string(responseJSON), `"password"`) {
		t.Fatalf("API response contains a password field or value: %s", responseJSON)
	}
	if store.record.SecretCipher == "" || strings.Contains(store.record.SecretCipher, "smtp-password") {
		t.Fatalf("credential was not encrypted at rest: %q", store.record.SecretCipher)
	}
	publicJSON, _ := json.Marshal(store.record.PublicConfig)
	if strings.Contains(string(publicJSON), "smtp-password") || strings.Contains(string(publicJSON), "secretAccessKey") {
		t.Fatalf("public/audit-safe config contains a credential: %s", publicJSON)
	}
	loaded, err := service.Settings(context.Background())
	if err != nil || loaded.SMTP.Password != "" || !loaded.Secrets.SMTPPassword {
		t.Fatalf("loaded response must remain redacted: %#v, %v", loaded, err)
	}
}

func TestEmailSettingsEmptySecretPreservesExistingCredential(t *testing.T) {
	store := &memoryEmailStore{}
	service := newTestEmailService(store, &recordingEmailSender{})
	current, err := service.Save(context.Background(), validSMTPSettings(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	update := validSMTPSettings()
	update.ExpectedUpdatedAt = current.UpdatedAt
	update.SMTP.Password = ""
	update.FromName = "O11y Control Plane"
	if _, err := service.Save(context.Background(), update, "admin"); err != nil {
		t.Fatalf("empty secret should retain existing credential: %v", err)
	}
	_, secrets, _, _, _, err := service.load(context.Background())
	if err != nil || secrets.SMTPPassword != "smtp-password" {
		t.Fatalf("existing credential was not retained: %#v, %v", secrets, err)
	}
}

func TestEmailSettingsDoesNotReuseSecretForDifferentDestination(t *testing.T) {
	store := &memoryEmailStore{}
	service := newTestEmailService(store, &recordingEmailSender{})
	current, err := service.Save(context.Background(), validSMTPSettings(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	update := validSMTPSettings()
	update.ExpectedUpdatedAt = current.UpdatedAt
	update.SMTP.Host = "other-smtp.example.test"
	update.SMTP.Password = ""
	if _, err := service.Save(context.Background(), update, "admin"); err == nil ||
		!strings.Contains(err.Error(), "smtp password") {
		t.Fatalf("changing destination without re-entering its secret must fail, got %v", err)
	}
	update.SMTP.Password = "new-destination-password"
	if _, err := service.Save(context.Background(), update, "admin"); err != nil {
		t.Fatalf("destination change with a new secret must succeed: %v", err)
	}
	_, secrets, _, _, _, err := service.load(context.Background())
	if err != nil || secrets.SMTPPassword != "new-destination-password" {
		t.Fatalf("new destination credential was not stored: %#v, %v", secrets, err)
	}
}

func TestEmailSettingsKeepsSecretsOnlyForActiveProvider(t *testing.T) {
	store := &memoryEmailStore{}
	service := newTestEmailService(store, &recordingEmailSender{})
	current, err := service.Save(context.Background(), validSMTPSettings(), "admin")
	if err != nil {
		t.Fatal(err)
	}
	aws := EmailDeliverySettings{
		Enabled: true, Provider: emailProviderAWSSES,
		FromName: "O11y", FromAddress: "no-reply@example.test",
		AWSSES: AWSSESEmailConfig{
			Region: "us-east-1", AccessKeyID: "AKIATEST",
			SecretAccessKey: "aws-secret",
		},
	}
	aws.ExpectedUpdatedAt = current.UpdatedAt
	if _, err := service.Save(context.Background(), aws, "admin"); err != nil {
		t.Fatalf("switch provider: %v", err)
	}
	_, secrets, _, _, _, err := service.load(context.Background())
	if err != nil || secrets.SMTPPassword != "" ||
		secrets.AWSSecretAccessKey != "aws-secret" || secrets.AzureAccessKey != "" {
		t.Fatalf("inactive provider credentials were retained: %#v, %v", secrets, err)
	}
}

func TestEmailSettingsRejectsUnencryptedRemoteSMTP(t *testing.T) {
	settings := publicSettings(validSMTPSettings())
	settings.SMTP.TLSMode = "NONE"
	err := validateEmailSettings(settings, emailSecretEnvelope{SMTPPassword: "smtp-password"}, true)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected remote plaintext SMTP rejection, got %v", err)
	}
	settings.SMTP.Host = "127.0.0.1"
	if err := validateEmailSettings(settings, emailSecretEnvelope{SMTPPassword: "smtp-password"}, true); err != nil {
		t.Fatalf("loopback SMTP test server should be allowed: %v", err)
	}
}

func TestEmailSettingsModificationRequiresFullAdmin(t *testing.T) {
	viewer := Identity{Roles: []string{"viewer"}}
	viewer.Permissions = permissionsForRoles(viewer.Roles)
	if hasPermission(viewer, "settings.email.view") || hasPermission(viewer, "settings.email.edit") {
		t.Fatal("viewer must not see email provider metadata")
	}
	securityAdmin := Identity{Roles: []string{"security-admin"}}
	securityAdmin.Permissions = permissionsForRoles(securityAdmin.Roles)
	if !hasPermission(securityAdmin, "settings.email.view") ||
		hasPermission(securityAdmin, "settings.email.edit") {
		t.Fatal("security-admin must inspect but not redirect the root recovery channel")
	}
	admin := Identity{Roles: []string{"admin"}}
	admin.Permissions = permissionsForRoles(admin.Roles)
	if !hasPermission(admin, "settings.email.edit") {
		t.Fatal("full admin must be able to configure email delivery")
	}
}

func TestSecurityAdminReceivesForbiddenFromEmailEditEndpoint(t *testing.T) {
	user := localUserFixture(t, "security-user", "secure-test-password", false)
	user.Roles = []string{"security-admin"}
	repository := &memoryLocalUserRepository{
		users:  map[string]LocalUser{user.Username: user},
		tokens: map[string]memoryPasswordResetToken{},
	}
	auth := useIdentityTestState(t, repository)
	token, _, ok := auth.login(user.Username, "secure-test-password")
	if !ok {
		t.Fatal("expected security-admin login")
	}
	request := httptest.NewRequest(http.MethodPut, "/api/settings/email", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	response := httptest.NewRecorder()
	requirePermission("settings.email.edit", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}).ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("security-admin must not redirect the root recovery channel, got %d", response.Code)
	}
}

func TestEmailSettingsCanBeReconfiguredAfterEncryptionKeyRotation(t *testing.T) {
	store := &memoryEmailStore{}
	first := newEmailDeliveryService(
		store,
		&Authenticator{signingKey: []byte("first-mail-encryption-key")},
		&recordingEmailSender{},
	)
	if _, err := first.Save(context.Background(), validSMTPSettings(), "admin"); err != nil {
		t.Fatal(err)
	}
	rotated := newEmailDeliveryService(
		store,
		&Authenticator{signingKey: []byte("rotated-mail-encryption-key")},
		&recordingEmailSender{},
	)
	settings, err := rotated.Settings(context.Background())
	if err != nil || !settings.CredentialsUnavailable {
		t.Fatalf("rotated key must expose a recoverable credential state, got %#v, %v", settings, err)
	}
	replacement := validSMTPSettings()
	replacement.ExpectedUpdatedAt = settings.UpdatedAt
	replacement.SMTP.Password = "replacement-password"
	if _, err := rotated.Save(context.Background(), replacement, "admin"); err == nil {
		t.Fatal("unreadable credentials must not be overwritten without explicit clearSecrets")
	}
	replacement.ClearSecrets = true
	if _, err := rotated.Save(context.Background(), replacement, "admin"); err != nil {
		t.Fatalf("explicit credential replacement after key rotation must succeed: %v", err)
	}
	loaded, err := rotated.Settings(context.Background())
	if err != nil || loaded.CredentialsUnavailable || !loaded.Secrets.SMTPPassword {
		t.Fatalf("replacement credentials must be readable and redacted: %#v, %v", loaded, err)
	}
}

func TestStaleEmailSettingsUpdateIsRejected(t *testing.T) {
	store := &memoryEmailStore{}
	service := newTestEmailService(store, &recordingEmailSender{})
	initial, err := service.Save(context.Background(), validSMTPSettings(), "admin-a")
	if err != nil {
		t.Fatal(err)
	}
	firstUpdate := validSMTPSettings()
	firstUpdate.FromName = "First editor"
	firstUpdate.ExpectedUpdatedAt = initial.UpdatedAt
	if _, err := service.Save(context.Background(), firstUpdate, "admin-a"); err != nil {
		t.Fatal(err)
	}
	staleUpdate := validSMTPSettings()
	staleUpdate.FromName = "Stale editor"
	staleUpdate.ExpectedUpdatedAt = initial.UpdatedAt
	if _, err := service.Save(context.Background(), staleUpdate, "admin-b"); !errors.Is(err, errConcurrentEmailSettingsUpdate) {
		t.Fatalf("stale email update must fail with a conflict, got %v", err)
	}
}

func TestPasswordRecoveryUsesConfiguredProviderWithoutExposingToken(t *testing.T) {
	store := &memoryEmailStore{}
	sender := &recordingEmailSender{}
	service := newTestEmailService(store, sender)
	if _, err := service.Save(context.Background(), validSMTPSettings(), "admin"); err != nil {
		t.Fatal(err)
	}
	message := PasswordResetMessage{
		ToEmail: "ana@example.test", Username: "Ana", Token: "one-time-token",
		ExpiresAt: service.now().Add(15 * time.Minute),
		ResetURL:  "https://o11y.example.test/reset?token=one-time-token",
	}
	if !service.Available(context.Background()) {
		t.Fatal("configured enabled mailer should be available")
	}
	if err := service.SendPasswordReset(context.Background(), message); err != nil {
		t.Fatal(err)
	}
	if sender.calls != 1 || sender.message.ToEmail != message.ToEmail ||
		!strings.Contains(sender.message.Text, message.ResetURL) || sender.secrets.SMTPPassword != "smtp-password" {
		t.Fatalf("unexpected password reset delivery: %#v", sender)
	}
	if strings.Contains(sender.message.Subject, message.Token) {
		t.Fatal("password reset token must not appear in the subject")
	}
}

func TestEmailTestAuditsOnlyRecipientDomain(t *testing.T) {
	store := &memoryEmailStore{}
	service := newTestEmailService(store, &recordingEmailSender{})
	if _, err := service.Save(context.Background(), validSMTPSettings(), "admin"); err != nil {
		t.Fatal(err)
	}
	provider, err := service.Test(context.Background(), "person@Example.TEST", "security-admin")
	if err != nil {
		t.Fatal(err)
	}
	if provider != emailProviderSMTP || store.testActor != "security-admin" || store.testDomain != "example.test" {
		t.Fatalf("unexpected safe audit metadata: %#v", store)
	}
}
