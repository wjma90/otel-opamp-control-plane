package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	emailProviderSMTP     = "SMTP"
	emailProviderAWSSES   = "AWS_SES"
	emailProviderAzureACS = "AZURE_ACS"
)

var (
	awsRegionPattern = regexp.MustCompile(`^[a-z]{2}(?:-gov)?-[a-z]+-\d$`)
	hostPattern      = regexp.MustCompile(`^[A-Za-z0-9.-]+$`)
)

type SMTPEmailConfig struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password,omitempty"`
	TLSMode  string `json:"tlsMode"`
}

type AWSSESEmailConfig struct {
	Region          string `json:"region"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
	SessionToken    string `json:"sessionToken,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
}

type AzureACSEmailConfig struct {
	Endpoint   string `json:"endpoint"`
	AccessKey  string `json:"accessKey,omitempty"`
	APIVersion string `json:"apiVersion"`
}

type EmailDeliverySettings struct {
	Enabled                bool                `json:"enabled"`
	Provider               string              `json:"provider"`
	FromName               string              `json:"fromName"`
	FromAddress            string              `json:"fromAddress"`
	SMTP                   SMTPEmailConfig     `json:"smtp"`
	AWSSES                 AWSSESEmailConfig   `json:"awsSes"`
	AzureACS               AzureACSEmailConfig `json:"azureAcs"`
	Secrets                EmailSecretsStatus  `json:"secretsConfigured"`
	UpdatedAt              *time.Time          `json:"updatedAt,omitempty"`
	ExpectedUpdatedAt      *time.Time          `json:"expectedUpdatedAt,omitempty"`
	UpdatedBy              string              `json:"updatedBy,omitempty"`
	ClearSecrets           bool                `json:"clearSecrets,omitempty"`
	CredentialsUnavailable bool                `json:"credentialsUnavailable,omitempty"`
}

var errEmailCredentialsUnavailable = errors.New("stored email credentials cannot be decrypted")
var errConcurrentEmailSettingsUpdate = errors.New("email settings changed concurrently")

type EmailSecretsStatus struct {
	SMTPPassword       bool `json:"smtpPassword"`
	AWSSecretAccessKey bool `json:"awsSecretAccessKey"`
	AWSSessionToken    bool `json:"awsSessionToken"`
	AzureAccessKey     bool `json:"azureAccessKey"`
}

type emailSecretEnvelope struct {
	SMTPPassword       string `json:"smtpPassword,omitempty"`
	AWSSecretAccessKey string `json:"awsSecretAccessKey,omitempty"`
	AWSSessionToken    string `json:"awsSessionToken,omitempty"`
	AzureAccessKey     string `json:"azureAccessKey,omitempty"`
}

type emailPublicConfig struct {
	Enabled     bool                `json:"enabled"`
	Provider    string              `json:"provider"`
	FromName    string              `json:"fromName"`
	FromAddress string              `json:"fromAddress"`
	SMTP        SMTPEmailConfig     `json:"smtp"`
	AWSSES      AWSSESEmailConfig   `json:"awsSes"`
	AzureACS    AzureACSEmailConfig `json:"azureAcs"`
}

type emailSettingsPersistence interface {
	loadEmailSettings(context.Context) (EmailSettingsRecord, bool, error)
	saveEmailSettings(context.Context, EmailSettingsRecord, string, *time.Time) error
	auditEmailTest(context.Context, string, string, string) error
}

type emailSecretCodec interface {
	encryptSecret(string) (string, error)
	decryptSecret(string) (string, error)
}

type OutboundEmail struct {
	ToEmail string
	Subject string
	Text    string
	HTML    string
}

type outboundEmailSender interface {
	Send(context.Context, emailPublicConfig, emailSecretEnvelope, OutboundEmail) error
}

// PasswordResetMessage is intentionally provider-agnostic. The identity module
// creates tokens and URLs; this module only delivers them.
type PasswordResetMessage struct {
	ToEmail   string
	Username  string
	Token     string
	ExpiresAt time.Time
	ResetURL  string
}

type PasswordRecoveryMailer interface {
	Available(context.Context) bool
	SendPasswordReset(context.Context, PasswordResetMessage) error
}

type unavailablePasswordRecoveryMailer struct{}

func (unavailablePasswordRecoveryMailer) Available(context.Context) bool { return false }
func (unavailablePasswordRecoveryMailer) SendPasswordReset(context.Context, PasswordResetMessage) error {
	return errors.New("email delivery is not configured")
}

var passwordRecoveryMailer PasswordRecoveryMailer = unavailablePasswordRecoveryMailer{}

type EmailDeliveryService struct {
	store  emailSettingsPersistence
	codec  emailSecretCodec
	sender outboundEmailSender
	now    func() time.Time
}

func newEmailDeliveryService(
	store emailSettingsPersistence,
	codec emailSecretCodec,
	sender outboundEmailSender,
) *EmailDeliveryService {
	return &EmailDeliveryService{store: store, codec: codec, sender: sender, now: time.Now}
}

func defaultEmailSettings() EmailDeliverySettings {
	return EmailDeliverySettings{
		Provider: emailProviderSMTP,
		SMTP:     SMTPEmailConfig{Port: 587, TLSMode: "STARTTLS"},
		AzureACS: AzureACSEmailConfig{APIVersion: "2025-09-01"},
	}
}

func (s *EmailDeliveryService) Settings(ctx context.Context) (EmailDeliverySettings, error) {
	public, secrets, updatedAt, updatedBy, found, err := s.load(ctx)
	credentialsUnavailable := errors.Is(err, errEmailCredentialsUnavailable)
	if err != nil && !credentialsUnavailable {
		return EmailDeliverySettings{}, err
	}
	if !found {
		return defaultEmailSettings(), nil
	}
	response := settingsResponse(public, secrets, &updatedAt, updatedBy)
	response.CredentialsUnavailable = credentialsUnavailable
	return response, nil
}

func (s *EmailDeliveryService) Save(
	ctx context.Context,
	input EmailDeliverySettings,
	actor string,
) (EmailDeliverySettings, error) {
	previousPublic, existingSecrets, previousUpdatedAt, _, found, err := s.load(ctx)
	if err != nil && !(input.ClearSecrets && errors.Is(err, errEmailCredentialsUnavailable)) {
		return EmailDeliverySettings{}, err
	}
	if !found {
		defaults := defaultEmailSettings()
		previousPublic = publicSettings(defaults)
	}
	var expectedUpdatedAt *time.Time
	if found {
		if input.ExpectedUpdatedAt == nil ||
			!previousUpdatedAt.Equal(input.ExpectedUpdatedAt.UTC().Truncate(time.Microsecond)) {
			return EmailDeliverySettings{}, errConcurrentEmailSettingsUpdate
		}
		expected := input.ExpectedUpdatedAt.UTC().Truncate(time.Microsecond)
		expectedUpdatedAt = &expected
	} else if input.ExpectedUpdatedAt != nil {
		return EmailDeliverySettings{}, errConcurrentEmailSettingsUpdate
	}
	public := publicSettings(input)
	applyEmailDefaults(&public)
	secrets := existingSecrets
	if input.ClearSecrets {
		secrets = emailSecretEnvelope{}
	}
	secrets = secretsBoundToDestination(previousPublic, public, secrets)
	if input.SMTP.Password != "" {
		secrets.SMTPPassword = input.SMTP.Password
	}
	if input.AWSSES.SecretAccessKey != "" {
		secrets.AWSSecretAccessKey = input.AWSSES.SecretAccessKey
		if input.AWSSES.SessionToken == "" {
			secrets.AWSSessionToken = ""
		}
	}
	if input.AWSSES.SessionToken != "" {
		secrets.AWSSessionToken = input.AWSSES.SessionToken
	}
	if input.AzureACS.AccessKey != "" {
		secrets.AzureAccessKey = input.AzureACS.AccessKey
	}
	if err := validateEmailSettings(public, secrets, public.Enabled); err != nil {
		return EmailDeliverySettings{}, err
	}
	secretJSON, err := json.Marshal(secrets)
	if err != nil {
		return EmailDeliverySettings{}, fmt.Errorf("encode email credentials: %w", err)
	}
	secretCipher, err := s.codec.encryptSecret(string(secretJSON))
	if err != nil {
		return EmailDeliverySettings{}, fmt.Errorf("encrypt email credentials: %w", err)
	}
	publicJSON, err := json.Marshal(public)
	if err != nil {
		return EmailDeliverySettings{}, fmt.Errorf("encode email public configuration: %w", err)
	}
	publicMap := map[string]any{}
	if err := json.Unmarshal(publicJSON, &publicMap); err != nil {
		return EmailDeliverySettings{}, fmt.Errorf("normalize email public configuration: %w", err)
	}
	updatedAt := s.now().UTC().Truncate(time.Microsecond)
	if found && !updatedAt.After(previousUpdatedAt) {
		updatedAt = previousUpdatedAt.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
	}
	record := EmailSettingsRecord{
		PublicConfig: publicMap,
		SecretCipher: secretCipher,
		UpdatedAt:    updatedAt,
		UpdatedBy:    actor,
	}
	if err := s.store.saveEmailSettings(ctx, record, public.Provider, expectedUpdatedAt); err != nil {
		return EmailDeliverySettings{}, err
	}
	return settingsResponse(public, secrets, &updatedAt, actor), nil
}

// secretsBoundToDestination prevents a write-only credential from being
// silently reused against a different server, account or provider. Changing
// the credential binding requires entering the secret again in the same PUT.
func secretsBoundToDestination(
	previous emailPublicConfig,
	next emailPublicConfig,
	secrets emailSecretEnvelope,
) emailSecretEnvelope {
	switch next.Provider {
	case emailProviderSMTP:
		secrets.AWSSecretAccessKey = ""
		secrets.AWSSessionToken = ""
		secrets.AzureAccessKey = ""
		if previous.Provider != next.Provider ||
			previous.SMTP.Host != next.SMTP.Host ||
			previous.SMTP.Port != next.SMTP.Port ||
			previous.SMTP.Username != next.SMTP.Username ||
			previous.SMTP.TLSMode != next.SMTP.TLSMode ||
			next.SMTP.Username == "" {
			secrets.SMTPPassword = ""
		}
	case emailProviderAWSSES:
		secrets.SMTPPassword = ""
		secrets.AzureAccessKey = ""
		if previous.Provider != next.Provider ||
			previous.AWSSES.Region != next.AWSSES.Region ||
			previous.AWSSES.AccessKeyID != next.AWSSES.AccessKeyID ||
			previous.AWSSES.Endpoint != next.AWSSES.Endpoint {
			secrets.AWSSecretAccessKey = ""
			secrets.AWSSessionToken = ""
		}
	case emailProviderAzureACS:
		secrets.SMTPPassword = ""
		secrets.AWSSecretAccessKey = ""
		secrets.AWSSessionToken = ""
		if previous.Provider != next.Provider ||
			previous.AzureACS.Endpoint != next.AzureACS.Endpoint {
			secrets.AzureAccessKey = ""
		}
	default:
		return emailSecretEnvelope{}
	}
	return secrets
}

func (s *EmailDeliveryService) Available(ctx context.Context) bool {
	public, secrets, _, _, found, err := s.load(ctx)
	return err == nil && found && public.Enabled && validateEmailSettings(public, secrets, true) == nil
}

func (s *EmailDeliveryService) SendPasswordReset(
	ctx context.Context,
	message PasswordResetMessage,
) error {
	recipient, err := mail.ParseAddress(message.ToEmail)
	if err != nil {
		return fmt.Errorf("invalid reset recipient: %w", err)
	}
	resetURL, err := url.ParseRequestURI(strings.TrimSpace(message.ResetURL))
	if err != nil || resetURL.Host == "" ||
		(resetURL.Scheme != "https" && !(resetURL.Scheme == "http" && isLoopbackHost(resetURL.Hostname()))) {
		return errors.New("password reset URL must use HTTPS (HTTP is allowed only for loopback tests)")
	}
	if strings.TrimSpace(message.Token) == "" || !message.ExpiresAt.After(s.now()) {
		return errors.New("password reset token is missing or expired")
	}
	public, secrets, _, _, found, err := s.load(ctx)
	if err != nil {
		return err
	}
	if !found || !public.Enabled {
		return errors.New("email delivery is disabled")
	}
	if err := validateEmailSettings(public, secrets, true); err != nil {
		return err
	}
	username := strings.TrimSpace(message.Username)
	if username == "" {
		username = "usuario"
	}
	expires := message.ExpiresAt.UTC().Format("2006-01-02 15:04 MST")
	textBody := fmt.Sprintf(
		"Hola %s,\n\nUsa este enlace para cambiar tu contraseña de O11y:\n%s\n\nEl enlace vence el %s. Si no solicitaste el cambio, ignora este mensaje.\n",
		username,
		message.ResetURL,
		expires,
	)
	htmlBody := renderPasswordResetHTML(username, message.ResetURL, expires)
	return s.sender.Send(ctx, public, secrets, OutboundEmail{
		ToEmail: recipient.Address,
		Subject: "Restablece tu contraseña de O11y",
		Text:    textBody,
		HTML:    htmlBody,
	})
}

func renderPasswordResetHTML(username, resetURL, expires string) string {
	escape := template.HTMLEscapeString
	return "<!doctype html><html><body>" +
		"<p>Hola " + escape(username) + ",</p>" +
		"<p>Usa el siguiente enlace para cambiar tu contraseña de O11y:</p>" +
		"<p><a href=\"" + escape(resetURL) + "\">Cambiar contraseña</a></p>" +
		"<p>El enlace vence el " + escape(expires) + ".</p>" +
		"<p>Si no solicitaste el cambio, ignora este mensaje.</p>" +
		"</body></html>"
}

func (s *EmailDeliveryService) Test(ctx context.Context, recipient string, actor string) (string, error) {
	parsedRecipient, err := mail.ParseAddress(recipient)
	if err != nil {
		return "", fmt.Errorf("invalid test recipient: %w", err)
	}
	public, secrets, _, _, found, err := s.load(ctx)
	if err != nil {
		return "", err
	}
	if !found {
		return "", errors.New("email delivery is not configured")
	}
	if err := validateEmailSettings(public, secrets, true); err != nil {
		return "", err
	}
	if err := s.sender.Send(ctx, public, secrets, OutboundEmail{
		ToEmail: parsedRecipient.Address,
		Subject: "Prueba de correo de O11y",
		Text:    "La configuración de correo de O11y funciona correctamente.\n",
		HTML:    "<!doctype html><html><body><p>La configuración de correo de <strong>O11y</strong> funciona correctamente.</p></body></html>",
	}); err != nil {
		return "", err
	}
	domain := ""
	if at := strings.LastIndex(parsedRecipient.Address, "@"); at >= 0 {
		domain = strings.ToLower(parsedRecipient.Address[at+1:])
	}
	if err := s.store.auditEmailTest(ctx, public.Provider, actor, domain); err != nil {
		return "", err
	}
	return public.Provider, nil
}

func (s *EmailDeliveryService) load(
	ctx context.Context,
) (emailPublicConfig, emailSecretEnvelope, time.Time, string, bool, error) {
	record, found, err := s.store.loadEmailSettings(ctx)
	if err != nil || !found {
		return emailPublicConfig{}, emailSecretEnvelope{}, time.Time{}, "", found, err
	}
	publicJSON, err := json.Marshal(record.PublicConfig)
	if err != nil {
		return emailPublicConfig{}, emailSecretEnvelope{}, time.Time{}, "", false, err
	}
	var public emailPublicConfig
	if err := json.Unmarshal(publicJSON, &public); err != nil {
		return emailPublicConfig{}, emailSecretEnvelope{}, time.Time{}, "", false,
			fmt.Errorf("decode email public configuration: %w", err)
	}
	var secrets emailSecretEnvelope
	if record.SecretCipher != "" {
		plain, err := s.codec.decryptSecret(record.SecretCipher)
		if err != nil {
			applyEmailDefaults(&public)
			return public, emailSecretEnvelope{}, record.UpdatedAt, record.UpdatedBy, true,
				fmt.Errorf("%w: %v", errEmailCredentialsUnavailable, err)
		}
		if err := json.Unmarshal([]byte(plain), &secrets); err != nil {
			return emailPublicConfig{}, emailSecretEnvelope{}, time.Time{}, "", false,
				fmt.Errorf("decode email credentials: %w", err)
		}
	}
	applyEmailDefaults(&public)
	return public, secrets, record.UpdatedAt, record.UpdatedBy, true, nil
}

func publicSettings(input EmailDeliverySettings) emailPublicConfig {
	return emailPublicConfig{
		Enabled:     input.Enabled,
		Provider:    strings.ToUpper(strings.TrimSpace(input.Provider)),
		FromName:    strings.TrimSpace(input.FromName),
		FromAddress: strings.TrimSpace(input.FromAddress),
		SMTP: SMTPEmailConfig{
			Host: strings.TrimSpace(input.SMTP.Host), Port: input.SMTP.Port,
			Username: strings.TrimSpace(input.SMTP.Username), TLSMode: strings.ToUpper(strings.TrimSpace(input.SMTP.TLSMode)),
		},
		AWSSES: AWSSESEmailConfig{
			Region: strings.TrimSpace(input.AWSSES.Region), AccessKeyID: strings.TrimSpace(input.AWSSES.AccessKeyID),
			Endpoint: strings.TrimRight(strings.TrimSpace(input.AWSSES.Endpoint), "/"),
		},
		AzureACS: AzureACSEmailConfig{
			Endpoint:   strings.TrimRight(strings.TrimSpace(input.AzureACS.Endpoint), "/"),
			APIVersion: strings.TrimSpace(input.AzureACS.APIVersion),
		},
	}
}

func applyEmailDefaults(settings *emailPublicConfig) {
	if settings.Provider == "" {
		settings.Provider = emailProviderSMTP
	}
	if settings.SMTP.Port == 0 {
		settings.SMTP.Port = 587
	}
	if settings.SMTP.TLSMode == "" {
		settings.SMTP.TLSMode = "STARTTLS"
	}
	if settings.AzureACS.APIVersion == "" {
		settings.AzureACS.APIVersion = "2025-09-01"
	}
}

func settingsResponse(
	public emailPublicConfig,
	secrets emailSecretEnvelope,
	updatedAt *time.Time,
	updatedBy string,
) EmailDeliverySettings {
	return EmailDeliverySettings{
		Enabled: public.Enabled, Provider: public.Provider,
		FromName: public.FromName, FromAddress: public.FromAddress,
		SMTP: public.SMTP, AWSSES: public.AWSSES, AzureACS: public.AzureACS,
		Secrets: EmailSecretsStatus{
			SMTPPassword: secrets.SMTPPassword != "", AWSSecretAccessKey: secrets.AWSSecretAccessKey != "",
			AWSSessionToken: secrets.AWSSessionToken != "", AzureAccessKey: secrets.AzureAccessKey != "",
		},
		UpdatedAt: updatedAt, UpdatedBy: updatedBy,
	}
}

func validateEmailSettings(public emailPublicConfig, secrets emailSecretEnvelope, requireDelivery bool) error {
	switch public.Provider {
	case emailProviderSMTP, emailProviderAWSSES, emailProviderAzureACS:
	default:
		return errors.New("provider must be SMTP, AWS_SES or AZURE_ACS")
	}
	if public.FromAddress != "" {
		address, err := mail.ParseAddress(public.FromAddress)
		if err != nil || address.Address != public.FromAddress || !strings.Contains(address.Address, "@") {
			return errors.New("fromAddress must be a valid email address")
		}
	} else if requireDelivery {
		return errors.New("fromAddress is required")
	}
	if len(public.FromName) > 128 {
		return errors.New("fromName must not exceed 128 characters")
	}
	if !requireDelivery {
		return nil
	}
	switch public.Provider {
	case emailProviderSMTP:
		if public.SMTP.Host == "" || !hostPattern.MatchString(public.SMTP.Host) {
			return errors.New("smtp.host must be a valid hostname")
		}
		if public.SMTP.Port < 1 || public.SMTP.Port > 65535 {
			return errors.New("smtp.port must be between 1 and 65535")
		}
		if public.SMTP.TLSMode != "STARTTLS" && public.SMTP.TLSMode != "TLS" && public.SMTP.TLSMode != "NONE" {
			return errors.New("smtp.tlsMode must be STARTTLS, TLS or NONE")
		}
		if public.SMTP.TLSMode == "NONE" && !isLoopbackHost(public.SMTP.Host) {
			return errors.New("smtp.tlsMode NONE is allowed only for loopback tests")
		}
		if (public.SMTP.Username == "") != (secrets.SMTPPassword == "") {
			return errors.New("smtp.username and smtp password must both be configured, or both omitted")
		}
	case emailProviderAWSSES:
		if !awsRegionPattern.MatchString(public.AWSSES.Region) {
			return errors.New("awsSes.region is invalid")
		}
		if public.AWSSES.AccessKeyID == "" || secrets.AWSSecretAccessKey == "" {
			return errors.New("awsSes accessKeyId and secretAccessKey are required")
		}
		if public.AWSSES.Endpoint != "" {
			if err := validateHTTPSServiceURL(public.AWSSES.Endpoint); err != nil {
				return fmt.Errorf("awsSes.endpoint: %w", err)
			}
		}
	case emailProviderAzureACS:
		if err := validateHTTPSServiceURL(public.AzureACS.Endpoint); err != nil {
			return fmt.Errorf("azureAcs.endpoint: %w", err)
		}
		if secrets.AzureAccessKey == "" {
			return errors.New("azureAcs.accessKey is required")
		}
		if public.AzureACS.APIVersion != "2025-09-01" {
			return errors.New("azureAcs.apiVersion must be 2025-09-01")
		}
	}
	return nil
}

func validateHTTPSServiceURL(value string) error {
	parsed, err := url.ParseRequestURI(value)
	if err != nil || parsed.Host == "" {
		return errors.New("must be an absolute URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("must not include credentials, query or fragment")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return errors.New("must use HTTPS (HTTP is allowed only for loopback tests)")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

func registerEmailAdministration(mux *http.ServeMux, store *PostgresStore, auth *Authenticator) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := store.migrateEmailSettings(ctx); err != nil {
		return err
	}
	service := newEmailDeliveryService(store, auth, &multiProviderEmailSender{client: secureEmailHTTPClient()})
	passwordRecoveryMailer = service
	mux.Handle("GET /api/settings/email", requirePermission("settings.email.view", service.getSettings))
	mux.Handle("PUT /api/settings/email", requirePermission("settings.email.edit", service.putSettings))
	mux.Handle("POST /api/settings/email/test", requirePermission("settings.email.edit", service.testSettings))
	return nil
}

func (s *EmailDeliveryService) getSettings(w http.ResponseWriter, r *http.Request) {
	settings, err := s.Settings(r.Context())
	if err != nil {
		http.Error(w, "email settings unavailable", http.StatusServiceUnavailable)
		return
	}
	jsonOut(w, settings)
}

func (s *EmailDeliveryService) putSettings(w http.ResponseWriter, r *http.Request) {
	var input EmailDeliverySettings
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid email settings", http.StatusBadRequest)
		return
	}
	identity, _ := authenticatedIdentity(r)
	settings, err := s.Save(r.Context(), input, identity.Username)
	if err != nil {
		if errors.Is(err, errConcurrentEmailSettingsUpdate) {
			http.Error(w, "email settings changed; reload before saving", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	emitAuditLog("email.settings.updated", identity.Username, map[string]any{
		"email.provider": settings.Provider,
		"email.enabled":  settings.Enabled,
	})
	jsonOut(w, settings)
}

func (s *EmailDeliveryService) testSettings(w http.ResponseWriter, r *http.Request) {
	var input struct {
		To string `json:"to"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		http.Error(w, "invalid test email request", http.StatusBadRequest)
		return
	}
	identity, _ := authenticatedIdentity(r)
	provider, err := s.Test(r.Context(), strings.TrimSpace(input.To), identity.Username)
	if err != nil {
		emitAuditLog("email.test.failed", identity.Username, map[string]any{
			"delivery.status": "failed",
		})
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	emitAuditLog("email.test.sent", identity.Username, map[string]any{"email.provider": provider})
	jsonOut(w, map[string]string{"status": "SENT", "provider": provider})
}
