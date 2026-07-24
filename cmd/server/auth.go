package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	sessionCookieName               = "o11y_session"
	oidcCookieName                  = "o11y_oidc_flow"
	minimumAuthSigningKeyBytes      = 32
	maximumAuthSigningKeyBytes      = 64 << 10
	maxExternalIdentityCacheEntries = 1024
)

type authContextKey struct{}

type Identity struct {
	Username    string   `json:"username"`
	FirstName   string   `json:"firstName,omitempty"`
	LastName    string   `json:"lastName,omitempty"`
	Email       string   `json:"email,omitempty"`
	Provider    string   `json:"provider"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	AuthVersion int64    `json:"-"`
}

type sessionClaims struct {
	Subject  string   `json:"sub"`
	Provider string   `json:"provider"`
	Roles    []string `json:"roles"`
	Expires  int64    `json:"exp"`
	Nonce    string   `json:"nonce"`
	Version  int64    `json:"ver,omitempty"`
}

type cachedIdentity struct {
	identity Identity
	expires  time.Time
}

type authProviderConfig struct {
	ID                string
	Label             string
	Protocol          string
	Status            string
	ValidationMessage string
	ValidatedAt       *time.Time
	UpdatedAt         time.Time
	UpdatedBy         string
	// CredentialsUnavailable means the public provider configuration was
	// recovered from PostgreSQL, but its write-only secret could not be
	// decrypted with the current AUTH_SIGNING_KEY. Keeping the revision visible
	// lets an administrator replace the secret without deleting the row.
	CredentialsUnavailable bool

	Issuer       string
	ClientID     string
	ClientSecret string
	UserClaim    string
	RoleClaim    string

	SPEntityID      string
	MetadataURL     string
	MetadataXML     string
	NameIDAttribute string
	UserAttribute   string
	RoleAttribute   string

	RoleMappings map[string]string
}

func (p authProviderConfig) Configured() bool {
	if p.CredentialsUnavailable {
		return false
	}
	switch p.Protocol {
	case "OIDC":
		return p.Issuer != "" && p.ClientID != "" && p.ClientSecret != ""
	case "SAML":
		return p.SPEntityID != "" && (p.MetadataURL != "" || p.MetadataXML != "")
	default:
		return false
	}
}

func (p authProviderConfig) Enabled() bool {
	return p.Status == "VALIDATED" && p.Configured() && len(p.RoleMappings) > 0
}

type oidcFlowClaims struct {
	Provider string `json:"provider"`
	State    string `json:"state"`
	Nonce    string `json:"nonce"`
	Verifier string `json:"verifier"`
	Expires  int64  `json:"exp"`
}

type Authenticator struct {
	masterUsername        string
	masterPassword        string
	signingKey            []byte
	introspectionURL      string
	introspectionID       string
	introspectionSecret   string
	introspectionAudience string
	introspectionIssuer   string
	roleClaim             string
	roleMappings          map[string]string // OAuth2 introspection compatibility mapping.
	publicURL             string
	network               networkConfiguration
	providers             map[string]authProviderConfig
	localUsers            LocalUserRepository
	client                *http.Client
	mu                    sync.Mutex
	cache                 map[string]cachedIdentity
}

var rolePermissions = map[string][]string{
	"viewer": {
		"agents.view", "audit.view", "business-events.view",
		"collectors.view", "security.view",
	},
	"business-editor": {
		"agents.view", "audit.view", "business-events.view", "business-events.edit",
		"collectors.view", "security.view",
	},
	"collector-editor": {
		"agents.view", "audit.view", "business-events.view",
		"collectors.view", "collectors.edit", "security.view",
	},
	"security-admin": {
		"agents.view", "audit.view", "business-events.view",
		"collectors.view", "security.view", "security.edit", "auth.admin",
		"settings.email.view",
	},
	"admin": {"*"},
}

var authenticator *Authenticator

func newAuthenticator() (*Authenticator, error) {
	networkSettings, err := loadNetworkConfiguration(os.LookupEnv)
	if err != nil {
		return nil, err
	}
	masterUsername := normalizeUsername(os.Getenv("MASTER_USERNAME"))
	if masterUsername == "" {
		return nil, errors.New("MASTER_USERNAME is required")
	}
	if err := validateUsername(masterUsername); err != nil {
		return nil, fmt.Errorf("invalid MASTER_USERNAME: %w", err)
	}
	masterPassword, configured := os.LookupEnv("MASTER_PASSWORD")
	if !configured || strings.TrimSpace(masterPassword) == "" {
		return nil, errors.New("MASTER_PASSWORD is required")
	}
	if err := validatePassword(masterPassword); err != nil {
		return nil, fmt.Errorf("invalid MASTER_PASSWORD: %w", err)
	}
	if networkSettings.LegacyPublicURL {
		fmt.Fprintln(os.Stderr, "AUTH_PUBLIC_URL is deprecated; configure SERVER_PUBLIC_URL instead")
	}
	signingSecret, _, err := loadAuthSigningSecret()
	if err != nil {
		return nil, err
	}
	introspectionURL := strings.TrimSpace(os.Getenv("AUTH_INTROSPECTION_URL"))
	if introspectionURL != "" && !validAuthEndpointURL(introspectionURL) {
		fmt.Fprintln(os.Stderr, "AUTH_INTROSPECTION_URL ignored: use absolute HTTPS (HTTP is allowed only for loopback tests)")
		introspectionURL = ""
	}
	return &Authenticator{
		masterUsername:        masterUsername,
		masterPassword:        masterPassword,
		signingKey:            []byte(signingSecret),
		introspectionURL:      introspectionURL,
		introspectionID:       strings.TrimSpace(os.Getenv("AUTH_CLIENT_ID")),
		introspectionSecret:   strings.TrimSpace(os.Getenv("AUTH_CLIENT_SECRET")),
		introspectionAudience: strings.TrimSpace(os.Getenv("AUTH_EXPECTED_AUDIENCE")),
		introspectionIssuer:   strings.TrimSpace(os.Getenv("AUTH_EXPECTED_ISSUER")),
		roleClaim:             envOr("AUTH_ROLE_CLAIM", "roles"),
		roleMappings:          parseRoleMappings(os.Getenv("AUTH_ROLE_MAPPINGS")),
		publicURL:             networkSettings.ServerPublicURL,
		network:               networkSettings,
		providers:             configuredProviders(),
		client:                secureAuthHTTPClient(strings.EqualFold(strings.TrimSpace(os.Getenv("AUTH_ALLOW_PRIVATE_IDP_NETWORKS")), "true")),
		cache:                 map[string]cachedIdentity{},
	}, nil
}

func loadAuthSigningSecret() (string, bool, error) {
	inline := strings.TrimSpace(os.Getenv("AUTH_SIGNING_KEY"))
	path := strings.TrimSpace(os.Getenv("AUTH_SIGNING_KEY_FILE"))
	if inline != "" && path != "" {
		return "", false, errors.New("configure only one of AUTH_SIGNING_KEY or AUTH_SIGNING_KEY_FILE")
	}
	if path != "" {
		file, err := os.Open(path)
		if err != nil {
			return "", false, fmt.Errorf("open AUTH_SIGNING_KEY_FILE: %w", err)
		}
		defer file.Close()
		contents, err := io.ReadAll(io.LimitReader(file, maximumAuthSigningKeyBytes+1))
		if err != nil {
			return "", false, fmt.Errorf("read AUTH_SIGNING_KEY_FILE: %w", err)
		}
		if len(contents) > maximumAuthSigningKeyBytes {
			return "", false, fmt.Errorf("AUTH_SIGNING_KEY_FILE exceeds %d bytes", maximumAuthSigningKeyBytes)
		}
		inline = strings.TrimSpace(string(contents))
	}
	if inline == "" {
		return "", false, errors.New("AUTH_SIGNING_KEY or AUTH_SIGNING_KEY_FILE is required")
	}
	if len(inline) < minimumAuthSigningKeyBytes || len(inline) > maximumAuthSigningKeyBytes {
		return "", false, fmt.Errorf(
			"authentication signing key must contain between %d and %d bytes",
			minimumAuthSigningKeyBytes,
			maximumAuthSigningKeyBytes,
		)
	}
	return inline, true, nil
}

func secureAuthHTTPClient(allowPrivate bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: 4 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network string, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid identity provider address: %w", err)
		}
		if allowPrivate {
			return dialer.DialContext(ctx, network, address)
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("resolve identity provider: %w", err)
		}
		for _, candidate := range addresses {
			if authProviderIPAllowed(host, candidate.IP, false) {
				return dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
			}
		}
		return nil, fmt.Errorf("identity provider resolves only to a private or special-use network")
	}
	return &http.Client{
		Transport: transport,
		Timeout:   4 * time.Second,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 || !validAuthEndpointURL(request.URL.String()) {
				return errors.New("unsafe identity provider redirect")
			}
			return nil
		},
	}
}

func authProviderIPAllowed(host string, ip net.IP, allowPrivate bool) bool {
	if allowPrivate {
		return true
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if (host == "localhost" || host == "127.0.0.1" || host == "::1") && ip.IsLoopback() {
		return true
	}
	return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() &&
		!ip.IsUnspecified() && !ip.IsMulticast()
}

func configuredProviders() map[string]authProviderConfig {
	providers := map[string]authProviderConfig{
		"microsoft": {
			ID:           "microsoft",
			Label:        "Continuar con Microsoft",
			Protocol:     "OIDC",
			Status:       "CONFIGURED",
			Issuer:       strings.TrimRight(strings.TrimSpace(os.Getenv("AUTH_OIDC_MICROSOFT_ISSUER")), "/"),
			ClientID:     strings.TrimSpace(os.Getenv("AUTH_OIDC_MICROSOFT_CLIENT_ID")),
			ClientSecret: strings.TrimSpace(os.Getenv("AUTH_OIDC_MICROSOFT_CLIENT_SECRET")),
			UserClaim:    "preferred_username",
			RoleClaim:    envOr("AUTH_ROLE_CLAIM", "roles"),
			RoleMappings: parseRoleMappings(os.Getenv("AUTH_ROLE_MAPPINGS")),
		},
		"google": {
			ID:           "google",
			Label:        "Continuar con Google",
			Protocol:     "OIDC",
			Status:       "CONFIGURED",
			Issuer:       envOr("AUTH_OIDC_GOOGLE_ISSUER", "https://accounts.google.com"),
			ClientID:     strings.TrimSpace(os.Getenv("AUTH_OIDC_GOOGLE_CLIENT_ID")),
			ClientSecret: strings.TrimSpace(os.Getenv("AUTH_OIDC_GOOGLE_CLIENT_SECRET")),
			UserClaim:    "email",
			RoleClaim:    envOr("AUTH_ROLE_CLAIM", "roles"),
			RoleMappings: parseRoleMappings(os.Getenv("AUTH_ROLE_MAPPINGS")),
		},
		"corporate": {
			ID:           "corporate",
			Label:        envOr("AUTH_OIDC_CORPORATE_LABEL", "Continuar con SSO corporativo"),
			Protocol:     "OIDC",
			Status:       "CONFIGURED",
			Issuer:       strings.TrimRight(strings.TrimSpace(os.Getenv("AUTH_OIDC_CORPORATE_ISSUER")), "/"),
			ClientID:     strings.TrimSpace(os.Getenv("AUTH_OIDC_CORPORATE_CLIENT_ID")),
			ClientSecret: strings.TrimSpace(os.Getenv("AUTH_OIDC_CORPORATE_CLIENT_SECRET")),
			UserClaim:    "preferred_username",
			RoleClaim:    envOr("AUTH_ROLE_CLAIM", "roles"),
			RoleMappings: parseRoleMappings(os.Getenv("AUTH_ROLE_MAPPINGS")),
		},
	}
	for id, provider := range providers {
		if !provider.Configured() {
			delete(providers, id)
			continue
		}
		providers[id] = provider
	}
	return providers
}

func envOr(name string, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func parseRoleMappings(raw string) map[string]string {
	result := map[string]string{}
	for _, item := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(parts) == 2 && strings.TrimSpace(parts[0]) != "" {
			localRole := strings.TrimSpace(parts[1])
			if _, known := rolePermissions[localRole]; known {
				result[strings.TrimSpace(parts[0])] = localRole
			}
		}
	}
	return result
}

func permissionsForRoles(roles []string) []string {
	set := map[string]bool{}
	for _, role := range roles {
		for _, permission := range rolePermissions[role] {
			set[permission] = true
		}
	}
	result := make([]string, 0, len(set))
	for permission := range set {
		result = append(result, permission)
	}
	sort.Strings(result)
	return result
}

func (a *Authenticator) login(username string, password string) (string, Identity, bool) {
	return a.loginContext(context.Background(), username, password)
}

func (a *Authenticator) loginContext(
	ctx context.Context,
	username string,
	password string,
) (string, Identity, bool) {
	if a.localUsers != nil {
		user, ok := authenticateStoredLocalUser(ctx, a.localUsers, username, password)
		if !ok {
			return "", Identity{}, false
		}
		identity := identityFromLocalUser(user)
		return a.issueSession(identity), identity, true
	}
	// Compatibility path for isolated unit tests. Production always attaches
	// PostgreSQL before serving the login endpoint.
	userMatch := subtle.ConstantTimeCompare([]byte(username), []byte(a.masterUsername)) == 1
	passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(a.masterPassword)) == 1
	if !userMatch || !passwordMatch {
		return "", Identity{}, false
	}
	identity := Identity{
		Username: username,
		Provider: "local",
		Roles:    []string{"admin"},
	}
	identity.Permissions = permissionsForRoles(identity.Roles)
	return a.issueSession(identity), identity, true
}

func (a *Authenticator) issueSession(identity Identity) string {
	claims := sessionClaims{
		Subject:  identity.Username,
		Provider: identity.Provider,
		Roles:    identity.Roles,
		Expires:  time.Now().Add(8 * time.Hour).Unix(),
		Nonce:    randomToken(12),
		Version:  identity.AuthVersion,
	}
	encoded, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(encoded)
	signature := a.sign(payload)
	return payload + "." + signature
}

func randomToken(size int) string {
	value := make([]byte, size)
	_, _ = rand.Read(value)
	return base64.RawURLEncoding.EncodeToString(value)
}

func (a *Authenticator) sign(payload string) string {
	mac := hmac.New(sha256.New, a.signingKey)
	_, _ = mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (a *Authenticator) encryptSecret(value string) (string, error) {
	key := sha256.Sum256(a.signingKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(value), nil)
	return base64.RawURLEncoding.EncodeToString(sealed), nil
}

func (a *Authenticator) decryptSecret(value string) (string, error) {
	sealed, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	key := sha256.Sum256(a.signingKey)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(sealed) < gcm.NonceSize() {
		return "", fmt.Errorf("invalid encrypted OIDC secret")
	}
	plain, err := gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (a *Authenticator) applyStoredProviders(records []AuthProviderRecord) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.providers == nil {
		a.providers = map[string]authProviderConfig{}
	}
	for _, record := range records {
		secret := ""
		credentialsUnavailable := false
		if record.Protocol == "OIDC" && record.SecretCipher != "" {
			var decryptErr error
			secret, decryptErr = a.decryptSecret(record.SecretCipher)
			credentialsUnavailable = decryptErr != nil
		}
		status := record.Status
		validationMessage := record.ValidationMessage
		if credentialsUnavailable {
			status = "ERROR"
			validationMessage = "El client secret guardado no puede descifrarse. Ingresa uno nuevo y guarda la configuración."
		}
		provider := authProviderConfig{
			ID:                     record.ProviderID,
			Label:                  record.Label,
			Protocol:               record.Protocol,
			Status:                 status,
			ValidationMessage:      validationMessage,
			ValidatedAt:            record.ValidatedAt,
			UpdatedAt:              record.UpdatedAt,
			UpdatedBy:              record.UpdatedBy,
			CredentialsUnavailable: credentialsUnavailable,
			Issuer:                 strings.TrimRight(record.Config["issuer"], "/"),
			ClientID:               record.Config["clientId"],
			ClientSecret:           secret,
			UserClaim:              record.Config["userClaim"],
			RoleClaim:              record.Config["roleClaim"],
			SPEntityID:             record.Config["spEntityId"],
			MetadataURL:            record.Config["metadataUrl"],
			MetadataXML:            record.Config["metadataXml"],
			NameIDAttribute:        record.Config["nameIdAttribute"],
			UserAttribute:          record.Config["userAttribute"],
			RoleAttribute:          record.Config["roleAttribute"],
			RoleMappings:           record.RoleMappings,
		}
		applyProviderDefaults(&provider)
		a.providers[record.ProviderID] = provider
	}
	return nil
}

func applyProviderDefaults(provider *authProviderConfig) {
	if provider.UserClaim == "" {
		provider.UserClaim = "preferred_username"
	}
	if provider.RoleClaim == "" {
		provider.RoleClaim = "roles"
	}
	if provider.UserAttribute == "" {
		provider.UserAttribute = "email"
	}
	if provider.RoleAttribute == "" {
		provider.RoleAttribute = "roles"
	}
	if provider.NameIDAttribute == "" {
		provider.NameIDAttribute = "nameid"
	}
	if provider.RoleMappings == nil {
		provider.RoleMappings = map[string]string{}
	}
}

func (a *Authenticator) localIdentity(token string) (Identity, bool) {
	return a.localIdentityContext(context.Background(), token)
}

func (a *Authenticator) localIdentityContext(ctx context.Context, token string) (Identity, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(a.sign(parts[0]))) {
		return Identity{}, false
	}
	encoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Identity{}, false
	}
	var claims sessionClaims
	if json.Unmarshal(encoded, &claims) != nil || claims.Expires < time.Now().Unix() {
		return Identity{}, false
	}
	if claims.Provider == "local" && a.localUsers != nil {
		user, err := a.localUsers.localUser(ctx, claims.Subject)
		if err != nil || !user.Active || user.AuthVersion != claims.Version {
			return Identity{}, false
		}
		return identityFromLocalUser(user), true
	}
	if claims.Provider != "local" {
		a.mu.Lock()
		provider, known := a.providers[claims.Provider]
		a.mu.Unlock()
		if !known || !provider.Enabled() || claims.Version != providerAuthVersion(provider) {
			return Identity{}, false
		}
	}
	identity := Identity{
		Username: claims.Subject,
		Provider: claims.Provider,
		Roles:    claims.Roles,
	}
	identity.Permissions = permissionsForRoles(identity.Roles)
	return identity, true
}

func providerAuthVersion(provider authProviderConfig) int64 {
	if provider.UpdatedAt.IsZero() {
		return 0
	}
	// PostgreSQL TIMESTAMPTZ persists microsecond precision. Using the same
	// precision keeps a valid SSO session stable across process restarts while
	// still invalidating it on every provider revision.
	return provider.UpdatedAt.UnixMicro()
}

func nextProviderUpdatedAt(previous time.Time) time.Time {
	next := time.Now().UTC().Truncate(time.Microsecond)
	if !previous.IsZero() && !next.After(previous) {
		return previous.UTC().Truncate(time.Microsecond).Add(time.Microsecond)
	}
	return next
}

func (a *Authenticator) externalIdentity(ctx context.Context, token string) (Identity, bool) {
	if a.introspectionURL == "" {
		return Identity{}, false
	}
	hash := sha256.Sum256([]byte(token))
	cacheKey := base64.RawURLEncoding.EncodeToString(hash[:])
	a.mu.Lock()
	entry, found := a.cache[cacheKey]
	if found && entry.expires.After(time.Now()) {
		a.mu.Unlock()
		return entry.identity, true
	}
	if found {
		delete(a.cache, cacheKey)
	}
	a.mu.Unlock()

	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		a.introspectionURL,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return Identity{}, false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if a.introspectionID != "" {
		req.SetBasicAuth(a.introspectionID, a.introspectionSecret)
	}
	client := *a.client
	// Introspection carries the bearer token in the request body and optional
	// Basic credentials. Never replay either across a redirect.
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	response, err := client.Do(req)
	if err != nil {
		return Identity{}, false
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, response.Body)
		return Identity{}, false
	}
	var payload map[string]any
	if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&payload) != nil ||
		payload["active"] != true {
		return Identity{}, false
	}
	now := time.Now()
	expiresAt, validExpiry := numericDate(payload["exp"])
	if !validExpiry || !expiresAt.After(now) || a.introspectionAudience == "" ||
		!audienceContains(payload["aud"], a.introspectionAudience) ||
		(a.introspectionIssuer != "" && firstString(payload, "iss") != a.introspectionIssuer) {
		return Identity{}, false
	}
	username := firstString(payload, "preferred_username", "username", "sub")
	if username == "" {
		return Identity{}, false
	}
	externalRoles := stringList(payload[a.roleClaim])
	roles := mappedLocalRoles(externalRoles, a.roleMappings)
	if len(roles) == 0 {
		return Identity{}, false
	}
	identity := Identity{
		Username: username,
		Provider: "oauth2-introspection",
		Roles:    roles,
	}
	identity.Permissions = permissionsForRoles(identity.Roles)
	cacheExpiry := now.Add(30 * time.Second)
	if expiresAt.Before(cacheExpiry) {
		cacheExpiry = expiresAt
	}
	a.cacheExternalIdentity(cacheKey, cachedIdentity{identity: identity, expires: cacheExpiry}, now)
	return identity, true
}

func (a *Authenticator) cacheExternalIdentity(
	cacheKey string,
	entry cachedIdentity,
	now time.Time,
) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for key, candidate := range a.cache {
		if !candidate.expires.After(now) {
			delete(a.cache, key)
		}
	}
	if _, exists := a.cache[cacheKey]; !exists && len(a.cache) >= maxExternalIdentityCacheEntries {
		oldestKey := ""
		var oldestExpiry time.Time
		for key, candidate := range a.cache {
			if oldestKey == "" || candidate.expires.Before(oldestExpiry) {
				oldestKey = key
				oldestExpiry = candidate.expires
			}
		}
		delete(a.cache, oldestKey)
	}
	a.cache[cacheKey] = entry
}

func numericDate(value any) (time.Time, bool) {
	var seconds int64
	switch typed := value.(type) {
	case float64:
		seconds = int64(typed)
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return time.Time{}, false
		}
		seconds = parsed
	case int64:
		seconds = typed
	case int:
		seconds = int64(typed)
	default:
		return time.Time{}, false
	}
	if seconds <= 0 {
		return time.Time{}, false
	}
	return time.Unix(seconds, 0), true
}

func audienceContains(value any, expected string) bool {
	for _, audience := range stringList(value) {
		if subtle.ConstantTimeCompare([]byte(audience), []byte(expected)) == 1 {
			return true
		}
	}
	return false
}

func firstString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value, ok := values[key].(string); ok && value != "" {
			return value
		}
	}
	return ""
}

func stringList(value any) []string {
	switch typed := value.(type) {
	case []any:
		result := []string{}
		for _, item := range typed {
			if text, ok := item.(string); ok {
				result = append(result, text)
			}
		}
		return result
	case []string:
		return typed
	case string:
		return strings.Fields(typed)
	default:
		return nil
	}
}

func uniqueStrings(values []string) []string {
	set := map[string]bool{}
	result := []string{}
	for _, value := range values {
		if !set[value] {
			set[value] = true
			result = append(result, value)
		}
	}
	return result
}

func mappedLocalRoles(externalRoles []string, mappings map[string]string) []string {
	roles := make([]string, 0, len(externalRoles))
	for _, externalRole := range externalRoles {
		if localRole := mappings[externalRole]; localRole != "" {
			roles = append(roles, localRole)
		}
	}
	return uniqueStrings(roles)
}

func bearerToken(r *http.Request) string {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
}

func (a *Authenticator) identity(r *http.Request) (Identity, bool) {
	if token := bearerToken(r); token != "" {
		if identity, ok := a.localIdentityContext(r.Context(), token); ok {
			return identity, true
		}
		return a.externalIdentity(r.Context(), token)
	}
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return Identity{}, false
	}
	// Browser session cookies are created and verified only by this Control
	// Plane. Never forward them to a remote OAuth introspection endpoint.
	return a.localIdentityContext(r.Context(), strings.TrimSpace(cookie.Value))
}

func requestUsesTLS(r *http.Request) bool {
	configuration := activeNetworkConfiguration()
	if configuration.ServerPublicURL != "" {
		parsed, err := url.Parse(configuration.ServerPublicURL)
		return err == nil && parsed.Scheme == "https"
	}
	if r.TLS != nil {
		return true
	}
	forwarded, ok := trustedForwardedOrigin(r, configuration)
	return ok && forwarded.Scheme == "https"
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	// Local HTTP remains supported; externally published HTTPS origins always set Secure.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   maxAge,
		Expires:  time.Now().Add(time.Duration(maxAge) * time.Second),
		HttpOnly: true,
		Secure:   requestUsesTLS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(w http.ResponseWriter, r *http.Request, name string) {
	// Match the original cookie's scheme-aware Secure setting so deletion works locally and remotely.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		HttpOnly: true,
		Secure:   requestUsesTLS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func hasPermission(identity Identity, permission string) bool {
	for _, candidate := range identity.Permissions {
		if candidate == "*" || candidate == permission {
			return true
		}
	}
	return false
}

func canDelegateRoles(identity Identity, roles []string) bool {
	for _, role := range roles {
		permissions, known := rolePermissions[role]
		if !known {
			return false
		}
		for _, permission := range permissions {
			if !hasPermission(identity, permission) {
				return false
			}
		}
	}
	return true
}

func assignableRoleIDs(identity Identity) []string {
	roles := make([]string, 0, len(rolePermissions))
	for role := range rolePermissions {
		if canDelegateRoles(identity, []string{role}) {
			roles = append(roles, role)
		}
	}
	sort.Strings(roles)
	return roles
}

func requirePermission(permission string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := authenticator.identity(r)
		if !ok {
			emitAuditLog("auth.request.unauthorized", "anonymous", map[string]any{
				"http.request.method": r.Method,
				"url.path":            r.URL.Path,
			})
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if !hasPermission(identity, permission) {
			emitAuditLog("auth.request.forbidden", identity.Username, map[string]any{
				"auth.permission.required": permission,
				"http.request.method":      r.Method,
				"url.path":                 r.URL.Path,
			})
			http.Error(w, fmt.Sprintf("permission %s required", permission), http.StatusForbidden)
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), authContextKey{}, identity)))
	})
}

func authenticatedIdentity(r *http.Request) (Identity, bool) {
	identity, ok := r.Context().Value(authContextKey{}).(Identity)
	if ok {
		return identity, true
	}
	if authenticator == nil {
		return Identity{}, false
	}
	return authenticator.identity(r)
}

func authLogin(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		http.Error(w, "Content-Type application/json is required", http.StatusUnsupportedMediaType)
		return
	}
	var credentials struct {
		Username string
		Password string
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&credentials) != nil {
		http.Error(w, "invalid credentials", http.StatusBadRequest)
		return
	}
	token, identity, ok := authenticator.loginContext(
		r.Context(), credentials.Username, credentials.Password,
	)
	if !ok {
		emitAuditLog("auth.login.failed", credentials.Username, map[string]any{
			"auth.provider": "local",
		})
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	emitAuditLog("auth.login.succeeded", identity.Username, map[string]any{
		"auth.provider": identity.Provider,
	})
	setSessionCookie(w, r, token, 8*60*60)
	jsonOut(w, map[string]any{"identity": identity, "expiresIn": 28800})
}

func webSecurityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		if requestUsesTLS(r) {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if requestRequiresSameOrigin(r) && !requestHasTrustedOrigin(r) {
			http.Error(w, "cross-site request rejected", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requestRequiresSameOrigin(r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return false
	}
	return !strings.HasPrefix(r.URL.Path, "/api/auth/saml/") || !strings.HasSuffix(r.URL.Path, "/acs")
}

func requestHasTrustedOrigin(r *http.Request) bool {
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")), "cross-site") {
		return false
	}
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin == "" {
		if subtle.ConstantTimeCompare(
			[]byte(strings.TrimSpace(r.Header.Get("X-O11y-CSRF"))), []byte("1"),
		) == 1 {
			return true
		}
		if _, err := r.Cookie(sessionCookieName); err == nil {
			referer := strings.TrimSpace(r.Header.Get("Referer"))
			return referer != "" && sameWebOrigin(referer, expectedWebOrigin(r))
		}
		return true
	}
	return sameWebOrigin(origin, expectedWebOrigin(r))
}

func expectedWebOrigin(r *http.Request) string {
	return effectiveRequestOrigin(r, activeNetworkConfiguration())
}

func sameWebOrigin(candidate string, expected string) bool {
	candidateURL, candidateErr := url.Parse(candidate)
	expectedURL, expectedErr := url.Parse(expected)
	return candidateErr == nil && expectedErr == nil &&
		candidateURL.Scheme != "" && candidateURL.Host != "" &&
		strings.EqualFold(candidateURL.Scheme, expectedURL.Scheme) &&
		strings.EqualFold(candidateURL.Host, expectedURL.Host)
}

func authLogout(w http.ResponseWriter, r *http.Request) {
	identity, _ := authenticator.identity(r)
	clearCookie(w, r, sessionCookieName)
	clearCookie(w, r, oidcCookieName)
	emitAuditLog("auth.logout", identity.Username, map[string]any{
		"auth.provider": identity.Provider,
	})
	w.WriteHeader(http.StatusNoContent)
}

func authSession(w http.ResponseWriter, r *http.Request) {
	identity, ok := authenticatedIdentity(r)
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	jsonOut(w, identity)
}

func (a *Authenticator) providerList() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	ids := make([]string, 0, len(a.providers))
	for id := range a.providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	providers := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		provider := a.providers[id]
		providers = append(providers, map[string]any{
			"id":                provider.ID,
			"label":             provider.Label,
			"protocol":          provider.Protocol,
			"status":            provider.Status,
			"validationMessage": provider.ValidationMessage,
			"enabled":           a.providerEnabled(provider),
			"startUrl":          providerStartURL(provider),
		})
	}
	return providers
}

func authPublicProviders(w http.ResponseWriter, _ *http.Request) {
	configured := []map[string]any{}
	for _, provider := range authenticator.providerList() {
		if provider["enabled"] == true {
			configured = append(configured, provider)
		}
	}
	jsonOut(w, map[string]any{"providers": configured})
}

func (a *Authenticator) providerConfigurationList() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	ids := make([]string, 0, len(a.providers))
	for id := range a.providers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		result = append(result, a.providerConfiguration(a.providers[id]))
	}
	return result
}

func providerStartURL(provider authProviderConfig) string {
	if provider.Protocol == "SAML" {
		return "/api/auth/saml/" + provider.ID + "/start"
	}
	return "/api/auth/oidc/" + provider.ID + "/start"
}

func (a *Authenticator) providerConfiguration(provider authProviderConfig) map[string]any {
	result := map[string]any{
		"id":                provider.ID,
		"label":             provider.Label,
		"protocol":          provider.Protocol,
		"status":            provider.Status,
		"validationMessage": provider.ValidationMessage,
		"enabled":           a.providerEnabled(provider),
		"startUrl":          providerStartURL(provider),
		"updatedAt":         provider.UpdatedAt,
		"updatedBy":         provider.UpdatedBy,
		"roleMappings":      provider.RoleMappings,
	}
	if provider.ValidatedAt != nil {
		result["validatedAt"] = provider.ValidatedAt
	}
	if provider.Protocol == "SAML" {
		result["spEntityId"] = provider.SPEntityID
		result["metadataUrl"] = provider.MetadataURL
		result["metadataXml"] = provider.MetadataXML
		result["metadataConfigured"] = provider.MetadataURL != "" || provider.MetadataXML != ""
		result["nameIdAttribute"] = provider.NameIDAttribute
		result["userAttribute"] = provider.UserAttribute
		result["roleAttribute"] = provider.RoleAttribute
		if a.publicURL != "" {
			result["acsUrl"] = a.publicURL + "/api/auth/saml/" + provider.ID + "/acs"
			result["spMetadataUrl"] = a.publicURL + "/api/auth/saml/" + provider.ID + "/metadata"
		}
	} else {
		if a.publicURL != "" {
			result["callbackUrl"] = a.publicURL + "/api/auth/oidc/" + provider.ID + "/callback"
		}
		result["issuer"] = provider.Issuer
		result["clientId"] = provider.ClientID
		result["secretConfigured"] = provider.ClientSecret != ""
		result["credentialsUnavailable"] = provider.CredentialsUnavailable
		result["userClaim"] = provider.UserClaim
		result["roleClaim"] = provider.RoleClaim
	}
	return result
}

func validIssuer(raw string) bool {
	return validAuthEndpointURL(raw)
}

func validAuthEndpointURL(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Opaque != "" || parsed.Host == "" ||
		parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return false
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	return strings.EqualFold(parsed.Scheme, "https") ||
		(strings.EqualFold(parsed.Scheme, "http") &&
			(host == "localhost" || host == "127.0.0.1" || host == "::1"))
}

// oidcAdvertisedEndpoints contains the URL-bearing discovery fields that the
// Control Plane or a closely related OAuth/OIDC flow can use. Discovery is
// remote input: validating only the issuer would still let a compromised IdP
// redirect the browser or send client credentials/tokens to an HTTP endpoint.
type oidcAdvertisedEndpoints struct {
	Issuer                             string `json:"issuer"`
	AuthorizationEndpoint              string `json:"authorization_endpoint"`
	TokenEndpoint                      string `json:"token_endpoint"`
	JWKSURI                            string `json:"jwks_uri"`
	UserInfoEndpoint                   string `json:"userinfo_endpoint"`
	DeviceAuthorizationEndpoint        string `json:"device_authorization_endpoint"`
	PushedAuthorizationRequestEndpoint string `json:"pushed_authorization_request_endpoint"`
	RegistrationEndpoint               string `json:"registration_endpoint"`
	RevocationEndpoint                 string `json:"revocation_endpoint"`
	IntrospectionEndpoint              string `json:"introspection_endpoint"`
	EndSessionEndpoint                 string `json:"end_session_endpoint"`
}

func validateOIDCDiscoveryEndpoints(discovery *oidc.Provider) error {
	if discovery == nil {
		return fmt.Errorf("OIDC discovery is unavailable")
	}
	var advertised oidcAdvertisedEndpoints
	if err := discovery.Claims(&advertised); err != nil {
		return fmt.Errorf("read OIDC discovery endpoints: %w", err)
	}

	// Validate the exact endpoints exposed by go-oidc for the active flow, plus
	// JWKS (used by ID-token verification). The remaining standard endpoints are
	// optional, but when advertised they must obey the same transport policy.
	endpoint := discovery.Endpoint()
	checks := []struct {
		name     string
		value    string
		required bool
	}{
		{name: "issuer", value: advertised.Issuer, required: true},
		{name: "authorization_endpoint", value: endpoint.AuthURL, required: true},
		{name: "token_endpoint", value: endpoint.TokenURL, required: true},
		{name: "jwks_uri", value: advertised.JWKSURI, required: true},
		{name: "userinfo_endpoint", value: discovery.UserInfoEndpoint()},
		{name: "device_authorization_endpoint", value: endpoint.DeviceAuthURL},
		{name: "pushed_authorization_request_endpoint", value: advertised.PushedAuthorizationRequestEndpoint},
		{name: "registration_endpoint", value: advertised.RegistrationEndpoint},
		{name: "revocation_endpoint", value: advertised.RevocationEndpoint},
		{name: "introspection_endpoint", value: advertised.IntrospectionEndpoint},
		{name: "end_session_endpoint", value: advertised.EndSessionEndpoint},
	}
	for _, check := range checks {
		if strings.TrimSpace(check.value) == "" {
			if check.required {
				return fmt.Errorf("OIDC discovery does not expose %s", check.name)
			}
			continue
		}
		if !validAuthEndpointURL(check.value) {
			return fmt.Errorf(
				"OIDC discovery exposes unsafe %s; use absolute HTTPS (HTTP is allowed only for loopback tests)",
				check.name,
			)
		}
	}
	return nil
}

type authProviderPayload struct {
	Protocol          string            `json:"protocol"`
	Label             string            `json:"label"`
	Issuer            string            `json:"issuer"`
	ClientID          string            `json:"clientId"`
	ClientSecret      string            `json:"clientSecret"`
	UserClaim         string            `json:"userClaim"`
	RoleClaim         string            `json:"roleClaim"`
	SPEntityID        string            `json:"spEntityId"`
	MetadataURL       string            `json:"metadataUrl"`
	MetadataXML       string            `json:"metadataXml"`
	NameIDAttribute   string            `json:"nameIdAttribute"`
	UserAttribute     string            `json:"userAttribute"`
	RoleAttribute     string            `json:"roleAttribute"`
	RoleMappings      map[string]string `json:"roleMappings"`
	ExpectedUpdatedAt *time.Time        `json:"expectedUpdatedAt"`
}

func validProviderID(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func updateAuthProvider(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("provider")
	if !validProviderID(providerID) {
		http.Error(w, "provider ID must be a lowercase slug", http.StatusUnprocessableEntity)
		return
	}
	authenticator.mu.Lock()
	current := authenticator.providers[providerID]
	authenticator.mu.Unlock()
	identity, _ := authenticatedIdentity(r)
	if len(current.RoleMappings) > 0 &&
		!canDelegateRoles(identity, mappedRoleValues(current.RoleMappings)) {
		http.Error(w, "cannot modify a provider mapped to permissions the current user does not possess", http.StatusForbidden)
		return
	}
	var payload authProviderPayload
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&payload) != nil {
		http.Error(w, "invalid identity provider configuration", http.StatusBadRequest)
		return
	}
	var expectedUpdatedAt *time.Time
	if !current.UpdatedAt.IsZero() {
		if payload.ExpectedUpdatedAt == nil ||
			!current.UpdatedAt.Equal(payload.ExpectedUpdatedAt.UTC().Truncate(time.Microsecond)) {
			http.Error(w, "identity provider changed; reload before saving", http.StatusConflict)
			return
		}
		expected := payload.ExpectedUpdatedAt.UTC().Truncate(time.Microsecond)
		expectedUpdatedAt = &expected
	} else if payload.ExpectedUpdatedAt != nil {
		http.Error(w, "identity provider changed; reload before saving", http.StatusConflict)
		return
	}
	payload.Protocol = strings.ToUpper(strings.TrimSpace(payload.Protocol))
	payload.Label = strings.TrimSpace(payload.Label)
	payload.Issuer = strings.TrimRight(strings.TrimSpace(payload.Issuer), "/")
	payload.ClientID = strings.TrimSpace(payload.ClientID)
	if payload.Label == "" || (payload.Protocol != "OIDC" && payload.Protocol != "SAML") {
		http.Error(w, "label and protocol OIDC or SAML are required", http.StatusUnprocessableEntity)
		return
	}
	effectiveRoleMappings := current.RoleMappings
	if payload.RoleMappings != nil {
		if err := validateRoleMappings(payload.RoleMappings); err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		effectiveRoleMappings = payload.RoleMappings
	}
	if !canDelegateRoles(identity, mappedRoleValues(effectiveRoleMappings)) {
		http.Error(w, "cannot map a role with permissions the current user does not possess", http.StatusForbidden)
		return
	}
	provider := authProviderConfig{
		ID:              providerID,
		Label:           payload.Label,
		Protocol:        payload.Protocol,
		Status:          "CONFIGURED",
		UserClaim:       strings.TrimSpace(payload.UserClaim),
		RoleClaim:       strings.TrimSpace(payload.RoleClaim),
		SPEntityID:      strings.TrimSpace(payload.SPEntityID),
		MetadataURL:     strings.TrimSpace(payload.MetadataURL),
		MetadataXML:     strings.TrimSpace(payload.MetadataXML),
		NameIDAttribute: strings.TrimSpace(payload.NameIDAttribute),
		UserAttribute:   strings.TrimSpace(payload.UserAttribute),
		RoleAttribute:   strings.TrimSpace(payload.RoleAttribute),
		RoleMappings:    effectiveRoleMappings,
	}
	applyProviderDefaults(&provider)
	secretCipher := ""
	if provider.Protocol == "OIDC" {
		provider.Issuer = payload.Issuer
		provider.ClientID = payload.ClientID
		provider.ClientSecret = oidcSecretBoundToClient(
			current,
			provider.Issuer,
			provider.ClientID,
			strings.TrimSpace(payload.ClientSecret),
		)
		if !validIssuer(provider.Issuer) || provider.ClientID == "" || provider.ClientSecret == "" {
			http.Error(w, "HTTPS issuer, client ID and client secret are required", http.StatusUnprocessableEntity)
			return
		}
		var err error
		secretCipher, err = authenticator.encryptSecret(provider.ClientSecret)
		if err != nil {
			http.Error(w, "identity provider secret could not be encrypted", http.StatusInternalServerError)
			return
		}
	} else {
		var err error
		secretCipher, err = authenticator.encryptSecret("")
		if err != nil {
			http.Error(w, "identity provider state could not be encrypted", http.StatusInternalServerError)
			return
		}
		if provider.SPEntityID == "" && authenticator.publicURL != "" {
			provider.SPEntityID = authenticator.publicURL + "/api/auth/saml/" + providerID + "/metadata"
		}
		if provider.SPEntityID == "" || (provider.MetadataURL == "" && provider.MetadataXML == "") {
			http.Error(w, "SP entity ID and IdP metadata URL or XML are required", http.StatusUnprocessableEntity)
			return
		}
		if provider.MetadataURL != "" && provider.MetadataXML != "" {
			http.Error(w, "configure either SAML metadata URL or XML, not both", http.StatusUnprocessableEntity)
			return
		}
		if provider.MetadataURL != "" && !validIssuer(provider.MetadataURL) {
			http.Error(w, "SAML metadata URL must use HTTPS (HTTP is allowed only for localhost)", http.StatusUnprocessableEntity)
			return
		}
	}
	now := nextProviderUpdatedAt(current.UpdatedAt)
	provider.UpdatedAt = now
	provider.UpdatedBy = identity.Username
	record := authProviderRecord(provider, secretCipher)
	if err := database.saveAuthProviderWithRoleMappings(r.Context(), record, expectedUpdatedAt); err != nil {
		if errors.Is(err, errConcurrentAuthProviderUpdate) {
			http.Error(w, "identity provider changed; reload before saving", http.StatusConflict)
			return
		}
		logAuthError("persist auth provider", err)
		http.Error(w, "identity provider could not be persisted", http.StatusInternalServerError)
		return
	}
	authenticator.mu.Lock()
	authenticator.providers[providerID] = provider
	authenticator.mu.Unlock()
	emitAuditLog("auth.provider.updated", identity.Username, map[string]any{
		"auth.provider": providerID, "auth.protocol": provider.Protocol,
	})
	jsonOut(w, authenticator.providerConfiguration(provider))
}

func oidcSecretBoundToClient(
	current authProviderConfig,
	issuer string,
	clientID string,
	providedSecret string,
) string {
	if providedSecret != "" {
		return providedSecret
	}
	if current.Protocol == "OIDC" && current.Issuer == issuer && current.ClientID == clientID {
		return current.ClientSecret
	}
	return ""
}

func authProviderRecord(provider authProviderConfig, secretCipher string) AuthProviderRecord {
	return AuthProviderRecord{
		ProviderID: provider.ID,
		Protocol:   provider.Protocol,
		Label:      provider.Label,
		Config: map[string]string{
			"issuer": provider.Issuer, "clientId": provider.ClientID,
			"userClaim": provider.UserClaim, "roleClaim": provider.RoleClaim,
			"spEntityId": provider.SPEntityID, "metadataUrl": provider.MetadataURL,
			"metadataXml": provider.MetadataXML, "nameIdAttribute": provider.NameIDAttribute,
			"userAttribute": provider.UserAttribute, "roleAttribute": provider.RoleAttribute,
		},
		SecretCipher:      secretCipher,
		Status:            provider.Status,
		ValidationMessage: provider.ValidationMessage,
		ValidatedAt:       provider.ValidatedAt,
		UpdatedAt:         provider.UpdatedAt,
		UpdatedBy:         provider.UpdatedBy,
		RoleMappings:      provider.RoleMappings,
	}
}

func deleteAuthProvider(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("provider")
	authenticator.mu.Lock()
	provider, known := authenticator.providers[providerID]
	authenticator.mu.Unlock()
	if !known {
		http.Error(w, "unknown identity provider", http.StatusNotFound)
		return
	}
	identity, _ := authenticatedIdentity(r)
	if !canDelegateRoles(identity, mappedRoleValues(provider.RoleMappings)) {
		http.Error(w, "cannot delete a provider mapped to permissions the current user does not possess", http.StatusForbidden)
		return
	}
	if err := database.deleteAuthProvider(r.Context(), providerID); err != nil {
		logAuthError("delete auth provider", err)
		http.Error(w, "identity provider could not be deleted", http.StatusInternalServerError)
		return
	}
	authenticator.mu.Lock()
	delete(authenticator.providers, providerID)
	authenticator.mu.Unlock()
	emitAuditLog("auth.provider.deleted", identity.Username, map[string]any{
		"auth.provider": providerID,
	})
	w.WriteHeader(http.StatusNoContent)
}

func preflightAuthProvider(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("provider")
	authenticator.mu.Lock()
	provider, known := authenticator.providers[providerID]
	authenticator.mu.Unlock()
	if !known {
		http.Error(w, "unknown identity provider", http.StatusNotFound)
		return
	}
	identity, _ := authenticatedIdentity(r)
	if !canDelegateRoles(identity, mappedRoleValues(provider.RoleMappings)) {
		http.Error(w, "cannot validate a provider mapped to permissions the current user does not possess", http.StatusForbidden)
		return
	}
	message, err := authenticator.preflightProvider(r.Context(), provider)
	status := "VALIDATED"
	var validatedAt *time.Time
	if err != nil {
		status = "ERROR"
		message = err.Error()
	} else {
		now := time.Now().UTC()
		validatedAt = &now
	}
	provider.Status = status
	provider.ValidationMessage = message
	provider.ValidatedAt = validatedAt
	var expectedUpdatedAt *time.Time
	if !provider.UpdatedAt.IsZero() {
		expected := provider.UpdatedAt.UTC().Truncate(time.Microsecond)
		expectedUpdatedAt = &expected
	}
	provider.UpdatedAt = nextProviderUpdatedAt(provider.UpdatedAt)
	provider.UpdatedBy = identity.Username
	secretCipher, encryptErr := authenticator.encryptSecret(provider.ClientSecret)
	if encryptErr != nil {
		http.Error(w, "provider validation result could not be encrypted", http.StatusInternalServerError)
		return
	}
	if persistErr := database.saveAuthProviderWithRoleMappings(
		r.Context(), authProviderRecord(provider, secretCipher), expectedUpdatedAt,
	); persistErr != nil {
		if errors.Is(persistErr, errConcurrentAuthProviderUpdate) {
			http.Error(w, "identity provider changed during validation; reload and retry", http.StatusConflict)
			return
		}
		http.Error(w, "provider validation result could not be persisted", http.StatusInternalServerError)
		return
	}
	authenticator.mu.Lock()
	authenticator.providers[providerID] = provider
	authenticator.mu.Unlock()
	emitAuditLog("auth.provider.preflight", identity.Username, map[string]any{
		"auth.provider": providerID, "auth.protocol": provider.Protocol, "auth.status": status,
	})
	if err != nil {
		jsonError(w, message, http.StatusUnprocessableEntity)
		return
	}
	jsonOut(w, authenticator.providerConfiguration(provider))
}

func (a *Authenticator) preflightProvider(ctx context.Context, provider authProviderConfig) (string, error) {
	if len(provider.RoleMappings) == 0 {
		return "", fmt.Errorf("at least one external-to-local role mapping is required")
	}
	if err := validateRoleMappings(provider.RoleMappings); err != nil {
		return "", err
	}
	if provider.Protocol == "OIDC" {
		if !provider.Configured() || !validIssuer(provider.Issuer) {
			return "", fmt.Errorf("OIDC configuration is incomplete")
		}
		ctx = oidc.ClientContext(ctx, a.client)
		discovery, err := oidc.NewProvider(ctx, provider.Issuer)
		if err != nil {
			return "", fmt.Errorf("OIDC discovery failed: %w", err)
		}
		if err := validateOIDCDiscoveryEndpoints(discovery); err != nil {
			return "", err
		}
		return "OIDC discovery validado; las credenciales se verifican al iniciar sesión.", nil
	}
	if provider.Protocol == "SAML" {
		if !a.samlHTTPSReady() {
			return "", fmt.Errorf("SAML browser login requires SERVER_PUBLIC_URL with HTTPS so the cross-site ACS POST can carry its secure flow cookie")
		}
		if _, err := a.samlServiceProvider(ctx, provider); err != nil {
			return "", err
		}
		return "Metadata IdP, endpoints SSO e identidad criptográfica del SP validados.", nil
	}
	return "", fmt.Errorf("unsupported provider protocol")
}

func validateRoleMappings(mappings map[string]string) error {
	for externalRole, localRole := range mappings {
		if strings.TrimSpace(externalRole) == "" {
			return fmt.Errorf("external role cannot be empty")
		}
		if _, known := rolePermissions[localRole]; !known {
			return fmt.Errorf("unknown local role %s", localRole)
		}
	}
	return nil
}

func mappedRoleValues(mappings map[string]string) []string {
	roles := make([]string, 0, len(mappings))
	for _, role := range mappings {
		roles = append(roles, role)
	}
	return roles
}

func authProviderRoleMappings(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("provider")
	authenticator.mu.Lock()
	provider, known := authenticator.providers[providerID]
	authenticator.mu.Unlock()
	if !known {
		http.Error(w, "unknown identity provider", http.StatusNotFound)
		return
	}
	jsonOut(w, map[string]any{"provider": providerID, "roleMappings": provider.RoleMappings})
}

func updateAuthProviderRoleMappings(w http.ResponseWriter, r *http.Request) {
	providerID := r.PathValue("provider")
	var payload struct {
		RoleMappings      map[string]string `json:"roleMappings"`
		ExpectedUpdatedAt *time.Time        `json:"expectedUpdatedAt"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 128<<10)).Decode(&payload) != nil ||
		payload.RoleMappings == nil {
		http.Error(w, "roleMappings object is required", http.StatusBadRequest)
		return
	}
	if err := validateRoleMappings(payload.RoleMappings); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	identity, _ := authenticatedIdentity(r)
	if !canDelegateRoles(identity, mappedRoleValues(payload.RoleMappings)) {
		http.Error(w, "cannot map a role with permissions the current user does not possess", http.StatusForbidden)
		return
	}
	authenticator.mu.Lock()
	provider, known := authenticator.providers[providerID]
	authenticator.mu.Unlock()
	if !known {
		http.Error(w, "unknown identity provider", http.StatusNotFound)
		return
	}
	if payload.ExpectedUpdatedAt == nil ||
		!provider.UpdatedAt.Equal(payload.ExpectedUpdatedAt.UTC().Truncate(time.Microsecond)) {
		http.Error(w, "identity provider changed; reload before saving", http.StatusConflict)
		return
	}
	if !canDelegateRoles(identity, mappedRoleValues(provider.RoleMappings)) {
		http.Error(w, "cannot modify a provider mapped to permissions the current user does not possess", http.StatusForbidden)
		return
	}
	provider.RoleMappings = payload.RoleMappings
	expectedUpdatedAt := provider.UpdatedAt.UTC().Truncate(time.Microsecond)
	provider.UpdatedAt = nextProviderUpdatedAt(provider.UpdatedAt)
	provider.UpdatedBy = identity.Username
	secretCipher, err := authenticator.encryptSecret(provider.ClientSecret)
	if err != nil {
		http.Error(w, "identity provider secret could not be encrypted", http.StatusInternalServerError)
		return
	}
	if err := database.saveAuthProviderWithRoleMappings(
		r.Context(), authProviderRecord(provider, secretCipher), &expectedUpdatedAt,
	); err != nil {
		if errors.Is(err, errConcurrentAuthProviderUpdate) {
			http.Error(w, "identity provider changed; reload before saving", http.StatusConflict)
			return
		}
		http.Error(w, "identity provider revision could not be persisted", http.StatusInternalServerError)
		return
	}
	authenticator.mu.Lock()
	authenticator.providers[providerID] = provider
	authenticator.mu.Unlock()
	emitAuditLog("auth.provider.role-mappings.updated", identity.Username, map[string]any{
		"auth.provider": providerID, "auth.mapping.count": len(payload.RoleMappings),
	})
	jsonOut(w, map[string]any{"provider": providerID, "roleMappings": payload.RoleMappings})
}

func logAuthError(operation string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", operation, err)
}

func jsonError(w http.ResponseWriter, message string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}

func (a *Authenticator) externalBaseURL(r *http.Request) string {
	configuration := a.network
	if configuration.ServerPublicURL == "" && a.publicURL != "" {
		configuration.ServerPublicURL = a.publicURL
	}
	return effectiveRequestOrigin(r, configuration)
}

func (a *Authenticator) oauthConfig(
	r *http.Request,
	provider authProviderConfig,
	discovery *oidc.Provider,
) oauth2.Config {
	return oauth2.Config{
		ClientID:     provider.ClientID,
		ClientSecret: provider.ClientSecret,
		Endpoint:     discovery.Endpoint(),
		RedirectURL: a.externalBaseURL(r) +
			"/api/auth/oidc/" + provider.ID + "/callback",
		Scopes: []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail},
	}
}

func encodeOIDCFlow(a *Authenticator, flow oidcFlowClaims) string {
	encoded, _ := json.Marshal(flow)
	payload := base64.RawURLEncoding.EncodeToString(encoded)
	return payload + "." + a.sign(payload)
}

func decodeOIDCFlow(a *Authenticator, raw string) (oidcFlowClaims, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 2 || !hmac.Equal([]byte(parts[1]), []byte(a.sign(parts[0]))) {
		return oidcFlowClaims{}, false
	}
	encoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return oidcFlowClaims{}, false
	}
	var flow oidcFlowClaims
	if json.Unmarshal(encoded, &flow) != nil || flow.Expires < time.Now().Unix() {
		return oidcFlowClaims{}, false
	}
	return flow, true
}

func setOIDCFlowCookie(w http.ResponseWriter, r *http.Request, value string) {
	// Local HTTP remains supported; externally published HTTPS origins always set Secure.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     oidcCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   10 * 60,
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   requestUsesTLS(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func oidcProviderForRequest(r *http.Request) (authProviderConfig, bool) {
	authenticator.mu.Lock()
	defer authenticator.mu.Unlock()
	provider, ok := authenticator.providers[r.PathValue("provider")]
	return provider, ok && provider.Protocol == "OIDC" && provider.Enabled()
}

func (a *Authenticator) samlHTTPSReady() bool {
	publicURL, err := url.Parse(a.publicURL)
	return err == nil && publicURL.Scheme == "https" && publicURL.Host != ""
}

func (a *Authenticator) providerEnabled(provider authProviderConfig) bool {
	return provider.Enabled() && (provider.Protocol != "SAML" || a.samlHTTPSReady())
}

func authOIDCStart(w http.ResponseWriter, r *http.Request) {
	provider, ok := oidcProviderForRequest(r)
	if !ok {
		http.Error(w, "identity provider is not configured", http.StatusServiceUnavailable)
		return
	}
	ctx := oidc.ClientContext(r.Context(), authenticator.client)
	discovery, err := oidc.NewProvider(ctx, provider.Issuer)
	if err != nil {
		emitAuditLog("auth.oidc.discovery.failed", "anonymous", map[string]any{
			"auth.provider": provider.ID,
			"error.type":    fmt.Sprintf("%T", err),
		})
		http.Error(w, "identity provider is unavailable", http.StatusBadGateway)
		return
	}
	if err := validateOIDCDiscoveryEndpoints(discovery); err != nil {
		emitAuditLog("auth.oidc.discovery.rejected", "anonymous", map[string]any{
			"auth.provider": provider.ID,
			"error.type":    fmt.Sprintf("%T", err),
		})
		http.Error(w, "identity provider discovery is unsafe", http.StatusBadGateway)
		return
	}
	flow := oidcFlowClaims{
		Provider: provider.ID,
		State:    randomToken(24),
		Nonce:    randomToken(24),
		Verifier: oauth2.GenerateVerifier(),
		Expires:  time.Now().Add(10 * time.Minute).Unix(),
	}
	setOIDCFlowCookie(w, r, encodeOIDCFlow(authenticator, flow))
	config := authenticator.oauthConfig(r, provider, discovery)
	location := config.AuthCodeURL(
		flow.State,
		oidc.Nonce(flow.Nonce),
		oauth2.S256ChallengeOption(flow.Verifier),
	)
	http.Redirect(w, r, location, http.StatusFound)
}

func redirectAuthError(w http.ResponseWriter, r *http.Request, message string) {
	location := "/?auth_error=" + url.QueryEscape(message)
	http.Redirect(w, r, location, http.StatusFound)
}

func authOIDCCallback(w http.ResponseWriter, r *http.Request) {
	provider, ok := oidcProviderForRequest(r)
	if !ok {
		redirectAuthError(w, r, "El proveedor de identidad no está configurado.")
		return
	}
	cookie, err := r.Cookie(oidcCookieName)
	if err != nil {
		redirectAuthError(w, r, "La sesión de autenticación expiró.")
		return
	}
	flow, valid := decodeOIDCFlow(authenticator, cookie.Value)
	clearCookie(w, r, oidcCookieName)
	if !valid || flow.Provider != provider.ID ||
		subtle.ConstantTimeCompare([]byte(flow.State), []byte(r.URL.Query().Get("state"))) != 1 {
		redirectAuthError(w, r, "La respuesta del proveedor no coincide con la sesión iniciada.")
		return
	}
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		redirectAuthError(w, r, "El proveedor canceló o rechazó el acceso.")
		return
	}
	ctx := oidc.ClientContext(r.Context(), authenticator.client)
	discovery, err := oidc.NewProvider(ctx, provider.Issuer)
	if err != nil {
		redirectAuthError(w, r, "No se pudo consultar el proveedor de identidad.")
		return
	}
	if err := validateOIDCDiscoveryEndpoints(discovery); err != nil {
		redirectAuthError(w, r, "Los endpoints del proveedor de identidad no son seguros.")
		return
	}
	config := authenticator.oauthConfig(r, provider, discovery)
	oauthToken, err := config.Exchange(
		ctx,
		r.URL.Query().Get("code"),
		oauth2.VerifierOption(flow.Verifier),
	)
	if err != nil {
		redirectAuthError(w, r, "No se pudo completar el intercambio de autorización.")
		return
	}
	rawIDToken, ok := oauthToken.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		redirectAuthError(w, r, "El proveedor no devolvió un ID token.")
		return
	}
	idToken, err := discovery.Verifier(&oidc.Config{ClientID: provider.ClientID}).Verify(ctx, rawIDToken)
	if err != nil {
		redirectAuthError(w, r, "El ID token no superó la verificación.")
		return
	}
	var claims map[string]any
	if idToken.Claims(&claims) != nil ||
		subtle.ConstantTimeCompare([]byte(firstString(claims, "nonce")), []byte(flow.Nonce)) != 1 {
		redirectAuthError(w, r, "El nonce del ID token no coincide.")
		return
	}
	externalRoles := stringList(claims[provider.RoleClaim])
	roles := mappedLocalRoles(externalRoles, provider.RoleMappings)
	if len(roles) == 0 {
		redirectAuthError(w, r, "La identidad no tiene ningún rol autorizado en este Control Plane.")
		return
	}
	username := firstString(claims, provider.UserClaim, "preferred_username", "email", "name", "sub")
	if username == "" {
		redirectAuthError(w, r, "La identidad no contiene un identificador de usuario válido.")
		return
	}
	identity := Identity{
		Username:    username,
		Provider:    provider.ID,
		Roles:       roles,
		AuthVersion: providerAuthVersion(provider),
	}
	identity.Permissions = permissionsForRoles(identity.Roles)
	setSessionCookie(w, r, authenticator.issueSession(identity), 8*60*60)
	emitAuditLog("auth.login.succeeded", identity.Username, map[string]any{
		"auth.provider": identity.Provider,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

func authProviders(w http.ResponseWriter, r *http.Request) {
	identity, _ := authenticatedIdentity(r)
	payload := map[string]any{
		"identity":        identity,
		"providers":       authenticator.providerList(),
		"roles":           rolePermissions,
		"assignableRoles": assignableRoleIDs(identity),
		"roleMappings":    authenticator.roleMappings,
	}
	if hasPermission(identity, "auth.admin") {
		payload["configurations"] = authenticator.providerConfigurationList()
	}
	jsonOut(w, payload)
}
