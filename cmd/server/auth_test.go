package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthenticationSigningKeyCanComeFromProtectedFile(t *testing.T) {
	t.Setenv("AUTH_SIGNING_KEY", "")
	path := filepath.Join(t.TempDir(), "signing.key")
	want := strings.Repeat("k", minimumAuthSigningKeyBytes)
	if err := os.WriteFile(path, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AUTH_SIGNING_KEY_FILE", path)
	got, persistent, err := loadAuthSigningSecret()
	if err != nil || !persistent || got != want {
		t.Fatalf("unexpected signing key file result: persistent=%v key=%q err=%v", persistent, got, err)
	}
}

func TestAuthenticationSigningKeyConfigurationFailsClosed(t *testing.T) {
	t.Setenv("AUTH_SIGNING_KEY", strings.Repeat("i", minimumAuthSigningKeyBytes))
	t.Setenv("AUTH_SIGNING_KEY_FILE", "/tmp/ambiguous-auth-signing-key")
	if _, _, err := loadAuthSigningSecret(); err == nil {
		t.Fatal("inline and file signing keys must be rejected as ambiguous")
	}
	t.Setenv("AUTH_SIGNING_KEY_FILE", "")
	t.Setenv("AUTH_SIGNING_KEY", "too-short")
	if _, _, err := loadAuthSigningSecret(); err == nil {
		t.Fatal("weak signing key was accepted")
	}
	t.Setenv("AUTH_SIGNING_KEY", "")
	if _, _, err := loadAuthSigningSecret(); err == nil {
		t.Fatal("missing signing key must fail closed")
	}
}

func TestAuthenticatorRequiresExplicitValidBootstrapCredentials(t *testing.T) {
	t.Setenv("AUTH_SIGNING_KEY", strings.Repeat("s", minimumAuthSigningKeyBytes))
	t.Setenv("AUTH_SIGNING_KEY_FILE", "")
	t.Setenv("MASTER_USERNAME", "")
	t.Setenv("MASTER_PASSWORD", "valid-bootstrap-password")
	if _, err := newAuthenticator(); err == nil || !strings.Contains(err.Error(), "MASTER_USERNAME is required") {
		t.Fatalf("missing bootstrap username must fail closed, got %v", err)
	}

	t.Setenv("MASTER_USERNAME", "O11Y-ADMIN")
	t.Setenv("MASTER_PASSWORD", "")
	if _, err := newAuthenticator(); err == nil || !strings.Contains(err.Error(), "MASTER_PASSWORD is required") {
		t.Fatalf("missing bootstrap password must fail closed, got %v", err)
	}

	t.Setenv("MASTER_PASSWORD", "too-short")
	if _, err := newAuthenticator(); err == nil || !strings.Contains(err.Error(), "at least 12") {
		t.Fatalf("weak bootstrap password must be rejected, got %v", err)
	}

	t.Setenv("MASTER_PASSWORD", "valid-bootstrap-password")
	auth, err := newAuthenticator()
	if err != nil {
		t.Fatalf("valid explicit bootstrap credentials must be accepted: %v", err)
	}
	if auth.masterUsername != "o11y-admin" || auth.masterPassword != "valid-bootstrap-password" {
		t.Fatalf("unexpected normalized bootstrap credentials: %#v", auth)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestMasterSessionIsSignedAndHasAdminPermissions(t *testing.T) {
	auth := &Authenticator{
		masterUsername: "master",
		masterPassword: "secret",
		signingKey:     []byte("test-signing-key"),
	}
	token, identity, ok := auth.login("master", "secret")
	if !ok || token == "" {
		t.Fatal("expected master login to succeed")
	}
	if !hasPermission(identity, "collectors.edit") {
		t.Fatal("master must have all permissions")
	}
	restored, ok := auth.localIdentity(token)
	if !ok || restored.Username != "master" {
		t.Fatalf("expected signed session for master, got %#v", restored)
	}
}

func TestEmptyExternalRoleMappingGrantsNothing(t *testing.T) {
	if mappings := parseRoleMappings(""); len(mappings) != 0 {
		t.Fatalf("empty mapping must fail closed, got %#v", mappings)
	}
	mappings := parseRoleMappings("platform-viewers=viewer,attackers=unknown-role")
	if mappings["platform-viewers"] != "viewer" || mappings["attackers"] != "" {
		t.Fatalf("only explicit known local roles must be accepted: %#v", mappings)
	}
}

func TestExternalIdentityCacheIsBoundedAndDropsExpiredEntries(t *testing.T) {
	now := time.Now()
	auth := &Authenticator{cache: map[string]cachedIdentity{
		"expired": {identity: Identity{Username: "expired"}, expires: now.Add(-time.Second)},
	}}
	for index := 0; index < maxExternalIdentityCacheEntries+25; index++ {
		auth.cacheExternalIdentity(
			fmt.Sprintf("token-%d", index),
			cachedIdentity{
				identity: Identity{Username: fmt.Sprintf("user-%d", index)},
				expires:  now.Add(time.Duration(index+1) * time.Second),
			},
			now,
		)
	}
	if _, exists := auth.cache["expired"]; exists {
		t.Fatal("expired introspection identity was retained")
	}
	if len(auth.cache) != maxExternalIdentityCacheEntries {
		t.Fatalf("introspection cache is not bounded: got %d entries", len(auth.cache))
	}
}

func TestRolesDoNotGrantRemovedCaptureInventoryPermissions(t *testing.T) {
	removed := map[string]struct{}{
		"captures.view":  {},
		"captures.edit":  {},
		"inventory.view": {},
	}
	for role, permissions := range rolePermissions {
		for _, permission := range permissions {
			if _, obsolete := removed[permission]; obsolete {
				t.Fatalf("role %s still grants removed permission %s", role, permission)
			}
		}
	}
}

func TestExternalAuthEndpointRequiresConfidentialTransport(t *testing.T) {
	for _, rejected := range []string{
		"http://identity.example.test/introspect",
		"https://user:password@identity.example.test/introspect",
		"https://identity.example.test/introspect#fragment",
		"not-a-url",
	} {
		if validAuthEndpointURL(rejected) {
			t.Fatalf("unsafe authentication endpoint accepted: %s", rejected)
		}
	}
	for _, accepted := range []string{
		"https://identity.example.test/introspect",
		"http://localhost:8081/introspect",
		"http://127.0.0.1:8081/introspect",
		"http://[::1]:8081/introspect",
	} {
		if !validAuthEndpointURL(accepted) {
			t.Fatalf("valid authentication endpoint rejected: %s", accepted)
		}
	}
}

func TestIdentityProviderNetworkPolicyRejectsSpecialUseAddresses(t *testing.T) {
	for _, blocked := range []string{"10.0.0.1", "169.254.169.254", "192.168.1.10", "::1"} {
		if authProviderIPAllowed("idp.example.test", net.ParseIP(blocked), false) {
			t.Fatalf("special-use IdP address accepted by default: %s", blocked)
		}
	}
	if !authProviderIPAllowed("localhost", net.ParseIP("127.0.0.1"), false) {
		t.Fatal("loopback test IdP should be allowed only through the localhost hostname")
	}
	if !authProviderIPAllowed("idp.example.test", net.ParseIP("8.8.8.8"), false) {
		t.Fatal("public IdP address was rejected")
	}
	if !authProviderIPAllowed("idp.internal", net.ParseIP("10.0.0.1"), true) {
		t.Fatal("explicit private IdP network opt-in must allow enterprise endpoints")
	}
}

func TestIntrospectionClaimsRequireCurrentExpiryAndExpectedAudience(t *testing.T) {
	now := time.Now()
	validExpiry, ok := numericDate(float64(now.Add(time.Minute).Unix()))
	if !ok || !validExpiry.After(now) {
		t.Fatal("valid numeric date was rejected")
	}
	if _, ok := numericDate(float64(0)); ok {
		t.Fatal("invalid numeric date was accepted")
	}
	if !audienceContains([]any{"unrelated", "o11y-control-plane"}, "o11y-control-plane") {
		t.Fatal("expected audience was not recognized")
	}
	if audienceContains("another-api", "o11y-control-plane") {
		t.Fatal("wrong audience was accepted")
	}
}

func TestBrowserSessionUsesHttpOnlyCookie(t *testing.T) {
	auth := &Authenticator{
		masterUsername: "o11y-admin",
		masterPassword: "secret",
		signingKey:     []byte("test-signing-key"),
	}
	token, _, ok := auth.login("o11y-admin", "secret")
	if !ok {
		t.Fatal("expected local login to succeed")
	}
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://control-plane/api/auth/login", nil)
	setSessionCookie(recorder, request, token, 8*60*60)
	response := recorder.Result()
	cookies := response.Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].Name != sessionCookieName {
		t.Fatalf("expected an HttpOnly session cookie, got %#v", cookies)
	}
	authenticatedRequest := httptest.NewRequest(http.MethodGet, "/api/agents", nil)
	authenticatedRequest.AddCookie(cookies[0])
	identity, valid := auth.identity(authenticatedRequest)
	if !valid || identity.Username != "o11y-admin" {
		t.Fatalf("expected cookie session to be accepted, got %#v", identity)
	}
}

func TestLoginRequiresJSONContentType(t *testing.T) {
	previous := authenticator
	defer func() { authenticator = previous }()
	authenticator = &Authenticator{
		masterUsername: "admin", masterPassword: "password", signingKey: []byte("login-content-type-key"),
	}
	request := httptest.NewRequest(
		http.MethodPost, "/api/auth/login", strings.NewReader(`{"username":"admin","password":"password"}`),
	)
	response := httptest.NewRecorder()
	authLogin(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("non-JSON login must be rejected, got %d", response.Code)
	}
}

func TestWebSecurityRejectsCrossSiteCookieMutationAndSetsHeaders(t *testing.T) {
	previous := authenticator
	defer func() { authenticator = previous }()
	authenticator = &Authenticator{publicURL: "https://o11y.example.test"}
	calls := 0
	handler := webSecurityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	}))
	crossSite := httptest.NewRequest(http.MethodPost, "https://o11y.example.test/api/auth/logout", nil)
	crossSite.Header.Set("Origin", "https://attacker.example.test")
	crossSite.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session"})
	crossSiteResponse := httptest.NewRecorder()
	handler.ServeHTTP(crossSiteResponse, crossSite)
	if crossSiteResponse.Code != http.StatusForbidden || calls != 0 {
		t.Fatalf("cross-site cookie mutation must be rejected: status=%d calls=%d", crossSiteResponse.Code, calls)
	}
	cliRequest := httptest.NewRequest(http.MethodPost, "https://o11y.example.test/api/auth/logout", nil)
	cliRequest.Header.Set("X-O11y-CSRF", "1")
	cliRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session"})
	cliResponse := httptest.NewRecorder()
	handler.ServeHTTP(cliResponse, cliRequest)
	if cliResponse.Code != http.StatusNoContent || calls != 1 {
		t.Fatalf("cookie CLI request with explicit CSRF header must pass: status=%d calls=%d", cliResponse.Code, calls)
	}
	sameOrigin := httptest.NewRequest(http.MethodPost, "https://o11y.example.test/api/auth/logout", nil)
	sameOrigin.Header.Set("Origin", "https://o11y.example.test")
	sameOrigin.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session"})
	sameOriginResponse := httptest.NewRecorder()
	handler.ServeHTTP(sameOriginResponse, sameOrigin)
	if sameOriginResponse.Code != http.StatusNoContent || calls != 2 {
		t.Fatalf("same-origin request must pass: status=%d calls=%d", sameOriginResponse.Code, calls)
	}
	csp := sameOriginResponse.Header().Get("Content-Security-Policy")
	if csp == "" || strings.Contains(csp, "unsafe-inline") ||
		!strings.Contains(csp, "style-src 'self'") ||
		!strings.Contains(csp, "font-src 'self'") ||
		strings.Contains(csp, "fonts.googleapis.com") ||
		strings.Contains(csp, "fonts.gstatic.com") ||
		sameOriginResponse.Header().Get("Strict-Transport-Security") == "" ||
		sameOriginResponse.Header().Get("X-Content-Type-Options") != "nosniff" ||
		sameOriginResponse.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("security headers are incomplete: %#v", sameOriginResponse.Header())
	}
}

func TestSAMLFlowCookieUsesSchemeAppropriateSameSitePolicy(t *testing.T) {
	httpResponse := httptest.NewRecorder()
	setSAMLFlowCookie(
		httpResponse,
		httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/auth/saml/test/start", nil),
		"test", "secret", 600,
	)
	httpCookie := httpResponse.Result().Cookies()[0]
	if httpCookie.Secure || httpCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("loopback HTTP SAML cookie must be Lax and non-Secure: %#v", httpCookie)
	}
	httpsResponse := httptest.NewRecorder()
	setSAMLFlowCookie(
		httpsResponse,
		httptest.NewRequest(http.MethodGet, "https://o11y.example.test/api/auth/saml/test/start", nil),
		"test", "secret", 600,
	)
	httpsCookie := httpsResponse.Result().Cookies()[0]
	if !httpsCookie.Secure || httpsCookie.SameSite != http.SameSiteNoneMode {
		t.Fatalf("HTTPS SAML cookie must be Secure and SameSite=None: %#v", httpsCookie)
	}
}

func TestMasterRejectsInvalidPassword(t *testing.T) {
	auth := &Authenticator{
		masterUsername: "master",
		masterPassword: "secret",
		signingKey:     []byte("test-signing-key"),
	}
	if _, _, ok := auth.login("master", "wrong"); ok {
		t.Fatal("invalid password must be rejected")
	}
}

func TestLoginCookieKeepsSubsequentBrowserRequestAuthenticated(t *testing.T) {
	previous := authenticator
	defer func() { authenticator = previous }()
	authenticator = &Authenticator{
		masterUsername: "o11y-admin",
		masterPassword: "o11y-admin-password",
		signingKey:     []byte("test-signing-key"),
		providers:      configuredProviders(),
	}
	loginRequest := httptest.NewRequest(
		http.MethodPost,
		"http://control-plane/api/auth/login",
		strings.NewReader(`{"Username":"o11y-admin","Password":"o11y-admin-password"}`),
	)
	loginRequest.Header.Set("Content-Type", "application/json")
	loginRecorder := httptest.NewRecorder()
	authLogin(loginRecorder, loginRequest)
	if loginRecorder.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d: %s", loginRecorder.Code, loginRecorder.Body.String())
	}
	cookies := loginRecorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected one session cookie, got %d", len(cookies))
	}
	sessionRequest := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	sessionRequest.AddCookie(cookies[0])
	sessionRecorder := httptest.NewRecorder()
	requirePermission("agents.view", authSession).ServeHTTP(sessionRecorder, sessionRequest)
	if sessionRecorder.Code != http.StatusOK {
		t.Fatalf("expected cookie session 200, got %d: %s", sessionRecorder.Code, sessionRecorder.Body.String())
	}
}

func TestPublicProvidersOnlyReturnsFullyConfiguredButtons(t *testing.T) {
	previous := authenticator
	defer func() { authenticator = previous }()
	authenticator = &Authenticator{
		signingKey: []byte("test-signing-key"),
		providers: map[string]authProviderConfig{
			"microsoft": {ID: "microsoft", Label: "Microsoft", Protocol: "OIDC", Status: "INACTIVE"},
			"google": {
				ID: "google", Label: "Google", Protocol: "OIDC", Issuer: "https://accounts.google.com",
				ClientID: "client", ClientSecret: "secret", Status: "VALIDATED",
				RoleMappings: map[string]string{"users": "viewer"},
			},
			"corporate": {ID: "corporate", Label: "SSO", Protocol: "SAML", Status: "INACTIVE"},
		},
	}
	recorder := httptest.NewRecorder()
	authPublicProviders(recorder, httptest.NewRequest(http.MethodGet, "/api/auth/public-providers", nil))
	if recorder.Code != http.StatusOK || strings.Contains(recorder.Body.String(), "microsoft") ||
		!strings.Contains(recorder.Body.String(), "google") {
		t.Fatalf("unexpected public provider response: %s", recorder.Body.String())
	}
}

func TestControlTokenCannotAuthenticateAdministrativeAPI(t *testing.T) {
	previous := authenticator
	defer func() { authenticator = previous }()
	auth := &Authenticator{signingKey: []byte("key")}
	authenticator = auth
	request := httptest.NewRequest("GET", "/api/agents", nil)
	request.Header.Set("Authorization", "Bearer break-glass")
	if identity, ok := auth.identity(request); ok {
		t.Fatalf("CONTROL_TOKEN must never create an administrative identity, got %#v", identity)
	}
	response := httptest.NewRecorder()
	requirePermission("agents.view", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}).ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("CONTROL_TOKEN must receive 401 from administrative APIs, got %d", response.Code)
	}
}

func TestBrowserCookieIsNeverForwardedToOAuthIntrospection(t *testing.T) {
	calls := 0
	auth := &Authenticator{
		signingKey:       []byte("cookie-boundary-test-key"),
		introspectionURL: "https://identity.example.test/introspect",
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			return nil, errors.New("test transport")
		})},
	}
	request := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "untrusted-browser-cookie"})
	if _, ok := auth.identity(request); ok {
		t.Fatal("invalid browser cookie must not authenticate")
	}
	if calls != 0 {
		t.Fatalf("browser cookie was sent to introspection %d times", calls)
	}
	bearerRequest := httptest.NewRequest(http.MethodGet, "/api/auth/session", nil)
	bearerRequest.Header.Set("Authorization", "Bearer opaque-api-token")
	_, _ = auth.identity(bearerRequest)
	if calls != 1 {
		t.Fatalf("opaque Authorization bearer token should use introspection, got %d calls", calls)
	}
}

func TestOIDCConfigurationReturnsCanonicalPublicCallbackURL(t *testing.T) {
	auth := &Authenticator{publicURL: "https://o11y.example.test"}
	configuration := auth.providerConfiguration(authProviderConfig{
		ID: "corporate", Protocol: "OIDC",
	})
	if configuration["callbackUrl"] != "https://o11y.example.test/api/auth/oidc/corporate/callback" {
		t.Fatalf("unexpected canonical callback URL: %#v", configuration["callbackUrl"])
	}
}

func TestOIDCSecretIsOnlyPreservedForSameIssuerAndClient(t *testing.T) {
	current := authProviderConfig{
		Protocol: "OIDC", Issuer: "https://issuer.example.test",
		ClientID: "client-a", ClientSecret: "stored-secret",
	}
	if got := oidcSecretBoundToClient(
		current, current.Issuer, current.ClientID, "",
	); got != "stored-secret" {
		t.Fatalf("same client must preserve its write-only secret, got %q", got)
	}
	if got := oidcSecretBoundToClient(
		current, "https://other.example.test", current.ClientID, "",
	); got != "" {
		t.Fatalf("issuer change must require a new secret, got %q", got)
	}
	if got := oidcSecretBoundToClient(
		current, current.Issuer, "client-b", "",
	); got != "" {
		t.Fatalf("client ID change must require a new secret, got %q", got)
	}
	if got := oidcSecretBoundToClient(
		current, "https://other.example.test", "client-b", "new-secret",
	); got != "new-secret" {
		t.Fatalf("explicit replacement secret must be accepted, got %q", got)
	}
}

func TestExternalSessionRequiresCurrentProviderRevision(t *testing.T) {
	provider := authProviderConfig{
		ID:           "corporate",
		Protocol:     "OIDC",
		Issuer:       "https://issuer.example.test",
		ClientID:     "client",
		ClientSecret: "secret",
		Status:       "VALIDATED",
		RoleMappings: map[string]string{"users": "viewer"},
		UpdatedAt:    time.Date(2026, time.July, 19, 12, 0, 0, 0, time.UTC),
	}
	auth := &Authenticator{
		signingKey: []byte("external-session-test-key"),
		providers:  map[string]authProviderConfig{provider.ID: provider},
	}
	identity := Identity{
		Username:    "ana@example.test",
		Provider:    provider.ID,
		Roles:       []string{"viewer"},
		AuthVersion: providerAuthVersion(provider),
	}
	token := auth.issueSession(identity)
	if _, ok := auth.localIdentity(token); !ok {
		t.Fatal("session must be accepted while the provider revision is current")
	}
	provider.UpdatedAt = provider.UpdatedAt.Add(time.Microsecond)
	auth.providers[provider.ID] = provider
	if _, ok := auth.localIdentity(token); ok {
		t.Fatal("provider update must invalidate sessions issued by the previous revision")
	}
	delete(auth.providers, provider.ID)
	if _, ok := auth.localIdentity(token); ok {
		t.Fatal("deleted provider must not authenticate an existing session")
	}
}

func TestSecurityAdminCannotTakeOverOrValidateAdminMappedProvider(t *testing.T) {
	previous := authenticator
	defer func() { authenticator = previous }()
	provider := authProviderConfig{
		ID: "privileged", Label: "Privileged SSO", Protocol: "OIDC",
		Issuer: "https://trusted.example.test", ClientID: "trusted-client",
		ClientSecret: "trusted-secret", Status: "CONFIGURED",
		RoleMappings: map[string]string{"platform-admins": "admin"},
	}
	authenticator = &Authenticator{
		signingKey: []byte("provider-takeover-test-key"),
		providers:  map[string]authProviderConfig{provider.ID: provider},
	}
	securityAdmin := Identity{
		Username: "security", Provider: "local", Roles: []string{"security-admin"},
	}
	securityAdmin.Permissions = permissionsForRoles(securityAdmin.Roles)

	updateRequest := httptest.NewRequest(
		http.MethodPut,
		"/api/auth/providers/privileged",
		strings.NewReader(`{"protocol":"OIDC","label":"Captured","issuer":"https://attacker.example.test","clientId":"attacker","clientSecret":"secret"}`),
	)
	updateRequest.SetPathValue("provider", provider.ID)
	updateRequest = updateRequest.WithContext(context.WithValue(
		updateRequest.Context(), authContextKey{}, securityAdmin,
	))
	updateResponse := httptest.NewRecorder()
	updateAuthProvider(updateResponse, updateRequest)
	if updateResponse.Code != http.StatusForbidden {
		t.Fatalf("provider takeover without roleMappings must be forbidden, got %d", updateResponse.Code)
	}

	preflightRequest := httptest.NewRequest(
		http.MethodPost, "/api/auth/providers/privileged/preflight", nil,
	)
	preflightRequest.SetPathValue("provider", provider.ID)
	preflightRequest = preflightRequest.WithContext(context.WithValue(
		preflightRequest.Context(), authContextKey{}, securityAdmin,
	))
	preflightResponse := httptest.NewRecorder()
	preflightAuthProvider(preflightResponse, preflightRequest)
	if preflightResponse.Code != http.StatusForbidden {
		t.Fatalf("privileged provider preflight must be forbidden, got %d", preflightResponse.Code)
	}
}

func TestStoredOIDCProviderRemainsRepairableAfterSigningKeyRotation(t *testing.T) {
	original := &Authenticator{signingKey: []byte("original-signing-key")}
	secretCipher, err := original.encryptSecret("client-secret")
	if err != nil {
		t.Fatal(err)
	}
	updatedAt := time.Date(2026, time.July, 19, 12, 30, 0, 0, time.UTC)
	record := AuthProviderRecord{
		ProviderID: "corporate",
		Protocol:   "OIDC",
		Label:      "Empresa",
		Config: map[string]string{
			"issuer": "https://idp.example.test", "clientId": "control-plane",
			"userClaim": "email", "roleClaim": "groups",
		},
		SecretCipher: secretCipher,
		Status:       "VALIDATED",
		UpdatedAt:    updatedAt,
		UpdatedBy:    "admin",
		RoleMappings: map[string]string{"platform-viewers": "viewer"},
	}
	rotated := &Authenticator{
		signingKey: []byte("rotated-signing-key"),
		providers:  map[string]authProviderConfig{},
	}
	if err := rotated.applyStoredProviders([]AuthProviderRecord{record}); err != nil {
		t.Fatalf("public provider configuration must still load: %v", err)
	}
	provider, found := rotated.providers[record.ProviderID]
	if !found || !provider.CredentialsUnavailable || provider.Status != "ERROR" {
		t.Fatalf("expected visible repairable provider, got %#v", provider)
	}
	configuration := rotated.providerConfiguration(provider)
	if configuration["credentialsUnavailable"] != true || configuration["updatedAt"] != updatedAt {
		t.Fatalf("repair metadata missing from provider response: %#v", configuration)
	}
}

func TestSAMLLoginRequiresHTTPSPublicURL(t *testing.T) {
	provider := authProviderConfig{
		ID: "saml", Protocol: "SAML", Status: "VALIDATED",
		SPEntityID: "urn:o11y:test", MetadataXML: "<EntityDescriptor/>",
		RoleMappings: map[string]string{"users": "viewer"},
	}
	httpAuth := &Authenticator{publicURL: "http://localhost:8080"}
	if httpAuth.providerEnabled(provider) {
		t.Fatal("SAML login must stay disabled when the public ACS is HTTP")
	}
	if _, err := httpAuth.preflightProvider(context.Background(), provider); err == nil ||
		!strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected actionable HTTPS preflight error, got %v", err)
	}
	httpsAuth := &Authenticator{publicURL: "https://o11y.example.test"}
	if !httpsAuth.providerEnabled(provider) {
		t.Fatal("validated SAML provider should be enabled on an HTTPS public URL")
	}
}

func TestAuthProviderLoopbackPolicySupportsLocalMocks(t *testing.T) {
	for host, address := range map[string]string{
		"localhost": "127.0.0.1", "127.0.0.1": "127.0.0.1", "::1": "::1",
	} {
		if !authProviderIPAllowed(host, net.ParseIP(address), false) {
			t.Fatalf("loopback host %q must be available to local identity-provider mocks", host)
		}
	}
	if authProviderIPAllowed("idp.internal", net.ParseIP("10.0.0.10"), false) {
		t.Fatal("private IdP addresses must require explicit opt-in")
	}
}
