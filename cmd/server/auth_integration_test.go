//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"html"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crewjam/saml"
	jose "github.com/go-jose/go-jose/v4"
	dsig "github.com/russellhaering/goxmldsig"
)

func TestOIDCPreflightUsesDiscoveryAndDoesNotTrustFieldsAlone(t *testing.T) {
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		jsonOut(w, map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/keys",
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer server.Close()
	issuer = server.URL
	auth := &Authenticator{client: server.Client()}
	message, err := auth.preflightProvider(context.Background(), authProviderConfig{
		ID: "test", Protocol: "OIDC", Issuer: issuer,
		ClientID: "client", ClientSecret: "secret",
		RoleMappings: map[string]string{"platform-viewers": "viewer"},
	})
	if err != nil || !strings.Contains(message, "discovery") {
		t.Fatalf("expected real OIDC discovery preflight, got message=%q err=%v", message, err)
	}
	if _, err := auth.preflightProvider(context.Background(), authProviderConfig{
		ID: "invalid", Protocol: "OIDC", Issuer: issuer + "/missing",
		ClientID: "client", ClientSecret: "secret",
		RoleMappings: map[string]string{"platform-viewers": "viewer"},
	}); err == nil {
		t.Fatal("field-complete OIDC provider must not validate when discovery fails")
	}
	if _, err := auth.preflightProvider(context.Background(), authProviderConfig{
		ID: "unmapped", Protocol: "OIDC", Issuer: issuer,
		ClientID: "client", ClientSecret: "secret",
	}); err == nil {
		t.Fatal("provider without role mappings must not be enabled")
	}
}

func TestOIDCPreflightRejectsUnsafeAdvertisedEndpoints(t *testing.T) {
	fields := []string{
		"authorization_endpoint",
		"token_endpoint",
		"jwks_uri",
		"userinfo_endpoint",
		"device_authorization_endpoint",
		"pushed_authorization_request_endpoint",
		"registration_endpoint",
		"revocation_endpoint",
		"introspection_endpoint",
		"end_session_endpoint",
	}
	for _, field := range fields {
		t.Run(field, func(t *testing.T) {
			var issuer string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/openid-configuration" {
					http.NotFound(w, r)
					return
				}
				discovery := map[string]any{
					"issuer":                                issuer,
					"authorization_endpoint":                issuer + "/authorize",
					"token_endpoint":                        issuer + "/token",
					"jwks_uri":                              issuer + "/keys",
					"userinfo_endpoint":                     issuer + "/userinfo",
					"device_authorization_endpoint":         issuer + "/device",
					"pushed_authorization_request_endpoint": issuer + "/par",
					"registration_endpoint":                 issuer + "/registration",
					"revocation_endpoint":                   issuer + "/revoke",
					"introspection_endpoint":                issuer + "/introspect",
					"end_session_endpoint":                  issuer + "/logout",
					"subject_types_supported":               []string{"public"},
					"id_token_signing_alg_values_supported": []string{"RS256"},
				}
				discovery[field] = "http://identity.example.test/unsafe"
				jsonOut(w, discovery)
			}))
			defer server.Close()
			issuer = server.URL
			auth := &Authenticator{client: server.Client()}
			_, err := auth.preflightProvider(context.Background(), authProviderConfig{
				ID: "unsafe", Protocol: "OIDC", Issuer: issuer,
				ClientID: "client", ClientSecret: "secret",
				RoleMappings: map[string]string{"platform-viewers": "viewer"},
			})
			if err == nil || !strings.Contains(err.Error(), field) {
				t.Fatalf("unsafe %s must fail preflight, got %v", field, err)
			}
		})
	}
}

func TestOIDCLoginRevalidatesAdvertisedEndpoints(t *testing.T) {
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		jsonOut(w, map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                "http://identity.example.test/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/keys",
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	}))
	defer server.Close()
	issuer = server.URL
	provider := authProviderConfig{
		ID: "unsafe", Protocol: "OIDC", Status: "VALIDATED", Issuer: issuer,
		ClientID: "client", ClientSecret: "secret",
		RoleMappings: map[string]string{"platform-viewers": "viewer"},
	}
	previous := authenticator
	defer func() { authenticator = previous }()
	authenticator = &Authenticator{
		signingKey: []byte("test-signing-key"),
		providers:  map[string]authProviderConfig{provider.ID: provider},
		client:     server.Client(),
	}
	request := httptest.NewRequest(http.MethodGet, "/api/auth/oidc/unsafe/start", nil)
	request.SetPathValue("provider", provider.ID)
	response := httptest.NewRecorder()
	authOIDCStart(response, request)
	if response.Code != http.StatusBadGateway || response.Header().Get("Location") != "" {
		t.Fatalf("runtime discovery revalidation must block unsafe redirect, got %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestOIDCAuthorizationCodeFlowCreatesMappedSession(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "oidc-test-key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	var issuer, expectedNonce string
	var tokenRequestHadVerifier bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			jsonOut(w, map[string]any{
				"issuer": issuer, "authorization_endpoint": issuer + "/authorize",
				"token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys",
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/keys":
			jsonOut(w, map[string]any{"keys": []jose.JSONWebKey{{
				Key: &key.PublicKey, KeyID: "oidc-test-key", Algorithm: string(jose.RS256), Use: "sig",
			}}})
		case "/token":
			_ = r.ParseForm()
			tokenRequestHadVerifier = r.Form.Get("code_verifier") != ""
			now := time.Now()
			claims, _ := json.Marshal(map[string]any{
				"iss": issuer, "sub": "ana", "aud": "control-plane-client",
				"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
				"nonce": expectedNonce, "email": "ana@example.test",
				"groups": []string{"platform-security"},
			})
			signed, signErr := signer.Sign(claims)
			if signErr != nil {
				http.Error(w, "sign token", http.StatusInternalServerError)
				return
			}
			compact, _ := signed.CompactSerialize()
			jsonOut(w, map[string]any{
				"access_token": "access", "token_type": "Bearer", "expires_in": 300,
				"id_token": compact,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	issuer = server.URL
	provider := authProviderConfig{
		ID: "oidc-test", Label: "OIDC Test", Protocol: "OIDC", Status: "VALIDATED",
		Issuer: issuer, ClientID: "control-plane-client", ClientSecret: "secret",
		UserClaim: "email", RoleClaim: "groups",
		RoleMappings: map[string]string{"platform-security": "security-admin"},
	}
	previous := authenticator
	defer func() { authenticator = previous }()
	authenticator = &Authenticator{
		signingKey: []byte("oidc-session-key"), publicURL: "http://localhost:8080",
		providers: map[string]authProviderConfig{provider.ID: provider}, client: server.Client(),
	}
	startRequest := httptest.NewRequest(
		http.MethodGet,
		"http://localhost:8080/api/auth/oidc/oidc-test/start",
		nil,
	)
	startRequest.SetPathValue("provider", provider.ID)
	startResponse := httptest.NewRecorder()
	authOIDCStart(startResponse, startRequest)
	if startResponse.Code != http.StatusFound {
		t.Fatalf("expected OIDC authorization redirect, got %d: %s", startResponse.Code, startResponse.Body.String())
	}
	authorizationURL, err := url.Parse(startResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	expectedNonce = authorizationURL.Query().Get("nonce")
	state := authorizationURL.Query().Get("state")
	if expectedNonce == "" || state == "" || authorizationURL.Query().Get("code_challenge") == "" ||
		authorizationURL.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("OIDC redirect is missing state, nonce or PKCE: %s", authorizationURL)
	}
	flowCookies := startResponse.Result().Cookies()
	if len(flowCookies) != 1 || flowCookies[0].Name != oidcCookieName || !flowCookies[0].HttpOnly {
		t.Fatalf("expected protected OIDC flow cookie, got %#v", flowCookies)
	}
	callbackRequest := httptest.NewRequest(
		http.MethodGet,
		"http://localhost:8080/api/auth/oidc/oidc-test/callback?code=valid-code&state="+url.QueryEscape(state),
		nil,
	)
	callbackRequest.SetPathValue("provider", provider.ID)
	callbackRequest.AddCookie(flowCookies[0])
	callbackResponse := httptest.NewRecorder()
	authOIDCCallback(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusFound || callbackResponse.Header().Get("Location") != "/" {
		t.Fatalf("expected successful OIDC callback, got %d: %s (%s)", callbackResponse.Code, callbackResponse.Body.String(), callbackResponse.Header().Get("Location"))
	}
	if !tokenRequestHadVerifier {
		t.Fatal("OIDC token exchange must include the PKCE verifier")
	}
	var sessionCookie *http.Cookie
	for _, cookie := range callbackResponse.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly {
		t.Fatalf("expected common HttpOnly session cookie, got %#v", callbackResponse.Result().Cookies())
	}
	sessionRequest := httptest.NewRequest(http.MethodGet, "http://localhost:8080/api/auth/session", nil)
	sessionRequest.AddCookie(sessionCookie)
	identity, ok := authenticator.identity(sessionRequest)
	if !ok || identity.Username != "ana@example.test" || !hasPermission(identity, "auth.admin") {
		t.Fatalf("unexpected OIDC identity: %#v", identity)
	}
}

func TestRBACDeniesViewerAndAllowsSecurityAdmin(t *testing.T) {
	previous := authenticator
	defer func() { authenticator = previous }()
	provider := authProviderConfig{
		ID: "test", Protocol: "OIDC", Issuer: "https://issuer.example.test",
		ClientID: "client", ClientSecret: "secret", Status: "VALIDATED",
		RoleMappings: map[string]string{"users": "viewer"}, UpdatedAt: time.Now().UTC(),
	}
	authenticator = &Authenticator{
		signingKey: []byte("rbac-test-key"),
		providers:  map[string]authProviderConfig{provider.ID: provider},
	}
	handler := requirePermission("auth.admin", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	viewer := Identity{
		Username: "viewer", Provider: "test", Roles: []string{"viewer"},
		AuthVersion: providerAuthVersion(provider),
	}
	viewer.Permissions = permissionsForRoles(viewer.Roles)
	viewerRequest := httptest.NewRequest(http.MethodGet, "/api/auth/providers", nil)
	viewerRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: authenticator.issueSession(viewer)})
	viewerResponse := httptest.NewRecorder()
	handler.ServeHTTP(viewerResponse, viewerRequest)
	if viewerResponse.Code != http.StatusForbidden {
		t.Fatalf("viewer must be denied auth.admin, got %d", viewerResponse.Code)
	}

	securityAdmin := Identity{
		Username: "security", Provider: "test", Roles: []string{"security-admin"},
		AuthVersion: providerAuthVersion(provider),
	}
	securityAdmin.Permissions = permissionsForRoles(securityAdmin.Roles)
	adminRequest := httptest.NewRequest(http.MethodGet, "/api/auth/providers", nil)
	adminRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: authenticator.issueSession(securityAdmin)})
	adminResponse := httptest.NewRecorder()
	handler.ServeHTTP(adminResponse, adminRequest)
	if adminResponse.Code != http.StatusNoContent {
		t.Fatalf("security-admin must be allowed auth.admin, got %d", adminResponse.Code)
	}
}

func TestUnknownExternalRoleFailsClosed(t *testing.T) {
	roles := mappedLocalRoles(
		[]string{"unmapped-tenant-role"},
		map[string]string{"known-role": "viewer"},
	)
	if len(roles) != 0 {
		t.Fatalf("an unknown external role must not implicitly receive viewer: %#v", roles)
	}
}

func TestViewerCannotPublishConfigurationEndpoint(t *testing.T) {
	previous := authenticator
	defer func() { authenticator = previous }()
	provider := authProviderConfig{
		ID: "test", Protocol: "OIDC", Issuer: "https://issuer.example.test",
		ClientID: "client", ClientSecret: "secret", Status: "VALIDATED",
		RoleMappings: map[string]string{"users": "viewer"}, UpdatedAt: time.Now().UTC(),
	}
	authenticator = &Authenticator{
		signingKey: []byte("config-rbac-key"),
		providers:  map[string]authProviderConfig{provider.ID: provider},
	}
	viewer := Identity{
		Username: "viewer", Provider: "test", Roles: []string{"viewer"},
		AuthVersion: providerAuthVersion(provider),
	}
	viewer.Permissions = permissionsForRoles(viewer.Roles)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/configs",
		strings.NewReader(`{"id":"test","target":"java-extension","body":"{}"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: authenticator.issueSession(viewer)})
	response := httptest.NewRecorder()
	saveConfig(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("viewer must not publish configurations, got %d: %s", response.Code, response.Body.String())
	}
}

func TestLoginResponseKeepsSessionTokenOnlyInHttpOnlyCookie(t *testing.T) {
	previous := authenticator
	defer func() { authenticator = previous }()
	authenticator = &Authenticator{
		masterUsername: "admin", masterPassword: "password", signingKey: []byte("login-key"),
	}
	request := httptest.NewRequest(
		http.MethodPost,
		"http://control-plane/api/auth/login",
		strings.NewReader(`{"username":"admin","password":"password"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	authLogin(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), `"token"`) {
		t.Fatalf("session token must not be returned in JSON: %s", response.Body.String())
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly {
		t.Fatalf("expected one HttpOnly session cookie, got %#v", cookies)
	}
}

type memorySAMLFlowRepository struct {
	mu    sync.Mutex
	flows map[string]struct {
		providerID  string
		requestID   string
		browserHash string
		expiresAt   time.Time
	}
}

func (repository *memorySAMLFlowRepository) saveSAMLFlow(
	_ context.Context,
	relayState string,
	providerID string,
	requestID string,
	browserHash string,
	expiresAt time.Time,
) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.flows == nil {
		repository.flows = map[string]struct {
			providerID  string
			requestID   string
			browserHash string
			expiresAt   time.Time
		}{}
	}
	repository.flows[relayState] = struct {
		providerID  string
		requestID   string
		browserHash string
		expiresAt   time.Time
	}{providerID: providerID, requestID: requestID, browserHash: browserHash, expiresAt: expiresAt}
	return nil
}

func (repository *memorySAMLFlowRepository) consumeSAMLFlow(
	_ context.Context,
	relayState string,
	providerID string,
	browserHash string,
) (string, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	flow, ok := repository.flows[relayState]
	if !ok || flow.providerID != providerID || flow.browserHash != browserHash || !flow.expiresAt.After(time.Now()) {
		return "", false, nil
	}
	delete(repository.flows, relayState)
	return flow.requestID, true, nil
}

type testSAMLSessionProvider struct{}

func (testSAMLSessionProvider) GetSession(
	_ http.ResponseWriter,
	_ *http.Request,
	_ *saml.IdpAuthnRequest,
) *saml.Session {
	now := time.Now()
	return &saml.Session{
		ID: "session-1", CreateTime: now, ExpireTime: now.Add(time.Hour), Index: "index-1",
		NameID: "ana@example.test", NameIDFormat: string(saml.EmailAddressNameIDFormat),
		UserEmail: "ana@example.test",
		CustomAttributes: []saml.Attribute{
			{Name: "roles", Values: []saml.AttributeValue{{Value: "platform-security"}}},
		},
	}
}

type testServiceProviderProvider struct{ metadata *saml.EntityDescriptor }

func (provider testServiceProviderProvider) GetServiceProvider(
	_ *http.Request,
	_ string,
) (*saml.EntityDescriptor, error) {
	return provider.metadata, nil
}

func generateTestCertificate(t *testing.T, commonName string) (*rsa.PrivateKey, *x509.Certificate, []byte, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, certificate, certificatePEM, keyPEM
}

func hiddenFormValue(t *testing.T, markup string, name string) string {
	t.Helper()
	pattern := regexp.MustCompile(`name="` + regexp.QuoteMeta(name) + `" value="([^"]+)"`)
	match := pattern.FindStringSubmatch(markup)
	if len(match) != 2 {
		t.Fatalf("hidden input %s not found in %s", name, markup)
	}
	return html.UnescapeString(match[1])
}

func TestSignedSAMLLoginUsesCookieIndependentOneTimeRelayState(t *testing.T) {
	spKey, _, spCertificatePEM, spKeyPEM := generateTestCertificate(t, "control-plane-sp")
	_ = spKey
	t.Setenv("AUTH_SAML_SP_CERT", string(spCertificatePEM))
	t.Setenv("AUTH_SAML_SP_KEY", string(spKeyPEM))

	idpKey, idpCertificate, _, _ := generateTestCertificate(t, "test-idp")
	var idp *saml.IdentityProvider
	idpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sso" {
			idp.ServeSSO(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	defer idpServer.Close()
	metadataURL, _ := url.Parse(idpServer.URL + "/metadata")
	ssoURL, _ := url.Parse(idpServer.URL + "/sso")
	idp = &saml.IdentityProvider{
		Key: idpKey, Signer: idpKey, Certificate: idpCertificate,
		MetadataURL: *metadataURL, SSOURL: *ssoURL, LoginURL: *ssoURL,
		SessionProvider: testSAMLSessionProvider{}, SignatureMethod: dsig.RSASHA256SignatureMethod,
		Logger: log.New(io.Discard, "", 0),
	}
	idpMetadataXML, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	provider := authProviderConfig{
		ID: "native-saml", Label: "Native SAML", Protocol: "SAML", Status: "VALIDATED",
		SPEntityID:  "https://localhost:8080/api/auth/saml/native-saml/metadata",
		MetadataXML: string(idpMetadataXML), UserAttribute: "email", RoleAttribute: "roles",
		RoleMappings: map[string]string{"platform-security": "security-admin"},
	}
	previousAuthenticator, previousFlows := authenticator, samlFlows
	defer func() { authenticator, samlFlows = previousAuthenticator, previousFlows }()
	authenticator = &Authenticator{
		signingKey: []byte("saml-session-key"), publicURL: "https://localhost:8080",
		providers: map[string]authProviderConfig{provider.ID: provider}, client: idpServer.Client(),
	}
	samlFlows = &memorySAMLFlowRepository{}
	serviceProvider, err := authenticator.samlServiceProvider(context.Background(), provider)
	if err != nil {
		t.Fatalf("build SAML SP: %v", err)
	}
	idp.ServiceProviderProvider = testServiceProviderProvider{metadata: serviceProvider.Metadata()}

	startRequest := httptest.NewRequest(http.MethodGet, "https://localhost:8080/api/auth/saml/native-saml/start", nil)
	startRequest.SetPathValue("provider", provider.ID)
	startResponse := httptest.NewRecorder()
	authSAMLStart(startResponse, startRequest)
	if startResponse.Code != http.StatusFound {
		t.Fatalf("expected SAML redirect, got %d: %s", startResponse.Code, startResponse.Body.String())
	}
	var flowCookie *http.Cookie
	for _, cookie := range startResponse.Result().Cookies() {
		if cookie.Name == samlFlowCookieName {
			flowCookie = cookie
		}
	}
	if flowCookie == nil || !flowCookie.HttpOnly {
		t.Fatalf("expected browser-bound SAML flow cookie, got %#v", startResponse.Result().Cookies())
	}
	idpResponse, err := idpServer.Client().Get(startResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	idpBody, _ := io.ReadAll(idpResponse.Body)
	_ = idpResponse.Body.Close()
	if idpResponse.StatusCode != http.StatusOK {
		t.Fatalf("IdP rejected AuthnRequest: %d %s", idpResponse.StatusCode, idpBody)
	}
	samlResponse := hiddenFormValue(t, string(idpBody), "SAMLResponse")
	relayState := hiddenFormValue(t, string(idpBody), "RelayState")
	flowRepository := samlFlows.(*memorySAMLFlowRepository)
	flowRepository.mu.Lock()
	requestID := flowRepository.flows[relayState].requestID
	flowRepository.mu.Unlock()
	verificationRequest := httptest.NewRequest(
		http.MethodPost,
		"https://localhost:8080/api/auth/saml/native-saml/acs",
		strings.NewReader(url.Values{"SAMLResponse": {samlResponse}}.Encode()),
	)
	verificationRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = verificationRequest.ParseForm()
	if _, verificationErr := serviceProvider.ParseResponse(verificationRequest, []string{requestID}); verificationErr != nil {
		if invalid, ok := verificationErr.(*saml.InvalidResponseError); ok {
			t.Fatalf("generated signed SAML response did not verify: %v", invalid.PrivateErr)
		}
		t.Fatalf("generated signed SAML response did not verify: %v", verificationErr)
	}

	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}}
	attackRequest := httptest.NewRequest(
		http.MethodPost,
		"https://localhost:8080/api/auth/saml/native-saml/acs",
		strings.NewReader(form.Encode()),
	)
	attackRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	attackRequest.SetPathValue("provider", provider.ID)
	attackResponse := httptest.NewRecorder()
	authSAMLACS(attackResponse, attackRequest)
	if attackResponse.Header().Get("Location") == "/" {
		t.Fatal("SAML ACS without the initiating browser cookie must be rejected")
	}

	acsRequest := httptest.NewRequest(
		http.MethodPost,
		"https://localhost:8080/api/auth/saml/native-saml/acs",
		strings.NewReader(form.Encode()),
	)
	acsRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	acsRequest.SetPathValue("provider", provider.ID)
	acsRequest.AddCookie(flowCookie)
	acsResponse := httptest.NewRecorder()
	authSAMLACS(acsResponse, acsRequest)
	if acsResponse.Code != http.StatusFound || acsResponse.Header().Get("Location") != "/" {
		t.Fatalf("expected successful SAML ACS, got %d: %s", acsResponse.Code, acsResponse.Body.String())
	}
	var sessionCookie *http.Cookie
	for _, cookie := range acsResponse.Result().Cookies() {
		if cookie.Name == sessionCookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || !sessionCookie.HttpOnly {
		t.Fatalf("expected common HttpOnly session cookie, got %#v", acsResponse.Result().Cookies())
	}
	sessionRequest := httptest.NewRequest(http.MethodGet, "https://localhost:8080/api/auth/session", nil)
	sessionRequest.AddCookie(sessionCookie)
	identity, ok := authenticator.identity(sessionRequest)
	if !ok || identity.Username != "ana@example.test" || !hasPermission(identity, "auth.admin") {
		t.Fatalf("unexpected SAML identity: %#v", identity)
	}

	replayRequest := httptest.NewRequest(
		http.MethodPost,
		"https://localhost:8080/api/auth/saml/native-saml/acs",
		strings.NewReader(form.Encode()),
	)
	replayRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayRequest.SetPathValue("provider", provider.ID)
	replayResponse := httptest.NewRecorder()
	authSAMLACS(replayResponse, replayRequest)
	if replayResponse.Code != http.StatusFound || !strings.Contains(replayResponse.Header().Get("Location"), "auth_error") {
		t.Fatalf("replayed SAML response must be rejected, got %d %s", replayResponse.Code, replayResponse.Header().Get("Location"))
	}
}
