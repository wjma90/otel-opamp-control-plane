package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerPublicURLValidation(t *testing.T) {
	for _, test := range []struct {
		name      string
		value     string
		canonical string
		valid     bool
	}{
		{name: "https", value: "https://control.example.test", canonical: "https://control.example.test", valid: true},
		{name: "root slash", value: "https://control.example.test/", canonical: "https://control.example.test", valid: true},
		{name: "loopback http", value: "http://127.0.0.1:8080", canonical: "http://127.0.0.1:8080", valid: true},
		{name: "loopback range", value: "http://127.10.20.30:8080", canonical: "http://127.10.20.30:8080", valid: true},
		{name: "loopback ipv6", value: "http://[::1]:8080", canonical: "http://[::1]:8080", valid: true},
		{name: "relative", value: "control.example.test", valid: false},
		{name: "remote http", value: "http://control.example.test", valid: false},
		{name: "userinfo", value: "https://admin:secret@control.example.test", valid: false},
		{name: "query", value: "https://control.example.test?tenant=a", valid: false},
		{name: "fragment", value: "https://control.example.test#settings", valid: false},
		{name: "subpath", value: "https://control.example.test/o11y", valid: false},
		{name: "lookalike loopback", value: "http://localhost.example.test", valid: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			actual, err := validateServerPublicURL(test.value)
			if test.valid && (err != nil || actual != test.canonical) {
				t.Fatalf("expected %q, got %q, %v", test.canonical, actual, err)
			}
			if !test.valid && err == nil {
				t.Fatalf("unsafe public URL was accepted as %q", actual)
			}
		})
	}
}

func TestOPAMPPublicURLAcceptsEndpointPathButRejectsCredentialsAndInsecureRemoteSchemes(t *testing.T) {
	for _, accepted := range []string{
		"https://opamp.example.test/v1/opamp",
		"http://localhost:4320/v1/opamp",
	} {
		if _, err := validateOPAMPPublicURL(accepted); err != nil {
			t.Fatalf("valid OpAMP public URL %q rejected: %v", accepted, err)
		}
	}
	for _, rejected := range []string{
		"http://opamp.example.test/v1/opamp",
		"ws://opamp.example.test/v1/opamp",
		"ws://[::1]:4320/v1/opamp",
		"wss://opamp.example.test/v1/opamp",
		"wss://token@opamp.example.test/v1/opamp",
		"wss://opamp.example.test/v1/opamp?token=secret",
		"wss://opamp.example.test/v1/opamp#fragment",
		"wss://opamp.example.test",
		"wss://opamp.example.test/",
		"wss://opamp.example.test/opamp",
		"wss://opamp.example.test/v1/opamp/other",
	} {
		if _, err := validateOPAMPPublicURL(rejected); err == nil {
			t.Fatalf("unsafe OpAMP public URL accepted: %s", rejected)
		}
	}
	canonical, err := validateOPAMPPublicURL("https://opamp.example.test/v1/opamp/")
	if err != nil || canonical != "https://opamp.example.test/v1/opamp" {
		t.Fatalf("trailing slash was not canonicalized: %q, %v", canonical, err)
	}
}

func TestNetworkConfigurationPrefersServerPublicURLAndSupportsLegacyFallback(t *testing.T) {
	configuration, err := loadNetworkConfiguration(mapEnvironment(map[string]string{
		"SERVER_PUBLIC_URL": "https://new.example.test/",
		"AUTH_PUBLIC_URL":   "https://legacy.example.test",
		"OPAMP_PUBLIC_URL":  "https://opamp.example.test/v1/opamp",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if configuration.ServerPublicURL != "https://new.example.test" ||
		configuration.ServerPublicURLSource != publicURLSourceServer || configuration.LegacyPublicURL {
		t.Fatalf("SERVER_PUBLIC_URL did not take precedence: %#v", configuration)
	}

	legacy, err := loadNetworkConfiguration(mapEnvironment(map[string]string{
		"AUTH_PUBLIC_URL": "https://legacy.example.test/",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if legacy.ServerPublicURL != "https://legacy.example.test" ||
		legacy.ServerPublicURLSource != publicURLSourceLegacy || !legacy.LegacyPublicURL {
		t.Fatalf("legacy fallback was not identified: %#v", legacy)
	}
}

func TestTrustedProxyCIDRsAreStrictCanonicalAndDeduplicated(t *testing.T) {
	configuration, err := loadNetworkConfiguration(mapEnvironment(map[string]string{
		"SERVER_TRUSTED_PROXY_CIDRS": "10.0.1.7/8, 2001:db8::5/32,10.0.0.0/8",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "2001:db8::/32"}
	if len(configuration.TrustedProxyCIDRNames) != len(want) {
		t.Fatalf("unexpected trusted proxy CIDRs: %#v", configuration.TrustedProxyCIDRNames)
	}
	for index := range want {
		if configuration.TrustedProxyCIDRNames[index] != want[index] {
			t.Fatalf("unexpected trusted proxy CIDRs: %#v", configuration.TrustedProxyCIDRNames)
		}
	}
	for _, invalid := range []string{"10.0.0.1", "10.0.0.0/8,", "not-a-cidr"} {
		if _, err := loadNetworkConfiguration(mapEnvironment(map[string]string{
			"SERVER_TRUSTED_PROXY_CIDRS": invalid,
		})); err == nil {
			t.Fatalf("invalid trusted proxy list accepted: %q", invalid)
		}
	}
}

func TestForwardedHeadersAreUsedOnlyFromTrustedRemoteAddress(t *testing.T) {
	configuration, err := loadNetworkConfiguration(mapEnvironment(map[string]string{
		"SERVER_TRUSTED_PROXY_CIDRS": "10.0.0.0/8",
	}))
	if err != nil {
		t.Fatal(err)
	}
	trusted := httptest.NewRequest(http.MethodGet, "http://internal:8080/api/auth/session", nil)
	trusted.RemoteAddr = "10.20.30.40:41234"
	trusted.Header.Set("Forwarded", `for=192.0.2.10;proto=https;host="control.example.test"`)
	if got := effectiveRequestOrigin(trusted, configuration); got != "https://control.example.test" {
		t.Fatalf("trusted RFC Forwarded origin ignored: %s", got)
	}

	xForwarded := httptest.NewRequest(http.MethodGet, "http://internal:8080/api/auth/session", nil)
	xForwarded.RemoteAddr = "10.20.30.41:41234"
	xForwarded.Header.Set("X-Forwarded-Proto", "https")
	xForwarded.Header.Set("X-Forwarded-Host", "x-forwarded.example.test")
	if got := effectiveRequestOrigin(xForwarded, configuration); got != "https://x-forwarded.example.test" {
		t.Fatalf("trusted X-Forwarded origin ignored: %s", got)
	}

	untrusted := httptest.NewRequest(http.MethodGet, "http://internal:8080/api/auth/session", nil)
	untrusted.RemoteAddr = "192.0.2.50:41234"
	untrusted.Header = trusted.Header.Clone()
	untrusted.Header.Set("X-Forwarded-Proto", "https")
	untrusted.Header.Set("X-Forwarded-Host", "attacker.example.test")
	if got := effectiveRequestOrigin(untrusted, configuration); got != "http://internal:8080" {
		t.Fatalf("untrusted forwarding headers changed public origin: %s", got)
	}
}

func TestMalformedForwardedHeaderFailsClosedWithoutUsingXForwardedFallback(t *testing.T) {
	configuration, err := loadNetworkConfiguration(mapEnvironment(map[string]string{
		"SERVER_TRUSTED_PROXY_CIDRS": "10.0.0.0/8",
	}))
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://internal:8080/", nil)
	request.RemoteAddr = "10.0.0.10:1234"
	request.Header.Set("Forwarded", "proto=javascript;host=attacker.example.test")
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-Host", "fallback.example.test")
	if got := effectiveRequestOrigin(request, configuration); got != "http://internal:8080" {
		t.Fatalf("malformed Forwarded header must fail closed, got %s", got)
	}
}

func TestCanonicalPublicURLControlsCookiesRedirectBaseAndCSRF(t *testing.T) {
	previous := authenticator
	t.Cleanup(func() { authenticator = previous })
	configuration, err := loadNetworkConfiguration(mapEnvironment(map[string]string{
		"SERVER_PUBLIC_URL":          "https://control.example.test",
		"SERVER_TRUSTED_PROXY_CIDRS": "10.0.0.0/8",
	}))
	if err != nil {
		t.Fatal(err)
	}
	authenticator = &Authenticator{publicURL: configuration.ServerPublicURL, network: configuration}

	request := httptest.NewRequest(http.MethodPost, "http://internal:8080/api/auth/logout", nil)
	request.RemoteAddr = "10.0.0.10:1234"
	request.Header.Set("Forwarded", "proto=http;host=attacker.example.test")
	if got := authenticator.externalBaseURL(request); got != "https://control.example.test" {
		t.Fatalf("canonical public URL must win over forwarded headers: %s", got)
	}
	if !requestUsesTLS(request) {
		t.Fatal("canonical HTTPS URL must produce secure browser behavior behind an HTTP proxy hop")
	}

	recorder := httptest.NewRecorder()
	setSessionCookie(recorder, request, "signed-session", 60)
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure {
		t.Fatalf("canonical HTTPS URL must create a Secure cookie: %#v", cookies)
	}

	request.Header.Set("Origin", "https://control.example.test")
	if !requestHasTrustedOrigin(request) {
		t.Fatal("canonical public origin must pass CSRF validation")
	}
	request.Header.Set("Origin", "https://attacker.example.test")
	if requestHasTrustedOrigin(request) {
		t.Fatal("forwarded host must not override canonical CSRF origin")
	}
}

func TestSystemNetworkEndpointIsAuthenticatedReadOnlyAndSecretFree(t *testing.T) {
	previous := authenticator
	t.Cleanup(func() { authenticator = previous })
	configuration, err := loadNetworkConfiguration(mapEnvironment(map[string]string{
		"SERVER_PUBLIC_URL":          "https://control.example.test",
		"OPAMP_PUBLIC_URL":           "https://opamp.example.test/v1/opamp",
		"SERVER_TRUSTED_PROXY_CIDRS": "10.0.0.0/8",
	}))
	if err != nil {
		t.Fatal(err)
	}
	authenticator = &Authenticator{
		masterUsername: "admin", masterPassword: "do-not-expose",
		signingKey: []byte("do-not-expose-signing-key"), publicURL: configuration.ServerPublicURL,
		network: configuration,
	}
	handler := requirePermission("agents.view", systemNetwork)

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/system/network", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("network configuration must require authentication, got %d", unauthorized.Code)
	}

	token, _, ok := authenticator.login("admin", "do-not-expose")
	if !ok {
		t.Fatal("test administrator login failed")
	}
	request := httptest.NewRequest(http.MethodGet, "/api/system/network", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected network endpoint status %d: %s", response.Code, response.Body.String())
	}
	var payload map[string]any
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload["publicUrl"] != "https://control.example.test" ||
		payload["opampPublicUrl"] != "https://opamp.example.test/v1/opamp" ||
		payload["opampTlsEnabled"] != false ||
		payload["publicUrlSource"] != publicURLSourceServer ||
		payload["proxyMode"] != "TRUSTED" || payload["httpListenAddress"] != ":8080" ||
		payload["opampListenAddress"] != ":4320" || payload["subpathSupported"] != false ||
		payload["publicUrlValid"] != true {
		t.Fatalf("unexpected public network response: %#v", payload)
	}
	if len(payload) != 10 {
		t.Fatalf("network endpoint contract changed unexpectedly: %#v", payload)
	}
	serialized, _ := json.Marshal(payload)
	for _, secret := range []string{"do-not-expose", "signing-key", "MASTER_PASSWORD", "AUTH_SIGNING_KEY"} {
		if strings.Contains(string(serialized), secret) {
			t.Fatalf("network endpoint exposed secret material: %s", serialized)
		}
	}
}

func TestSystemNetworkEndpointReportsDirectRequestDerivedMode(t *testing.T) {
	previous := authenticator
	t.Cleanup(func() { authenticator = previous })
	authenticator = &Authenticator{
		network: networkConfiguration{ServerPublicURLSource: publicURLSourceRequest},
	}
	response := httptest.NewRecorder()
	systemNetwork(response, httptest.NewRequest(http.MethodGet, "/api/system/network", nil))
	var payload networkStatusResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.PublicURL != "" || payload.PublicURLSource != "request" ||
		payload.ProxyMode != "DIRECT" || payload.PublicURLValid || payload.SubpathSupported {
		t.Fatalf("unexpected direct network status: %#v", payload)
	}
}

func TestOPAMPPublicURLDoesNotOverrideAgentReportedEndpoint(t *testing.T) {
	previous := authenticator
	t.Cleanup(func() { authenticator = previous })
	configuration, err := loadNetworkConfiguration(mapEnvironment(map[string]string{
		"OPAMP_PUBLIC_URL": "https://opamp.example.test/v1/opamp",
	}))
	if err != nil {
		t.Fatal(err)
	}
	authenticator = &Authenticator{network: configuration}
	request := httptest.NewRequest(http.MethodPost, "http://internal:4320/v1/opamp", nil)
	request.Header.Set("X-O11y-Transport", "http-poll")
	request.Header.Set("X-O11y-OpAMP-Endpoint", "http://stale.internal:4320/v1/opamp")
	if got := agentHints(request).opampEndpoint; got != "http://stale.internal:4320/v1/opamp" {
		t.Fatalf("diagnostic OPAMP_PUBLIC_URL must not alter an existing agent connection: %s", got)
	}
}

func mapEnvironment(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}
