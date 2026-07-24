//go:build integration

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNetworkEndpointThroughHTTPStackRequiresSessionAndReportsCanonicalConfiguration(t *testing.T) {
	previous := authenticator
	t.Cleanup(func() { authenticator = previous })
	configuration, err := loadNetworkConfiguration(mapEnvironment(map[string]string{
		"SERVER_PUBLIC_URL":          "https://control.example.test",
		"OPAMP_PUBLIC_URL":           "https://opamp.example.test/v1/opamp",
		"SERVER_TRUSTED_PROXY_CIDRS": "127.0.0.0/8,::1/128",
	}))
	if err != nil {
		t.Fatal(err)
	}
	authenticator = &Authenticator{
		masterUsername: "admin", masterPassword: "integration-password",
		signingKey: []byte("integration-network-signing-key"),
		publicURL:  configuration.ServerPublicURL,
		network:    configuration,
	}

	mux := http.NewServeMux()
	mux.Handle("GET /api/system/network", requirePermission("agents.view", systemNetwork))
	server := httptest.NewServer(webSecurityMiddleware(mux))
	defer server.Close()

	unauthorized, err := server.Client().Get(server.URL + "/api/system/network")
	if err != nil {
		t.Fatal(err)
	}
	_ = unauthorized.Body.Close()
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous request must receive 401, got %d", unauthorized.StatusCode)
	}

	token, _, ok := authenticator.login("admin", "integration-password")
	if !ok {
		t.Fatal("test administrator login failed")
	}
	request, _ := http.NewRequest(http.MethodGet, server.URL+"/api/system/network", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Forwarded", "proto=http;host=attacker.example.test")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("authenticated request failed: %d", response.StatusCode)
	}
	if response.Header.Get("Strict-Transport-Security") == "" {
		t.Fatal("canonical HTTPS URL must enable HSTS through the internal HTTP hop")
	}
	var payload networkStatusResponse
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.PublicURL != "https://control.example.test" ||
		payload.OPAMPPublicURL != "https://opamp.example.test/v1/opamp" ||
		payload.ProxyMode != "TRUSTED" || !payload.PublicURLValid || payload.SubpathSupported {
		t.Fatalf("unexpected network configuration: %#v", payload)
	}
}
