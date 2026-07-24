package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	publicURLSourceServer  = "SERVER_PUBLIC_URL"
	publicURLSourceLegacy  = "AUTH_PUBLIC_URL"
	publicURLSourceRequest = "request"
)

type networkConfiguration struct {
	ServerPublicURL       string
	ServerPublicURLSource string
	OPAMPPublicURL        string
	OPAMPTLS              opampTLSConfiguration
	TrustedProxyCIDRs     []*net.IPNet
	TrustedProxyCIDRNames []string
	LegacyPublicURL       bool
}

type networkStatusResponse struct {
	PublicURL          string   `json:"publicUrl"`
	PublicURLSource    string   `json:"publicUrlSource"`
	OPAMPPublicURL     string   `json:"opampPublicUrl"`
	OPAMPTLSEnabled    bool     `json:"opampTlsEnabled"`
	TrustedProxyCIDRs  []string `json:"trustedProxyCidrs"`
	ProxyMode          string   `json:"proxyMode"`
	HTTPListenAddress  string   `json:"httpListenAddress"`
	OPAMPListenAddress string   `json:"opampListenAddress"`
	SubpathSupported   bool     `json:"subpathSupported"`
	PublicURLValid     bool     `json:"publicUrlValid"`
}

func loadNetworkConfiguration(lookup func(string) (string, bool)) (networkConfiguration, error) {
	configuration := networkConfiguration{ServerPublicURLSource: publicURLSourceRequest}
	opampTLS, err := loadOpAMPTLSConfiguration(lookup)
	if err != nil {
		return networkConfiguration{}, err
	}
	configuration.OPAMPTLS = opampTLS
	serverPublicURL, serverConfigured := lookup("SERVER_PUBLIC_URL")
	serverPublicURL = strings.TrimSpace(serverPublicURL)
	legacyPublicURL, legacyConfigured := lookup("AUTH_PUBLIC_URL")
	legacyPublicURL = strings.TrimSpace(legacyPublicURL)

	if serverConfigured && serverPublicURL != "" {
		canonical, err := validateServerPublicURL(serverPublicURL)
		if err != nil {
			return networkConfiguration{}, fmt.Errorf("SERVER_PUBLIC_URL: %w", err)
		}
		configuration.ServerPublicURL = canonical
		configuration.ServerPublicURLSource = publicURLSourceServer
	} else if legacyConfigured && legacyPublicURL != "" {
		canonical, err := validateServerPublicURL(legacyPublicURL)
		if err != nil {
			return networkConfiguration{}, fmt.Errorf("AUTH_PUBLIC_URL: %w", err)
		}
		configuration.ServerPublicURL = canonical
		configuration.ServerPublicURLSource = publicURLSourceLegacy
		configuration.LegacyPublicURL = true
	}

	if raw, configured := lookup("OPAMP_PUBLIC_URL"); configured && strings.TrimSpace(raw) != "" {
		canonical, err := validateOPAMPPublicURL(strings.TrimSpace(raw))
		if err != nil {
			return networkConfiguration{}, fmt.Errorf("OPAMP_PUBLIC_URL: %w", err)
		}
		configuration.OPAMPPublicURL = canonical
	}

	if raw, configured := lookup("SERVER_TRUSTED_PROXY_CIDRS"); configured && strings.TrimSpace(raw) != "" {
		networks, names, err := parseTrustedProxyCIDRs(raw)
		if err != nil {
			return networkConfiguration{}, fmt.Errorf("SERVER_TRUSTED_PROXY_CIDRS: %w", err)
		}
		configuration.TrustedProxyCIDRs = networks
		configuration.TrustedProxyCIDRNames = names
	}
	return configuration, nil
}

func validateServerPublicURL(raw string) (string, error) {
	parsed, err := validatePublicURL(raw, map[string]bool{"http": true, "https": true}, false)
	if err != nil {
		return "", err
	}
	parsed.Path = ""
	return parsed.String(), nil
}

func validateOPAMPPublicURL(raw string) (string, error) {
	parsed, err := validatePublicURL(raw, map[string]bool{
		"http": true, "https": true,
	}, true)
	if err != nil {
		return "", err
	}
	if parsed.EscapedPath() != "/v1/opamp" && parsed.EscapedPath() != "/v1/opamp/" {
		return "", fmt.Errorf("path must be /v1/opamp")
	}
	parsed.Path = "/v1/opamp"
	parsed.RawPath = ""
	return parsed.String(), nil
}

func validatePublicURL(raw string, allowedSchemes map[string]bool, allowPath bool) (*url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !parsed.IsAbs() || parsed.Opaque != "" || parsed.Host == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("must be an absolute URL")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	if !allowedSchemes[parsed.Scheme] {
		return nil, fmt.Errorf("uses an unsupported scheme")
	}
	if parsed.User != nil {
		return nil, fmt.Errorf("must not contain user information")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		return nil, fmt.Errorf("must not contain a query")
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("must not contain a fragment")
	}
	if !allowPath && parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
		return nil, fmt.Errorf("must not contain a subpath")
	}
	if !allowPath {
		parsed.RawPath = ""
		parsed.Path = ""
	}
	if parsed.Scheme == "http" || parsed.Scheme == "ws" {
		host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("insecure schemes are allowed only for loopback")
		}
	}
	return parsed, nil
}

func parseTrustedProxyCIDRs(raw string) ([]*net.IPNet, []string, error) {
	byName := map[string]*net.IPNet{}
	for _, candidate := range strings.Split(raw, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return nil, nil, fmt.Errorf("contains an empty CIDR")
		}
		_, network, err := net.ParseCIDR(candidate)
		if err != nil {
			return nil, nil, fmt.Errorf("contains an invalid CIDR")
		}
		byName[network.String()] = network
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	networks := make([]*net.IPNet, 0, len(names))
	for _, name := range names {
		networks = append(networks, byName[name])
	}
	return networks, names, nil
}

func activeNetworkConfiguration() networkConfiguration {
	if authenticator == nil {
		return networkConfiguration{ServerPublicURLSource: publicURLSourceRequest}
	}
	configuration := authenticator.network
	// Keep lightweight test fixtures and older embedders that set publicURL
	// directly compatible while all production construction goes through the
	// validated network configuration.
	if configuration.ServerPublicURL == "" && authenticator.publicURL != "" {
		configuration.ServerPublicURL = authenticator.publicURL
		configuration.ServerPublicURLSource = publicURLSourceServer
	}
	if configuration.ServerPublicURLSource == "" {
		configuration.ServerPublicURLSource = publicURLSourceRequest
	}
	return configuration
}

func requestComesFromTrustedProxy(r *http.Request, configuration networkConfiguration) bool {
	if len(configuration.TrustedProxyCIDRs) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		host = strings.Trim(strings.TrimSpace(r.RemoteAddr), "[]")
	}
	remoteIP := net.ParseIP(host)
	if remoteIP == nil {
		return false
	}
	for _, network := range configuration.TrustedProxyCIDRs {
		if network.Contains(remoteIP) {
			return true
		}
	}
	return false
}

type forwardedOrigin struct {
	Scheme string
	Host   string
}

func trustedForwardedOrigin(r *http.Request, configuration networkConfiguration) (forwardedOrigin, bool) {
	if !requestComesFromTrustedProxy(r, configuration) {
		return forwardedOrigin{}, false
	}
	if raw := strings.TrimSpace(r.Header.Get("Forwarded")); raw != "" {
		return parseForwardedOrigin(raw)
	}
	return parseXForwardedOrigin(r.Header)
}

func parseForwardedOrigin(raw string) (forwardedOrigin, bool) {
	if strings.ContainsAny(raw, "\r\n") {
		return forwardedOrigin{}, false
	}
	first := strings.TrimSpace(strings.Split(raw, ",")[0])
	result := forwardedOrigin{}
	seen := map[string]bool{}
	for _, parameter := range strings.Split(first, ";") {
		parts := strings.SplitN(strings.TrimSpace(parameter), "=", 2)
		if len(parts) != 2 {
			return forwardedOrigin{}, false
		}
		name := strings.ToLower(strings.TrimSpace(parts[0]))
		if name != "proto" && name != "host" {
			continue
		}
		if seen[name] {
			return forwardedOrigin{}, false
		}
		seen[name] = true
		value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
		switch name {
		case "proto":
			result.Scheme = strings.ToLower(value)
		case "host":
			result.Host = value
		}
	}
	return validateForwardedOrigin(result)
}

func parseXForwardedOrigin(header http.Header) (forwardedOrigin, bool) {
	result := forwardedOrigin{
		Scheme: firstForwardedValue(header.Get("X-Forwarded-Proto")),
		Host:   firstForwardedValue(header.Get("X-Forwarded-Host")),
	}
	result.Scheme = strings.ToLower(result.Scheme)
	return validateForwardedOrigin(result)
}

func firstForwardedValue(raw string) string {
	return strings.TrimSpace(strings.Split(raw, ",")[0])
}

func validateForwardedOrigin(origin forwardedOrigin) (forwardedOrigin, bool) {
	if origin.Scheme == "" && origin.Host == "" {
		return forwardedOrigin{}, false
	}
	if origin.Scheme != "" && origin.Scheme != "http" && origin.Scheme != "https" {
		return forwardedOrigin{}, false
	}
	if origin.Host != "" && !validForwardedHost(origin.Host) {
		return forwardedOrigin{}, false
	}
	return origin, true
}

func validForwardedHost(raw string) bool {
	if strings.ContainsAny(raw, "\r\n/\\@,;") || strings.ContainsAny(raw, " \t") {
		return false
	}
	parsed, err := url.Parse("//" + raw)
	return err == nil && parsed.Host == raw && parsed.Hostname() != "" && parsed.User == nil && parsed.Path == ""
}

func effectiveRequestOrigin(r *http.Request, configuration networkConfiguration) string {
	if configuration.ServerPublicURL != "" {
		return configuration.ServerPublicURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if forwarded, ok := trustedForwardedOrigin(r, configuration); ok {
		if forwarded.Scheme != "" {
			scheme = forwarded.Scheme
		}
		if forwarded.Host != "" {
			host = forwarded.Host
		}
	}
	return scheme + "://" + host
}

func systemNetwork(w http.ResponseWriter, _ *http.Request) {
	configuration := activeNetworkConfiguration()
	proxyMode := "DIRECT"
	if len(configuration.TrustedProxyCIDRs) > 0 {
		proxyMode = "TRUSTED"
	}
	jsonOut(w, networkStatusResponse{
		PublicURL:          configuration.ServerPublicURL,
		PublicURLSource:    configuration.ServerPublicURLSource,
		OPAMPPublicURL:     configuration.OPAMPPublicURL,
		OPAMPTLSEnabled:    configuration.OPAMPTLS.Enabled,
		TrustedProxyCIDRs:  append([]string(nil), configuration.TrustedProxyCIDRNames...),
		ProxyMode:          proxyMode,
		HTTPListenAddress:  ":8080",
		OPAMPListenAddress: ":4320",
		SubpathSupported:   false,
		PublicURLValid:     configuration.ServerPublicURL != "",
	})
}
