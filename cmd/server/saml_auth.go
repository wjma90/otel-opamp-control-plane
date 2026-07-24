package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	dsig "github.com/russellhaering/goxmldsig"
)

type samlFlowRepository interface {
	saveSAMLFlow(context.Context, string, string, string, string, time.Time) error
	consumeSAMLFlow(context.Context, string, string, string) (string, bool, error)
}

var samlFlows samlFlowRepository

const samlFlowCookieName = "o11y_saml_flow"

func samlFlowBrowserHash(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])
}

func setSAMLFlowCookie(w http.ResponseWriter, r *http.Request, providerID string, secret string, maxAge int) {
	secure := requestUsesTLS(r)
	sameSite := http.SameSiteLaxMode
	if secure {
		sameSite = http.SameSiteNoneMode
	}
	// Local HTTP remains supported; SAML is enabled only for an externally published HTTPS URL.
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name:     samlFlowCookieName,
		Value:    secret,
		Path:     "/api/auth/saml/" + providerID + "/acs",
		MaxAge:   maxAge,
		Expires:  time.Now().Add(time.Duration(maxAge) * time.Second),
		HttpOnly: true,
		Secure:   secure,
		SameSite: sameSite,
	})
}

func readSecretOrFile(valueName string, fileName string) ([]byte, error) {
	if value := strings.TrimSpace(os.Getenv(valueName)); value != "" {
		return []byte(strings.ReplaceAll(value, `\n`, "\n")), nil
	}
	if path := strings.TrimSpace(os.Getenv(fileName)); path != "" {
		value, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", fileName, err)
		}
		return value, nil
	}
	return nil, fmt.Errorf("%s or %s is required", valueName, fileName)
}

func loadSAMLSPKeyPair() (crypto.Signer, *x509.Certificate, string, error) {
	certificatePEM, err := readSecretOrFile("AUTH_SAML_SP_CERT", "AUTH_SAML_SP_CERT_FILE")
	if err != nil {
		return nil, nil, "", err
	}
	privateKeyPEM, err := readSecretOrFile("AUTH_SAML_SP_KEY", "AUTH_SAML_SP_KEY_FILE")
	if err != nil {
		return nil, nil, "", err
	}
	keyPair, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, nil, "", fmt.Errorf("parse SAML SP certificate/key: %w", err)
	}
	if len(keyPair.Certificate) == 0 {
		return nil, nil, "", fmt.Errorf("SAML SP certificate chain is empty")
	}
	certificate, err := x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, nil, "", fmt.Errorf("parse SAML SP leaf certificate: %w", err)
	}
	if time.Now().Before(certificate.NotBefore) || time.Now().After(certificate.NotAfter) {
		return nil, nil, "", fmt.Errorf("SAML SP certificate is not currently valid")
	}
	signer, ok := keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, nil, "", fmt.Errorf("SAML SP private key does not implement crypto.Signer")
	}
	var signatureMethod string
	switch signer.(type) {
	case *rsa.PrivateKey:
		signatureMethod = dsig.RSASHA256SignatureMethod
	case *ecdsa.PrivateKey:
		signatureMethod = dsig.ECDSASHA256SignatureMethod
	default:
		return nil, nil, "", fmt.Errorf("SAML SP private key must be RSA or ECDSA")
	}
	return signer, certificate, signatureMethod, nil
}

func (a *Authenticator) samlMetadata(
	ctx context.Context,
	provider authProviderConfig,
) (*saml.EntityDescriptor, error) {
	if provider.MetadataXML != "" {
		metadata, err := samlsp.ParseMetadata([]byte(provider.MetadataXML))
		if err != nil {
			return nil, fmt.Errorf("invalid SAML IdP metadata XML: %w", err)
		}
		return metadata, nil
	}
	if provider.MetadataURL == "" || !validIssuer(provider.MetadataURL) {
		return nil, fmt.Errorf("valid SAML IdP metadata URL or XML is required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, provider.MetadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create SAML metadata request: %w", err)
	}
	response, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch SAML IdP metadata: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return nil, fmt.Errorf("fetch SAML IdP metadata: HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (2<<20)+1))
	if err != nil {
		return nil, fmt.Errorf("read SAML IdP metadata: %w", err)
	}
	if len(body) > 2<<20 {
		return nil, fmt.Errorf("SAML IdP metadata exceeds 2 MiB")
	}
	metadata, err := samlsp.ParseMetadata(body)
	if err != nil {
		return nil, fmt.Errorf("invalid SAML IdP metadata: %w", err)
	}
	return metadata, nil
}

func (a *Authenticator) samlServiceProvider(
	ctx context.Context,
	provider authProviderConfig,
) (*saml.ServiceProvider, error) {
	if !a.samlHTTPSReady() {
		return nil, fmt.Errorf("SERVER_PUBLIC_URL with HTTPS is required for SAML")
	}
	metadata, err := a.samlMetadata(ctx, provider)
	if err != nil {
		return nil, err
	}
	if len(metadata.IDPSSODescriptors) == 0 {
		return nil, fmt.Errorf("SAML metadata has no IDPSSODescriptor")
	}
	if err := validateSAMLSSOEndpoints(metadata); err != nil {
		return nil, err
	}
	key, certificate, signatureMethod, err := loadSAMLSPKeyPair()
	if err != nil {
		return nil, err
	}
	metadataURL, _ := url.Parse(a.publicURL + "/api/auth/saml/" + provider.ID + "/metadata")
	acsURL, _ := url.Parse(a.publicURL + "/api/auth/saml/" + provider.ID + "/acs")
	serviceProvider := &saml.ServiceProvider{
		EntityID:          provider.SPEntityID,
		Key:               key,
		Certificate:       certificate,
		MetadataURL:       *metadataURL,
		AcsURL:            *acsURL,
		IDPMetadata:       metadata,
		HTTPClient:        a.client,
		SignatureMethod:   signatureMethod,
		AuthnNameIDFormat: saml.UnspecifiedNameIDFormat,
		AllowIDPInitiated: false,
	}
	return serviceProvider, nil
}

func validateSAMLSSOEndpoints(metadata *saml.EntityDescriptor) error {
	if metadata == nil {
		return fmt.Errorf("SAML metadata is unavailable")
	}
	foundSupported := false
	for _, descriptor := range metadata.IDPSSODescriptors {
		for _, endpoint := range descriptor.SingleSignOnServices {
			if endpoint.Binding != saml.HTTPRedirectBinding && endpoint.Binding != saml.HTTPPostBinding {
				continue
			}
			foundSupported = true
			if !validAuthEndpointURL(endpoint.Location) {
				return fmt.Errorf(
					"SAML metadata exposes an unsafe %s SSO endpoint; use absolute HTTPS (HTTP is allowed only for loopback tests)",
					endpoint.Binding,
				)
			}
			if endpoint.ResponseLocation != "" && !validAuthEndpointURL(endpoint.ResponseLocation) {
				return fmt.Errorf(
					"SAML metadata exposes an unsafe %s response endpoint; use absolute HTTPS (HTTP is allowed only for loopback tests)",
					endpoint.Binding,
				)
			}
		}
	}
	if !foundSupported {
		return fmt.Errorf("SAML metadata has no supported Redirect or POST SSO endpoint")
	}
	return nil
}

func samlProviderForRequest(r *http.Request, requireValidated bool) (authProviderConfig, bool) {
	authenticator.mu.Lock()
	defer authenticator.mu.Unlock()
	provider, ok := authenticator.providers[r.PathValue("provider")]
	if !ok || provider.Protocol != "SAML" || !provider.Configured() {
		return authProviderConfig{}, false
	}
	if requireValidated && !authenticator.providerEnabled(provider) {
		return authProviderConfig{}, false
	}
	return provider, true
}

func authSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	provider, ok := samlProviderForRequest(r, false)
	if !ok {
		http.Error(w, "SAML provider is not configured", http.StatusNotFound)
		return
	}
	serviceProvider, err := authenticator.samlServiceProvider(r.Context(), provider)
	if err != nil {
		http.Error(w, "SAML service provider is unavailable", http.StatusServiceUnavailable)
		return
	}
	value, err := xml.MarshalIndent(serviceProvider.Metadata(), "", "  ")
	if err != nil {
		http.Error(w, "SAML metadata could not be generated", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// xml.MarshalIndent produced the document and nosniff prevents HTML interpretation.
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	_, _ = w.Write(value)
}

func authSAMLStart(w http.ResponseWriter, r *http.Request) {
	provider, ok := samlProviderForRequest(r, true)
	if !ok {
		http.Error(w, "SAML provider is not validated", http.StatusServiceUnavailable)
		return
	}
	serviceProvider, err := authenticator.samlServiceProvider(r.Context(), provider)
	if err != nil {
		http.Error(w, "SAML identity provider is unavailable", http.StatusBadGateway)
		return
	}
	binding := saml.HTTPRedirectBinding
	destination := serviceProvider.GetSSOBindingLocation(binding)
	if destination == "" {
		binding = saml.HTTPPostBinding
		destination = serviceProvider.GetSSOBindingLocation(binding)
	}
	if !validAuthEndpointURL(destination) {
		http.Error(w, "SAML identity provider destination is unsafe", http.StatusBadGateway)
		return
	}
	authRequest, err := serviceProvider.MakeAuthenticationRequest(
		destination,
		binding,
		saml.HTTPPostBinding,
	)
	if err != nil {
		http.Error(w, "SAML authentication request could not be generated", http.StatusInternalServerError)
		return
	}
	relayState := randomToken(24)
	browserSecret := randomToken(32)
	if samlFlows == nil || samlFlows.saveSAMLFlow(
		r.Context(), relayState, provider.ID, authRequest.ID,
		samlFlowBrowserHash(browserSecret), time.Now().Add(10*time.Minute),
	) != nil {
		http.Error(w, "SAML authentication flow could not be persisted", http.StatusInternalServerError)
		return
	}
	setSAMLFlowCookie(w, r, provider.ID, browserSecret, 10*60)
	if binding == saml.HTTPRedirectBinding {
		redirectURL, err := authRequest.Redirect(relayState, serviceProvider)
		if err != nil {
			http.Error(w, "SAML redirect could not be generated", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
		return
	}
	destinationURL, _ := url.Parse(destination)
	formAction := destinationURL.Scheme + "://" + destinationURL.Host
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; form-action "+formAction)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// crewjam/saml generates the signed form; destination was URL-validated and CSP restricts form-action.
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	_, _ = w.Write(bytes.Join([][]byte{
		[]byte("<!doctype html><html><body>"), authRequest.Post(relayState), []byte("</body></html>"),
	}, nil))
}

func assertionValues(assertion *saml.Assertion, name string) []string {
	values := []string{}
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			if attribute.Name != name && attribute.FriendlyName != name {
				continue
			}
			for _, value := range attribute.Values {
				if strings.TrimSpace(value.Value) != "" {
					values = append(values, strings.TrimSpace(value.Value))
				}
			}
		}
	}
	return values
}

func authSAMLACS(w http.ResponseWriter, r *http.Request) {
	provider, ok := samlProviderForRequest(r, true)
	if !ok {
		redirectAuthError(w, r, "El proveedor SAML no está configurado.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	if err := r.ParseForm(); err != nil {
		redirectAuthError(w, r, "La respuesta SAML no pudo procesarse.")
		return
	}
	relayState := strings.TrimSpace(r.Form.Get("RelayState"))
	if relayState == "" || samlFlows == nil {
		redirectAuthError(w, r, "La sesión SAML no existe o ya fue utilizada.")
		return
	}
	browserCookie, cookieErr := r.Cookie(samlFlowCookieName)
	if cookieErr != nil || strings.TrimSpace(browserCookie.Value) == "" {
		redirectAuthError(w, r, "La sesión SAML no pertenece a este navegador.")
		return
	}
	setSAMLFlowCookie(w, r, provider.ID, "", -1)
	requestID, valid, err := samlFlows.consumeSAMLFlow(
		r.Context(), relayState, provider.ID, samlFlowBrowserHash(browserCookie.Value),
	)
	if err != nil || !valid {
		redirectAuthError(w, r, "La sesión SAML no existe, expiró o ya fue utilizada.")
		return
	}
	serviceProvider, err := authenticator.samlServiceProvider(r.Context(), provider)
	if err != nil {
		redirectAuthError(w, r, "No se pudo verificar la respuesta SAML.")
		return
	}
	assertion, err := serviceProvider.ParseResponse(r, []string{requestID})
	if err != nil {
		emitAuditLog("auth.saml.response.rejected", "anonymous", map[string]any{
			"auth.provider": provider.ID, "error.type": fmt.Sprintf("%T", err),
		})
		redirectAuthError(w, r, "La firma o las condiciones de la respuesta SAML no son válidas.")
		return
	}
	usernameValues := assertionValues(assertion, provider.UserAttribute)
	username := ""
	if len(usernameValues) > 0 {
		username = usernameValues[0]
	}
	if username == "" && provider.NameIDAttribute != "" && provider.NameIDAttribute != "nameid" {
		nameIDValues := assertionValues(assertion, provider.NameIDAttribute)
		if len(nameIDValues) > 0 {
			username = nameIDValues[0]
		}
	}
	if username == "" && assertion.Subject != nil && assertion.Subject.NameID != nil {
		username = strings.TrimSpace(assertion.Subject.NameID.Value)
	}
	if username == "" {
		redirectAuthError(w, r, "La respuesta SAML no contiene una identidad de usuario.")
		return
	}
	externalRoles := assertionValues(assertion, provider.RoleAttribute)
	roles := mappedLocalRoles(externalRoles, provider.RoleMappings)
	if len(roles) == 0 {
		redirectAuthError(w, r, "La identidad SAML no tiene ningún rol autorizado en este Control Plane.")
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
		"auth.provider": provider.ID, "auth.protocol": "SAML",
	})
	http.Redirect(w, r, "/", http.StatusFound)
}
