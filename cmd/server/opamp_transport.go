package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-telemetry/opamp-go/protobufs"
	"google.golang.org/protobuf/proto"
)

const (
	maxOpAMPRequestBytes            = 4 << 20
	maxKnownOpAMPAgents             = 4096
	maxReportedAttributes           = 128
	maxReportedAttributeKeyBytes    = 256
	maxReportedAttributeValueBytes  = 4096
	maxReportedAttributesTotalBytes = 64 << 10
	maxEffectiveConfigFiles         = 32
	maxEffectiveConfigNameBytes     = 256
	maxEffectiveConfigContentType   = 128
	maxEffectiveConfigFileBytes     = 1 << 20
	maxEffectiveConfigTotalBytes    = 2 << 20
	agentInventoryTTL               = 30 * 24 * time.Hour
	opampAuthModeDisabled           = "disabled"
	opampAuthModeToken              = "token"
)

type opampAuthentication struct {
	Mode  string
	Token string
}

type opampTLSConfiguration struct {
	Enabled  bool
	CertFile string
	KeyFile  string
}

func loadOpAMPTLSConfiguration(lookup func(string) (string, bool)) (opampTLSConfiguration, error) {
	rawEnabled, _ := lookup("OPAMP_TLS_ENABLED")
	rawEnabled = strings.TrimSpace(rawEnabled)
	enabled := false
	if rawEnabled != "" {
		parsed, err := strconv.ParseBool(rawEnabled)
		if err != nil {
			return opampTLSConfiguration{}, errors.New("OPAMP_TLS_ENABLED must be true or false")
		}
		enabled = parsed
	}

	certFile, _ := lookup("OPAMP_TLS_CERT_FILE")
	keyFile, _ := lookup("OPAMP_TLS_KEY_FILE")
	certFile = strings.TrimSpace(certFile)
	keyFile = strings.TrimSpace(keyFile)
	if !enabled {
		if certFile != "" || keyFile != "" {
			return opampTLSConfiguration{}, errors.New(
				"OPAMP_TLS_CERT_FILE and OPAMP_TLS_KEY_FILE require OPAMP_TLS_ENABLED=true",
			)
		}
		return opampTLSConfiguration{}, nil
	}
	if certFile == "" || keyFile == "" {
		return opampTLSConfiguration{}, errors.New(
			"OPAMP_TLS_CERT_FILE and OPAMP_TLS_KEY_FILE are required when OPAMP_TLS_ENABLED=true",
		)
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return opampTLSConfiguration{}, fmt.Errorf("load OpAMP TLS certificate: %w", err)
	}
	return opampTLSConfiguration{Enabled: true, CertFile: certFile, KeyFile: keyFile}, nil
}

func serveOpAMPHTTPServer(server *http.Server, configuration opampTLSConfiguration) error {
	if !configuration.Enabled {
		return server.ListenAndServe()
	}
	server.TLSConfig = opampServerTLSConfiguration()
	return server.ListenAndServeTLS(configuration.CertFile, configuration.KeyFile)
}

func opampServerTLSConfiguration() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12}
}

func opampAuthenticationFromEnvironment() (opampAuthentication, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("OPAMP_AUTH_MODE")))
	if mode == "" {
		mode = opampAuthModeDisabled
	}
	if mode != opampAuthModeDisabled && mode != opampAuthModeToken {
		return opampAuthentication{}, errors.New("OPAMP_AUTH_MODE must be disabled or token")
	}
	if mode == opampAuthModeDisabled {
		return opampAuthentication{Mode: mode}, nil
	}
	token := strings.TrimSpace(os.Getenv("CONTROL_TOKEN"))
	if token == "" {
		return opampAuthentication{}, errors.New("CONTROL_TOKEN is required when OPAMP_AUTH_MODE=token")
	}
	if len(token) > 4096 || strings.IndexFunc(token, func(character rune) bool {
		return character <= 0x20 || character > 0x7e
	}) >= 0 {
		return opampAuthentication{}, errors.New("CONTROL_TOKEN must contain at most 4096 visible ASCII characters")
	}
	return opampAuthentication{Mode: mode, Token: token}, nil
}

func (authentication opampAuthentication) authorized(value string) bool {
	if authentication.Mode == opampAuthModeDisabled {
		return true
	}
	expected := "Bearer " + authentication.Token
	return len(value) == len(expected) &&
		subtle.ConstantTimeCompare([]byte(value), []byte(expected)) == 1
}

// opampRequestMiddleware keeps untrusted bytes away from opamp-go's internal
// unbounded HTTP/WebSocket readers. This deployment deliberately supports only
// OpAMP HTTP polling; all current Java agents and Supervisors use that transport.
func opampRequestMiddleware(authentication opampAuthentication, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !authentication.authorized(r.Header.Get("Authorization")) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "OpAMP HTTP polling requires POST", http.StatusMethodNotAllowed)
			return
		}
		if strings.TrimSpace(r.Header.Get("Upgrade")) != "" {
			http.Error(w, "WebSocket transport is disabled; use HTTP polling", http.StatusUpgradeRequired)
			return
		}
		encoding := strings.TrimSpace(r.Header.Get("Content-Encoding"))
		if encoding != "" && !strings.EqualFold(encoding, "identity") {
			http.Error(w, "compressed OpAMP requests are not accepted", http.StatusUnsupportedMediaType)
			return
		}
		if r.ContentLength > maxOpAMPRequestBytes {
			http.Error(w, "OpAMP request is too large", http.StatusRequestEntityTooLarge)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxOpAMPRequestBytes+1))
		if err != nil {
			http.Error(w, "cannot read OpAMP request", http.StatusBadRequest)
			return
		}
		if len(body) > maxOpAMPRequestBytes {
			http.Error(w, "OpAMP request is too large", http.StatusRequestEntityTooLarge)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		next.ServeHTTP(w, r)
	})
}

func newOpAMPHTTPServer(
	handler http.Handler,
	connContext func(context.Context, net.Conn) context.Context,
) *http.Server {
	return &http.Server{
		Addr:              ":4320",
		Handler:           handler,
		ConnContext:       connContext,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func opampProtocolError(message string) *protobufs.ServerToAgent {
	return &protobufs.ServerToAgent{
		ErrorResponse: &protobufs.ServerErrorResponse{ErrorMessage: message},
	}
}

// validateAgentMessageLimits runs before any inventory mutation. The HTTP body
// limit protects the protobuf decoder; these semantic limits protect the
// long-lived in-memory and PostgreSQL inventory from a small but pathological
// protobuf containing thousands of keys or oversized effective config files.
func validateAgentMessageLimits(message *protobufs.AgentToServer) error {
	if message == nil {
		return errors.New("OpAMP message is required")
	}
	if description := message.AgentDescription; description != nil {
		if err := validateReportedAttributes(
			description.IdentifyingAttributes,
			description.NonIdentifyingAttributes,
		); err != nil {
			return err
		}
	}
	if message.EffectiveConfig != nil && message.EffectiveConfig.ConfigMap != nil {
		if err := validateReportedEffectiveConfig(message.EffectiveConfig.ConfigMap); err != nil {
			return err
		}
	}
	return nil
}

func validateReportedAttributes(attributeGroups ...[]*protobufs.KeyValue) error {
	count := 0
	total := 0
	for _, attributes := range attributeGroups {
		if len(attributes) > maxReportedAttributes-count {
			return fmt.Errorf("reported attributes exceed the limit of %d", maxReportedAttributes)
		}
		count += len(attributes)
		for _, attribute := range attributes {
			if attribute == nil || attribute.Value == nil {
				return errors.New("reported attribute key and value are required")
			}
			keyBytes := len(attribute.Key)
			valueBytes := proto.Size(attribute.Value)
			if keyBytes == 0 || keyBytes > maxReportedAttributeKeyBytes || !utf8.ValidString(attribute.Key) {
				return fmt.Errorf("reported attribute key must contain 1 to %d valid UTF-8 bytes", maxReportedAttributeKeyBytes)
			}
			if valueBytes > maxReportedAttributeValueBytes {
				return fmt.Errorf("reported attribute %q exceeds the value limit of %d bytes", attribute.Key, maxReportedAttributeValueBytes)
			}
			if keyBytes > maxReportedAttributesTotalBytes-total ||
				valueBytes > maxReportedAttributesTotalBytes-total-keyBytes {
				return fmt.Errorf("reported attributes exceed the total limit of %d bytes", maxReportedAttributesTotalBytes)
			}
			total += keyBytes + valueBytes
		}
	}
	return nil
}

func validateReportedAttributeMap(attributes map[string]string) error {
	if len(attributes) > maxReportedAttributes {
		return fmt.Errorf("reported attributes exceed the limit of %d", maxReportedAttributes)
	}
	total := 0
	for key, value := range attributes {
		keyBytes, valueBytes := len(key), len(value)
		if keyBytes == 0 || keyBytes > maxReportedAttributeKeyBytes || !utf8.ValidString(key) {
			return fmt.Errorf("reported attribute key must contain 1 to %d valid UTF-8 bytes", maxReportedAttributeKeyBytes)
		}
		if valueBytes > maxReportedAttributeValueBytes || !utf8.ValidString(value) {
			return fmt.Errorf("reported attribute %q exceeds the value limit of %d valid UTF-8 bytes", key, maxReportedAttributeValueBytes)
		}
		if keyBytes > maxReportedAttributesTotalBytes-total ||
			valueBytes > maxReportedAttributesTotalBytes-total-keyBytes {
			return fmt.Errorf("reported attributes exceed the total limit of %d bytes", maxReportedAttributesTotalBytes)
		}
		total += keyBytes + valueBytes
	}
	return nil
}

func validateReportedEffectiveConfig(configMap *protobufs.AgentConfigMap) error {
	if len(configMap.ConfigMap) > maxEffectiveConfigFiles {
		return fmt.Errorf("effective config exceeds the limit of %d files", maxEffectiveConfigFiles)
	}
	total := 0
	for name, file := range configMap.ConfigMap {
		if len(name) > maxEffectiveConfigNameBytes || !utf8.ValidString(name) {
			return fmt.Errorf("effective config filename exceeds the limit of %d valid UTF-8 bytes", maxEffectiveConfigNameBytes)
		}
		if file == nil {
			return fmt.Errorf("effective config file %q is required", name)
		}
		if len(file.ContentType) > maxEffectiveConfigContentType || !utf8.ValidString(file.ContentType) {
			return fmt.Errorf("effective config content type exceeds the limit of %d valid UTF-8 bytes", maxEffectiveConfigContentType)
		}
		if len(file.Body) > maxEffectiveConfigFileBytes {
			return fmt.Errorf("effective config file %q exceeds the limit of %d bytes", name, maxEffectiveConfigFileBytes)
		}
		entryBytes := len(name) + len(file.ContentType) + len(file.Body)
		if entryBytes > maxEffectiveConfigTotalBytes-total {
			return fmt.Errorf("effective config exceeds the total limit of %d bytes", maxEffectiveConfigTotalBytes)
		}
		total += entryBytes
	}
	return nil
}
