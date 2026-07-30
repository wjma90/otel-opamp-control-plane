package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxCollectorValidationOutput = 32 << 10
const collectorValidatorExecutable = "/otelcol-contrib"

var collectorEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var allowedCollectorEnvironment = map[string]bool{
	"POD_NAME":      true,
	"K8S_NODE_NAME": true,
	"K8S_NODE_IP":   true,
}

type collectorValidationResult struct {
	Valid            bool   `json:"valid"`
	ValidatorVersion string `json:"validatorVersion"`
	Output           string `json:"output,omitempty"`
}

var collectorValidator = validateCollectorWithBinary

func collectorValidatorVersion() string {
	if value := strings.TrimSpace(os.Getenv("COLLECTOR_VALIDATOR_VERSION")); value != "" {
		return value
	}
	return "0.156.0"
}

func validateCollectorWithBinary(parent context.Context, body string) (collectorValidationResult, error) {
	result := collectorValidationResult{ValidatorVersion: collectorValidatorVersion()}
	if err := validateCollectorConfigReferences(body); err != nil {
		result.Output = err.Error()
		return result, nil
	}
	file, err := os.CreateTemp("", "o11y-collector-*.yaml")
	if err != nil {
		return result, fmt.Errorf("create temporary Collector config: %w", err)
	}
	name := file.Name()
	defer os.Remove(name)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.WriteString(body)
	}
	closeErr := file.Close()
	if err != nil {
		return result, fmt.Errorf("write temporary Collector config: %w", err)
	}
	if closeErr != nil {
		return result, fmt.Errorf("close temporary Collector config: %w", closeErr)
	}

	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	validatorPath, err := collectorValidatorPath()
	if err != nil {
		return result, err
	}
	command := exec.CommandContext(
		ctx,
		validatorPath,
		"validate",
		"--config",
		name,
	)
	// Do not expose Control Plane credentials to Collector config expansion.
	command.Env = collectorValidationEnvironment()
	output, commandErr := command.CombinedOutput()
	if len(output) > maxCollectorValidationOutput {
		output = output[:maxCollectorValidationOutput]
	}
	result.Output = strings.TrimSpace(string(output))
	if commandErr == nil {
		result.Valid = true
		return result, nil
	}
	if ctx.Err() != nil {
		return result, fmt.Errorf("Collector validation timed out: %w", ctx.Err())
	}
	var exitErr *exec.ExitError
	if errors.As(commandErr, &exitErr) {
		if result.Output == "" {
			result.Output = "otelcol-contrib rejected the configuration"
		}
		return result, nil
	}
	return result, fmt.Errorf("start Collector validator: %w", commandErr)
}

// collectorValidatorPath keeps the container contract (/otelcol-contrib) and
// also supports the portable release bundle, where the validator is shipped
// next to the Control Plane binary. It deliberately does not accept a path
// from configuration: operators must not be able to execute an arbitrary
// binary through the Collector validation endpoint.
func collectorValidatorPath() (string, error) {
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve Control Plane executable: %w", err)
	}
	return resolveCollectorValidatorPath(
		collectorValidatorExecutable,
		filepath.Join(filepath.Dir(executable), "otelcol-contrib"),
	)
}

func resolveCollectorValidatorPath(primary, bundled string) (string, error) {
	for _, candidate := range []string{primary, bundled} {
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return "", fmt.Errorf("inspect Collector validator: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", errors.New("Collector validator must be a regular file and cannot be a symbolic link")
		}
		if info.Mode().Perm()&0o111 == 0 {
			return "", errors.New("Collector validator is not executable")
		}
		return candidate, nil
	}
	return "", errors.New("Collector validator executable was not found")
}

// validateCollectorConfigReferences runs before the config is written or passed
// to otelcol-contrib. Collector confmap providers resolve while loading a config;
// allowing file, HTTP, or another provider here would let an editor make the
// validator read Control Plane files or reach internal services. The validator
// receives a deliberately small environment, so explicit env references are the
// only supported expansion mechanism.
func validateCollectorConfigReferences(body string) error {
	for offset := 0; offset < len(body); {
		relativeStart := strings.Index(body[offset:], "${")
		if relativeStart < 0 {
			return nil
		}
		start := offset + relativeStart
		if start > 0 && (body[start-1] == '$' || body[start-1] == '\\') {
			return collectorConfigReferenceError()
		}

		relativeEnd := strings.IndexByte(body[start+2:], '}')
		if relativeEnd < 0 {
			return collectorConfigReferenceError()
		}
		end := start + 2 + relativeEnd
		reference := body[start+2 : end]
		if strings.Contains(reference, "${") || !strings.HasPrefix(reference, "env:") {
			return collectorConfigReferenceError()
		}
		name := strings.TrimPrefix(reference, "env:")
		if !collectorEnvironmentName.MatchString(name) || !allowedCollectorEnvironment[name] {
			return collectorConfigReferenceError()
		}
		offset = end + 1
	}
	return nil
}

func collectorConfigReferenceError() error {
	return errors.New("Collector configuration may only use ${env:POD_NAME}, ${env:K8S_NODE_NAME}, or ${env:K8S_NODE_IP}; secret, shorthand, escaped, nested, file, HTTP, and HTTPS references are not allowed")
}

func collectorValidationEnvironment() []string {
	return []string{
		"HOME=/tmp",
		"TMPDIR=/tmp",
		"POD_NAME=o11y-validation-pod",
		"K8S_NODE_NAME=o11y-validation-node",
		"K8S_NODE_IP=127.0.0.1",
	}
}

func collectorValidation(w http.ResponseWriter, r *http.Request) {
	if !authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var request struct {
		Body string
	}
	if err := decodeJSONBody(w, r, &request); err != nil || strings.TrimSpace(request.Body) == "" {
		http.Error(w, "Collector YAML is required", http.StatusUnprocessableEntity)
		return
	}
	result, err := collectorValidator(r.Context(), request.Body)
	if err != nil {
		logCollectorValidationUnavailable(w, err)
		return
	}
	if !result.Valid {
		writeJSONStatus(w, http.StatusUnprocessableEntity, result)
		return
	}
	jsonOut(w, result)
}

func validateCollectorBeforeSave(w http.ResponseWriter, ctx context.Context, body string) bool {
	result, err := collectorValidator(ctx, body)
	if err != nil {
		logCollectorValidationUnavailable(w, err)
		return false
	}
	if !result.Valid {
		writeJSONStatus(w, http.StatusUnprocessableEntity, result)
		return false
	}
	return true
}

func logCollectorValidationUnavailable(w http.ResponseWriter, err error) {
	// The caller receives no filesystem or process details.
	log.Printf("Collector validator unavailable: %v", err)
	writeJSONStatus(w, http.StatusServiceUnavailable, map[string]any{
		"valid":            false,
		"validatorVersion": collectorValidatorVersion(),
		"output":           "Collector validator is unavailable",
	})
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, value any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
