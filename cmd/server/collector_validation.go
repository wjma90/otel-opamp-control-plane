package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const maxCollectorValidationOutput = 32 << 10
const maxCollectorValidationEnvironmentFile = 64 << 10
const maxCollectorValidationVariables = 32
const maxCollectorValidationVariableValue = 1024
const collectorValidatorExecutable = "/otelcol-contrib"
const collectorValidatorEnvironmentFileVariable = "COLLECTOR_VALIDATOR_ENV_FILE"

var collectorEnvironmentName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var defaultCollectorValidationVariables = []collectorValidationVariable{
	{Name: "POD_NAME", Value: "o11y-validation-pod"},
	{Name: "K8S_POD_NAME", Value: "o11y-validation-pod"},
	{Name: "K8S_NODE_NAME", Value: "o11y-validation-node"},
	{Name: "K8S_NODE_IP", Value: "127.0.0.1"},
}

var reservedCollectorValidationEnvironment = map[string]bool{
	"HOME":                          true,
	"TMPDIR":                        true,
	"KUBERNETES_SERVICE_HOST":       true,
	"KUBERNETES_SERVICE_PORT":       true,
	"KUBERNETES_SERVICE_PORT_HTTPS": true,
	"KUBERNETES_PORT":               true,
	"COLLECTOR_VALIDATOR_ENV_FILE":  true,
}

type collectorValidationResult struct {
	Valid            bool   `json:"valid"`
	ValidatorVersion string `json:"validatorVersion"`
	Output           string `json:"output,omitempty"`
}

type collectorValidationVariable struct {
	Name  string `json:"name"`
	Value string `json:"value"`
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
	variables, err := collectorValidationVariables()
	if err != nil {
		return result, fmt.Errorf("load Collector validation environment: %w", err)
	}
	if err := validateCollectorConfigReferencesWithVariables(body, variables); err != nil {
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
	command.Env = collectorValidationProcessEnvironment(variables)
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
	variables, err := collectorValidationVariables()
	if err != nil {
		return fmt.Errorf("load Collector validation environment: %w", err)
	}
	return validateCollectorConfigReferencesWithVariables(body, variables)
}

func validateCollectorConfigReferencesWithVariables(
	body string,
	variables []collectorValidationVariable,
) error {
	allowed := make(map[string]bool, len(variables))
	for _, variable := range variables {
		allowed[variable.Name] = true
	}
	for offset := 0; offset < len(body); {
		relativeStart := strings.Index(body[offset:], "${")
		if relativeStart < 0 {
			return nil
		}
		start := offset + relativeStart
		if start > 0 && (body[start-1] == '$' || body[start-1] == '\\') {
			return collectorConfigReferenceError(variables)
		}

		relativeEnd := strings.IndexByte(body[start+2:], '}')
		if relativeEnd < 0 {
			return collectorConfigReferenceError(variables)
		}
		end := start + 2 + relativeEnd
		reference := body[start+2 : end]
		if strings.Contains(reference, "${") || !strings.HasPrefix(reference, "env:") {
			return collectorConfigReferenceError(variables)
		}
		name := strings.TrimPrefix(reference, "env:")
		if !collectorEnvironmentName.MatchString(name) || !allowed[name] {
			return collectorConfigReferenceError(variables)
		}
		offset = end + 1
	}
	return nil
}

func collectorConfigReferenceError(variables []collectorValidationVariable) error {
	names := make([]string, 0, len(variables))
	for _, variable := range variables {
		names = append(names, fmt.Sprintf("${env:%s}", variable.Name))
	}
	sort.Strings(names)
	return fmt.Errorf(
		"Collector configuration may only use %s; secret, shorthand, escaped, nested, file, HTTP, and HTTPS references are not allowed",
		strings.Join(names, ", "),
	)
}

func collectorValidationVariables() ([]collectorValidationVariable, error) {
	path := strings.TrimSpace(os.Getenv(collectorValidatorEnvironmentFileVariable))
	if path == "" {
		return append([]collectorValidationVariable(nil), defaultCollectorValidationVariables...), nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open configured environment file: %w", err)
	}
	defer file.Close()
	limited := io.LimitReader(file, maxCollectorValidationEnvironmentFile+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read configured environment file: %w", err)
	}
	if len(content) > maxCollectorValidationEnvironmentFile {
		return nil, errors.New("configured environment file is too large")
	}
	var variables []collectorValidationVariable
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&variables); err != nil {
		return nil, fmt.Errorf("decode configured environment file: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("configured environment file must contain one JSON document")
	}
	if err := validateCollectorValidationVariables(variables); err != nil {
		return nil, err
	}
	return variables, nil
}

func validateCollectorValidationVariables(variables []collectorValidationVariable) error {
	if len(variables) == 0 {
		return errors.New("configured environment allowlist cannot be empty")
	}
	if len(variables) > maxCollectorValidationVariables {
		return fmt.Errorf(
			"configured environment allowlist exceeds %d entries",
			maxCollectorValidationVariables,
		)
	}
	seen := make(map[string]bool, len(variables))
	for _, variable := range variables {
		if !collectorEnvironmentName.MatchString(variable.Name) {
			return fmt.Errorf("invalid configured environment name %q", variable.Name)
		}
		if reservedCollectorValidationEnvironment[variable.Name] {
			return fmt.Errorf("configured environment name %q is reserved", variable.Name)
		}
		if seen[variable.Name] {
			return fmt.Errorf("configured environment name %q is duplicated", variable.Name)
		}
		if variable.Value == "" {
			return fmt.Errorf("configured environment value for %q cannot be empty", variable.Name)
		}
		if len(variable.Value) > maxCollectorValidationVariableValue ||
			strings.ContainsAny(variable.Value, "\x00\r\n") {
			return fmt.Errorf("configured environment value for %q is invalid", variable.Name)
		}
		seen[variable.Name] = true
	}
	return nil
}

func collectorValidationProcessEnvironment(variables []collectorValidationVariable) []string {
	environment := []string{
		"HOME=/tmp",
		"TMPDIR=/tmp",
		"KUBERNETES_SERVICE_HOST=127.0.0.1",
		"KUBERNETES_SERVICE_PORT=443",
	}
	for _, variable := range variables {
		environment = append(environment, variable.Name+"="+variable.Value)
	}
	return environment
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
