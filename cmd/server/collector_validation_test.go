package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func stubCollectorValidator(
	t *testing.T,
	result collectorValidationResult,
	err error,
) {
	t.Helper()
	original := collectorValidator
	collectorValidator = func(context.Context, string) (collectorValidationResult, error) {
		return result, err
	}
	t.Cleanup(func() { collectorValidator = original })
}

func TestCollectorValidationReturnsCollectorError(t *testing.T) {
	stubCollectorValidator(t, collectorValidationResult{
		Valid:            false,
		ValidatorVersion: "0.156.0",
		Output:           "extensions::health_check: v2 feature gate is disabled",
	}, nil)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/configs/validate",
		strings.NewReader(`{"Body":"extensions: {}"}`),
	)
	identity := Identity{Username: "collector-editor", Roles: []string{"collector-editor"}}
	identity.Permissions = permissionsForRoles(identity.Roles)
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, identity))

	collectorValidation(recorder, request)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d: %s", recorder.Code, recorder.Body.String())
	}
	var result collectorValidationResult
	if err := json.NewDecoder(recorder.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	if result.Valid || !strings.Contains(result.Output, "feature gate") {
		t.Fatalf("unexpected validation result: %+v", result)
	}
}

func TestInvalidCollectorConfigIsNotPersistedOrPublished(t *testing.T) {
	stubCollectorValidator(t, collectorValidationResult{
		Valid:            false,
		ValidatorVersion: "0.156.0",
		Output:           "invalid Collector configuration",
	}, nil)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/configs",
		strings.NewReader(`{"ID":"gateway","Target":"collector","Body":"extensions: {}"}`),
	)
	identity := Identity{Username: "collector-editor", Roles: []string{"collector-editor"}}
	identity.Permissions = permissionsForRoles(identity.Roles)
	request = request.WithContext(context.WithValue(request.Context(), authContextKey{}, identity))

	saveConfig(recorder, request)

	if recorder.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 before persistence, got %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestCollectorValidationEnvironmentUsesOnlySafePlaceholders(t *testing.T) {
	t.Setenv(collectorValidatorEnvironmentFileVariable, "")
	variables, err := collectorValidationVariables()
	if err != nil {
		t.Fatal(err)
	}
	environment := collectorValidationProcessEnvironment(variables)
	want := []string{
		"HOME=/tmp",
		"TMPDIR=/tmp",
		"KUBERNETES_SERVICE_HOST=127.0.0.1",
		"KUBERNETES_SERVICE_PORT=443",
		"POD_NAME=o11y-validation-pod",
		"K8S_POD_NAME=o11y-validation-pod",
		"K8S_NODE_NAME=o11y-validation-node",
		"K8S_NODE_IP=127.0.0.1",
	}
	if len(environment) != len(want) {
		t.Fatalf("unexpected validation environment: %#v", environment)
	}
	for index := range want {
		if environment[index] != want[index] {
			t.Fatalf("unexpected validation environment: %#v", environment)
		}
	}
}

func TestCollectorValidationEnvironmentDoesNotInheritBackendSecrets(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://must-not-leak")
	t.Setenv("OPAMP_TOKEN", "must-not-leak")
	t.Setenv(collectorValidatorEnvironmentFileVariable, "")
	variables, err := collectorValidationVariables()
	if err != nil {
		t.Fatal(err)
	}
	environment := strings.Join(collectorValidationProcessEnvironment(variables), "\n")
	for _, secret := range []string{"DATABASE_URL", "OPAMP_TOKEN", "must-not-leak"} {
		if strings.Contains(environment, secret) {
			t.Fatalf("backend secret leaked to validation process: %s", environment)
		}
	}
}

func TestCollectorValidationEnvironmentFileIsReloaded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment.json")
	t.Setenv(collectorValidatorEnvironmentFileVariable, path)
	writeValidationEnvironment(t, path, `[
  {"name":"POD_NAME","value":"first-pod"},
  {"name":"CUSTOM_CLUSTER","value":"first-cluster"}
]`)

	first, err := collectorValidationVariables()
	if err != nil {
		t.Fatal(err)
	}
	if got := first[1].Value; got != "first-cluster" {
		t.Fatalf("unexpected first value %q", got)
	}

	writeValidationEnvironment(t, path, `[
  {"name":"POD_NAME","value":"second-pod"},
  {"name":"CUSTOM_CLUSTER","value":"second-cluster"}
]`)
	second, err := collectorValidationVariables()
	if err != nil {
		t.Fatal(err)
	}
	if got := second[1].Value; got != "second-cluster" {
		t.Fatalf("projected ConfigMap update was not reloaded: %q", got)
	}
}

func TestCollectorValidationEnvironmentFileFailsClosed(t *testing.T) {
	tests := map[string]string{
		"empty":          `[]`,
		"unknown field":  `[{"name":"POD_NAME","value":"pod","secret":"x"}]`,
		"duplicate":      `[{"name":"POD_NAME","value":"a"},{"name":"POD_NAME","value":"b"}]`,
		"reserved host":  `[{"name":"KUBERNETES_SERVICE_HOST","value":"api.default.svc"}]`,
		"reserved token": `[{"name":"COLLECTOR_VALIDATOR_ENV_FILE","value":"other"}]`,
		"newline":        "[{\"name\":\"POD_NAME\",\"value\":\"pod\\nLEAK=value\"}]",
		"empty value":    `[{"name":"POD_NAME","value":""}]`,
		"invalid name":   `[{"name":"BAD-NAME","value":"x"}]`,
	}
	for name, content := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "environment.json")
			t.Setenv(collectorValidatorEnvironmentFileVariable, path)
			writeValidationEnvironment(t, path, content)
			if _, err := collectorValidationVariables(); err == nil {
				t.Fatalf("expected invalid environment file to fail closed: %s", content)
			}
		})
	}
}

func TestCollectorConfigReferencesAllowExplicitEnvironmentPlaceholders(t *testing.T) {
	t.Setenv(collectorValidatorEnvironmentFileVariable, "")
	body := `receivers:
  kubeletstats:
    endpoint: ${env:K8S_NODE_IP}:10250
service:
  telemetry:
    resource:
      service.instance.id: ${env:POD_NAME}
      k8s.pod.name: ${env:K8S_POD_NAME}
      k8s.node.name: ${env:K8S_NODE_NAME}
`

	if err := validateCollectorConfigReferences(body); err != nil {
		t.Fatalf("explicit environment placeholders must be allowed: %v", err)
	}
}

func TestCollectorConfigReferencesUseConfiguredAllowlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "environment.json")
	t.Setenv(collectorValidatorEnvironmentFileVariable, path)
	writeValidationEnvironment(t, path, `[
  {"name":"POD_NAME","value":"validation-pod"},
  {"name":"OTEL_RESOURCE_ATTRIBUTES","value":"k8s.cluster.name=validation"}
]`)

	if err := validateCollectorConfigReferences(
		`resource: ${env:OTEL_RESOURCE_ATTRIBUTES}`,
	); err != nil {
		t.Fatalf("configured environment placeholder must be accepted: %v", err)
	}
	err := validateCollectorConfigReferences(`node: ${env:K8S_NODE_NAME}`)
	if err == nil {
		t.Fatal("an environment placeholder absent from the configured allowlist was accepted")
	}
	if !strings.Contains(err.Error(), "${env:OTEL_RESOURCE_ATTRIBUTES}") ||
		strings.Contains(err.Error(), "${env:K8S_NODE_NAME}") {
		t.Fatalf("rejection must describe the current allowlist: %v", err)
	}
}

func TestCollectorPreflightDoesNotRestrictCollectorComponents(t *testing.T) {
	t.Setenv(collectorValidatorEnvironmentFileVariable, "")
	for _, fixture := range []string{
		"testdata/collector-filter-debug.yaml",
		"testdata/collector-kubernetes-infra.yaml",
	} {
		body, err := os.ReadFile(fixture)
		if err != nil {
			t.Fatal(err)
		}
		if err := validateCollectorConfigReferences(string(body)); err != nil {
			t.Fatalf(
				"%s component compatibility must be delegated to otelcol-contrib: %v",
				fixture,
				err,
			)
		}
	}
}

func TestCollectorConfigReferencesRejectUnsafeProvidersAndAmbiguousForms(t *testing.T) {
	t.Setenv(collectorValidatorEnvironmentFileVariable, "")
	tests := map[string]string{
		"file provider":         `${file:/etc/passwd}`,
		"HTTP provider":         `${http:http://169.254.169.254/latest/meta-data}`,
		"HTTPS provider":        `${https:https://internal.example/config.yaml}`,
		"shorthand":             `${POD_NAME}`,
		"nested provider":       `${env:${file:/etc/passwd}}`,
		"dollar escaped":        `$${file:/etc/passwd}`,
		"backslash escaped":     `\${file:/etc/passwd}`,
		"invalid env name":      `${env:BAD-NAME}`,
		"empty env name":        `${env:}`,
		"secret env":            `${env:OPAMP_TOKEN}`,
		"database env":          `${env:DATABASE_URL}`,
		"unapproved env":        `${env:OTLP_ENDPOINT}`,
		"unterminated provider": `${file:/etc/passwd`,
	}

	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			err := validateCollectorConfigReferences("exporters:\n  debug:\n    verbosity: " + body)
			if err == nil {
				t.Fatalf("expected %q to be rejected", body)
			}
			if !strings.Contains(err.Error(), "Collector configuration may only use") {
				t.Fatalf("unexpected rejection message: %v", err)
			}
		})
	}
}

func TestUnsafeCollectorReferenceIsRejectedBeforeStartingValidator(t *testing.T) {
	t.Setenv(collectorValidatorEnvironmentFileVariable, "")
	result, err := validateCollectorWithBinary(
		context.Background(),
		"exporters:\n  debug:\n    verbosity: ${file:/etc/hostname}\n",
	)
	if err != nil {
		t.Fatalf("unsafe reference must be a validation result, not an infrastructure error: %v", err)
	}
	if result.Valid || !strings.Contains(result.Output, "file, HTTP, and HTTPS") {
		t.Fatalf("unexpected validation result: %+v", result)
	}
}

func TestCollectorValidatorPathPrefersContainerBinary(t *testing.T) {
	directory := t.TempDir()
	primary := filepath.Join(directory, "container-otelcol")
	bundled := filepath.Join(directory, "bundled-otelcol")
	writeExecutable(t, primary)
	writeExecutable(t, bundled)

	got, err := resolveCollectorValidatorPath(primary, bundled)
	if err != nil {
		t.Fatal(err)
	}
	if got != primary {
		t.Fatalf("expected primary validator %q, got %q", primary, got)
	}
}

func TestCollectorValidatorPathUsesBundledBinaryWhenContainerBinaryIsAbsent(t *testing.T) {
	directory := t.TempDir()
	bundled := filepath.Join(directory, "otelcol-contrib")
	writeExecutable(t, bundled)

	got, err := resolveCollectorValidatorPath(
		filepath.Join(directory, "missing-container-otelcol"),
		bundled,
	)
	if err != nil {
		t.Fatal(err)
	}
	if got != bundled {
		t.Fatalf("expected bundled validator %q, got %q", bundled, got)
	}
}

func TestCollectorValidatorPathRejectsSymbolicLinks(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "otelcol-contrib")
	writeExecutable(t, target)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	_, err := resolveCollectorValidatorPath(
		filepath.Join(directory, "missing-container-otelcol"),
		link,
	)
	if err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected symbolic-link rejection, got %v", err)
	}
}

func TestCollectorValidatorPathRejectsNonExecutableFiles(t *testing.T) {
	directory := t.TempDir()
	validator := filepath.Join(directory, "otelcol-contrib")
	if err := os.WriteFile(validator, []byte("not executable"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := resolveCollectorValidatorPath(
		filepath.Join(directory, "missing-container-otelcol"),
		validator,
	)
	if err == nil || !strings.Contains(err.Error(), "not executable") {
		t.Fatalf("expected executable-bit rejection, got %v", err)
	}
}

func writeExecutable(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
}

func writeValidationEnvironment(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
