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
	environment := collectorValidationEnvironment()
	want := []string{
		"HOME=/tmp",
		"TMPDIR=/tmp",
		"POD_NAME=o11y-validation-pod",
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

func TestCollectorConfigReferencesAllowExplicitEnvironmentPlaceholders(t *testing.T) {
	body := `receivers:
  kubeletstats:
    endpoint: ${env:K8S_NODE_IP}:10250
service:
  telemetry:
    resource:
      service.instance.id: ${env:POD_NAME}
      k8s.node.name: ${env:K8S_NODE_NAME}
`

	if err := validateCollectorConfigReferences(body); err != nil {
		t.Fatalf("explicit environment placeholders must be allowed: %v", err)
	}
}

func TestCollectorConfigReferencesRejectUnsafeProvidersAndAmbiguousForms(t *testing.T) {
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
			if !strings.Contains(err.Error(), "may only use ${env:POD_NAME}") {
				t.Fatalf("unexpected rejection message: %v", err)
			}
		})
	}
}

func TestUnsafeCollectorReferenceIsRejectedBeforeStartingValidator(t *testing.T) {
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
