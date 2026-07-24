package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// validatePolicyRequiredFields rejects ambiguous JSON that Go and Java would
// otherwise interpret differently because their primitive defaults differ.
// It runs in addition to the strict typed decoder, which remains responsible
// for types, unknown fields and the rest of the policy schema.
func validatePolicyRequiredFields(body []byte) error {
	var document map[string]json.RawMessage
	if err := json.Unmarshal(body, &document); err != nil {
		return err
	}

	metricPolicies, err := policyObjectArray(document, "metricPolicies")
	if err != nil {
		return err
	}
	for index, metric := range metricPolicies {
		location := fmt.Sprintf("metricPolicies[%d]", index)
		if err := requirePolicyBoolean(metric, "enabled", location); err != nil {
			return err
		}
		if err := validateNestedValueSourcePresence(metric, "value", location+".value"); err != nil {
			return err
		}
	}

	methodPolicies, err := policyObjectArray(document, "methodPolicies")
	if err != nil {
		return err
	}
	for methodIndex, method := range methodPolicies {
		location := fmt.Sprintf("methodPolicies[%d]", methodIndex)
		if err := requirePolicyBoolean(method, "enabled", location); err != nil {
			return err
		}
		if err := rejectExplicitPolicyNull(method, "log", location+".log"); err != nil {
			return err
		}

		captures, err := nestedPolicyObjectArray(method, "captures", location)
		if err != nil {
			return err
		}
		for captureIndex, capture := range captures {
			captureLocation := fmt.Sprintf("%s.captures[%d]", location, captureIndex)
			if err := rejectExplicitPolicyNull(
				capture,
				"valuePolicy",
				captureLocation+".valuePolicy",
			); err != nil {
				return err
			}
			if err := validateValueSourcePresence(capture, captureLocation); err != nil {
				return err
			}
		}

		metrics, err := nestedPolicyObjectArray(method, "metrics", location)
		if err != nil {
			return err
		}
		for metricIndex, metric := range metrics {
			metricLocation := fmt.Sprintf("%s.metrics[%d].value", location, metricIndex)
			if err := validateNestedValueSourcePresence(metric, "value", metricLocation); err != nil {
				return err
			}
		}
	}

	for _, section := range []string{
		"bodyEventPolicies",
		"eventMetricPolicies",
		"messagingEventPolicies",
		"messagingMetricPolicies",
	} {
		policies, err := policyObjectArray(document, section)
		if err != nil {
			return err
		}
		for index, policy := range policies {
			if err := requirePolicyBoolean(policy, "enabled", fmt.Sprintf("%s[%d]", section, index)); err != nil {
				return err
			}
		}
	}
	return nil
}

func rejectExplicitPolicyNull(
	object map[string]json.RawMessage,
	field string,
	location string,
) error {
	raw, exists := object[field]
	if exists && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%s must not be null", location)
	}
	return nil
}

func policyObjectArray(document map[string]json.RawMessage, field string) ([]map[string]json.RawMessage, error) {
	raw, exists := document[field]
	if !exists || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	return decodePolicyObjectArray(raw, field)
}

func nestedPolicyObjectArray(object map[string]json.RawMessage, field, location string) ([]map[string]json.RawMessage, error) {
	raw, exists := object[field]
	if !exists || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil, nil
	}
	return decodePolicyObjectArray(raw, location+"."+field)
}

func decodePolicyObjectArray(raw json.RawMessage, location string) ([]map[string]json.RawMessage, error) {
	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("%s must be an array", location)
	}
	objects := make([]map[string]json.RawMessage, 0, len(entries))
	for index, entry := range entries {
		var object map[string]json.RawMessage
		if len(bytes.TrimSpace(entry)) == 0 || bytes.Equal(bytes.TrimSpace(entry), []byte("null")) || json.Unmarshal(entry, &object) != nil || object == nil {
			return nil, fmt.Errorf("%s[%d] must be an object", location, index)
		}
		objects = append(objects, object)
	}
	return objects, nil
}

func requirePolicyBoolean(object map[string]json.RawMessage, field, location string) error {
	raw, exists := object[field]
	if !exists {
		return fmt.Errorf("%s.%s is required", location, field)
	}
	trimmed := bytes.TrimSpace(raw)
	if !bytes.Equal(trimmed, []byte("true")) && !bytes.Equal(trimmed, []byte("false")) {
		return fmt.Errorf("%s.%s must be a boolean", location, field)
	}
	return nil
}

func validateNestedValueSourcePresence(object map[string]json.RawMessage, field, location string) error {
	raw, exists := object[field]
	if !exists || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return nil
	}
	var valueSource map[string]json.RawMessage
	if err := json.Unmarshal(raw, &valueSource); err != nil || valueSource == nil {
		return fmt.Errorf("%s must be an object", location)
	}
	return validateValueSourcePresence(valueSource, location)
}

func validateValueSourcePresence(source map[string]json.RawMessage, location string) error {
	rawSource, exists := source["source"]
	if !exists {
		return nil
	}
	var sourceName string
	if err := json.Unmarshal(rawSource, &sourceName); err != nil {
		return nil
	}
	switch sourceName {
	case "ARGUMENT":
		return requirePolicyInteger(source, "argumentIndex", location)
	case "CONSTANT":
		return requirePolicyNumber(source, "constant", location)
	default:
		return nil
	}
}

func requirePolicyInteger(object map[string]json.RawMessage, field, location string) error {
	raw, exists := object[field]
	if !exists || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%s.%s is required when source is ARGUMENT", location, field)
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("%s.%s must be an integer", location, field)
	}
	return nil
}

func requirePolicyNumber(object map[string]json.RawMessage, field, location string) error {
	raw, exists := object[field]
	if !exists || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%s.%s is required when source is CONSTANT", location, field)
	}
	var value float64
	if err := json.Unmarshal(raw, &value); err != nil {
		return fmt.Errorf("%s.%s must be a number", location, field)
	}
	return nil
}
