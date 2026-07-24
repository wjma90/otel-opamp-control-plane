package main

import (
	"fmt"
	"strings"
)

var messagingScopes = []string{
	"KAFKA_PRODUCER",
	"KAFKA_CONSUMER",
	"JMS_PRODUCER",
	"JMS_CONSUMER",
}

var messagingSources = []string{
	"DESTINATION",
	"MESSAGE_KEY",
	"MESSAGE_HEADER",
	"MESSAGE_PROPERTY",
	"PAYLOAD",
}

func validateMessagingEventPolicies(
	owner string,
	policy javaPolicy,
	seenNames map[string]bool,
	seenPrometheus map[string]bool,
	seenPolicyIDs map[string]bool,
) ([]metricDefinition, error) {
	if len(policy.MessagingEventPolicies) > maxMessagingEventPolicies {
		return nil, fmt.Errorf("messagingEventPolicies exceeds its limit of %d", maxMessagingEventPolicies)
	}
	if len(policy.MessagingMetricPolicies) > maxMessagingMetricPolicies {
		return nil, fmt.Errorf("messagingMetricPolicies exceeds its limit of %d", maxMessagingMetricPolicies)
	}

	declaredEventNames := map[string]string{}
	for _, event := range policy.BodyEventPolicies {
		if !isPolicyBlank(event.EventName) {
			declaredEventNames[event.EventName] = event.ID
		}
	}
	for _, event := range policy.MessagingEventPolicies {
		if isPolicyBlank(event.EventName) {
			continue
		}
		if previous, exists := declaredEventNames[event.EventName]; exists {
			return nil, fmt.Errorf(
				"%s eventName %s duplicates %s; eventName must be unique across HTTP and messaging rules",
				event.ID,
				event.EventName,
				previous,
			)
		}
		declaredEventNames[event.EventName] = event.ID
	}

	enabledMetricEvents := map[string]bool{}
	for _, metric := range policy.MessagingMetricPolicies {
		if metric.Enabled {
			enabledMetricEvents[metric.EventName] = true
		}
	}
	eventFields := map[string]map[string]eventFieldDefinition{}
	headerSelectors := map[string]bool{}
	propertySelectors := map[string]bool{}
	for _, event := range policy.MessagingEventPolicies {
		if !event.Enabled {
			continue
		}
		if isPolicyBlank(event.ID) || seenPolicyIDs[event.ID] {
			return nil, fmt.Errorf("messaging event policies require unique IDs")
		}
		seenPolicyIDs[event.ID] = true
		if isPolicyBlank(event.RuleName) || len(event.RuleName) > 128 {
			return nil, fmt.Errorf("%s ruleName is required and limited to 128 characters", event.ID)
		}
		if !contains(messagingScopes, event.Scope) {
			return nil, fmt.Errorf("%s has unsupported messaging scope %s", event.ID, event.Scope)
		}
		if !validEventValue(event.EventName) {
			return nil, fmt.Errorf("%s eventName must be a stable identifier", event.ID)
		}
		if err := validateMessagingStaticAttributes(event); err != nil {
			return nil, err
		}
		if err := validateMessagingConditions(event); err != nil {
			return nil, err
		}
		if event.MaxPayloadBytes < 1024 || event.MaxPayloadBytes > 262144 {
			return nil, fmt.Errorf("%s maxPayloadBytes must be between 1024 and 262144", event.ID)
		}
		if len(event.Fields) > 32 {
			return nil, fmt.Errorf("%s fields exceeds its limit of 32 entries", event.ID)
		}

		fields := map[string]eventFieldDefinition{}
		selectors := map[string]bool{}
		for _, field := range event.Fields {
			if !validAttributeName(field.Attribute) {
				return nil, fmt.Errorf("%s has invalid messaging attribute %s", event.ID, field.Attribute)
			}
			if _, exists := fields[field.Attribute]; exists {
				return nil, fmt.Errorf("%s has duplicated messaging field %s", event.ID, field.Attribute)
			}
			selector, err := normalizedMessagingSelector(field.Source, field.Path)
			if err != nil {
				return nil, fmt.Errorf("%s field %s: %w", event.ID, field.Attribute, err)
			}
			identity := field.Source + "|" + selector
			if selectors[identity] {
				return nil, fmt.Errorf("%s has duplicated messaging selector %s", event.ID, field.Path)
			}
			selectors[identity] = true
			if strings.HasPrefix(event.Scope, "KAFKA_") && field.Source == "MESSAGE_PROPERTY" {
				return nil, fmt.Errorf("%s MESSAGE_PROPERTY is available only for JMS scopes", event.ID)
			}
			if !contains([]string{"STRING", "DOUBLE", "LONG", "BOOLEAN"}, field.Type) {
				return nil, fmt.Errorf("%s has unsupported messaging field type %s", event.ID, field.Type)
			}
			if len(field.Destinations) == 0 {
				return nil, fmt.Errorf("%s messaging fields require at least one destination", event.ID)
			}
			for _, destination := range field.Destinations {
				if !contains([]string{"SPAN", "LOG", "METRIC"}, destination) {
					return nil, fmt.Errorf("%s has unsupported messaging destination %s", event.ID, destination)
				}
			}
			if contains(field.Destinations, "METRIC") {
				if err := validateBoundedPolicy(field.ValuePolicy); err != nil {
					return nil, fmt.Errorf("%s metric dimension %s: %w", event.ID, field.Attribute, err)
				}
			}
			collectMessagingSelector(field.Source, selector, headerSelectors, propertySelectors)
			fields[field.Attribute] = eventFieldDefinition{
				Type:         field.Type,
				Destinations: field.Destinations,
				ValuePolicy:  field.ValuePolicy,
			}
		}
		for _, condition := range event.Conditions {
			selector, err := normalizedMessagingSelector(condition.Source, condition.Path)
			if err == nil {
				collectMessagingSelector(condition.Source, selector, headerSelectors, propertySelectors)
			}
		}
		if err := validateLogPolicy(event.ID, event.Log); err != nil {
			return nil, err
		}
		if !messagingEventHasEffectiveOutput(event, enabledMetricEvents) {
			return nil, fmt.Errorf(
				"%s must define at least one effective output: SPAN, enabled log, or enabled messaging metric",
				event.ID,
			)
		}
		eventFields[event.EventName] = fields
	}
	if len(headerSelectors) > 16 {
		return nil, fmt.Errorf("MESSAGE_HEADER selectors exceed their limit of 16 unique names")
	}
	if len(propertySelectors) > 16 {
		return nil, fmt.Errorf("MESSAGE_PROPERTY selectors exceed their limit of 16 unique names")
	}

	definitions := []metricDefinition{}
	for _, metric := range policy.MessagingMetricPolicies {
		if !metric.Enabled {
			continue
		}
		if isPolicyBlank(metric.ID) || seenPolicyIDs[metric.ID] {
			return nil, fmt.Errorf("messaging metric policies require unique IDs")
		}
		seenPolicyIDs[metric.ID] = true
		if metric.Instrument != "COUNTER" && metric.Instrument != "HISTOGRAM" {
			return nil, fmt.Errorf("%s messaging metrics support COUNTER or HISTOGRAM", metric.Name)
		}
		definition, err := validateMetricDefinition(
			owner,
			metric.Name,
			metric.Instrument,
			metric.Unit,
			metric.Buckets,
			seenNames,
			seenPrometheus,
		)
		if err != nil {
			return nil, err
		}
		fields, exists := eventFields[metric.EventName]
		if !exists {
			return nil, fmt.Errorf("%s eventName does not reference an enabled messaging event", metric.Name)
		}
		if isPolicyBlank(metric.ValueField) {
			if metric.Instrument != "COUNTER" {
				return nil, fmt.Errorf("%s requires a valueField for a value metric", metric.Name)
			}
		} else {
			field, exists := fields[metric.ValueField]
			if !exists || field.Type != "DOUBLE" && field.Type != "LONG" {
				return nil, fmt.Errorf("%s valueField must reference a numeric messaging field", metric.Name)
			}
		}
		if len(metric.Dimensions) > maxMetricDimensions {
			return nil, fmt.Errorf("%s dimensions exceeds its limit of %d", metric.Name, maxMetricDimensions)
		}
		seenDimensions := map[string]bool{}
		cardinality := 1
		for _, dimension := range metric.Dimensions {
			field, exists := fields[dimension]
			if seenDimensions[dimension] || !exists || !contains(field.Destinations, "METRIC") {
				return nil, fmt.Errorf(
					"%s dimension must reference a unique bounded messaging field: %s",
					metric.Name,
					dimension,
				)
			}
			seenDimensions[dimension] = true
			cardinality = boundedCardinalityProduct(cardinality, boundedValueCardinality(field.ValuePolicy))
		}
		if cardinality > maxMetricCardinality {
			return nil, fmt.Errorf("%s dimension cardinality exceeds its limit of %d", metric.Name, maxMetricCardinality)
		}
		definitions = append(definitions, definition)
	}
	return definitions, nil
}

func validateMessagingStaticAttributes(event messagingEventPolicy) error {
	if len(event.StaticAttributes) > 16 {
		return fmt.Errorf("%s staticAttributes exceeds its limit of 16", event.ID)
	}
	seen := map[string]bool{}
	for _, attribute := range event.StaticAttributes {
		if !validAttributeName(attribute.Attribute) || seen[attribute.Attribute] {
			return fmt.Errorf("%s has an invalid or duplicated static attribute %s", event.ID, attribute.Attribute)
		}
		seen[attribute.Attribute] = true
		if err := validateStaticAttributeValue(attribute); err != nil {
			return fmt.Errorf("%s: %w", event.ID, err)
		}
		if len(attribute.Destinations) == 0 {
			return fmt.Errorf("%s static attributes require at least one destination", event.ID)
		}
		for _, destination := range attribute.Destinations {
			if destination != "SPAN" && destination != "LOG" {
				return fmt.Errorf("%s static attributes support SPAN or LOG destination", event.ID)
			}
		}
	}
	return nil
}

func validateMessagingConditions(event messagingEventPolicy) error {
	if len(event.Conditions) == 0 || len(event.Conditions) > 16 {
		return fmt.Errorf("%s conditions requires between 1 and 16 AND conditions", event.ID)
	}
	hasDestination := false
	seen := map[string]bool{}
	for _, condition := range event.Conditions {
		if !contains(messagingSources, condition.Source) {
			return fmt.Errorf("%s has unsupported messaging condition source %s", event.ID, condition.Source)
		}
		if condition.Operator != "EQUALS" && condition.Operator != "IN" {
			return fmt.Errorf("%s condition operator must be EQUALS or IN", event.ID)
		}
		if len(condition.Values) == 0 || len(condition.Values) > 16 || condition.Operator == "EQUALS" && len(condition.Values) != 1 {
			return fmt.Errorf("%s EQUALS needs one value and IN supports at most 16 values", event.ID)
		}
		for _, value := range condition.Values {
			if strings.TrimSpace(value) == "" || len(value) > 256 {
				return fmt.Errorf("%s condition values are required and limited to 256 characters", event.ID)
			}
		}
		selector, err := normalizedMessagingSelector(condition.Source, condition.Path)
		if err != nil {
			return fmt.Errorf("%s condition: %w", event.ID, err)
		}
		identity := condition.Source + "|" + selector
		if seen[identity] {
			return fmt.Errorf("%s has duplicated messaging condition selector %s", event.ID, condition.Path)
		}
		seen[identity] = true
		if strings.HasPrefix(event.Scope, "KAFKA_") && condition.Source == "MESSAGE_PROPERTY" {
			return fmt.Errorf("%s MESSAGE_PROPERTY is available only for JMS scopes", event.ID)
		}
		hasDestination = hasDestination || condition.Source == "DESTINATION"
	}
	if !hasDestination {
		return fmt.Errorf("%s requires a DESTINATION condition", event.ID)
	}
	return nil
}

func normalizedMessagingSelector(source, value string) (string, error) {
	value = strings.TrimSpace(value)
	switch source {
	case "DESTINATION", "MESSAGE_KEY":
		if value != "" {
			return "", fmt.Errorf("%s does not use a selector path", source)
		}
		return "", nil
	case "MESSAGE_HEADER":
		value = strings.ToLower(value)
		if !validHeaderName(value) {
			return "", fmt.Errorf("invalid message header name %s", value)
		}
		return value, nil
	case "MESSAGE_PROPERTY":
		if !validMessagePropertyName(value) {
			return "", fmt.Errorf("invalid message property name %s", value)
		}
		return value, nil
	case "PAYLOAD":
		if !validJSONPath(value) {
			return "", fmt.Errorf("invalid payload JSON path %s", value)
		}
		return normalizeJSONPath(value), nil
	default:
		return "", fmt.Errorf("unsupported messaging source %s", source)
	}
}

func validMessagePropertyName(value string) bool {
	return len(value) <= 128 && validJavaIdentifier(value)
}

func collectMessagingSelector(source, selector string, headers, properties map[string]bool) {
	switch source {
	case "MESSAGE_HEADER":
		headers[selector] = true
	case "MESSAGE_PROPERTY":
		properties[selector] = true
	}
}

func validateLogPolicy(owner string, policy logPolicy) error {
	if policy.Enabled && (!contains([]string{"TRACE", "DEBUG", "INFO", "WARN", "ERROR"}, policy.Severity) || isPolicyBlank(policy.Body) || len(policy.Body) > 256) {
		return fmt.Errorf("%s has invalid log severity or body", owner)
	}
	return nil
}

func messagingEventHasEffectiveOutput(event messagingEventPolicy, enabledMetricEvents map[string]bool) bool {
	if event.Log.Enabled || enabledMetricEvents[event.EventName] {
		return true
	}
	for _, attribute := range event.StaticAttributes {
		if contains(attribute.Destinations, "SPAN") {
			return true
		}
	}
	for _, field := range event.Fields {
		if contains(field.Destinations, "SPAN") {
			return true
		}
	}
	return false
}

func validateMessagingSelectorAgainstDenylist(
	owner string,
	source string,
	selector string,
	checkHeader func(string, string) error,
	checkPath func(string, string, string) error,
) error {
	switch source {
	case "MESSAGE_HEADER":
		return checkHeader(owner, selector)
	case "MESSAGE_PROPERTY":
		return checkPath("MESSAGE_PROPERTY", owner, selector)
	case "PAYLOAD":
		return checkPath("BODY_PATH", owner, selector)
	default:
		return nil
	}
}
