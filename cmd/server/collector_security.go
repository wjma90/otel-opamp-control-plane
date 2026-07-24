package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

var allowedCollectorComponents = map[string]map[string]bool{
	"extensions": {
		"health_check":       true,
		"k8s_leader_elector": true,
	},
	"receivers": {
		"nop":          true,
		"otlp":         true,
		"filelog":      true,
		"hostmetrics":  true,
		"kubeletstats": true,
		"k8s_cluster":  true,
		"k8s_objects":  true,
		"prometheus":   true,
	},
	"processors": {
		"memory_limiter": true,
		"redaction":      true,
		"batch":          true,
		"k8s_attributes": true,
		"resource":       true,
	},
	"exporters": {
		"nop":                     true,
		"otlp":                    true,
		"otlphttp":                true,
		"otlp_grpc":               true,
		"otlp_http":               true,
		"prometheusremotewrite":   true,
		"prometheus_remote_write": true,
	},
}

var allowedCollectorExporterEndpoints = map[string]bool{
	"tempo.o11y-backends.svc.cluster.local:4317":                            true,
	"http://loki-gateway.o11y-backends.svc.cluster.local/otlp":              true,
	"http://prometheus-server.o11y-backends.svc.cluster.local/api/v1/write": true,
	"http://otel-gateway.o11y.svc.cluster.local:4318":                       true,
}

const allowedTargetAllocatorEndpoint = "http://otel-target-allocator.o11y.svc.cluster.local"

// validateCollectorConfigSafety is a semantic security boundary, not merely a
// YAML linter. Managed Collectors may hold Kubernetes read permissions and host
// log mounts, so remote configuration is deny-by-default and limited to the
// topology used by this installation.
func validateCollectorConfigSafety(body string) error {
	root, err := decodeSingleCollectorDocument(body)
	if err != nil {
		return fmt.Errorf("Collector YAML cannot be parsed safely: %w", err)
	}
	for key := range root {
		switch key {
		case "extensions", "receivers", "processors", "exporters", "connectors", "service":
		default:
			return fmt.Errorf("Collector top-level section %q is not allowed", key)
		}
	}

	componentsBySection := make(map[string]map[string]any, len(allowedCollectorComponents))
	for section, allowed := range allowedCollectorComponents {
		components, err := collectorMap(root[section], section)
		if err != nil {
			return err
		}
		componentsBySection[section] = components
		for id, raw := range components {
			componentType := strings.SplitN(id, "/", 2)[0]
			if !allowed[componentType] {
				return fmt.Errorf("Collector %s component type %q is not allowed", section, componentType)
			}
			if _, err := collectorMap(raw, section+"."+id); err != nil {
				return err
			}
		}
	}

	connectors, err := collectorMap(root["connectors"], "connectors")
	if err != nil {
		return err
	}
	if len(connectors) != 0 {
		return errors.New("Collector connectors are not allowed by the current security profile")
	}

	safeLeaderElectors := map[string]bool{}
	for id, raw := range componentsBySection["extensions"] {
		configuration, _ := collectorMap(raw, "extensions."+id)
		componentType := strings.SplitN(id, "/", 2)[0]
		if err := validateCollectorExtension(componentType, configuration); err != nil {
			return fmt.Errorf("extension %q: %w", id, err)
		}
		if componentType == "k8s_leader_elector" {
			safeLeaderElectors[id] = true
		}
	}

	safeRedactions := map[string]bool{}
	for id, raw := range componentsBySection["processors"] {
		configuration, _ := collectorMap(raw, "processors."+id)
		componentType := strings.SplitN(id, "/", 2)[0]
		if err := validateCollectorProcessor(componentType, configuration); err != nil {
			return fmt.Errorf("processor %q: %w", id, err)
		}
		if componentType == "redaction" {
			safeRedactions[id] = true
		}
	}

	for id, raw := range componentsBySection["receivers"] {
		configuration, _ := collectorMap(raw, "receivers."+id)
		componentType := strings.SplitN(id, "/", 2)[0]
		if err := validateCollectorReceiver(componentType, configuration, safeLeaderElectors); err != nil {
			return fmt.Errorf("receiver %q: %w", id, err)
		}
	}

	for id, raw := range componentsBySection["exporters"] {
		configuration, _ := collectorMap(raw, "exporters."+id)
		componentType := strings.SplitN(id, "/", 2)[0]
		if err := validateCollectorExporter(componentType, configuration); err != nil {
			return fmt.Errorf("exporter %q: %w", id, err)
		}
	}

	return validateCollectorService(root, componentsBySection["exporters"], safeRedactions)
}

func decodeSingleCollectorDocument(body string) (map[string]any, error) {
	decoder := yaml.NewDecoder(strings.NewReader(body))
	root := map[string]any{}
	if err := decoder.Decode(&root); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("multiple YAML documents are not allowed")
	}
	return root, nil
}

func collectorMap(value any, path string) (map[string]any, error) {
	if value == nil {
		return map[string]any{}, nil
	}
	mapping, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("Collector section %q must be a mapping", path)
	}
	return mapping, nil
}

func validateCollectorExtension(componentType string, configuration map[string]any) error {
	if componentType != "k8s_leader_elector" {
		return nil
	}
	if err := requireOnlyCollectorKeys(
		configuration,
		"k8s_leader_elector",
		"auth_type",
		"lease_name",
		"lease_namespace",
	); err != nil {
		return err
	}
	if configuration["auth_type"] != "serviceAccount" {
		return errors.New("auth_type must be serviceAccount")
	}
	leaseName, _ := configuration["lease_name"].(string)
	if !strings.HasPrefix(leaseName, "o11y-") || len(leaseName) > 63 {
		return errors.New("lease_name must be a non-empty o11y-* name of at most 63 characters")
	}
	if configuration["lease_namespace"] != "o11y" {
		return errors.New("lease_namespace must be o11y")
	}
	return nil
}

func validateCollectorProcessor(componentType string, configuration map[string]any) error {
	if componentType != "redaction" {
		return nil
	}
	if err := requireOnlyCollectorKeys(
		configuration,
		"redaction",
		"allow_all_keys",
		"redact_all_types",
		"blocked_key_patterns",
		"blocked_values",
		"summary",
	); err != nil {
		return err
	}
	if configuration["allow_all_keys"] != true {
		return errors.New("allow_all_keys must be true")
	}
	if configuration["redact_all_types"] != true {
		return errors.New("redact_all_types must be true")
	}
	blockedKeyPatterns, err := collectorNonEmptyStringList(
		configuration["blocked_key_patterns"],
		"redaction.blocked_key_patterns",
	)
	if err != nil || len(blockedKeyPatterns) == 0 {
		return errors.New("blocked_key_patterns must contain at least one non-empty pattern")
	}
	blockedValues, err := collectorNonEmptyStringList(
		configuration["blocked_values"],
		"redaction.blocked_values",
	)
	if err != nil || len(blockedValues) == 0 {
		return errors.New("blocked_values must contain at least one non-empty pattern")
	}
	if configuration["summary"] != "silent" {
		return errors.New("summary must be silent")
	}
	return nil
}

func validateCollectorReceiver(
	componentType string,
	configuration map[string]any,
	safeLeaderElectors map[string]bool,
) error {
	switch componentType {
	case "otlp":
		return validateOTLPReceiver(configuration)
	case "filelog":
		includes, err := collectorStringList(configuration["include"], "filelog.include")
		if err != nil {
			return err
		}
		if len(includes) != 1 || includes[0] != "/var/log/pods/*/*/*.log" {
			return errors.New("filelog.include is restricted to /var/log/pods/*/*/*.log")
		}
		excludes, err := collectorStringList(configuration["exclude"], "filelog.exclude")
		if err != nil {
			return err
		}
		for _, path := range excludes {
			if !strings.HasPrefix(path, "/var/log/pods/") {
				return errors.New("filelog.exclude paths must remain below /var/log/pods")
			}
		}
	case "hostmetrics":
		if rootPath, _ := configuration["root_path"].(string); rootPath != "/hostfs" {
			return errors.New("hostmetrics.root_path must be /hostfs")
		}
	case "kubeletstats":
		return validateKubeletStatsReceiver(configuration)
	case "k8s_cluster":
		if err := requireOnlyCollectorKeys(
			configuration,
			"k8s_cluster",
			"auth_type",
			"collection_interval",
			"k8s_leader_elector",
			"node_conditions_to_report",
			"allocatable_types_to_report",
		); err != nil {
			return err
		}
		if configuration["auth_type"] != "serviceAccount" {
			return errors.New("k8s_cluster.auth_type must be serviceAccount")
		}
		leaderElector, _ := configuration["k8s_leader_elector"].(string)
		if !safeLeaderElectors[leaderElector] {
			return errors.New("k8s_cluster must reference a configured safe k8s_leader_elector")
		}
	case "k8s_objects":
		return validateK8sObjectsReceiver(configuration, safeLeaderElectors)
	case "prometheus":
		if _, exists := configuration["config"]; exists {
			return errors.New("inline Prometheus scrape_configs are not allowed; use the Target Allocator")
		}
		targetAllocator, err := collectorMap(configuration["target_allocator"], "prometheus.target_allocator")
		if err != nil {
			return err
		}
		endpoint, _ := targetAllocator["endpoint"].(string)
		if strings.TrimSuffix(endpoint, "/") != allowedTargetAllocatorEndpoint {
			return errors.New("Prometheus receiver must use the in-cluster Target Allocator")
		}
	}
	return nil
}

func validateOTLPReceiver(configuration map[string]any) error {
	if err := requireOnlyCollectorKeys(configuration, "otlp", "protocols"); err != nil {
		return err
	}
	protocols, err := collectorMap(configuration["protocols"], "otlp.protocols")
	if err != nil {
		return err
	}
	if len(protocols) == 0 {
		return errors.New("otlp.protocols must configure grpc, http, or both")
	}
	allowedEndpoints := map[string]string{
		"grpc": "0.0.0.0:4317",
		"http": "0.0.0.0:4318",
	}
	for protocol, raw := range protocols {
		expectedEndpoint, allowed := allowedEndpoints[protocol]
		if !allowed {
			return fmt.Errorf("OTLP protocol %q is not allowed", protocol)
		}
		settings, err := collectorMap(raw, "otlp.protocols."+protocol)
		if err != nil {
			return err
		}
		if err := requireOnlyCollectorKeys(settings, "otlp.protocols."+protocol, "endpoint"); err != nil {
			return err
		}
		if settings["endpoint"] != expectedEndpoint {
			return fmt.Errorf("otlp.protocols.%s.endpoint must be %s", protocol, expectedEndpoint)
		}
	}
	return nil
}

func validateKubeletStatsReceiver(configuration map[string]any) error {
	if err := requireOnlyCollectorKeys(
		configuration,
		"kubeletstats",
		"auth_type",
		"collection_interval",
		"endpoint",
		"metric_groups",
	); err != nil {
		return err
	}
	if configuration["auth_type"] != "serviceAccount" {
		return errors.New("kubeletstats.auth_type must be serviceAccount")
	}
	if configuration["endpoint"] != "${env:K8S_NODE_IP}:10250" {
		return errors.New("kubeletstats.endpoint must be ${env:K8S_NODE_IP}:10250")
	}
	groups, err := collectorStringList(configuration["metric_groups"], "kubeletstats.metric_groups")
	if err != nil {
		return err
	}
	if !sameCollectorStringSet(groups, []string{"node", "pod", "container", "volume"}) {
		return errors.New("kubeletstats.metric_groups must contain exactly node, pod, container, and volume")
	}
	return nil
}

func validateK8sObjectsReceiver(configuration map[string]any, safeLeaderElectors map[string]bool) error {
	if err := requireOnlyCollectorKeys(
		configuration,
		"k8s_objects",
		"auth_type",
		"k8s_leader_elector",
		"objects",
	); err != nil {
		return err
	}
	if configuration["auth_type"] != "serviceAccount" {
		return errors.New("k8s_objects.auth_type must be serviceAccount")
	}
	leaderElector, _ := configuration["k8s_leader_elector"].(string)
	if !safeLeaderElectors[leaderElector] {
		return errors.New("k8s_objects must reference a configured safe k8s_leader_elector")
	}
	objects, ok := configuration["objects"].([]any)
	if !ok || len(objects) != 1 {
		return errors.New("k8s_objects.objects must contain exactly events.k8s.io/events in watch mode")
	}
	object, err := collectorMap(objects[0], "k8s_objects.objects[0]")
	if err != nil {
		return err
	}
	if err := requireOnlyCollectorKeys(object, "k8s_objects.objects[0]", "name", "group", "mode"); err != nil {
		return err
	}
	if object["name"] != "events" || object["group"] != "events.k8s.io" || object["mode"] != "watch" {
		return errors.New("k8s_objects may only watch events.k8s.io/events")
	}
	return nil
}

func validateCollectorExporter(componentType string, configuration map[string]any) error {
	if componentType == "nop" {
		return nil
	}
	endpoint, ok := configuration["endpoint"].(string)
	if !ok || strings.TrimSpace(endpoint) == "" {
		return errors.New("endpoint is required")
	}
	endpoint = strings.TrimSuffix(strings.TrimSpace(endpoint), "/")
	if allowedCollectorExporterEndpoints[endpoint] {
		return nil
	}
	return errors.New("endpoint is not an approved in-cluster destination")
}

func collectorStringList(value any, path string) ([]string, error) {
	if value == nil {
		return nil, nil
	}
	items, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a list", path)
	}
	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s entries must be strings", path)
		}
		result = append(result, text)
	}
	return result, nil
}

func collectorNonEmptyStringList(value any, path string) ([]string, error) {
	items, err := collectorStringList(value, path)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		if strings.TrimSpace(item) == "" {
			return nil, fmt.Errorf("%s entries must not be empty", path)
		}
	}
	return items, nil
}

func requireOnlyCollectorKeys(configuration map[string]any, path string, keys ...string) error {
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	for key := range configuration {
		if !allowed[key] {
			return fmt.Errorf("%s field %q is not allowed", path, key)
		}
	}
	return nil
}

func sameCollectorStringSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	wanted := make(map[string]bool, len(expected))
	for _, item := range expected {
		wanted[item] = true
	}
	seen := make(map[string]bool, len(actual))
	for _, item := range actual {
		if !wanted[item] || seen[item] {
			return false
		}
		seen[item] = true
	}
	return true
}

func validateCollectorService(
	root map[string]any,
	exporters map[string]any,
	safeRedactions map[string]bool,
) error {
	service, err := collectorMap(root["service"], "service")
	if err != nil {
		return err
	}
	if err := requireOnlyCollectorKeys(service, "service", "extensions", "pipelines", "telemetry"); err != nil {
		return err
	}
	if telemetry, exists := service["telemetry"]; exists {
		if err := validateSafeLocalTelemetry(telemetry); err != nil {
			return fmt.Errorf("service.telemetry: %w", err)
		}
	}
	pipelines, err := collectorMap(service["pipelines"], "service.pipelines")
	if err != nil {
		return err
	}
	for name, raw := range pipelines {
		pipeline, err := collectorMap(raw, "service.pipelines."+name)
		if err != nil {
			return err
		}
		pipelineExporters, err := collectorStringList(
			pipeline["exporters"],
			"service.pipelines."+name+".exporters",
		)
		if err != nil {
			return err
		}
		exportsToBackends := false
		for _, exporterID := range pipelineExporters {
			raw, exists := exporters[exporterID]
			if !exists {
				continue
			}
			configuration, _ := collectorMap(raw, "exporters."+exporterID)
			endpoint, _ := configuration["endpoint"].(string)
			if strings.Contains(endpoint, ".o11y-backends.svc.cluster.local") {
				exportsToBackends = true
				break
			}
		}
		if !exportsToBackends {
			continue
		}
		processors, err := collectorStringList(
			pipeline["processors"],
			"service.pipelines."+name+".processors",
		)
		if err != nil {
			return err
		}
		usesSafeRedaction := false
		for _, processor := range processors {
			if safeRedactions[processor] {
				usesSafeRedaction = true
				break
			}
		}
		if !usesSafeRedaction {
			return fmt.Errorf(
				"pipeline %q must reference a configured and safe redaction processor before exporting to backends",
				name,
			)
		}
	}
	return nil
}

func validateSafeLocalTelemetry(raw any) error {
	telemetry, err := collectorMap(raw, "service.telemetry")
	if err != nil {
		return err
	}
	if err := requireOnlyCollectorKeys(telemetry, "service.telemetry", "logs", "metrics"); err != nil {
		return err
	}
	if logsRaw, exists := telemetry["logs"]; exists {
		if err := validateSafeLocalTelemetryLogs(logsRaw); err != nil {
			return err
		}
	}
	if metricsRaw, exists := telemetry["metrics"]; exists {
		if err := validateSafeLocalTelemetryMetrics(metricsRaw); err != nil {
			return err
		}
	}
	return nil
}

func validateSafeLocalTelemetryLogs(raw any) error {
	logs, err := collectorMap(raw, "service.telemetry.logs")
	if err != nil {
		return err
	}
	if err := requireOnlyCollectorKeys(
		logs,
		"service.telemetry.logs",
		"level",
		"development",
		"encoding",
		"output_paths",
		"error_output_paths",
		"sampling",
	); err != nil {
		return err
	}
	if level, exists := logs["level"]; exists && !collectorStringAllowed(level, "debug", "info", "warn", "error") {
		return errors.New("logs.level is not allowed")
	}
	if development, exists := logs["development"]; exists {
		if _, ok := development.(bool); !ok {
			return errors.New("logs.development must be a boolean")
		}
	}
	if encoding, exists := logs["encoding"]; exists && !collectorStringAllowed(encoding, "console", "json") {
		return errors.New("logs.encoding must be console or json")
	}
	if paths, exists := logs["output_paths"]; exists {
		values, err := collectorStringList(paths, "service.telemetry.logs.output_paths")
		if err != nil || !sameCollectorStringSet(values, []string{"stdout"}) {
			return errors.New("logs.output_paths may only contain stdout")
		}
	}
	if paths, exists := logs["error_output_paths"]; exists {
		values, err := collectorStringList(paths, "service.telemetry.logs.error_output_paths")
		if err != nil || !sameCollectorStringSet(values, []string{"stderr"}) {
			return errors.New("logs.error_output_paths may only contain stderr")
		}
	}
	if samplingRaw, exists := logs["sampling"]; exists {
		if err := validateSafeTelemetrySampling(samplingRaw); err != nil {
			return err
		}
	}
	return nil
}

func validateSafeTelemetrySampling(raw any) error {
	sampling, err := collectorMap(raw, "service.telemetry.logs.sampling")
	if err != nil {
		return err
	}
	if err := requireOnlyCollectorKeys(sampling, "service.telemetry.logs.sampling", "enabled", "initial", "thereafter", "tick"); err != nil {
		return err
	}
	if enabled, exists := sampling["enabled"]; exists {
		if _, ok := enabled.(bool); !ok {
			return errors.New("logs.sampling.enabled must be a boolean")
		}
	}
	for _, field := range []string{"initial", "thereafter"} {
		if rawValue, exists := sampling[field]; exists {
			value, ok := rawValue.(int)
			if !ok || value < 0 || value > 1_000_000 {
				return fmt.Errorf("logs.sampling.%s must be an integer between 0 and 1000000", field)
			}
		}
	}
	if tickRaw, exists := sampling["tick"]; exists {
		tick, ok := tickRaw.(string)
		duration, parseErr := time.ParseDuration(tick)
		if !ok || parseErr != nil || duration < time.Second || duration > 10*time.Minute {
			return errors.New("logs.sampling.tick must be between 1s and 10m")
		}
	}
	return nil
}

func validateSafeLocalTelemetryMetrics(raw any) error {
	metrics, err := collectorMap(raw, "service.telemetry.metrics")
	if err != nil {
		return err
	}
	if err := requireOnlyCollectorKeys(metrics, "service.telemetry.metrics", "level", "readers"); err != nil {
		return err
	}
	if level, exists := metrics["level"]; exists && !collectorStringAllowedFold(level, "none", "basic", "normal", "detailed") {
		return errors.New("metrics.level is not allowed")
	}
	readersRaw, exists := metrics["readers"]
	if !exists {
		return nil
	}
	readers, ok := readersRaw.([]any)
	if !ok {
		return errors.New("metrics.readers must be a list")
	}
	for index, readerRaw := range readers {
		reader, err := collectorMap(readerRaw, fmt.Sprintf("service.telemetry.metrics.readers[%d]", index))
		if err != nil {
			return err
		}
		if err := requireOnlyCollectorKeys(reader, "service.telemetry.metrics.reader", "pull"); err != nil {
			return err
		}
		pull, err := collectorMap(reader["pull"], "service.telemetry.metrics.reader.pull")
		if err != nil {
			return err
		}
		if err := requireOnlyCollectorKeys(pull, "service.telemetry.metrics.reader.pull", "exporter"); err != nil {
			return err
		}
		exporter, err := collectorMap(pull["exporter"], "service.telemetry.metrics.reader.pull.exporter")
		if err != nil {
			return err
		}
		if err := requireOnlyCollectorKeys(exporter, "service.telemetry.metrics.reader.pull.exporter", "prometheus"); err != nil {
			return err
		}
		prometheus, err := collectorMap(exporter["prometheus"], "service.telemetry.metrics.reader.pull.exporter.prometheus")
		if err != nil {
			return err
		}
		if err := requireOnlyCollectorKeys(
			prometheus,
			"service.telemetry.metrics.reader.pull.exporter.prometheus",
			"host",
			"port",
			"without_scope_info",
			"without_type_suffix",
		); err != nil {
			return err
		}
		if !collectorStringAllowed(prometheus["host"], "localhost", "127.0.0.1") || prometheus["port"] != 8888 {
			return errors.New("telemetry Prometheus reader must listen on localhost:8888")
		}
		for _, field := range []string{"without_scope_info", "without_type_suffix"} {
			if rawValue, exists := prometheus[field]; exists {
				if _, ok := rawValue.(bool); !ok {
					return fmt.Errorf("telemetry Prometheus %s must be a boolean", field)
				}
			}
		}
	}
	return nil
}

func collectorStringAllowed(value any, allowed ...string) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	for _, candidate := range allowed {
		if text == candidate {
			return true
		}
	}
	return false
}

func collectorStringAllowedFold(value any, allowed ...string) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	for _, candidate := range allowed {
		if strings.EqualFold(text, candidate) {
			return true
		}
	}
	return false
}
