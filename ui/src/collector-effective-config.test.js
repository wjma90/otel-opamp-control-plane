import assert from "node:assert/strict";
import test from "node:test";
import {
  collectorConfigId,
  sanitizeEffectiveCollectorConfig,
} from "./collector-effective-config.js";

test("removes Supervisor-injected OpAMP and process identity", () => {
  const effective = `extensions:
    health_check:
        endpoint: 0.0.0.0:13133
        grpc: null
        http: null
    opamp:
        instance_uid: 019f759b-058f-785a-b31b-999a1962e04c
        server:
            ws:
                endpoint: ws://127.0.0.1:37923/v1/opamp
service:
    extensions:
        - health_check
        - opamp
    telemetry:
        logs:
            level: info
        resource:
            attributes:
                - name: host.name
                  value: otel-gateway-old-pod
                - name: service.instance.id
                  value: 019f759b-058f-785a-b31b-999a1962e04c
            schema_url: https://opentelemetry.io/schemas/1.40.0
`;

  const sanitized = sanitizeEffectiveCollectorConfig(effective);

  assert.deepEqual(sanitized.removed, [
    "service.telemetry.resource",
    "extensions.opamp",
    "service.extensions[opamp]",
    "extensions.health_check.http=null",
    "extensions.health_check.grpc=null",
  ]);
  assert.doesNotMatch(sanitized.body, /instance_uid|service\.instance\.id|127\.0\.0\.1/);
  assert.match(sanitized.body, /health_check/);
  assert.doesNotMatch(sanitized.body, /grpc: null|http: null/);
  assert.match(sanitized.body, /logs:\n\s+level: info/);
});

test("proposes a stable ID from cluster and collector role", () => {
  assert.equal(
    collectorConfigId({
      Service: "o11y-infra-gateway-supervisor",
      Attributes: {
        "k8s.cluster.name": "o11y-infra",
        "collector.role": "central-gateway",
      },
    }),
    "o11y-infra-central-gateway-config",
  );
});
