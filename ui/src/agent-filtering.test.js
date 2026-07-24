import assert from "node:assert/strict";
import test from "node:test";
import {
  filterFleetAgentRows,
  fleetAgentEffectiveStatus,
  fleetFilterValues,
  javaPolicySetEntries,
  projectFleetAgents,
} from "./agent-filtering.js";

const collectorBase = {
  ID: "collector-base.o11y-infra.gateway",
  Source: "ConfigMap/o11y/gateway-base:base.yaml",
  Revision: "sha256:base",
  Behavior: "NOP_ALL_SIGNALS",
  Services: ["gateway-supervisor", "monitoring-supervisor"],
};

const agents = [
  {
    UID: "gateway-1",
    Service: "gateway-supervisor",
    Kind: "collector",
    Transport: "http-poll",
    LiveStatus: "CONNECTED",
    ConfigStatus: "APPLIED",
    ConfigID: "gateway-managed",
    Version: 4,
    RemoteConfig: true,
    EffectiveConfigOrigin: "MANAGED",
    BaseConfig: { ID: collectorBase.ID },
    Attributes: {
      "cluster.name": "infra",
      "o11y.collector.version": "0.156.0",
      "o11y.supervisor.version": "0.4.1",
    },
  },
  {
    UID: "monitoring-1",
    Service: "monitoring-supervisor",
    Kind: "collector",
    Transport: "http-poll",
    LiveStatus: "STALE",
    ConfigStatus: "APPLIED",
    RemoteConfig: false,
    EffectiveConfigOrigin: "BASE",
    BaseConfig: { ID: collectorBase.ID },
    Attributes: { "collector.role": "cluster-monitoring" },
  },
  {
    UID: "exchange-a",
    Service: "exchange-service",
    Kind: "java-extension",
    Transport: "http-poll",
    LiveStatus: "ONLINE",
    ConfigStatus: "APPLIED",
    ConfigID: "java-policy-set",
    Version: 0,
    PolicyVersions: {
      "exchange-errors": 3,
      "exchange-amounts": 2,
    },
    Attributes: { "k8s.pod.name": "exchange-a" },
  },
  {
    UID: "rates-a",
    Service: "rates-service",
    Kind: "java-extension",
    Transport: "websocket",
    LiveStatus: "UNKNOWN",
    ConfigStatus: "FAILED",
    ConfigID: "java-policy-set",
    Version: 0,
    PolicyVersions: {},
    Attributes: { "deployment.environment.name": "local" },
  },
];

const rows = projectFleetAgents(agents, [collectorBase]);

test("projects the exact effective state displayed for managed, base and Java clients", () => {
  assert.equal(fleetAgentEffectiveStatus(agents[0], [collectorBase]), "APPLIED");
  assert.equal(fleetAgentEffectiveStatus(agents[1], [collectorBase]), "REPORT_ONLY");
  assert.equal(fleetAgentEffectiveStatus(agents[2], [collectorBase]), "APPLIED");
  assert.equal(fleetAgentEffectiveStatus(agents[3], [collectorBase]), "FAILED");
});

test("projects real Java policy versions instead of the technical PolicySet bundle", () => {
  assert.deepEqual(javaPolicySetEntries(agents[2]), [
    { id: "exchange-amounts", version: 2 },
    { id: "exchange-errors", version: 3 },
  ]);
  assert.deepEqual(javaPolicySetEntries(agents[3]), []);
  assert.deepEqual(javaPolicySetEntries(agents[0]), []);
});

test("treats empty selections as Todos and uses deterministic visual order", () => {
  const result = filterFleetAgentRows(rows, {});
  assert.deepEqual(result.map((row) => row.agent.UID), [
    "exchange-a",
    "gateway-1",
    "monitoring-1",
    "rates-a",
  ]);
});

test("combines multiple values inside one Fleet criterion with OR", () => {
  assert.deepEqual(
    filterFleetAgentRows(rows, {
      services: ["gateway-supervisor", "exchange-service"],
    }).map((row) => row.agent.UID),
    ["exchange-a", "gateway-1"],
  );
  assert.deepEqual(
    filterFleetAgentRows(rows, {
      availability: ["STALE", "UNKNOWN"],
    }).map((row) => row.agent.UID),
    ["monitoring-1", "rates-a"],
  );
  assert.deepEqual(
    filterFleetAgentRows(rows, {
      effectiveStatuses: ["APPLIED", "REPORT_ONLY"],
    }).map((row) => row.agent.UID),
    ["exchange-a", "gateway-1", "monitoring-1"],
  );
});

test("combines different Fleet criteria and search with AND", () => {
  assert.deepEqual(
    filterFleetAgentRows(rows, {
      services: ["gateway-supervisor", "monitoring-supervisor"],
      kinds: ["collector"],
      transports: ["http-poll"],
      availability: ["CONNECTED"],
      effectiveStatuses: ["APPLIED", "REPORT_ONLY"],
    }).map((row) => row.agent.UID),
    ["gateway-1"],
  );
  assert.deepEqual(
    filterFleetAgentRows(rows, {
      query: "  CLUSTER.NAME=INFRA ",
      kinds: ["collector"],
    }).map((row) => row.agent.UID),
    ["gateway-1"],
  );
  assert.deepEqual(
    filterFleetAgentRows(rows, {
      query: "cluster.name=infra",
      services: ["exchange-service"],
    }),
    [],
  );
});

test("searches UID, config, versions, fallback and resource attributes", () => {
  for (const [query, expected] of [
    ["gateway-1", ["gateway-1"]],
    ["gateway-managed", ["gateway-1"]],
    ["exchange-amounts v2", ["exchange-a"]],
    ["0.156.0", ["gateway-1"]],
    ["collector-base.o11y-infra.gateway", ["gateway-1", "monitoring-1"]],
    ["cluster.name=infra", ["gateway-1"]],
  ]) {
    assert.deepEqual(
      filterFleetAgentRows(rows, { query }).map((row) => row.agent.UID),
      expected,
      query,
    );
  }
});

test("derives sorted and unique options from the complete Fleet inventory", () => {
  assert.deepEqual(
    fleetFilterValues(rows, (row) => row.agent.Kind),
    ["collector", "java-extension"],
  );
  assert.deepEqual(
    fleetFilterValues(rows, (row) => row.effectiveStatus),
    ["APPLIED", "FAILED", "REPORT_ONLY"],
  );
});
