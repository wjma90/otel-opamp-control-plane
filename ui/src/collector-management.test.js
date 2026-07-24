import assert from "node:assert/strict";
import test from "node:test";
import {
  buildManagedCollectorConfigs,
  collectorAgentMode,
  collectorDeactivateConfirmation,
  collectorDeactivateEndpoint,
  documentButtonLabel,
  collectorReportedVersions,
  filterManagedCollectorConfigs,
} from "./collector-management.js";

test("labels documents according to their actual target type", () => {
  assert.equal(documentButtonLabel("java-extension"), "Ver policy");
  assert.equal(documentButtonLabel("collector"), "Ver configuración");
  assert.equal(documentButtonLabel("collector-base"), "Ver configuración");
  assert.equal(documentButtonLabel(" COLLECTOR "), "Ver configuración");
});

const base = {
  ID: "collector-base.o11y-infra.gateway",
  Source: "ConfigMap",
  Revision: "sha256:base",
  Immutable: true,
  Behavior: "NOP",
  Services: ["gateway-supervisor"],
};

const version = (number, overrides = {}) => ({
  configId: "gateway-managed",
  ID: "gateway-managed",
  Version: number,
  Target: "collector",
  Action: "PUBLISHED",
  Active: true,
  Body: "exporters:\n  nop: {}\n",
  CreatedBy: "operator",
  UpdatedAt: `2026-07-${String(number).padStart(2, "0")}T12:00:00Z`,
  Selector: { Services: ["gateway-supervisor"], Attributes: {} },
  ...overrides,
});

const deployment = (overrides = {}) => ({
  ConfigID: "gateway-managed",
  Version: 1,
  Target: "collector",
  AgentUID: "gateway-1",
  Service: "gateway-supervisor",
  CurrentConfigID: "gateway-managed",
  CurrentConfigVersion: 1,
  CurrentConfigStatus: "APPLIED",
  ObservedStatus: "APPLIED",
  DesiredPresence: true,
  ConnectionStatus: "ONLINE",
  ...overrides,
});

test("identifies the immutable NOP base as the effective fallback", () => {
  const mode = collectorAgentMode({
    UID: "gateway-1",
    Service: "gateway-supervisor",
    EffectiveConfigOrigin: "BASE",
    BaseConfig: { ID: base.ID },
    ConfigStatus: "APPLIED",
  }, [base]);

  assert.equal(mode.baseActive, true);
  assert.equal(mode.managedActive, false);
  assert.equal(mode.liveStatus, "BASE_APPLIED");
  assert.equal(mode.effectiveLabel, "Base activa · NOP");
  assert.match(mode.fallbackLabel, /ConfigMap inmutable/);
});

test("shows a managed version while preserving its immutable fallback", () => {
  const mode = collectorAgentMode({
    UID: "gateway-1",
    Service: "gateway-supervisor",
    EffectiveConfigOrigin: "MANAGED",
    BaseConfig: { ID: base.ID },
    ConfigID: "gateway-managed",
    Version: 7,
    ConfigStatus: "APPLIED",
  }, [base]);

  assert.equal(mode.managedActive, true);
  assert.equal(mode.effectiveLabel, "Administrada · gateway-managed v7");
  assert.match(mode.fallbackLabel, new RegExp(base.ID));
});

test("shows Collector and Supervisor versions only when agents report attributes", () => {
  assert.deepEqual(collectorReportedVersions({
    Attributes: {
      "o11y.collector.version": "0.156.0",
      "o11y.supervisor.version": "0.4.1",
    },
  }), {
    collector: "0.156.0",
    supervisor: "0.4.1",
  });
  assert.deepEqual(collectorReportedVersions({}), {
    collector: "",
    supervisor: "",
  });
});

test("offers removal only for the latest active managed Collector config", () => {
  const [managed] = buildManagedCollectorConfigs(
    [version(1)],
    [deployment()],
    [base],
  );

  assert.equal(managed.active, true);
  assert.equal(managed.actionLabel, "Retirar config y usar base NOP");
  assert.deepEqual(managed.fallbackBases.map((item) => item.ID), [base.ID]);
  assert.match(collectorDeactivateConfirmation(managed), /ConfigMap base y el historial no se modificarán/);
  assert.equal(
    collectorDeactivateEndpoint("gateway a/b"),
    "/api/collector-configs/gateway%20a%2Fb/deactivate",
  );
});

test("tracks removal until the Supervisor confirms the base", () => {
  const withdrawn = version(2, {
    Action: "DEACTIVATED",
    Active: false,
    Body: "",
  });
  let [managed] = buildManagedCollectorConfigs(
    [version(1), withdrawn],
    [deployment({
      Version: 2,
      DesiredPresence: false,
      LiveStatus: "BASE_PENDING",
    })],
    [base],
  );
  assert.equal(managed.action, "NONE");
  assert.equal(managed.destinationSummary.status, "BASE_PENDING");
  assert.equal(managed.lastContentVersion.Version, 1);

  [managed] = buildManagedCollectorConfigs(
    [version(1), withdrawn],
    [deployment({
      Version: 2,
      DesiredPresence: false,
      LiveStatus: "BASE_APPLIED",
      CurrentConfigOrigin: "BASE",
    })],
    [base],
  );
  assert.equal(managed.destinationSummary.status, "BASE_APPLIED");
});

test("surfaces a failed base activation and keeps configurations searchable", () => {
  const withdrawn = version(2, { Action: "DEACTIVATED", Active: false });
  const [managed] = buildManagedCollectorConfigs(
    [version(1), withdrawn],
    [deployment({
      Version: 2,
      DesiredPresence: false,
      LiveStatus: "BASE_FAILED",
    })],
    [base],
  );

  assert.equal(managed.destinationSummary.status, "BASE_FAILED");
  assert.equal(filterManagedCollectorConfigs([managed], { query: "infra.gateway" }).length, 1);
  assert.equal(filterManagedCollectorConfigs([managed], { status: "BASE_FAILED" }).length, 1);
  assert.equal(filterManagedCollectorConfigs([managed], { service: "other" }).length, 0);
});

test("filters Collector configs with OR inside multiselect criteria and AND across criteria", () => {
  const configs = [
    {
      id: "gateway-active",
      lifecycleStatus: "ACTIVE",
      destinationSummary: { status: "APPLIED" },
      services: ["gateway-supervisor"],
      latestVersion: { CreatedBy: "alice", Hash: "gateway-hash" },
      fallbackBases: [],
      selector: { Attributes: {} },
    },
    {
      id: "monitoring-failed",
      lifecycleStatus: "ACTIVE",
      destinationSummary: { status: "BASE_FAILED" },
      services: ["monitoring-supervisor"],
      latestVersion: { CreatedBy: "bob", Hash: "monitoring-hash" },
      fallbackBases: [],
      selector: { Attributes: {} },
    },
    {
      id: "legacy-retired",
      lifecycleStatus: "DEACTIVATED",
      destinationSummary: { status: "BASE_APPLIED" },
      services: ["legacy-supervisor"],
      latestVersion: { CreatedBy: "carol", Hash: "legacy-hash" },
      fallbackBases: [],
      selector: { Attributes: {} },
    },
  ];

  assert.equal(filterManagedCollectorConfigs(configs, { status: [] }).length, 3);
  assert.deepEqual(
    filterManagedCollectorConfigs(configs, {
      status: ["APPLIED", "BASE_FAILED"],
      service: ["gateway-supervisor", "monitoring-supervisor"],
    }).map((config) => config.id).sort(),
    ["gateway-active", "monitoring-failed"],
  );
  assert.deepEqual(
    filterManagedCollectorConfigs(configs, {
      query: "legacy",
      status: ["ACTIVE", "BASE_APPLIED"],
      service: ["monitoring-supervisor", "legacy-supervisor"],
    }).map((config) => config.id),
    ["legacy-retired"],
  );
  assert.equal(
    filterManagedCollectorConfigs(configs, {
      query: "legacy",
      service: ["gateway-supervisor"],
    }).length,
    0,
  );
});

test("base descriptors never expose a lifecycle action", () => {
  assert.equal(collectorDeactivateConfirmation({ ...base, active: false }), "");
  assert.equal("action" in base, false);
});

test("reports full Collector coverage from live matches and excludes old replicas", () => {
  const [managed] = buildManagedCollectorConfigs(
    [version(1)],
    [
      deployment({ AgentUID: "gateway-current" }),
      deployment({
        AgentUID: "gateway-replaced",
        ConnectionStatus: "OFFLINE",
        LiveStatus: "APPLIED_OFFLINE",
        CoverageState: "HISTORICAL",
        CountsForLiveCoverage: false,
      }),
    ],
    [base],
  );

  assert.equal(managed.destinationSummary.status, "APPLIED");
  assert.equal(managed.destinationSummary.matched, 1);
  assert.equal(managed.destinationSummary.observed, 2);
  assert.equal(managed.destinationSummary.historical, 1);
});

test("reports no live Collector targets when only historical records remain", () => {
  const [managed] = buildManagedCollectorConfigs(
    [version(1)],
    [deployment({
      AgentUID: "gateway-gone",
      ConnectionStatus: "OFFLINE",
      LiveStatus: "APPLIED_OFFLINE",
      CoverageState: "HISTORICAL",
      CountsForLiveCoverage: false,
    })],
    [base],
  );

  assert.equal(managed.destinationSummary.status, "NO_LIVE_TARGETS");
});

test("keeps a live Collector fallback obligation in the aggregate", () => {
  const [managed] = buildManagedCollectorConfigs(
    [version(2)],
    [deployment({
      Version: 2,
      AgentUID: "gateway-old-selector",
      DesiredPresence: false,
      LiveStatus: "BASE_PENDING",
      CoverageState: "IN_SCOPE",
      CountsForLiveCoverage: true,
    })],
    [base],
  );

  assert.equal(managed.destinationSummary.status, "BASE_PENDING");
  assert.equal(managed.destinationSummary.desiredMatched, 0);
  assert.equal(managed.destinationSummary.removalMatched, 1);
});

test("reports current Collector matches applied after old targets confirm fallback", () => {
  const [managed] = buildManagedCollectorConfigs(
    [version(2)],
    [
      deployment({
        Version: 2,
        AgentUID: "gateway-current",
        CurrentConfigVersion: 2,
      }),
      deployment({
        Version: 2,
        AgentUID: "gateway-old-selector",
        DesiredPresence: false,
        LiveStatus: "BASE_APPLIED",
        CurrentConfigOrigin: "BASE",
        CoverageState: "IN_SCOPE",
        CountsForLiveCoverage: true,
      }),
    ],
    [base],
  );

  assert.equal(managed.destinationSummary.status, "APPLIED");
  assert.equal(managed.destinationSummary.desiredMatched, 1);
  assert.equal(managed.destinationSummary.removalMatched, 1);
  assert.equal(managed.destinationSummary.baseApplied, 1);
});

test("recognizes a direct managed replacement as a completed Collector removal", () => {
  const withdrawn = version(3, { Action: "DEACTIVATED", Active: false });
  const [managed] = buildManagedCollectorConfigs(
    [version(2), withdrawn],
    [deployment({
      Version: 3,
      AgentUID: "gateway-reassigned",
      DesiredPresence: false,
      ObservedStatus: "REMOVED",
      LiveStatus: "REMOVED",
      CurrentConfigID: "replacement-config",
      CurrentConfigVersion: 1,
      CurrentConfigOrigin: "MANAGED",
      CoverageState: "IN_SCOPE",
      CountsForLiveCoverage: true,
    })],
    [base],
  );

  assert.equal(managed.destinationSummary.status, "REMOVED");
  assert.equal(managed.destinationSummary.removalMatched, 1);
  assert.equal(managed.destinationSummary.removed, 1);
  assert.equal(managed.destinationSummary.basePending, 0);
});
