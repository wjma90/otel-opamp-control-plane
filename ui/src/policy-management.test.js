import assert from "node:assert/strict";
import test from "node:test";
import {
  buildManagedPolicies,
  deploymentRecordStatus,
  filterManagedPolicies,
  managedPolicyDestinationSummary,
  policyLifecycleConfirmation,
  policyLifecycleEndpoint,
} from "./policy-management.js";

const version = (id, number, overrides = {}) => ({
  configId: id,
  ID: id,
  Version: number,
  Target: "java-extension",
  Action: "PUBLISHED",
  CreatedBy: "admin",
  UpdatedAt: `2026-07-${String(number).padStart(2, "0")}T12:00:00Z`,
  Selector: { Services: ["exchange-service"], Attributes: {} },
  ...overrides,
});

const deployment = (id, number, uid, overrides = {}) => ({
  ConfigID: id,
  Version: number,
  Target: "java-extension",
  AgentUID: uid,
  Service: "exchange-service",
  CurrentConfigID: "java-policy-set",
  CurrentConfigVersion: 0,
  CurrentConfigStatus: "APPLIED",
  ObservedStatus: "APPLIED",
  LiveStatus: "APPLIED",
  BundleHash: "bundle-sha256",
  DesiredPresence: true,
  ConnectionStatus: "ONLINE",
  ...overrides,
});

test("keeps multiple policies for the same microservice as separate managed rows", () => {
  const policies = buildManagedPolicies([
    version("exchange-risk", 1),
    version("exchange-business", 1),
  ], []);

  assert.deepEqual(policies.map((policy) => policy.id).sort(), [
    "exchange-business",
    "exchange-risk",
  ]);
  assert.ok(policies.every((policy) => policy.services.includes("exchange-service")));
});

test("offers the immediate previous content version only from the active policy", () => {
  const [policy] = buildManagedPolicies([
    version("exchange-business", 1),
    version("exchange-business", 2),
  ], []);

  assert.equal(policy.active, true);
  assert.equal(policy.action, "REVERT");
  assert.equal(policy.previousVersion.Version, 1);
  assert.equal(policy.actionLabel, "Restaurar contenido de v1");
  assert.match(policyLifecycleConfirmation(policy), /Se publicará una versión nueva/);
});

test("walks the original published lineage after a rollback instead of oscillating", () => {
  const [policy] = buildManagedPolicies([
    version("exchange-business", 1, { SourceVersion: 1 }),
    version("exchange-business", 2, { SourceVersion: 2 }),
    version("exchange-business", 3, {
      Action: "ROLLBACK",
      SourceVersion: 1,
      Active: true,
    }),
  ], []);

  assert.equal(policy.active, true);
  assert.equal(policy.previousVersion, null);
  assert.equal(policy.action, "DEACTIVATE");
  assert.equal(policy.actionLabel, "Retirar policy");
});

test("offers a clear removal instead of rollback to empty for the first active version", () => {
  const [policy] = buildManagedPolicies([version("exchange-business", 1)], []);

  assert.equal(policy.action, "DEACTIVATE");
  assert.equal(policy.actionLabel, "Retirar policy");
  assert.match(policyLifecycleConfirmation(policy), /instancias actuales y futuras/);
  assert.doesNotMatch(policyLifecycleConfirmation(policy), /rollback|vacío/i);
});

test("shows a deactivated policy without another destructive action", () => {
  const [policy] = buildManagedPolicies([
    version("exchange-business", 1),
    version("exchange-business", 2, { Action: "DEACTIVATED", Body: "" }),
  ], []);

  assert.equal(policy.active, false);
  assert.equal(policy.lifecycleStatus, "DEACTIVATED");
  assert.equal(policy.action, "NONE");
  assert.equal(policy.destinationSummary.status, "DEACTIVATED");
});

test("honors the persisted active flag and reports live removal acknowledgements", () => {
  const records = [
    deployment("exchange-business", 2, "pod-a", {
      DesiredPresence: false,
      ObservedStatus: "REMOVED",
      LiveStatus: "REMOVED",
    }),
    deployment("exchange-business", 2, "pod-b", {
      DesiredPresence: false,
      ObservedStatus: "REMOVAL_PENDING",
      LiveStatus: "REMOVAL_PENDING",
    }),
  ];
  const [policy] = buildManagedPolicies([
    version("exchange-business", 1, { Active: true }),
    version("exchange-business", 2, {
      Action: "ROLLBACK",
      Active: false,
    }),
  ], records);

  assert.equal(policy.active, false);
  assert.equal(policy.destinationSummary.status, "REMOVAL_PENDING");
  assert.equal(policy.destinationSummary.removed, 1);
  assert.equal(policy.destinationSummary.removalPending, 1);
  assert.match(
    managedPolicyDestinationSummary(policy.destinationSummary),
    /1 retiro\(s\) pendiente\(s\)/,
  );
});

test("aggregates live state per destination and keeps its details searchable", () => {
  const records = [
    deployment("exchange-business", 2, "pod-a"),
    deployment("exchange-business", 2, "pod-b", {
      ConnectionStatus: "OFFLINE",
      LiveStatus: "APPLIED_OFFLINE",
      CoverageState: "HISTORICAL",
      CountsForLiveCoverage: false,
    }),
    deployment("exchange-business", 2, "pod-c", {
      CurrentConfigStatus: "FAILED",
      LiveStatus: "FAILED",
    }),
  ];
  const [policy] = buildManagedPolicies([
    version("exchange-business", 1),
    version("exchange-business", 2),
  ], records);

  assert.equal(policy.destinationSummary.status, "PARTIAL");
  assert.equal(policy.destinationSummary.applied, 1);
  assert.equal(policy.destinationSummary.appliedOffline, 1);
  assert.equal(policy.destinationSummary.failed, 1);
  assert.match(
    managedPolicyDestinationSummary(policy.destinationSummary),
    /1 registro\(s\) histórico\(s\) excluido\(s\)/,
  );
  assert.equal(filterManagedPolicies([policy], { query: "exchange-service" }).length, 1);
  assert.equal(filterManagedPolicies([policy], { status: "ACTIVE" }).length, 1);
});

test("filters policies with OR inside multiselect criteria and AND across criteria", () => {
  const policies = buildManagedPolicies([
    version("exchange-active", 1),
    version("rates-active", 1, {
      Selector: { Services: ["rates-service"], Attributes: {} },
    }),
    version("legacy-retired", 1, {
      Active: false,
      Action: "DEACTIVATED",
      Selector: { Services: ["legacy-service"], Attributes: {} },
    }),
  ], []);

  assert.equal(filterManagedPolicies(policies, { status: [] }).length, 3);
  assert.deepEqual(
    filterManagedPolicies(policies, {
      status: ["ACTIVE", "DEACTIVATED"],
      service: ["exchange-service", "legacy-service"],
    }).map((policy) => policy.id).sort(),
    ["exchange-active", "legacy-retired"],
  );
  assert.deepEqual(
    filterManagedPolicies(policies, {
      query: "rates",
      status: ["ACTIVE", "DEACTIVATED"],
      service: ["exchange-service", "rates-service"],
    }).map((policy) => policy.id),
    ["rates-active"],
  );
  assert.equal(
    filterManagedPolicies(policies, {
      query: "rates",
      service: ["exchange-service"],
    }).length,
    0,
  );
});

test("preserves stale application and pending replacement as distinct live states", () => {
  const stale = deployment("exchange-business", 2, "pod-stale", {
    ConnectionStatus: "DEGRADED",
    LiveStatus: "APPLIED_STALE",
  });
  const pendingReplacement = deployment("exchange-business", 2, "pod-pending", {
    CurrentConfigStatus: "CONFIG_PENDING",
    CurrentPolicyVersion: 1,
    LiveStatus: "APPLIED_PENDING_REPLACEMENT",
  });

  assert.equal(deploymentRecordStatus(stale), "APPLIED_STALE");
  assert.equal(
    deploymentRecordStatus(pendingReplacement),
    "APPLIED_PENDING_REPLACEMENT",
  );

  const [policy] = buildManagedPolicies([
    version("exchange-business", 1),
    version("exchange-business", 2),
  ], [stale, pendingReplacement]);
  assert.equal(policy.destinationSummary.status, "APPLIED_PENDING_REPLACEMENT");
  assert.equal(policy.destinationSummary.applied, 0);
  assert.equal(policy.destinationSummary.appliedStale, 1);
  assert.equal(policy.destinationSummary.pendingReplacement, 1);
  assert.match(
    managedPolicyDestinationSummary(policy.destinationSummary),
    /confirmación\(es\) histórica\(s\) degradada\(s\)/,
  );
  assert.match(
    managedPolicyDestinationSummary(policy.destinationSummary),
    /reemplazo\(s\) pendiente\(s\)/,
  );
});

test("reports full live coverage when every current match applied despite old replicas", () => {
  const records = [
    deployment("exchange-business", 1, "pod-current"),
    deployment("exchange-business", 1, "pod-replaced", {
      ConnectionStatus: "OFFLINE",
      LiveStatus: "APPLIED_OFFLINE",
      CoverageState: "HISTORICAL",
      CountsForLiveCoverage: false,
    }),
    deployment("exchange-business", 1, "pod-stale", {
      ConnectionStatus: "DEGRADED",
      LiveStatus: "APPLIED_STALE",
      CoverageState: "IN_SCOPE_DEGRADED",
      CountsForLiveCoverage: false,
    }),
  ];

  const [policy] = buildManagedPolicies(
    [version("exchange-business", 1)],
    records,
  );

  assert.equal(policy.destinationSummary.status, "APPLIED");
  assert.equal(policy.destinationSummary.matched, 1);
  assert.equal(policy.destinationSummary.observed, 3);
  assert.equal(policy.destinationSummary.historical, 1);
  assert.equal(policy.destinationSummary.degraded, 1);
  assert.match(managedPolicyDestinationSummary(policy.destinationSummary), /1\/1 destino/);
  assert.doesNotMatch(managedPolicyDestinationSummary(policy.destinationSummary), /parcial/i);
});

test("does not call historical policy records an offline live destination", () => {
  const [policy] = buildManagedPolicies(
    [version("exchange-business", 1)],
    [deployment("exchange-business", 1, "pod-gone", {
      ConnectionStatus: "OFFLINE",
      LiveStatus: "APPLIED_OFFLINE",
      CoverageState: "HISTORICAL",
      CountsForLiveCoverage: false,
    })],
  );

  assert.equal(policy.destinationSummary.status, "NO_LIVE_TARGETS");
  assert.match(
    managedPolicyDestinationSummary(policy.destinationSummary),
    /registro\(s\) histórico\(s\)/,
  );
});

test("treats an unconfirmed replacement as pending even with a prior policy version", () => {
  const record = deployment("exchange-business", 2, "pod-a", {
    CurrentConfigStatus: "CONFIG_PENDING",
    CurrentPolicyVersion: 1,
    PolicyPresent: true,
    LiveStatus: "APPLIED_PENDING_REPLACEMENT",
  });
  const [policy] = buildManagedPolicies([
    version("exchange-business", 1),
    version("exchange-business", 2),
  ], [record]);

  assert.equal(policy.destinationSummary.status, "APPLIED_PENDING_REPLACEMENT");
  assert.equal(policy.destinationSummary.applied, 0);
  assert.equal(policy.destinationSummary.pendingReplacement, 1);
});

test("derives destination live status and URL-encodes the lifecycle endpoint", () => {
  assert.equal(deploymentRecordStatus(deployment("policy a/b", 1, "pod-a")), "APPLIED");
  assert.equal(
    deploymentRecordStatus(deployment("policy a/b", 1, "pod-a", {
      DesiredPresence: false,
      ObservedStatus: "REMOVAL_PENDING",
      LiveStatus: "REMOVAL_PENDING",
    })),
    "REMOVAL_PENDING",
  );
  assert.equal(
    policyLifecycleEndpoint("policy a/b"),
    "/api/policies/policy%20a%2Fb/rollback",
  );
});

test("uses Collector base activation as the live removal acknowledgement", () => {
  const collectorRecord = {
    ...deployment("gateway-config", 3, "gateway-1"),
    Target: "collector",
    DesiredPresence: false,
    LiveStatus: "BASE_PENDING",
  };
  assert.equal(deploymentRecordStatus(collectorRecord), "BASE_PENDING");

  assert.equal(deploymentRecordStatus({
    ...collectorRecord,
    LiveStatus: "",
    CurrentConfigOrigin: "BASE",
    CurrentConfigStatus: "APPLIED",
  }), "BASE_APPLIED");

  assert.equal(deploymentRecordStatus({
    ...collectorRecord,
    LiveStatus: "BASE_FAILED",
  }), "BASE_FAILED");
});

test("keeps a live selector-removal obligation in the aggregate", () => {
  const pendingRemoval = deployment("exchange-business", 2, "pod-old-selector", {
    DesiredPresence: false,
    ObservedStatus: "REMOVAL_PENDING",
    LiveStatus: "REMOVAL_PENDING",
    CoverageState: "IN_SCOPE",
    CountsForLiveCoverage: true,
    Selector: { Services: ["new-service"], Attributes: { region: "east" } },
  });
  const [policy] = buildManagedPolicies([
    version("exchange-business", 2, {
      Selector: { Services: ["new-service"], Attributes: { region: "east" } },
    }),
  ], [pendingRemoval]);

  assert.equal(policy.destinationSummary.status, "REMOVAL_PENDING");
  assert.equal(policy.destinationSummary.desiredMatched, 0);
  assert.equal(policy.destinationSummary.removalMatched, 1);
  assert.equal(policy.destinationSummary.removalPending, 1);
});

test("allows full current selector coverage only after the old target is removed", () => {
  const records = [
    deployment("exchange-business", 2, "pod-current"),
    deployment("exchange-business", 2, "pod-old-selector", {
      DesiredPresence: false,
      ObservedStatus: "REMOVED",
      LiveStatus: "REMOVED",
      CoverageState: "IN_SCOPE",
      CountsForLiveCoverage: true,
    }),
  ];
  const [policy] = buildManagedPolicies([version("exchange-business", 2)], records);

  assert.equal(policy.destinationSummary.status, "APPLIED");
  assert.equal(policy.destinationSummary.desiredMatched, 1);
  assert.equal(policy.destinationSummary.removalMatched, 1);
  assert.equal(policy.destinationSummary.removed, 1);
});
