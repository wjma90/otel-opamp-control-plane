import assert from "node:assert/strict";
import test from "node:test";
import {
  deploymentStatusForVersion,
  deploymentStatusSummary,
  publicationActionLabel,
} from "./deployment-status.js";

const version = {
  configId: "gateway-config",
  Version: 1,
  Target: "collector",
  IsLatest: true,
  Selector: {
    Services: ["gateway-supervisor"],
  },
};

const agent = (overrides = {}) => ({
  UID: "collector-1",
  Kind: "collector",
  Service: "gateway-supervisor",
  ConnectionStatus: "ONLINE",
  ConfigStatus: "CONFIG_PENDING",
  ConfigID: "gateway-config",
  Version: 1,
  RemoteConfig: true,
  Attributes: {},
  ...overrides,
});

test("reports a rejected publication separately from its audit action", () => {
  const deployment = deploymentStatusForVersion(version, [
    agent({ ConfigStatus: "FAILED" }),
  ]);

  assert.equal(publicationActionLabel("PUBLISHED"), "Publicación registrada");
  assert.equal(deployment.status, "FAILED");
  assert.equal(deployment.applied, 0);
  assert.equal(deployment.failed, 1);
  assert.equal(
    deploymentStatusSummary(deployment),
    "0/1 destino(s) vivo(s) aplicada(s) · 1 rechazada(s)",
  );
});

test("reports an applied publication only after every destination confirms", () => {
  const deployment = deploymentStatusForVersion(version, [
    agent({ ConfigStatus: "APPLIED" }),
    agent({ UID: "collector-2", ConfigStatus: "APPLIED" }),
  ]);

  assert.equal(deployment.status, "APPLIED");
  assert.equal(deployment.applied, 2);
  assert.equal(deployment.matched, 2);
});

test("keeps the latest version pending until a matching agent reports it", () => {
  const deployment = deploymentStatusForVersion(version, [
    agent({ ConfigID: "older-config", Version: 9, ConfigStatus: "APPLIED" }),
  ]);

  assert.equal(deployment.status, "CONFIG_PENDING");
  assert.equal(deployment.notInUse, 1);
});

test("marks an older version as not in use", () => {
  const deployment = deploymentStatusForVersion(
    { ...version, IsLatest: false },
    [agent({ ConfigID: "gateway-config", Version: 2, ConfigStatus: "APPLIED" })],
  );

  assert.equal(deployment.status, "NOT_IN_USE");
});

test("labels restoration and deactivation without implying a rollback to empty", () => {
  assert.equal(publicationActionLabel("ROLLBACK"), "Restauración publicada");
  assert.equal(publicationActionLabel("DEACTIVATED"), "Retiro publicado");
});

test("reads a Java policy version from the acknowledged policy bundle", () => {
  const javaVersion = {
    configId: "exchange-business",
    Version: 3,
    Target: "java-extension",
    IsLatest: true,
    Selector: { Services: ["exchange-service"] },
  };
  const javaAgent = {
    ...agent(),
    UID: "exchange-pod-1",
    Kind: "java-extension",
    Service: "exchange-service",
    ConfigID: "java-policy-set",
    Version: 0,
    ConfigStatus: "APPLIED",
    RemoteConfig: false,
    PolicyVersions: { "exchange-business": 3, "exchange-risk": 1 },
  };

  const deployment = deploymentStatusForVersion(javaVersion, [javaAgent]);
  assert.equal(deployment.status, "APPLIED");
  assert.equal(deployment.applied, 1);
});

test("excludes stale historical agents from version coverage", () => {
  const deployment = deploymentStatusForVersion(version, [
    agent({ UID: "collector-current", LiveStatus: "CONNECTED", ConfigStatus: "APPLIED" }),
    agent({
      UID: "collector-old",
      LiveStatus: "UNREACHABLE",
      ConnectionStatus: "OFFLINE",
      ConfigStatus: "APPLIED",
    }),
  ]);

  assert.equal(deployment.status, "APPLIED");
  assert.equal(deployment.matched, 1);
  assert.equal(deployment.observed, 2);
});

test("does not claim offline infrastructure when no agent has a live OpAMP signal", () => {
  const deployment = deploymentStatusForVersion(version, [
    agent({ LiveStatus: "UNKNOWN", ConnectionStatus: "OFFLINE" }),
  ]);

  assert.equal(deployment.status, "NO_LIVE_TARGETS");
  assert.match(deploymentStatusSummary(deployment), /No hay destinos actualmente en línea/);
});
