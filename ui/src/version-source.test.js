import assert from "node:assert/strict";
import test from "node:test";
import {
  filterStoredVersions,
  flattenStoredVersions,
  sortDestinationRecords,
  storedVersionSelectorSummary,
} from "./version-source.js";

const versions = [
  {
    configId: "exchange-approved",
    Version: 2,
    Target: "java-extension",
    UpdatedAt: "2026-07-21T10:00:00Z",
    Selector: {
      Services: ["exchange-service"],
      Attributes: {
        "deployment.environment.name": "local",
        "service.namespace": "cambistapp",
      },
    },
  },
  {
    configId: "gateway-config",
    Version: 4,
    Target: "collector",
    UpdatedAt: "2026-07-21T11:00:00Z",
    Selector: {
      InstanceUIDs: ["gateway-instance-a"],
      Attributes: { "collector.role": "central-gateway" },
    },
  },
  {
    configId: "exchange-approved",
    Version: 1,
    Target: "java-extension",
    UpdatedAt: "2026-07-20T10:00:00Z",
    Selector: { Services: ["exchange-service"] },
  },
];

test("searches stored versions by name, version and selector tokens", () => {
  assert.deepEqual(
    filterStoredVersions(versions, "exchange v2").map((item) => item.Version),
    [2],
  );
  assert.deepEqual(
    filterStoredVersions(versions, "service.namespace=cambistapp").map((item) => item.configId),
    ["exchange-approved"],
  );
  assert.deepEqual(
    filterStoredVersions(versions, "gateway-instance-a collector.role").map((item) => item.configId),
    ["gateway-config"],
  );
  assert.deepEqual(filterStoredVersions(versions, "missing"), []);
});

test("returns selector details in deterministic order", () => {
  assert.deepEqual(storedVersionSelectorSummary(versions[0]), {
    services: ["exchange-service"],
    instances: [],
    attributes: [
      "deployment.environment.name=local",
      "service.namespace=cambistapp",
    ],
  });
});

test("flattens config maps and marks the numeric latest version", () => {
  const flattened = flattenStoredVersions({
    "exchange-approved": [versions[0], versions[2]],
    "gateway-config": [versions[1]],
  });
  assert.deepEqual(
    flattened.map((item) => `${item.configId}:v${item.Version}:${item.IsLatest}`),
    [
      "gateway-config:v4:true",
      "exchange-approved:v2:true",
      "exchange-approved:v1:false",
    ],
  );
});

test("keeps destination rows stable when observation order changes", () => {
  const records = [
    { ConfigID: "policy-b", Version: 1, Service: "rates", AgentUID: "uid-2" },
    { ConfigID: "policy-a", Version: 2, Service: "exchange", AgentUID: "uid-3" },
    { ConfigID: "policy-a", Version: 2, Service: "exchange", AgentUID: "uid-1" },
  ];
  const expected = ["uid-1", "uid-3", "uid-2"];
  assert.deepEqual(sortDestinationRecords(records).map((item) => item.AgentUID), expected);
  assert.deepEqual(sortDestinationRecords(records.reverse()).map((item) => item.AgentUID), expected);
});
