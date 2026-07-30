import assert from "node:assert/strict";
import test from "node:test";

import {
  createTargetInventorySnapshot,
  filterVisibleTargetAgents,
  matchesTargetSelector,
} from "./target-selection.js";

const agent = (uid, service, attributes = {}) => ({
  UID: uid,
  Service: service,
  Attributes: {
    "service.name": service,
    ...attributes,
  },
});

const gateway = agent("gateway-uid", "gateway-supervisor", {
  "k8s.cluster.name": "infra",
});
const monitoring = agent("monitoring-uid", "monitoring-supervisor", {
  "k8s.cluster.name": "infra",
});

test("destination rows combine selectors and inventory search", () => {
  const agents = [monitoring, gateway];
  const selection = {
    selectedServices: ["gateway-supervisor"],
    selectorAttributes: [
      { key: "k8s.cluster.name", value: "infra" },
    ],
  };

  assert.equal(matchesTargetSelector(gateway, selection), true);
  assert.equal(matchesTargetSelector(monitoring, selection), false);
  assert.deepEqual(
    filterVisibleTargetAgents(agents, selection).map((item) => item.UID),
    ["gateway-uid"],
  );
  assert.deepEqual(
    filterVisibleTargetAgents(agents, {
      ...selection,
      query: "monitoring",
    }),
    [],
  );
});

test("an exact instance selection only leaves selected instances visible", () => {
  assert.deepEqual(
    filterVisibleTargetAgents([gateway, monitoring], {
      selectedAgentIds: ["monitoring-uid"],
    }).map((item) => item.UID),
    ["monitoring-uid"],
  );
});

test("inventory snapshots have a deterministic order and do not follow later arrays", () => {
  const liveAgents = [monitoring, gateway];
  const snapshot = createTargetInventorySnapshot(liveAgents);

  liveAgents.splice(0, liveAgents.length, agent("new-uid", "new-supervisor"));

  assert.deepEqual(
    snapshot.map((item) => item.Service),
    ["gateway-supervisor", "monitoring-supervisor"],
  );
});
