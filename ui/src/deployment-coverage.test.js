import assert from "node:assert/strict";
import test from "node:test";
import {
  coverageStatusForDisplay,
  deploymentConfirmation,
  deploymentCoverage,
} from "./deployment-coverage.js";

test("prioritizes the explicit backend live-coverage contract", () => {
  assert.deepEqual(deploymentCoverage({
    ConnectionStatus: "OFFLINE",
    CoverageState: "IN_SCOPE",
    CountsForLiveCoverage: true,
  }), {
    counts: true,
    state: "IN_SCOPE",
    explicit: true,
  });
});

test("does not infer deleted or offline infrastructure from a legacy transport state", () => {
  assert.deepEqual(deploymentCoverage({ ConnectionStatus: "OFFLINE" }), {
    counts: false,
    state: "UNKNOWN",
    explicit: false,
  });
});

test("presents historical and degraded coverage separately from config status", () => {
  assert.equal(coverageStatusForDisplay({
    CoverageState: "HISTORICAL",
    CountsForLiveCoverage: false,
  }), "HISTORICAL");
  assert.equal(coverageStatusForDisplay({
    CoverageState: "IN_SCOPE_DEGRADED",
    CountsForLiveCoverage: false,
  }), "IN_SCOPE_DEGRADED");
});

test("uses the current live report as confirmation for synthetic terminal records", () => {
  const observedAt = "2026-07-20T15:00:00Z";
  assert.deepEqual(deploymentConfirmation({
    LiveStatus: "APPLIED",
    LastObservedAt: observedAt,
  }), {
    confirmed: true,
    at: observedAt,
    source: "LIVE_REPORT",
  });
  assert.deepEqual(deploymentConfirmation({
    LiveStatus: "REMOVAL_PENDING",
    LastObservedAt: observedAt,
  }), {
    confirmed: false,
    at: null,
    source: "NONE",
  });
});
