import assert from "node:assert/strict";
import test from "node:test";
import {
  formatReportedAttributeValue,
  reportedAttributeEntries,
} from "./agent-attributes.js";

test("sorts reported attributes by key without changing their values", () => {
  const entries = reportedAttributeEntries({
    "service.version": "0.156.0",
    "host.arch": "arm64",
    "collector.role": "central-gateway",
  });

  assert.deepEqual(entries, [
    ["collector.role", "central-gateway"],
    ["host.arch", "arm64"],
    ["service.version", "0.156.0"],
  ]);
});

test("returns no entries for absent or malformed attribute maps", () => {
  assert.deepEqual(reportedAttributeEntries(null), []);
  assert.deepEqual(reportedAttributeEntries([]), []);
  assert.deepEqual(reportedAttributeEntries("host.arch=arm64"), []);
});

test("formats scalar and structured attribute values readably", () => {
  assert.equal(formatReportedAttributeValue("arm64"), "arm64");
  assert.equal(formatReportedAttributeValue(10), "10");
  assert.equal(formatReportedAttributeValue(false), "false");
  assert.equal(formatReportedAttributeValue(null), "null");
  assert.equal(
    formatReportedAttributeValue({ namespace: "o11y", replicas: 2 }),
    '{"namespace":"o11y","replicas":2}',
  );
});
