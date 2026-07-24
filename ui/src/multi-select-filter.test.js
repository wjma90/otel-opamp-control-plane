import assert from "node:assert/strict";
import test from "node:test";
import {
  matchesAnySelection,
  normalizeSelection,
  reconcileSelection,
  selectionSummary,
  toggleSelection,
} from "./multi-select-filter.js";

const options = [
  { value: "APPLIED", label: "Aplicadas" },
  { value: "FAILED", label: "Rechazadas" },
  { value: "PENDING", label: "Pendientes" },
];

test("normalizes string and array selections while keeping ALL as an empty list", () => {
  assert.deepEqual(normalizeSelection(undefined), []);
  assert.deepEqual(normalizeSelection(""), []);
  assert.deepEqual(normalizeSelection(" APPLIED "), ["APPLIED"]);
  assert.deepEqual(
    normalizeSelection(["APPLIED", "", "FAILED", "APPLIED"]),
    ["APPLIED", "FAILED"],
  );
});

test("reconciles dynamic selections with their currently available options", () => {
  assert.deepEqual(reconcileSelection([], options), []);
  assert.deepEqual(
    reconcileSelection(["APPLIED", "REMOVED", "FAILED"], options),
    ["APPLIED", "FAILED"],
  );
});

test("toggles one or many values and returns to ALL after removing the last one", () => {
  let selection = toggleSelection([], "APPLIED", true);
  assert.deepEqual(selection, ["APPLIED"]);

  selection = toggleSelection(selection, "FAILED", true);
  assert.deepEqual(selection, ["APPLIED", "FAILED"]);

  selection = toggleSelection(selection, "APPLIED", false);
  assert.deepEqual(selection, ["FAILED"]);

  selection = toggleSelection(selection, "FAILED", false);
  assert.deepEqual(selection, []);
  assert.deepEqual(toggleSelection(["APPLIED"], "", true), []);
});

test("matches ALL, one candidate or any candidate using OR semantics", () => {
  assert.equal(matchesAnySelection([], "FAILED"), true);
  assert.equal(matchesAnySelection(["APPLIED", "FAILED"], "FAILED"), true);
  assert.equal(matchesAnySelection(["APPLIED", "FAILED"], ["PENDING", "APPLIED"]), true);
  assert.equal(matchesAnySelection(["APPLIED", "FAILED"], ["PENDING"]), false);
});

test("summarizes ALL, one labeled selection and multiple selections", () => {
  assert.equal(selectionSummary([], options, "Todos los estados"), "Todos los estados");
  assert.equal(selectionSummary(["APPLIED"], options), "Aplicadas");
  assert.equal(selectionSummary(["UNKNOWN"], options), "UNKNOWN");
  assert.equal(selectionSummary(["APPLIED", "FAILED"], options), "2 seleccionados");
});
