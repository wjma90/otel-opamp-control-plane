import test from "node:test";
import assert from "node:assert/strict";

import { displayMetricUnit } from "./metric-unit.js";

test("muestra anotaciones UCUM como una unidad literal y no como una variable", () => {
  assert.equal(displayMetricUnit("{PEN}"), "PEN");
  assert.equal(displayMetricUnit("{operation}"), "operation");
  assert.equal(displayMetricUnit("s"), "s");
  assert.equal(displayMetricUnit(""), "");
});
