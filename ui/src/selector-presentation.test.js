import assert from "node:assert/strict";
import test from "node:test";
import { selectorDetails } from "./selector-presentation.js";

test("describes a dynamic selector without confusing observed destinations with scope", () => {
  const details = selectorDetails({
    Services: ["exchange-service"],
    Attributes: {
      "deployment.environment.name": "local",
      "k8s.namespace.name": "app",
    },
  });

  assert.equal(details.exact, false);
  assert.equal(details.scopeLabel, "Dinámico");
  assert.equal(details.summary, "1 servicio · 2 atributos");
  assert.deepEqual(details.attributes, [
    ["deployment.environment.name", "local"],
    ["k8s.namespace.name", "app"],
  ]);
});

test("marks InstanceUID selectors as exact and normalizes duplicate values", () => {
  const details = selectorDetails({
    Services: ["gateway-supervisor", "gateway-supervisor"],
    InstanceUIDs: ["uid-b", "uid-a", "uid-a"],
  });

  assert.equal(details.exact, true);
  assert.equal(details.scopeLabel, "Instancia exacta");
  assert.equal(details.summary, "1 servicio · 2 instancias");
  assert.deepEqual(details.instanceUIDs, ["uid-a", "uid-b"]);
});

test("identifies an empty selector as all compatible live destinations", () => {
  const details = selectorDetails();

  assert.equal(details.unrestricted, true);
  assert.equal(details.summary, "Todos los compatibles");
});
