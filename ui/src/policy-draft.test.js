import assert from "node:assert/strict";
import test from "node:test";
import {
  clearPolicyDraft,
  policyDraftStorageKey,
  readPolicyDraft,
  writePolicyDraft,
} from "./policy-draft.js";

const memoryStorage = () => {
  const values = new Map();
  return {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };
};

test("persists and restores a complete Policy Studio draft", () => {
  const storage = memoryStorage();
  const draft = {
    owner: "operator",
    configId: "exchange-policy",
    activeStep: 3,
    selectedServices: ["exchange-service"],
    policy: { apiVersion: "o11y.dev/v1" },
  };
  assert.equal(writePolicyDraft(storage, draft), true);
  assert.deepEqual(readPolicyDraft(storage), draft);
  clearPolicyDraft(storage);
  assert.equal(storage.getItem(policyDraftStorageKey), null);
});

test("ignores malformed or unavailable browser storage", () => {
  assert.equal(readPolicyDraft({ getItem: () => "not-json" }), null);
  assert.equal(writePolicyDraft({ setItem: () => { throw new Error("blocked"); } }, {}), false);
  assert.doesNotThrow(() => clearPolicyDraft({ removeItem: () => { throw new Error("blocked"); } }));
});
