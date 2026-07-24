export const policyDraftStorageKey = "o11y.policy-studio.draft.v2";

export const readPolicyDraft = (storage) => {
  try {
    const value = JSON.parse(storage?.getItem(policyDraftStorageKey) || "null");
    return value && typeof value === "object" && !Array.isArray(value) ? value : null;
  } catch {
    return null;
  }
};

export const writePolicyDraft = (storage, draft) => {
  try {
    storage?.setItem(policyDraftStorageKey, JSON.stringify(draft));
    return true;
  } catch {
    return false;
  }
};

export const clearPolicyDraft = (storage) => {
  try {
    storage?.removeItem(policyDraftStorageKey);
  } catch {
    // A disabled browser storage must not break Policy Studio.
  }
};
