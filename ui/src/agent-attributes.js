export const reportedAttributeEntries = (attributes) => {
  if (!attributes || typeof attributes !== "object" || Array.isArray(attributes)) {
    return [];
  }

  return Object.entries(attributes)
    .filter(([key]) => key.trim())
    .sort(([left], [right]) =>
      left.localeCompare(right, undefined, { sensitivity: "base" }),
    );
};

export const formatReportedAttributeValue = (value) => {
  if (typeof value === "string") {
    return value;
  }
  if (value === null) {
    return "null";
  }
  if (value === undefined) {
    return "undefined";
  }

  if (typeof value === "object") {
    try {
      return JSON.stringify(value);
    } catch {
      // Fall back to the runtime representation for unexpected cyclic values.
    }
  }

  return String(value);
};
