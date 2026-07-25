export const displayMetricUnit = (unit = "") => {
  const normalized = String(unit).trim();
  const annotated = normalized.match(/^\{([^{}]+)\}$/);
  return annotated ? annotated[1] : normalized;
};
