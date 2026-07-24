const normalizedStrings = (values) => [
  ...new Set((Array.isArray(values) ? values : [])
    .map((value) => String(value || "").trim())
    .filter(Boolean)),
].sort();

export const selectorDetails = (selector = {}) => {
  const instanceUIDs = normalizedStrings(selector.InstanceUIDs);
  const services = normalizedStrings(selector.Services);
  const attributes = Object.entries(selector.Attributes || {})
    .map(([key, value]) => [String(key || "").trim(), String(value ?? "")])
    .filter(([key]) => key)
    .sort(([left], [right]) => left.localeCompare(right));
  const exact = instanceUIDs.length > 0;
  const unrestricted = !exact && services.length === 0 && attributes.length === 0;
  const summaryParts = [];
  if (services.length) {
    summaryParts.push(`${services.length} servicio${services.length === 1 ? "" : "s"}`);
  }
  if (attributes.length) {
    summaryParts.push(`${attributes.length} atributo${attributes.length === 1 ? "" : "s"}`);
  }
  if (instanceUIDs.length) {
    summaryParts.push(`${instanceUIDs.length} instancia${instanceUIDs.length === 1 ? "" : "s"}`);
  }

  return {
    instanceUIDs,
    services,
    attributes,
    exact,
    unrestricted,
    scopeLabel: exact ? "Instancia exacta" : "Dinámico",
    summary: unrestricted ? "Todos los compatibles" : summaryParts.join(" · "),
  };
};
