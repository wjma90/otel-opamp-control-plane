const normalizedValues = (values) =>
  Array.isArray(values) ? values.filter(Boolean) : [];

export const matchesTargetSelector = (
  agent,
  {
    selectedAgentIds = [],
    selectedServices = [],
    selectorAttributes = [],
  } = {},
) => {
  const agentIds = normalizedValues(selectedAgentIds);
  const services = normalizedValues(selectedServices);
  const attributes = normalizedValues(selectorAttributes).filter(
    (attribute) => attribute?.key && attribute?.value,
  );

  return (
    (!agentIds.length || agentIds.includes(agent.UID)) &&
    (!services.length || services.includes(agent.Service)) &&
    attributes.every(
      (attribute) =>
        agent.Attributes?.[attribute.key] === attribute.value,
    )
  );
};

export const matchesTargetQuery = (agent, query = "") => {
  const normalizedQuery = String(query).trim().toLowerCase();
  if (!normalizedQuery) return true;

  return [
    agent.UID,
    agent.Service,
    ...Object.entries(agent.Attributes || {}).flatMap(([key, value]) => [
      key,
      value,
    ]),
  ]
    .join(" ")
    .toLowerCase()
    .includes(normalizedQuery);
};

export const filterVisibleTargetAgents = (agents, selection = {}) =>
  normalizedValues(agents).filter(
    (agent) =>
      matchesTargetSelector(agent, selection) &&
      matchesTargetQuery(agent, selection.query),
  );

export const createTargetInventorySnapshot = (agents) =>
  [...normalizedValues(agents)].sort(
    (left, right) =>
      String(left.Service || "").localeCompare(String(right.Service || "")) ||
      String(left.UID || "").localeCompare(String(right.UID || "")),
  );
