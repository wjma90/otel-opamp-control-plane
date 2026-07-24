const legacyLiveStatuses = new Set(["CONNECTED", "ONLINE"]);

const agentCountsForLiveCoverage = (agent = {}) => {
  const liveStatus = String(agent.LiveStatus || "").toUpperCase();
  if (liveStatus) return liveStatus === "CONNECTED";
  return legacyLiveStatuses.has(String(agent.ConnectionStatus || "").toUpperCase());
};

const matchesSelector = (agent, selector = {}) => {
  const instanceUIDs = selector.InstanceUIDs || [];
  const services = selector.Services || [];
  const attributes = selector.Attributes || {};
  return (
    (!instanceUIDs.length || instanceUIDs.includes(agent.UID)) &&
    (!services.length || services.includes(agent.Service)) &&
    Object.entries(attributes).every(
      ([key, value]) => agent.Attributes?.[key] === value,
    )
  );
};

const isCompatible = (agent, version) =>
  agent.Kind === version.Target &&
  (version.Target !== "collector" || agent.RemoteConfig) &&
  matchesSelector(agent, version.Selector);

const referencesVersion = (agent, version) => {
  const configId = version.configId || version.ConfigID || version.ID;
  if (version.Target === "java-extension") {
    return Number(agent.PolicyVersions?.[configId]) === Number(version.Version);
  }
  return agent.ConfigID === configId && Number(agent.Version) === Number(version.Version);
};

export const deploymentStatusForVersion = (version, agents) => {
  const compatible = agents.filter((agent) => isCompatible(agent, version));
  const destinations = compatible.filter(agentCountsForLiveCoverage);

  const result = {
    status: "NO_LIVE_TARGETS",
    observed: compatible.length,
    matched: destinations.length,
    applied: 0,
    failed: 0,
    pending: 0,
    notInUse: 0,
  };

  for (const agent of destinations) {
    if (!referencesVersion(agent, version)) {
      result.notInUse += 1;
      continue;
    }
    if (agent.ConfigStatus === "APPLIED") {
      result.applied += 1;
    } else if (agent.ConfigStatus === "FAILED") {
      result.failed += 1;
    } else {
      result.pending += 1;
    }
  }

  if (!result.matched) return result;
  if (result.applied === result.matched) {
    result.status = "APPLIED";
  } else if (result.failed > 0 && result.applied === 0) {
    result.status = "FAILED";
  } else if (result.applied > 0) {
    result.status = "PARTIAL";
  } else if (result.pending > 0 || (version.IsLatest && result.notInUse > 0)) {
    result.status = "CONFIG_PENDING";
  } else {
    result.status = "NOT_IN_USE";
  }
  return result;
};

export const deploymentStatusSummary = (deployment) => {
  if (!deployment.matched) {
    return "No hay destinos actualmente en línea para confirmar esta versión.";
  }
  const details = [`${deployment.applied}/${deployment.matched} destino(s) vivo(s) aplicada(s)`];
  if (deployment.failed) details.push(`${deployment.failed} rechazada(s)`);
  if (deployment.pending) details.push(`${deployment.pending} pendiente(s)`);
  if (deployment.notInUse) details.push(`${deployment.notInUse} no la usa(n)`);
  return details.join(" · ");
};

export const publicationActionLabel = (action) => {
  if (action === "ROLLBACK") return "Restauración publicada";
  if (action === "DEACTIVATED") return "Retiro publicado";
  return "Publicación registrada";
};
