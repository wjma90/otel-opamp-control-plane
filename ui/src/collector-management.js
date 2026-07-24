import { deploymentCoverage } from "./deployment-coverage.js";
import { matchesAnySelection } from "./multi-select-filter.js";

const connectedStatuses = new Set(["CONNECTED", "ONLINE", "DEGRADED"]);

const unique = (values) => [...new Set(values.filter(Boolean))];

export const documentButtonLabel = (target = "") =>
  String(target).trim().toLowerCase().startsWith("collector")
    ? "Ver configuración"
    : "Ver policy";

const versionID = (version = {}) =>
  version.configId || version.ConfigID || version.ID || "";

const versionNumber = (version = {}) =>
  Number(version.Version ?? version.version ?? 0);

const versionTimestamp = (version = {}) =>
  Date.parse(version.UpdatedAt || version.CreatedAt || 0) || 0;

const versionAction = (version = {}) =>
  String(version.Action || version.action || "PUBLISHED").toUpperCase();

export const isCollectorVersionInactive = (version = {}) =>
  versionAction(version) === "DEACTIVATED" ||
  version.Active === false ||
  version.active === false;

export const normalizeCollectorBase = (base = {}) => ({
  ...base,
  ID: String(base.ID || base.id || ""),
  Source: String(base.Source || base.source || "ConfigMap"),
  Revision: String(base.Revision || base.revision || ""),
  Immutable: base.Immutable ?? base.immutable ?? true,
  Behavior: String(base.Behavior || base.behavior || "NOP").toUpperCase(),
  Services: base.Services || base.services || [],
  AgentUIDs: base.AgentUIDs || base.agentUIDs || base.Agents || [],
});

export const collectorReportedVersions = (agent = {}) => {
  const attributes = agent.Attributes || agent.attributes || {};
  return {
    collector: String(attributes["o11y.collector.version"] || ""),
    supervisor: String(attributes["o11y.supervisor.version"] || ""),
  };
};

export const collectorBaseForAgent = (agent = {}, bases = []) => {
  const embedded = agent.BaseConfig;
  const embeddedID = typeof embedded === "string"
    ? embedded
    : embedded?.ID || embedded?.id;
  const normalized = bases.map(normalizeCollectorBase);
  if (embeddedID) {
    const registered = normalized.find((base) => base.ID === embeddedID);
    return normalizeCollectorBase({ ...(registered || {}), ...(typeof embedded === "object" ? embedded : {}), ID: embeddedID });
  }
  return normalized.find((base) =>
    (base.AgentUIDs || []).includes(agent.UID) ||
    (base.Services || []).includes(agent.Service),
  ) || null;
};

export const collectorAgentMode = (agent = {}, bases = []) => {
  const base = collectorBaseForAgent(agent, bases);
  const origin = String(agent.EffectiveConfigOrigin || "").toUpperCase();
  const status = String(agent.ConfigStatus || "NOT_REPORTED").toUpperCase();
  const baseActive = origin === "BASE" || status.startsWith("BASE_");
  const managedActive = !baseActive && Boolean(agent.ConfigID) && Number(agent.Version) > 0;

  let liveStatus = status;
  if (baseActive) {
    if (status === "FAILED" || status === "BASE_FAILED") liveStatus = "BASE_FAILED";
    else if (status === "CONFIG_PENDING" || status === "BASE_PENDING") liveStatus = "BASE_PENDING";
    else liveStatus = "BASE_APPLIED";
  }

  return {
    base,
    baseActive,
    managedActive,
    liveStatus,
    effectiveLabel: baseActive
      ? "Base activa · NOP"
      : managedActive
        ? `Administrada · ${agent.ConfigID} v${agent.Version}`
        : "Esperando configuración efectiva",
    fallbackLabel: base
      ? `${base.ID} · ${base.Source} inmutable · ${base.Behavior}`
      : "Base no reportada",
  };
};

const baseMatchesCollector = (base, services, agentUIDs) => {
  if ((base.AgentUIDs || []).some((uid) => agentUIDs.includes(uid))) return true;
  if ((base.Services || []).some((service) => services.includes(service))) return true;
  return false;
};

const collectorRecordStatus = (record = {}) => {
  const live = String(record.LiveStatus || "").toUpperCase();
  if (["BASE_PENDING", "BASE_APPLIED", "BASE_FAILED", "REMOVED"].includes(live)) {
    return live;
  }
  if (record.DesiredPresence === false) {
    if (String(
      record.CurrentEffectiveConfigOrigin || record.CurrentConfigOrigin || "",
    ).toUpperCase() === "BASE") {
      return record.CurrentConfigStatus === "FAILED" ? "BASE_FAILED" : "BASE_APPLIED";
    }
    return record.ObservedStatus === "FAILED" ? "BASE_FAILED" : "BASE_PENDING";
  }
  const current = record.CurrentConfigID === record.ConfigID &&
    Number(record.CurrentConfigVersion) === Number(record.Version);
  if (!current) return "SUPERSEDED";
  if (record.CurrentConfigStatus === "FAILED") return "FAILED";
  if (record.CurrentConfigStatus !== "APPLIED") {
    return record.CurrentConfigStatus || record.ObservedStatus || "CONFIG_PENDING";
  }
  return connectedStatuses.has(record.ConnectionStatus)
    ? "APPLIED"
    : "APPLIED_OFFLINE";
};

const summarizeCollectorRecords = (records, active) => {
  const liveRecords = records.filter((record) => deploymentCoverage(record).counts);
  const counts = {
    observed: records.length,
    matched: liveRecords.length,
    desiredMatched: 0,
    removalMatched: 0,
    historical: 0,
    degraded: 0,
    unknown: 0,
    applied: 0,
    offline: 0,
    pending: 0,
    failed: 0,
    superseded: 0,
    basePending: 0,
    baseApplied: 0,
    baseFailed: 0,
    removed: 0,
  };
  for (const record of records) {
    const coverage = deploymentCoverage(record);
    if (coverage.counts) continue;
    if (coverage.state === "HISTORICAL") counts.historical += 1;
    else if (coverage.state === "IN_SCOPE_DEGRADED") counts.degraded += 1;
    else counts.unknown += 1;
  }
  for (const record of liveRecords) {
    if (record.DesiredPresence === false) counts.removalMatched += 1;
    else counts.desiredMatched += 1;
    const status = collectorRecordStatus(record);
    if (status === "APPLIED") counts.applied += 1;
    else if (status === "APPLIED_OFFLINE") counts.offline += 1;
    else if (status === "FAILED") counts.failed += 1;
    else if (status === "SUPERSEDED") counts.superseded += 1;
    else if (status === "BASE_PENDING") counts.basePending += 1;
    else if (status === "BASE_APPLIED") counts.baseApplied += 1;
    else if (status === "BASE_FAILED") counts.baseFailed += 1;
    else if (status === "REMOVED") counts.removed += 1;
    else counts.pending += 1;
  }
  const confirmedRemovals = counts.baseApplied + counts.removed;
  let status = "NO_LIVE_TARGETS";
  if (!counts.matched) status = "NO_LIVE_TARGETS";
  else if (!active && confirmedRemovals === counts.matched) {
    status = counts.removed ? "REMOVED" : "BASE_APPLIED";
  }
  else if (!active && counts.baseFailed > 0) status = "BASE_FAILED";
  else if (!active) status = "BASE_PENDING";
  else if (!counts.desiredMatched && counts.baseFailed > 0) status = "BASE_FAILED";
  else if (!counts.desiredMatched && counts.basePending > 0) status = "BASE_PENDING";
  else if (!counts.desiredMatched) status = "NO_LIVE_TARGETS";
  else if (
    counts.applied === counts.desiredMatched &&
    confirmedRemovals === counts.removalMatched
  ) status = "APPLIED";
  else if (counts.offline === counts.matched) status = "APPLIED_OFFLINE";
  else if (counts.failed > 0 && counts.applied === 0) status = "FAILED";
  else if (counts.applied + counts.offline > 0) status = "PARTIAL";
  else if (counts.pending > 0) status = "CONFIG_PENDING";
  else status = "NOT_IN_USE";
  return { ...counts, status };
};

export const collectorSummaryText = (summary = {}) => {
  if (summary.status === "REMOVED") {
    return `${summary.removed}/${summary.matched} Supervisor(es) confirmaron el retiro mediante otra configuración administrada.`;
  }
  if (summary.status === "BASE_APPLIED") {
    return `${summary.baseApplied}/${summary.matched} Supervisor(es) confirmaron la base NOP.`;
  }
  if (summary.status === "BASE_PENDING") {
    return `${summary.baseApplied || 0}/${summary.matched || 0} en base; falta confirmar el fallback.`;
  }
  if (summary.status === "BASE_FAILED") {
    return `${summary.baseFailed} Supervisor(es) no pudieron activar la base.`;
  }
  if (!summary.matched) {
    const details = ["Sin destinos actualmente en línea"];
    if (summary.degraded) details.push(`${summary.degraded} señal(es) degradada(s)`);
    if (summary.historical) details.push(`${summary.historical} registro(s) histórico(s)`);
    if (summary.unknown) details.push(`${summary.unknown} estado(s) desconocido(s)`);
    return `${details.join(" · ")}.`;
  }
  const desiredMatched = summary.desiredMatched ?? summary.matched;
  const details = [`${summary.applied}/${desiredMatched} destino(s) vivo(s) coincidente(s) aplicada(s)`];
  if (summary.failed) details.push(`${summary.failed} rechazada(s)`);
  if (summary.pending) details.push(`${summary.pending} pendiente(s)`);
  if (summary.superseded) details.push(`${summary.superseded} reemplazada(s)`);
  if (summary.baseApplied && summary.removalMatched) {
    details.push(`${summary.baseApplied} fallback(s) confirmado(s)`);
  }
  if (summary.removed) {
    details.push(`${summary.removed} retiro(s) confirmado(s) por reemplazo administrado`);
  }
  if (summary.basePending) details.push(`${summary.basePending} fallback(s) pendiente(s)`);
  if (summary.historical) {
    details.push(`${summary.historical} registro(s) histórico(s) excluido(s)`);
  }
  if (summary.degraded) details.push(`${summary.degraded} señal(es) degradada(s)`);
  if (summary.unknown) details.push(`${summary.unknown} estado(s) desconocido(s)`);
  return details.join(" · ");
};

export const buildManagedCollectorConfigs = (versions = [], deployments = [], bases = []) => {
  const grouped = new Map();
  for (const version of versions) {
    if (version.Target !== "collector") continue;
    const id = versionID(version);
    if (!id) continue;
    grouped.set(id, [...(grouped.get(id) || []), version]);
  }

  return [...grouped.entries()].map(([id, items]) => {
    const sorted = [...items].sort((left, right) =>
      versionNumber(left) - versionNumber(right) ||
      versionTimestamp(left) - versionTimestamp(right),
    );
    const latestVersion = sorted.at(-1);
    const contentVersions = sorted.filter((version) => String(version.Body || "").trim());
    const active = !isCollectorVersionInactive(latestVersion);
    const records = deployments.filter((record) =>
      record.Target === "collector" &&
      record.ConfigID === id &&
      Number(record.Version) === versionNumber(latestVersion),
    );
    const selector = latestVersion.Selector || {};
    const services = unique([
      ...(selector.Services || []),
      ...records.map((record) => record.Service),
    ]).sort();
    const agentUIDs = unique([
      ...(selector.InstanceUIDs || []),
      ...records.map((record) => record.AgentUID),
    ]);
    const fallbackBases = bases
      .map(normalizeCollectorBase)
      .filter((base) => baseMatchesCollector(base, services, agentUIDs));
    return {
      id,
      versions: sorted,
      latestVersion,
      lastContentVersion: contentVersions.at(-1) || latestVersion,
      active,
      lifecycleStatus: active ? "ACTIVE" : "DEACTIVATED",
      selector,
      services,
      records,
      fallbackBases,
      destinationSummary: summarizeCollectorRecords(records, active),
      action: active ? "DEACTIVATE" : "NONE",
      actionLabel: active ? "Retirar config y usar base NOP" : "",
    };
  }).sort((left, right) =>
    versionTimestamp(right.latestVersion) - versionTimestamp(left.latestVersion) ||
    left.id.localeCompare(right.id, undefined, { numeric: true, sensitivity: "base" }),
  );
};

export const filterManagedCollectorConfigs = (
  configs,
  { query = "", status = "", service = "" } = {},
) => {
  const needle = query.trim().toLowerCase();
  return configs.filter((config) => {
    if (!matchesAnySelection(status, [
      config.lifecycleStatus,
      config.destinationSummary.status,
    ])) return false;
    if (!matchesAnySelection(service, config.services)) return false;
    if (!needle) return true;
    return [
      config.id,
      config.latestVersion.CreatedBy,
      config.latestVersion.Hash,
      config.lifecycleStatus,
      config.destinationSummary.status,
      ...config.services,
      ...config.fallbackBases.map((base) => base.ID),
      ...Object.entries(config.selector.Attributes || {}).map(([key, value]) => `${key}=${value}`),
    ].some((value) => String(value || "").toLowerCase().includes(needle));
  });
};

export const collectorDeactivateEndpoint = (configID) =>
  `/api/collector-configs/${encodeURIComponent(configID)}/deactivate`;

export const collectorDeactivateConfirmation = (config) => {
  if (!config?.active) return "";
  const fallback = config.fallbackBases.length
    ? config.fallbackBases.map((base) => base.ID).join(", ")
    : "la base NOP inmutable reportada por cada Supervisor";
  return `¿Retirar ${config.id} y activar ${fallback}? Se publicará una versión nueva de retiro; ninguna versión existente se sobrescribe. Los ConfigMap base y el historial no se modificarán.`;
};
