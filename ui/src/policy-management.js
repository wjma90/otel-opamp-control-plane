import { deploymentCoverage } from "./deployment-coverage.js";
import { matchesAnySelection } from "./multi-select-filter.js";

const connectedStatuses = new Set(["CONNECTED", "ONLINE", "DEGRADED"]);

const unique = (values) => [...new Set(values.filter(Boolean))];

export const policyConfigId = (version = {}) =>
  version.configId || version.ConfigID || version.ID || "";

export const policyVersionNumber = (version = {}) =>
  Number(version.Version ?? version.version ?? 0);

export const policyVersionAction = (version = {}) =>
  String(version.Action || version.action || "PUBLISHED").toUpperCase();

export const isDeactivatedPolicyVersion = (version) =>
  policyVersionAction(version) === "DEACTIVATED" ||
  version?.Active === false ||
  version?.active === false;

const versionTimestamp = (version = {}) =>
  Date.parse(version.UpdatedAt || version.CreatedAt || 0) || 0;

export const sortPolicyVersions = (versions = []) =>
  [...versions].sort((left, right) => {
    const versionDifference = policyVersionNumber(left) - policyVersionNumber(right);
    return versionDifference || versionTimestamp(left) - versionTimestamp(right);
  });

export const deploymentRecordStatus = (record = {}) => {
  if (record.Target === "java-extension") {
    const liveStatus = String(record.LiveStatus || "").toUpperCase();
    const observedStatus = String(record.ObservedStatus || "").toUpperCase();
    const currentStatus = String(record.CurrentConfigStatus || "").toUpperCase();

    // LiveStatus is calculated by the backend from the acknowledged policy
    // version, bundle status and current connection. It is authoritative when
    // present; CurrentConfigID identifies the bundle rather than this policy.
    if (liveStatus === "NOT_APPLIED") return "NOT_IN_USE";
    if (liveStatus) return liveStatus;

    if (record.DesiredPresence === false) {
      if (observedStatus === "REMOVED") return "REMOVED";
      if (observedStatus === "FAILED" || currentStatus === "FAILED") return "FAILED";
      return "REMOVAL_PENDING";
    }

    if (observedStatus === "FAILED" || currentStatus === "FAILED") return "FAILED";
    if (observedStatus === "APPLIED") {
      return connectedStatuses.has(record.ConnectionStatus)
        ? "APPLIED"
        : "APPLIED_OFFLINE";
    }
    return observedStatus || liveStatus || "CONFIG_PENDING";
  }

  const liveStatus = String(record.LiveStatus || "").toUpperCase();
  if (["BASE_PENDING", "BASE_APPLIED", "BASE_FAILED"].includes(liveStatus)) {
    return liveStatus;
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

export const summarizePolicyDestinations = (records = [], deactivated = false) => {
  const liveRecords = records.filter((record) => deploymentCoverage(record).counts);
  const result = {
    status: "NO_LIVE_TARGETS",
    observed: records.length,
    matched: liveRecords.length,
    desiredMatched: 0,
    removalMatched: 0,
    historical: 0,
    degraded: 0,
    unknown: 0,
    applied: 0,
    appliedOffline: 0,
    appliedStale: 0,
    pendingReplacement: 0,
    failed: 0,
    pending: 0,
    notInUse: 0,
    removed: 0,
    removalPending: 0,
  };

  // A record is retained for audit after its UID leaves the current live set.
  // It is useful evidence, but it must not reduce the selector coverage when
  // all currently connected destinations have applied the version.
  for (const record of records) {
    const status = deploymentRecordStatus(record);
    const coverage = deploymentCoverage(record);
    const live = coverage.counts;
    if (!live) {
      if (coverage.state === "HISTORICAL") result.historical += 1;
      else if (coverage.state === "IN_SCOPE_DEGRADED") result.degraded += 1;
      else result.unknown += 1;
      if (status === "APPLIED_OFFLINE") result.appliedOffline += 1;
      else if (status === "APPLIED_STALE") result.appliedStale += 1;
      continue;
    }
    if (record.DesiredPresence === false) result.removalMatched += 1;
    else result.desiredMatched += 1;
    if (status === "APPLIED") result.applied += 1;
    else if (status === "APPLIED_PENDING_REPLACEMENT") result.pendingReplacement += 1;
    else if (status === "FAILED") result.failed += 1;
    else if (status === "SUPERSEDED" || status === "NOT_IN_USE") result.notInUse += 1;
    else if (status === "REMOVED") result.removed += 1;
    else if (status === "REMOVAL_PENDING") result.removalPending += 1;
    else result.pending += 1;
  }

  if (!result.matched) {
    if (deactivated) result.status = "DEACTIVATED";
    return result;
  }
  if (deactivated) {
    if (result.removed === result.matched) result.status = "REMOVED";
    else if (result.failed > 0) result.status = "FAILED";
    else result.status = "REMOVAL_PENDING";
    return result;
  }
  const removalsComplete = result.removed === result.removalMatched;
  if (!result.desiredMatched) {
    if (result.failed > 0) result.status = "FAILED";
    else if (result.removalPending > 0) result.status = "REMOVAL_PENDING";
    else result.status = "NO_LIVE_TARGETS";
  }
  else if (result.applied === result.desiredMatched && removalsComplete) {
    result.status = "APPLIED";
  }
  else if (result.pendingReplacement === result.matched) {
    result.status = "APPLIED_PENDING_REPLACEMENT";
  } else if (result.applied > 0) {
    result.status = "PARTIAL";
  }
  else if (result.failed > 0) result.status = "FAILED";
  else if (result.pending + result.pendingReplacement > 0) result.status = "CONFIG_PENDING";
  else result.status = "NOT_IN_USE";
  return result;
};

export const managedPolicyDestinationSummary = (summary) => {
  if (summary.status === "DEACTIVATED") return "No se entrega a ningún destino.";
  if (summary.status === "REMOVED") return `${summary.removed}/${summary.matched} destino(s) confirmaron el retiro.`;
  if (!summary.matched) {
    const details = ["Sin destinos actualmente en línea"];
    if (summary.degraded) details.push(`${summary.degraded} señal(es) degradada(s)`);
    if (summary.historical) details.push(`${summary.historical} registro(s) histórico(s)`);
    if (summary.unknown) details.push(`${summary.unknown} estado(s) desconocido(s)`);
    return `${details.join(" · ")}.`;
  }
  const desiredMatched = summary.desiredMatched ?? summary.matched;
  const details = [`${summary.applied}/${desiredMatched} destino(s) vivo(s) coincidente(s) aplicada(s)`];
  if (summary.appliedStale) {
    details.push(`${summary.appliedStale} confirmación(es) histórica(s) degradada(s)`);
  }
  if (summary.pendingReplacement) {
    details.push(`${summary.pendingReplacement} reemplazo(s) pendiente(s)`);
  }
  if (summary.failed) details.push(`${summary.failed} rechazada(s)`);
  if (summary.pending) details.push(`${summary.pending} pendiente(s)`);
  if (summary.notInUse) details.push(`${summary.notInUse} usa(n) otra policy`);
  if (summary.removed) details.push(`${summary.removed} retirada(s)`);
  if (summary.removalPending) details.push(`${summary.removalPending} retiro(s) pendiente(s)`);
  if (summary.removalMatched && !summary.removalPending && summary.removed) {
    details.push(`${summary.removed} retiro(s) confirmado(s)`);
  }
  if (summary.historical) {
    details.push(`${summary.historical} registro(s) histórico(s) excluido(s)`);
  }
  if (summary.degraded) details.push(`${summary.degraded} señal(es) degradada(s)`);
  if (summary.unknown) details.push(`${summary.unknown} estado(s) desconocido(s)`);
  return details.join(" · ");
};

export const buildManagedPolicies = (versions = [], deployments = []) => {
  const grouped = new Map();
  for (const version of versions) {
    if (version.Target !== "java-extension") continue;
    const id = policyConfigId(version);
    if (!id) continue;
    grouped.set(id, [...(grouped.get(id) || []), version]);
  }

  return [...grouped.entries()].map(([id, unsortedVersions]) => {
    const policyVersions = sortPolicyVersions(unsortedVersions);
    const latestVersion = policyVersions.at(-1);
    const active = !isDeactivatedPolicyVersion(latestVersion);
    const contentVersions = policyVersions.filter(
      (version) => !isDeactivatedPolicyVersion(version),
    );
    const sourceVersion = Number(
      latestVersion.SourceVersion ?? latestVersion.sourceVersion ??
      policyVersionNumber(latestVersion),
    );
    const previousVersion = active
      ? policyVersions.filter(
        (version) => policyVersionAction(version) === "PUBLISHED" &&
          policyVersionNumber(version) < sourceVersion,
      ).at(-1) || null
      : null;
    const latestRecords = deployments.filter(
      (record) => record.ConfigID === id &&
        Number(record.Version) === policyVersionNumber(latestVersion),
    );
    const selector = latestVersion.Selector || {};
    const services = unique([
      ...(selector.Services || []),
      ...latestRecords.map((record) => record.Service),
    ]).sort();
    const destinationSummary = summarizePolicyDestinations(latestRecords, !active);

    return {
      id,
      target: latestVersion.Target,
      versions: policyVersions,
      versionCount: policyVersions.length,
      latestVersion,
      previousVersion,
      lastContentVersion: contentVersions.at(-1) || null,
      active,
      lifecycleStatus: active ? "ACTIVE" : "DEACTIVATED",
      action: active ? (previousVersion ? "REVERT" : "DEACTIVATE") : "NONE",
      actionLabel: !active
        ? ""
        : previousVersion
          ? `Restaurar contenido de v${policyVersionNumber(previousVersion)}`
          : "Retirar policy",
      selector,
      services,
      records: latestRecords,
      destinationSummary,
    };
  }).sort((left, right) =>
    versionTimestamp(right.latestVersion) - versionTimestamp(left.latestVersion) ||
    left.id.localeCompare(right.id, undefined, { numeric: true, sensitivity: "base" }),
  );
};

export const filterManagedPolicies = (
  policies,
  { query = "", status = "", service = "" } = {},
) => {
  const needle = query.trim().toLowerCase();
  return policies.filter((policy) => {
    if (!matchesAnySelection(status, [
      policy.lifecycleStatus,
      policy.destinationSummary.status,
    ])) {
      return false;
    }
    if (!matchesAnySelection(service, policy.services)) return false;
    if (!needle) return true;
    const attributes = Object.entries(policy.selector.Attributes || {})
      .map(([key, value]) => `${key}=${value}`);
    return [
      policy.id,
      policy.latestVersion.CreatedBy,
      policy.latestVersion.Hash,
      policy.lifecycleStatus,
      policy.destinationSummary.status,
      ...policy.services,
      ...attributes,
    ].some((value) => String(value || "").toLowerCase().includes(needle));
  });
};

export const policyLifecycleEndpoint = (policyId) =>
  `/api/policies/${encodeURIComponent(policyId)}/rollback`;

export const policyLifecycleConfirmation = (policy) => {
  if (policy.action === "REVERT") {
    const previous = policyVersionNumber(policy.previousVersion);
    return `¿Restaurar en ${policy.id} el contenido de v${previous}? Se publicará una versión nueva; ninguna versión existente se sobrescribe.`;
  }
  if (policy.action === "DEACTIVATE") {
    return `¿Retirar ${policy.id} de todos sus destinos? Se publicará una versión nueva de retiro. Dejará de entregarse a las instancias actuales y futuras que coincidan, pero el historial se conservará.`;
  }
  return "";
};
