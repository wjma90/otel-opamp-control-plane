const liveLegacyStatuses = new Set(["CONNECTED", "ONLINE"]);
const confirmedDeploymentStatuses = new Set([
  "APPLIED",
  "REMOVED",
  "BASE_APPLIED",
]);

export const deploymentCoverage = (record = {}) => {
  const explicitState = String(record.CoverageState || "").toUpperCase();
  if (typeof record.CountsForLiveCoverage === "boolean") {
    return {
      counts: record.CountsForLiveCoverage,
      state: explicitState || (record.CountsForLiveCoverage ? "IN_SCOPE" : "UNKNOWN"),
      explicit: true,
    };
  }

  const connectionStatus = String(record.ConnectionStatus || "").toUpperCase();
  if (liveLegacyStatuses.has(connectionStatus)) {
    return { counts: true, state: "IN_SCOPE", explicit: false };
  }
  if (connectionStatus === "DEGRADED") {
    return { counts: false, state: "IN_SCOPE_DEGRADED", explicit: false };
  }

  // The legacy transport status cannot prove whether a pod still exists. Never
  // turn OFFLINE/DISCONNECTED into a lifecycle assertion in the browser.
  return { counts: false, state: "UNKNOWN", explicit: false };
};

export const coverageStatusForDisplay = (record = {}) => {
  const coverage = deploymentCoverage(record);
  if (coverage.state === "HISTORICAL") return "HISTORICAL";
  if (coverage.state === "IN_SCOPE_DEGRADED") return "IN_SCOPE_DEGRADED";
  if (coverage.state === "UNKNOWN") return "UNKNOWN";
  return "";
};

export const deploymentConfirmation = (record = {}, status = "") => {
  if (record.AppliedAt) {
    return {
      confirmed: true,
      at: record.AppliedAt,
      source: "ACKNOWLEDGEMENT",
    };
  }

  const normalizedStatus = String(status || record.LiveStatus || "").toUpperCase();
  if (confirmedDeploymentStatuses.has(normalizedStatus) && record.LastObservedAt) {
    return {
      confirmed: true,
      at: record.LastObservedAt,
      source: "LIVE_REPORT",
    };
  }

  return {
    confirmed: false,
    at: null,
    source: "NONE",
  };
};
