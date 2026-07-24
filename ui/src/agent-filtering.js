import {
  collectorAgentMode,
  collectorReportedVersions,
} from "./collector-management.js";
import { formatReportedAttributeValue } from "./agent-attributes.js";
import { matchesAnySelection } from "./multi-select-filter.js";

const normalizedStatus = (value, fallback = "UNKNOWN") =>
  String(value || fallback).trim().toUpperCase();

const searchableAttributes = (attributes) =>
  Object.entries(attributes || {}).flatMap(([key, value]) => {
    const formatted = formatReportedAttributeValue(value);
    return [key, formatted, `${key}=${formatted}`];
  });

export const fleetAgentAvailability = (agent = {}) =>
  normalizedStatus(agent.LiveStatus || agent.ConnectionStatus);

export const fleetAgentEffectiveStatus = (agent = {}, collectorBases = []) => {
  if (agent.Kind === "collector" && !agent.RemoteConfig) {
    return "REPORT_ONLY";
  }
  if (agent.Kind === "collector") {
    return normalizedStatus(
      collectorAgentMode(agent, collectorBases).liveStatus,
      "NOT_REPORTED",
    );
  }
  return normalizedStatus(agent.ConfigStatus, "NOT_REPORTED");
};

export const javaPolicySetEntries = (agent = {}) => {
  if (agent.Kind !== "java-extension") return [];
  return Object.entries(agent.PolicyVersions || {})
    .map(([id, version]) => ({
      id: String(id || "").trim(),
      version: Number(version),
    }))
    .filter(({ id, version }) => id && Number.isSafeInteger(version) && version > 0)
    .sort((left, right) =>
      left.id.localeCompare(right.id, undefined, {
        numeric: true,
        sensitivity: "base",
      }),
    );
};

export const projectFleetAgent = (agent = {}, collectorBases = []) => {
  const collectorMode = agent.Kind === "collector"
    ? collectorAgentMode(agent, collectorBases)
    : null;
  const reportedVersions = agent.Kind === "collector"
    ? collectorReportedVersions(agent)
    : { collector: "", supervisor: "" };
  const availability = fleetAgentAvailability(agent);
  const effectiveStatus = fleetAgentEffectiveStatus(agent, collectorBases);
  const javaPolicies = javaPolicySetEntries(agent);
  const base = collectorMode?.base || agent.BaseConfig || {};
  const searchText = [
    agent.Service,
    agent.UID,
    agent.Kind,
    agent.Transport,
    agent.ConfigID,
    agent.Version,
    availability,
    effectiveStatus,
    collectorMode?.effectiveLabel,
    collectorMode?.fallbackLabel,
    reportedVersions.collector,
    reportedVersions.supervisor,
    base.ID,
    base.Source,
    base.Revision,
    base.Behavior,
    ...javaPolicies.flatMap(({ id, version }) => [id, version, `${id} v${version}`]),
    ...searchableAttributes(agent.Attributes),
  ]
    .filter((value) => value !== null && value !== undefined && value !== "")
    .join(" ")
    .toLowerCase();

  return {
    agent,
    collectorMode,
    reportedVersions,
    javaPolicies,
    availability,
    effectiveStatus,
    searchText,
  };
};

export const projectFleetAgents = (agents = [], collectorBases = []) =>
  agents
    .map((agent) => projectFleetAgent(agent, collectorBases))
    .sort((left, right) =>
      String(left.agent.Service || "").localeCompare(
        String(right.agent.Service || ""),
        undefined,
        { numeric: true, sensitivity: "base" },
      ) ||
      String(left.agent.Kind || "").localeCompare(
        String(right.agent.Kind || ""),
        undefined,
        { numeric: true, sensitivity: "base" },
      ) ||
      String(left.agent.UID || "").localeCompare(
        String(right.agent.UID || ""),
        undefined,
        { numeric: true, sensitivity: "base" },
      ),
    );

export const filterFleetAgentRows = (rows = [], filters = {}) => {
  const query = String(filters.query || "").trim().toLowerCase();
  return rows.filter((row) =>
    (!query || row.searchText.includes(query)) &&
    matchesAnySelection(filters.services, row.agent.Service) &&
    matchesAnySelection(filters.kinds, row.agent.Kind) &&
    matchesAnySelection(filters.transports, row.agent.Transport) &&
    matchesAnySelection(filters.availability, row.availability) &&
    matchesAnySelection(filters.effectiveStatuses, row.effectiveStatus));
};

export const fleetFilterValues = (rows = [], selector) =>
  [...new Set(rows.map(selector).filter(Boolean))].sort((left, right) =>
    String(left).localeCompare(String(right), undefined, { sensitivity: "base" }),
  );
