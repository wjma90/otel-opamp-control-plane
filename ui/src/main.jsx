import React, { useEffect, useId, useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/dm-sans/latin-400.css";
import "@fontsource/dm-sans/latin-500.css";
import "@fontsource/dm-sans/latin-600.css";
import "@fontsource/dm-sans/latin-700.css";
import "@fontsource/space-mono/latin-400.css";
import "@fontsource/space-mono/latin-700.css";
import { MultiSelectFilter } from "./components/MultiSelectFilter.jsx";
import { HttpRuleQuickGuide } from "./components/HttpRuleQuickGuide.jsx";
import { StoredVersionPicker } from "./components/StoredVersionPicker.jsx";
import {
  collectorConfigId,
  sanitizeEffectiveCollectorConfig,
} from "./collector-effective-config.js";
import {
  deploymentStatusForVersion,
  deploymentStatusSummary,
  publicationActionLabel,
} from "./deployment-status.js";
import {
  buildManagedPolicies,
  deploymentRecordStatus,
  filterManagedPolicies,
  isDeactivatedPolicyVersion,
  managedPolicyDestinationSummary,
  policyLifecycleConfirmation,
  policyLifecycleEndpoint,
  policyVersionNumber,
} from "./policy-management.js";
import {
  buildManagedCollectorConfigs,
  collectorDeactivateConfirmation,
  collectorDeactivateEndpoint,
  collectorSummaryText,
  documentButtonLabel,
  filterManagedCollectorConfigs,
  normalizeCollectorBase,
} from "./collector-management.js";
import {
  callbackURL,
  createLatestRequestGate,
  normalizeProvider,
  providerLoginEnabled,
  providerPayload,
  validateProviderDraft,
} from "./auth-providers.js";
import {
  canEditEmail,
  canManageEmail,
  canManageSecurity,
  emailSettingsPayload,
  identityPermissions,
  identityRoles,
  normalizeEmailSettings,
  normalizeProfile,
  normalizeUser,
  passwordResetToken,
  profilePayload,
  userPayload,
  validateEmailSettings,
  validatePasswordChange,
  validateProfile,
  validateUser,
} from "./account-settings.js";
import {
  policyCaptureDenyViolations,
  policyWireContractErrors,
} from "./capture-security.js";
import {
  canViewNetwork,
  normalizeNetworkSettings,
  proxyModeDetails,
  publicUrlSourceDetails,
} from "./network-settings.js";
import {
  formatReportedAttributeValue,
  reportedAttributeEntries,
} from "./agent-attributes.js";
import {
  filterFleetAgentRows,
  fleetAgentAvailability,
  fleetFilterValues,
  projectFleetAgents,
} from "./agent-filtering.js";
import { selectorDetails } from "./selector-presentation.js";
import {
  flattenStoredVersions,
  sortDestinationRecords,
} from "./version-source.js";
import {
  coverageStatusForDisplay,
  deploymentConfirmation,
  deploymentCoverage,
} from "./deployment-coverage.js";
import {
  clearPolicyDraft,
  readPolicyDraft,
  writePolicyDraft,
} from "./policy-draft.js";
import { tabFromLocation, urlForTab } from "./navigation.js";
import { matchesAnySelection } from "./multi-select-filter.js";
import {
  I18nProvider,
  translatedOptions,
  useI18n,
} from "./i18n.js";
import {
  agentSupportsPolicySchema,
  configureEventMetricIntent,
  ensurePolicySchema,
  eventMetricIntent,
  eventNameOutput,
  fieldsForHTTPEvent,
  httpConditionSourceOptions,
  httpEventSourceOptions,
  httpEventUsesBody,
  httpSourceSelector,
  legacyHTTPConfigurationCount,
  normalizeHTTPEventMetric,
  httpEventMetricStandardAttributes,
  normalizeHTTPEventPolicy,
  normalizeTelemetryEditorFocus,
  nextHTTPEventName,
  removeHTTPEventAt,
  renameHTTPEventAt,
  requiredPolicySchema,
  telemetryDirectionForFocus,
  telemetryEventCategories,
  withEventNameOutput,
} from "./telemetry-events.js";
import {
  duplicateTelemetryEventNames,
  messagingFamilyForScope,
  normalizeMessagingEventPolicy,
  normalizeMessagingMetric,
} from "./messaging-events.js";
import { MessagingPoliciesEditor } from "./messaging-editor.jsx";
import "./styles.css";
import "./agent-status.css";

const controlPlaneRefreshIntervalMs = 4_000;

function LanguageSelector({ compact = false }) {
  const { locale, setLocale, t } = useI18n();
  return (
    <label className={`language-selector ${compact ? "compact" : ""}`}>
      <span>{t("Idioma")}</span>
      <select
        value={locale}
        aria-label={t("Cambiar idioma")}
        onChange={(event) => setLocale(event.target.value)}
      >
        <option value="es">{t("Español")}</option>
        <option value="en">{t("Inglés")}</option>
      </select>
    </label>
  );
}

const collectorStatusFilterOptions = [
  { value: "ACTIVE", label: "Administradas activas" },
  { value: "DEACTIVATED", label: "Administradas retiradas" },
  { value: "APPLIED", label: "Aplicadas" },
  { value: "NO_LIVE_TARGETS", label: "Sin destinos vivos" },
  { value: "CONFIG_PENDING", label: "Pendientes" },
  { value: "FAILED", label: "Rechazadas" },
  { value: "BASE_PENDING", label: "Activando base" },
  { value: "BASE_APPLIED", label: "Base activa" },
  { value: "REMOVED", label: "Retirada por reemplazo" },
  { value: "BASE_FAILED", label: "Base rechazada" },
];

const policyStatusFilterOptions = [
  { value: "ACTIVE", label: "Activas" },
  { value: "DEACTIVATED", label: "Retiradas" },
  { value: "APPLIED", label: "Aplicadas y en línea" },
  { value: "NO_LIVE_TARGETS", label: "Sin destinos vivos" },
  { value: "APPLIED_PENDING_REPLACEMENT", label: "Reemplazo pendiente" },
  { value: "PARTIAL", label: "Aplicación parcial" },
  { value: "CONFIG_PENDING", label: "Pendiente" },
  { value: "FAILED", label: "Rechazada" },
  { value: "REMOVAL_PENDING", label: "Retiro pendiente" },
  { value: "REMOVED", label: "Retiradas de destinos" },
];

const destinationStatusFilterOptions = [
  { value: "APPLIED", label: "Aplicada y en línea" },
  { value: "IN_SCOPE_DEGRADED", label: "Señal OpAMP degradada" },
  { value: "HISTORICAL", label: "Registro histórico" },
  { value: "UNKNOWN", label: "Estado desconocido" },
  { value: "APPLIED_PENDING_REPLACEMENT", label: "Reemplazo pendiente" },
  { value: "CONFIG_PENDING", label: "Pendiente" },
  { value: "FAILED", label: "Rechazada" },
  { value: "SUPERSEDED", label: "Reemplazada" },
  { value: "REMOVAL_PENDING", label: "Retiro pendiente" },
  { value: "REMOVED", label: "Retirada de destinos" },
  { value: "BASE_PENDING", label: "Activando base" },
  { value: "BASE_APPLIED", label: "Base activa" },
  { value: "BASE_FAILED", label: "Base rechazada" },
];

const targetFilterOptions = [
  { value: "java-extension", label: "Java extension" },
  { value: "collector", label: "Collector" },
];

const versionStatusFilterOptions = [
  { value: "APPLIED", label: "Aplicada" },
  { value: "PARTIAL", label: "Parcial" },
  { value: "CONFIG_PENDING", label: "Pendiente" },
  { value: "FAILED", label: "Rechazada" },
  { value: "DEACTIVATED", label: "Retirada" },
  { value: "BASE_PENDING", label: "Activando base" },
  { value: "BASE_APPLIED", label: "Base activa" },
  { value: "BASE_FAILED", label: "Base rechazada" },
  { value: "NOT_IN_USE", label: "No está en uso" },
  { value: "NO_LIVE_TARGETS", label: "Sin destinos vivos" },
  { value: "NO_TARGETS", label: "Sin destinos" },
];

const defaultBuckets = [
  0.005,
  0.01,
  0.025,
  0.05,
  0.075,
  0.1,
  0.25,
  0.5,
  0.75,
  1,
  2.5,
  5,
  7.5,
  10,
];

const bounded = (allowed = ["VALUE_A", "VALUE_B"]) => ({
  type: "ENUM",
  allowed,
  fallback: "OTHER",
  ranges: [],
});

const rangePolicy = () => ({
  type: "RANGE",
  allowed: [],
  fallback: "OTHER",
  ranges: [
    { max: 1000, label: "0-1000" },
    { max: 3000, label: "1000-3000" },
    { max: 10000, label: "3000-10000" },
    { max: null, label: "10000+" },
  ],
});

const emptyPolicy = () => ({
  schemaVersion: "1.5",
  requestHeaders: [],
  responseHeaders: [],
  deniedHeaders: [],
  deniedBodyPaths: [],
  metricPolicies: [],
  methodPolicies: [],
  bodyEventPolicies: [],
  eventMetricPolicies: [],
  messagingEventPolicies: [],
  messagingMetricPolicies: [],
});

const normalizeHTTPDirection = (direction) =>
  String(direction || "INCOMING").trim().toUpperCase() || "INCOMING";

const capture = (
  source = "ARGUMENT",
  argumentIndex = 0,
  path = "",
  attribute = "custom.attribute",
  type = "STRING",
  destinations = ["SPAN"],
  valuePolicy = bounded(),
) => ({
  source,
  argumentIndex,
  path,
  constant: 1,
  attribute,
  type,
  destinations,
  valuePolicy,
});

const metric = () => ({
  name: "custom.java.method.events",
  instrument: "COUNTER",
  unit: "1",
  description: "Eventos registrados por la policy",
  value: {
    source: "CONSTANT",
    argumentIndex: -1,
    path: "",
    constant: 1,
  },
  buckets: [],
});

const newMethodPolicy = () => ({
  id: `method-${Date.now()}`,
  enabled: true,
  packagePrefix: "",
  className: "",
  methodName: "",
  captures: [],
  metrics: [],
  log: {
    enabled: false,
    severity: "INFO",
    body: "Method policy matched",
  },
});

const bodyCondition = (
  source = "REQUEST_PATH",
  values = [""],
  path = "",
  operator = "EQUALS",
) => ({ source, path, operator, values });

const bodyField = (
  source = "REQUEST_BODY",
  path = "",
  attribute = "",
  type = "STRING",
  destinations = ["SPAN", "LOG"],
) => ({
  source,
  path,
  attribute,
  type,
  destinations,
  valuePolicy: bounded(),
});

const derivedField = () => ({
  attribute: "",
  expression: "",
  type: "DOUBLE",
  destinations: ["SPAN", "LOG"],
  valuePolicy: rangePolicy(),
});

const newBodyEventPolicy = (direction = "INCOMING", eventName = "http-event") => ({
  id: `http-event-${Date.now()}`,
  enabled: true,
  ruleName: "Regla HTTP",
  direction,
  requestContentType: "application/json",
  responseContentType: "application/json",
  conditions: [
    bodyCondition(),
    bodyCondition("REQUEST_METHOD", ["POST"]),
    bodyCondition("RESPONSE_STATUS", ["200", "201"], "", "IN"),
  ],
  eventName,
  staticAttributes: [],
  maxBodyBytes: 65536,
  fields: [],
  derivedFields: [],
  log: {
    enabled: false,
    severity: "INFO",
    body: "HTTP telemetry event matched",
  },
});

const newEventMetric = (eventName = "http-event") => ({
  id: `event-metric-${Date.now()}`,
  enabled: true,
  eventName,
  name: "",
  instrument: "COUNTER",
  unit: "1",
  description: "",
  valueField: "",
  dimensions: [],
  standardAttributes: [],
  buckets: [],
});

const normalizePolicy = (value) => ({
  ...emptyPolicy(),
  ...value,
  requestHeaders: (value?.requestHeaders || []).map((header) => ({
    ...header,
    direction: normalizeHTTPDirection(header.direction),
  })),
  responseHeaders: (value?.responseHeaders || []).map((header) => ({
    ...header,
    direction: normalizeHTTPDirection(header.direction),
  })),
  deniedHeaders: [],
  deniedBodyPaths: [],
  metricPolicies: (value?.metricPolicies || []).map(({ source: _legacySource, ...metricPolicy }) => ({
    ...metricPolicy,
    direction: metricPolicy.direction || "INCOMING",
    value: metricPolicy.value || {
      source: "DURATION",
      argumentIndex: -1,
      path: "",
      constant: 1,
    },
  })),
  methodPolicies: value?.methodPolicies || [],
  bodyEventPolicies: (value?.bodyEventPolicies || []).map(normalizeHTTPEventPolicy),
  eventMetricPolicies: (value?.eventMetricPolicies || []).map(normalizeHTTPEventMetric),
  messagingEventPolicies: (value?.messagingEventPolicies || [])
    .map(normalizeMessagingEventPolicy),
  messagingMetricPolicies: (value?.messagingMetricPolicies || [])
    .map(normalizeMessagingMetric),
});

const unique = (values) => [...new Set(values.filter(Boolean))];

const isConnectedTarget = (agent) =>
  ["CONNECTED", "ONLINE"].includes(fleetAgentAvailability(agent));

const statusMeta = (status, type) => {
  if (type === "connection") {
    const connections = {
      CONNECTED: ["Conectado", "ok", "El cliente mantiene una señal OpAMP reciente."],
      DISCONNECTED: [
        "Desconectado",
        "bad",
        "No existe una señal OpAMP activa; esto no determina el estado de la infraestructura.",
      ],
      ONLINE: [
        "En línea",
        "ok",
        "El cliente respondió dentro de tres intervalos de polling.",
      ],
      DEGRADED: [
        "Degradado",
        "warn",
        "Se perdieron entre tres y seis intervalos de polling.",
      ],
      OFFLINE: [
        "Sin señal OpAMP",
        "bad",
        "No se reciben mensajes OpAMP recientes; esto no determina si el workload existe.",
      ],
      STALE: [
        "Señal degradada",
        "warn",
        "La señal OpAMP perdió varios intervalos y no se considera cobertura viva.",
      ],
      UNREACHABLE: [
        "Sin señal OpAMP",
        "bad",
        "El cliente dejó de reportar; sin un reconciliador de infraestructura no se afirma que esté eliminado.",
      ],
      UNKNOWN: [
        "Estado desconocido",
        "neutral",
        "No hay evidencia suficiente para determinar la disponibilidad actual.",
      ],
    };
    return (
      connections[status] || [
        status || "Desconocido",
        "neutral",
        "Estado de transporte OpAMP.",
      ]
    );
  }

  const values = {
    APPLIED: ["Aplicada", "ok", "El agente validó y activó esta versión."],
    APPLIED_OFFLINE: [
      "Aplicada · sin señal",
      "warn",
      "La última confirmación fue APPLIED, pero ya no existe una señal OpAMP reciente; la infraestructura no está verificada.",
    ],
    APPLIED_STALE: [
      "Última aplicación · degradada",
      "warn",
      "El agente conserva esta versión como última aplicación conocida, pero sus reportes están degradados.",
    ],
    APPLIED_PENDING_REPLACEMENT: [
      "Reemplazo pendiente",
      "warn",
      "La versión anterior aún está aplicada mientras el agente valida y activa el bundle de reemplazo.",
    ],
    SUPERSEDED: [
      "Reemplazada",
      "neutral",
      "El agente usa actualmente otra configuración o versión.",
    ],
    MATCHED: [
      "Coincidente",
      "neutral",
      "El selector coincide; aún no existe confirmación de aplicación.",
    ],
    CONFIG_PENDING: [
      "Pendiente",
      "warn",
      "Se envió la configuración; falta confirmación.",
    ],
    FAILED: ["Rechazada", "bad", "El agente rechazó la configuración."],
    PARTIAL: [
      "Aplicación parcial",
      "warn",
      "Al menos un destino la aplicó, pero el despliegue no terminó correctamente en todos.",
    ],
    NOT_IN_USE: [
      "No está en uso",
      "neutral",
      "Ningún destino coincidente reporta actualmente esta versión.",
    ],
    NO_TARGETS: [
      "Sin destinos",
      "neutral",
      "No hay destinos actuales o históricos que permitan confirmar esta versión.",
    ],
    NO_LIVE_TARGETS: [
      "Sin destinos vivos",
      "neutral",
      "No hay clientes actualmente en línea que coincidan. Los registros históricos no determinan la cobertura viva.",
    ],
    HISTORICAL: [
      "Histórico",
      "neutral",
      "Este registro se conserva para auditoría y no participa en la cobertura viva. No determina si el workload todavía existe.",
    ],
    IN_SCOPE_DEGRADED: [
      "Señal degradada",
      "warn",
      "El destino coincide, pero su señal OpAMP no es suficientemente reciente para contar como cobertura viva.",
    ],
    UNKNOWN: [
      "Estado desconocido",
      "neutral",
      "No existe evidencia suficiente para afirmar si la instancia está activa o eliminada.",
    ],
    DEACTIVATED: [
      "Retirada",
      "neutral",
      "La policy ya no se entrega a destinos actuales ni futuros.",
    ],
    REMOVAL_PENDING: [
      "Retiro pendiente",
      "warn",
      "La policy dejó de ser deseada; falta que el agente confirme que removió la versión.",
    ],
    REMOVED: [
      "Retirada de destinos",
      "ok",
      "El agente confirmó que la policy ya no forma parte de su bundle activo.",
    ],
    BASE_PENDING: [
      "Activando base",
      "warn",
      "La configuración administrada fue retirada; falta que el Supervisor confirme la base NOP.",
    ],
    BASE_APPLIED: [
      "Base activa · NOP",
      "ok",
      "El Supervisor confirmó la configuración base inmutable del ConfigMap.",
    ],
    BASE_FAILED: [
      "Base rechazada",
      "bad",
      "El Supervisor no pudo activar su configuración base inmutable.",
    ],
    NOT_REPORTED: ["Sin reporte", "neutral", "Aún no existe confirmación."],
    REPORT_ONLY: [
      "Sólo reporte",
      "neutral",
      "Este cliente OpAMP no acepta configuración remota.",
    ],
    VALIDATED: [
      "Validado",
      "ok",
      "La configuración fue comprobada contra el proveedor de identidad.",
    ],
    CONFIGURED: [
      "Configurado",
      "warn",
      "La configuración está guardada, pero todavía no superó la validación operativa.",
    ],
    ERROR: [
      "Error",
      "bad",
      "La última validación del proveedor no fue satisfactoria.",
    ],
    INACTIVE: [
      "Inactivo",
      "neutral",
      "El recurso no está activo.",
    ],
    ACTIVE: ["Activo", "ok", "El usuario puede iniciar sesión."],
  };
  return values[status] || [status || "Sin reporte", "neutral", "Estado OpAMP."];
};

function StatusBadge({ status, type }) {
  const { t } = useI18n();
  const [label, tone, help] = statusMeta(status, type);
  return (
    <em className={`badge ${tone}`} title={t(help)}>
      {t(label)}
    </em>
  );
}

function ValuePolicyEditor({ value, onChange }) {
  const { t } = useI18n();
  const rangesText = (value.ranges || [])
    .map((range) => `${range.max ?? "*"}:${range.label}`)
    .join(",");

  return (
    <div className="row compact value-policy">
      <label>
        {t("Control de cardinalidad")}
        <select
          value={value.type}
          onChange={(event) => {
            const type = event.target.value;
            onChange({
              ...value,
              type,
              allowed: type === "ENUM" ? ["VALUE_A", "VALUE_B"] : [],
              ranges: type === "RANGE" ? rangePolicy().ranges : [],
              fallback: type === "BOOLEAN" ? "false" : "OTHER",
            });
          }}
        >
          <option value="ENUM">{t("Lista permitida")}</option>
          <option value="RANGE">{t("Rangos")}</option>
          <option value="BOOLEAN">{t("Booleano")}</option>
        </select>
      </label>

      {value.type === "ENUM" && (
        <label>
          {t("Valores permitidos")}
          <input
            value={(value.allowed || []).join(",")}
            onChange={(event) =>
              onChange({
                ...value,
                allowed: event.target.value
                  .split(",")
                  .map((item) => item.trim())
                  .filter(Boolean),
              })
            }
          />
        </label>
      )}

      {value.type === "RANGE" && (
        <label>
          {t("Rangos `máximo:label`")}
          <input
            value={rangesText}
            onChange={(event) =>
              onChange({
                ...value,
                ranges: event.target.value
                  .split(",")
                  .map((item) => {
                    const [maximum, label] = item.split(":");
                    return {
                      max: maximum?.trim() === "*" ? null : Number(maximum),
                      label: label?.trim() || "",
                    };
                  })
                  .filter(
                    (item) =>
                      item.label && (item.max === null || Number.isFinite(item.max)),
                  ),
              })
            }
          />
        </label>
      )}

      <label>
        {t("Fallback")}
        <input
          value={value.fallback}
          onChange={(event) =>
            onChange({ ...value, fallback: event.target.value })
          }
        />
      </label>
    </div>
  );
}

function TargetSelector({
  agents,
  query,
  setQuery,
  selectedAgentIds,
  setSelectedAgentIds,
  selectedServices,
  setSelectedServices,
  selectorAttributes,
  setSelectorAttributes,
}) {
  const { t } = useI18n();
  const services = unique(agents.map((agent) => agent.Service)).sort();
  const agentIds = new Set(agents.map((agent) => agent.UID));
  const unavailableSelectedIds = selectedAgentIds.filter(
    (id) => !agentIds.has(id),
  );
  const unavailableSelectedServices = selectedServices.filter(
    (service) => !services.includes(service),
  );
  const hasInstanceFilter = selectedAgentIds.length > 0;
  const hasServiceFilter = selectedServices.length > 0;
  const attributes = selectorAttributes.filter(
    (attribute) => attribute.key && attribute.value,
  );

  const matches = (agent) =>
    (!hasInstanceFilter || selectedAgentIds.includes(agent.UID)) &&
    (!hasServiceFilter || selectedServices.includes(agent.Service)) &&
    attributes.every(
      (attribute) => agent.Attributes?.[attribute.key] === attribute.value,
    );

  const matchingAgents = agents.filter(matches);
  const normalizedQuery = query.trim().toLowerCase();
  const visibleAgents = agents.filter((agent) => {
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
  });

  const toggleService = (service) =>
    setSelectedServices((current) =>
      current.includes(service)
        ? current.filter((item) => item !== service)
        : [...current, service],
    );

  return (
    <section className="subpanel target-selector">
      <div className="section-heading">
        <div>
          <p className="eyebrow">{t("ENVIAR A DESTINOS")}</p>
          <h3>{t("Selecciona quién recibirá esta versión")}</h3>
        </div>
        <strong className="match-count">
          {matchingAgents.length} {t("de")} {agents.length} {t("coinciden")}
        </strong>
      </div>

      <p className="hint">
        {t("Instance IDs, servicios y resource attributes se combinan con lógica AND. Esta lista sólo contiene clientes conectados: Supervisors en CONNECTED y extensiones Java en ONLINE. Un selector vacío abarca todos los destinos conectados mostrados.")}
      </p>

      {(unavailableSelectedIds.length > 0 ||
        unavailableSelectedServices.length > 0) && (
        <div className="availability-warning">
          <span>
            {t("La versión cargada contiene selectores que ahora están desconectados y no pueden recibir la configuración.")}
          </span>
          <button
            type="button"
            className="ghost small"
            onClick={() => {
              setSelectedAgentIds((current) =>
                current.filter((id) => agentIds.has(id)),
              );
              setSelectedServices((current) =>
                current.filter((service) => services.includes(service)),
              );
            }}
          >
            {t("Quitar selectores no disponibles")}
          </button>
        </div>
      )}

      <label>
        {t("Buscar en el inventario")}
        <input
          placeholder={t("servicio, instance ID, cluster o resource attribute")}
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
      </label>

      <div className="selector-services">
        <span>{t("Servicios")}</span>
        {services.map((service) => (
          <label key={service} className="selector-chip">
            <input
              type="checkbox"
              checked={selectedServices.includes(service)}
              onChange={() => toggleService(service)}
            />
            {service}
          </label>
        ))}
        {!services.length && <small>{t("No hay servicios conectados compatibles.")}</small>}
      </div>

      <div className="selector-attributes">
        <div className="section-heading small-heading">
          <b>{t("Resource attributes exactos")}</b>
          <button
            type="button"
            className="ghost small"
            onClick={() =>
              setSelectorAttributes((current) => [
                ...current,
                { key: "", value: "" },
              ])
            }
          >
            {t("+ atributo")}
          </button>
        </div>
        {selectorAttributes.map((attribute, index) => (
          <div className="selector-attribute-row" key={`selector-${index}`}>
            <input
              aria-label="Resource attribute"
              placeholder="deployment.environment.name"
              value={attribute.key}
              onChange={(event) =>
                setSelectorAttributes((current) =>
                  current.map((item, itemIndex) =>
                    itemIndex === index
                      ? { ...item, key: event.target.value }
                      : item,
                  ),
                )
              }
            />
            <input
              aria-label={t("Valor exacto")}
              placeholder="production"
              value={attribute.value}
              onChange={(event) =>
                setSelectorAttributes((current) =>
                  current.map((item, itemIndex) =>
                    itemIndex === index
                      ? { ...item, value: event.target.value }
                      : item,
                  ),
                )
              }
            />
            <button
              type="button"
              className="icon-button"
              aria-label={t("Eliminar selector")}
              onClick={() =>
                setSelectorAttributes((current) =>
                  current.filter((_, itemIndex) => itemIndex !== index),
                )
              }
            >
              ×
            </button>
          </div>
        ))}
      </div>

      <div className="target-table">
        <div className="target-row head">
          <span>{t("Instancia")}</span>
          <span>{t("Servicio")}</span>
          <span>{t("Estado")}</span>
          <span>{t("Configuración actual")}</span>
          <span>{t("Resultado")}</span>
        </div>
        {visibleAgents.map((agent) => (
          <label className="target-row" key={agent.UID}>
            <span>
              <input
                type="checkbox"
                checked={selectedAgentIds.includes(agent.UID)}
                onChange={() =>
                  setSelectedAgentIds((current) =>
                    current.includes(agent.UID)
                      ? current.filter((id) => id !== agent.UID)
                      : [...current, agent.UID],
                  )
                }
              />
              <code>{agent.UID.slice(0, 12)}…</code>
            </span>
            <b>{agent.Service}</b>
            <StatusBadge status={fleetAgentAvailability(agent)} type="connection" />
            <span>
              {agent.ConfigID ? `${agent.ConfigID} · v${agent.Version}` : t("Sin configuración")}
            </span>
            <em className={`match-result ${matches(agent) ? "yes" : "no"}`}>
              {t(matches(agent) ? "Recibirá" : "No coincide")}
            </em>
          </label>
        ))}
        {!visibleAgents.length && (
          <div className="empty">{t("No hay destinos conectados con la búsqueda.")}</div>
        )}
      </div>

      <div className="selector-actions">
        <button
          type="button"
          className="ghost small"
          onClick={() => setSelectedAgentIds(visibleAgents.map((agent) => agent.UID))}
        >
          {t("Seleccionar instancias visibles")}
        </button>
        <button
          type="button"
          className="ghost small"
          onClick={() => {
            setSelectedAgentIds([]);
            setSelectedServices([]);
            setSelectorAttributes([]);
          }}
        >
          {t("Limpiar selectores")}
        </button>
      </div>
    </section>
  );
}

const workflowSteps = [
  {
    title: "Origen",
    description: "Carga o inicia una configuración",
  },
  {
    title: "Edición",
    description: "Define capturas, métricas o YAML",
  },
  {
    title: "Destinos",
    description: "Aplica selectores al inventario",
  },
  {
    title: "Revisión",
    description: "Valida y publica la versión",
  },
];

function PolicyStepper({ activeStep, setActiveStep }) {
  const { t } = useI18n();
  return (
    <ol className="workflow-stepper" aria-label={t("Flujo de publicación")}>
      {workflowSteps.map((step, index) => {
        const number = index + 1;
        const state = number === activeStep
          ? "active"
          : number < activeStep
            ? "completed"
            : "pending";
        return (
          <li key={step.title} className={state}>
            <button
              type="button"
              aria-current={number === activeStep ? "step" : undefined}
              onClick={() => setActiveStep(number)}
            >
              <span className="step-number">{number < activeStep ? "✓" : number}</span>
              <span>
                <b>{t(step.title)}</b>
                <small>{t(step.description)}</small>
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

function StepNavigation({ activeStep, setActiveStep, nextDisabled = false }) {
  const { t } = useI18n();
  if (activeStep === workflowSteps.length) return null;
  return (
    <div className="step-actions">
      {activeStep > 1 && (
        <button
          type="button"
          className="ghost"
          onClick={() => setActiveStep(activeStep - 1)}
        >
          {t("← Anterior")}
        </button>
      )}
      <button
        type="button"
        className="primary"
        disabled={nextDisabled}
        onClick={() => setActiveStep(activeStep + 1)}
      >
        {t("Continuar")}: {t(workflowSteps[activeStep].title)} →
      </button>
    </div>
  );
}

const configurationTypeOptions = [
  {
    id: "telemetry-events",
    target: "java-extension",
    editorFocus: "http-incoming",
    title: "Eventos de telemetría",
    description: "HTTP, método Java, Kafka o JMS hacia spans, logs y métricas.",
    icon: "⇄",
  },
  {
    id: "collector",
    target: "collector",
    title: "Collector",
    description: "Edita y valida la configuración completa de un Supervisor.",
    icon: "⬡",
  },
];

function ConfigurationTypeChooser({ target, editorFocus, onChoose }) {
  const { t } = useI18n();
  return (
    <div className="scope-chooser" aria-label={t("Tipo de configuración")}>
      {configurationTypeOptions.map((option) => {
        const selected = option.target === "collector"
          ? target === "collector"
          : target === "java-extension";
        return (
          <button
            type="button"
            key={option.id}
            className={`scope-card ${selected ? "active" : ""}`}
            onClick={() => onChoose(option)}
          >
            <span className="scope-icon">{option.icon}</span>
            <b>{t(option.title)}</b>
            <small>{t(option.description)}</small>
          </button>
        );
      })}
    </div>
  );
}

function PolicyFlowNavigator({ policy, editorFocus, setEditorFocus }) {
  const { t } = useI18n();
  const bodyEvents = policy.bodyEventPolicies || [];
  const direction = telemetryDirectionForFocus(editorFocus);
  const directionalEvents = bodyEvents.filter(
    (item) => normalizeHTTPDirection(item.direction) === direction,
  );
  const eventNames = new Set(directionalEvents.map((item) => item.eventName));
  const messagingFamily = ["kafka", "jms"].includes(editorFocus)
    ? editorFocus
    : null;
  const messagingEvents = (policy.messagingEventPolicies || []).filter(
    (item) => messagingFamilyForScope(item.scope) === messagingFamily,
  );
  const messagingEventNames = new Set(messagingEvents.map((item) => item.eventName));
  const flow = editorFocus === "method" ? {
      trigger: `${policy.methodPolicies?.length || 0} métodos`,
      captures: (policy.methodPolicies || []).reduce((sum, item) => sum + (item.captures?.length || 0), 0),
      enrichment: (policy.methodPolicies || []).filter((item) => item.log?.enabled).length,
      metrics: (policy.methodPolicies || []).reduce((sum, item) => sum + (item.metrics?.length || 0), 0),
    } : messagingFamily ? {
      trigger: `${messagingEvents.length} reglas`,
      captures: messagingEvents.reduce((sum, item) => sum + (item.fields?.length || 0), 0),
      enrichment: messagingEvents.reduce(
        (sum, item) => sum + [
          ...(item.staticAttributes || []),
          ...(item.fields || []),
        ].reduce(
          (outputSum, field) => outputSum + (field.destinations || [])
            .filter((destination) => destination === "SPAN" || destination === "LOG")
            .length,
          0,
        ),
        0,
      ) + messagingEvents.filter((item) => item.log?.enabled).length,
      metrics: (policy.messagingMetricPolicies || [])
        .filter((item) => messagingEventNames.has(item.eventName)).length,
    } : null;
  const steps = editorFocus === "method" || messagingFamily
    ? [
        [messagingFamily ? "1 · Cuándo" : "1 · Trigger", flow.trigger],
        [messagingFamily ? "2 · Datos" : "2 · Capturas", flow.captures],
        ["3 · Span / log", flow.enrichment],
        ["4 · Métricas", flow.metrics],
        ["5 · Destinos", "Paso siguiente"],
      ]
    : [
        ["1 · Cuándo", `${directionalEvents.length} reglas`],
        [
          "2 · Datos",
          directionalEvents.reduce(
            (sum, item) => sum + (item.fields?.length || 0) + (item.derivedFields?.length || 0),
            0,
          ),
        ],
        [
          "3 · Salidas",
          directionalEvents.reduce(
            (sum, item) => sum + [
              ...(item.staticAttributes || []),
              ...(item.fields || []),
              ...(item.derivedFields || []),
            ].reduce(
              (outputSum, field) => outputSum + (field.destinations || [])
                .filter((destination) => destination === "SPAN" || destination === "LOG")
                .length,
              0,
            ),
            0,
          )
            + directionalEvents.filter((item) => item.log?.enabled).length
            + (policy.eventMetricPolicies || []).filter((item) => eventNames.has(item.eventName)).length,
        ],
        ["4 · Destinos", "Paso siguiente"],
      ];
  return (
    <div className="policy-flow-panel">
      <div className="policy-scope-tabs" role="tablist" aria-label={t("Categoría del evento de telemetría")}>
        {telemetryEventCategories.map((option) => (
          <button
            type="button"
            role="tab"
            aria-selected={editorFocus === option.id}
            className={editorFocus === option.id ? "active" : ""}
            key={option.id}
            onClick={() => setEditorFocus(option.id)}
          >
            {t(option.title)}
          </button>
        ))}
      </div>
      <div
        className={`policy-flow${steps.length === 4 ? " four-steps" : ""}`}
        aria-label={t("Flujo de la policy seleccionada")}
      >
        {steps.map(([label, value], index) => (
          <React.Fragment key={label}>
            {index > 0 && <span>→</span>}
            <div><small>{t(label)}</small><b>{typeof value === "string" ? t(value) : value}</b></div>
          </React.Fragment>
        ))}
      </div>
      <p className="scope-boundary-note">
        {editorFocus === "method"
          ? t("Este evento usa únicamente datos disponibles en la invocación del método.")
          : messagingFamily
            ? t("Cada regla de mensajería observa una operación producer o consumer independiente; no espera ni une una respuesta posterior.")
          : t("Cada regla HTTP sigue el flujo Cuándo → Datos → Salidas y puede combinar request y response de la misma operación.")}
        {" "}{t("Los scopes no se mezclan en un único evento; pueden correlacionarse posteriormente por trace_id y contexto de mensajería.")}
      </p>
    </div>
  );
}

function HTTPEventMetricsEditor({
  policy,
  setPolicy,
  eventPolicy,
  nameErrors,
  direction,
}) {
  const { t } = useI18n();
  const fields = fieldsForHTTPEvent(policy, eventPolicy.eventName, direction);
  const numericFields = fields.filter((field) =>
    ["DOUBLE", "LONG"].includes(field.type),
  );
  const dimensionFields = fields.filter((field) =>
    (field.destinations || []).includes("METRIC"),
  );
  const standardAttributes = httpEventMetricStandardAttributes(direction);
  const metrics = (policy.eventMetricPolicies || [])
    .map((eventMetric, metricIndex) => ({ eventMetric, metricIndex }))
    .filter(({ eventMetric }) => eventMetric.eventName === eventPolicy.eventName);

  const updateEventMetric = (index, value) =>
    setPolicy((current) => ({
      ...current,
      eventMetricPolicies: current.eventMetricPolicies.map((item, itemIndex) =>
        itemIndex === index ? value : item,
      ),
    }));

  return (
    <div className="http-rule-output">
      <div className="section-heading small-heading">
        <div>
          <h4>{t("3 · Salidas: métricas")}</h4>
          <small>
            {t("Contar coincidencias suma 1 por cada coincidencia. Total acumula un campo numérico no negativo. Distribución registra sus valores para consultar count, sum y buckets.")}
          </small>
        </div>
        <button
          type="button"
          className="ghost small"
          onClick={() =>
            setPolicy((current) => ({
              ...current,
              eventMetricPolicies: [
                ...current.eventMetricPolicies,
                newEventMetric(eventPolicy.eventName),
              ],
            }))
          }
        >
          {t("+ agregar métrica")}
        </button>
      </div>

      {!metrics.length && (
        <p className="hint">
          {t("Opcional. La extensión crea la métrica cuando esta regla coincide; el Collector sólo la transporta.")}
        </p>
      )}

      {metrics.map(({ eventMetric, metricIndex }) => {
        const intent = eventMetricIntent(eventMetric);
        const valueFieldAvailable = !eventMetric.valueField || numericFields.some(
          (field) => field.attribute === eventMetric.valueField,
        );
        const unavailableDimensions = (eventMetric.dimensions || []).filter(
          (dimension) => !dimensionFields.some((field) => field.attribute === dimension),
        );
        const numericOptions = unique([
          eventMetric.valueField,
          ...numericFields.map((field) => field.attribute),
        ]).filter(Boolean);
        return (
          <div className="nested-card event-metric-card" key={eventMetric.id}>
            <button
              type="button"
              className="remove inline"
              onClick={() =>
                setPolicy((current) => ({
                  ...current,
                  eventMetricPolicies: current.eventMetricPolicies.filter(
                    (_, index) => index !== metricIndex,
                  ),
                }))
              }
            >
              {t("Eliminar métrica")}
            </button>

            <div className="row">
              <label>
                {t("Nombre OTel")}
                <input
                  className={
                    !String(eventMetric.name || "").trim()
                      || nameErrors.includes(eventMetric.name)
                      ? "invalid"
                      : ""
                  }
                  value={eventMetric.name}
                  placeholder="domain.operation.amount"
                  onChange={(event) =>
                    updateEventMetric(metricIndex, {
                      ...eventMetric,
                      name: event.target.value,
                    })
                  }
                />
                {!String(eventMetric.name || "").trim() && (
                  <small className="error">{t("Define un nombre OTel antes de publicar.")}</small>
                )}
                {!!String(eventMetric.name || "").trim()
                  && nameErrors.includes(eventMetric.name) && (
                  <small className="error">{t("Nombre reservado, duplicado o en uso.")}</small>
                )}
              </label>
              <label>
                {t("Qué medir")}
                <select
                  aria-label={t("Qué medir con la métrica")}
                  value={intent}
                  onChange={(event) =>
                    updateEventMetric(
                      metricIndex,
                      configureEventMetricIntent(
                        eventMetric,
                        event.target.value,
                        numericFields[0]?.attribute || "",
                      ),
                    )
                  }
                >
                  <option value="COUNT">{t("Contar coincidencias (+1)")}</option>
                  <option value="TOTAL" disabled={!numericFields.length}>
                    {t("Total acumulado de un campo no negativo")}
                  </option>
                  <option value="DISTRIBUTION" disabled={!numericFields.length}>
                    {t("Distribución de un campo")}
                  </option>
                </select>
              </label>
              {intent !== "COUNT" && (
                <label>
                  {t("Campo numérico")}
                  <select
                    value={eventMetric.valueField}
                    onChange={(event) =>
                      updateEventMetric(metricIndex, {
                        ...eventMetric,
                        valueField: event.target.value,
                      })
                    }
                  >
                    {numericOptions.map((field) => (
                      <option key={field} value={field}>{field}</option>
                    ))}
                  </select>
                  {!numericFields.length && (
                    <small className="error">
                      {t("Añade primero un dato numérico DOUBLE o LONG.")}
                    </small>
                  )}
                  {!valueFieldAvailable && (
                    <small className="error">
                      {t("El campo seleccionado ya no existe o dejó de ser numérico. Elige uno disponible antes de publicar.")}
                    </small>
                  )}
                </label>
              )}
            </div>

            <h5>{t("Labels de la métrica")}</h5>
            <p className="hint">
              {t("Atributos del contexto OTel disponibles al cerrar esta operación HTTP. Los valores ausentes se omiten.")}
            </p>
            <div className="dimension-picker">
              {standardAttributes.map((attribute) => (
                <label className="check-line" key={attribute.name}>
                  <input
                    type="checkbox"
                    checked={(eventMetric.standardAttributes || []).includes(attribute.name)}
                    onChange={() => {
                      const selected = (eventMetric.standardAttributes || [])
                        .includes(attribute.name);
                      updateEventMetric(metricIndex, {
                        ...eventMetric,
                        standardAttributes: selected
                          ? eventMetric.standardAttributes.filter(
                            (item) => item !== attribute.name,
                          )
                          : [...(eventMetric.standardAttributes || []), attribute.name],
                      });
                      if (!selected) {
                        setPolicy((current) => ({
                          ...current,
                          schemaVersion: ensurePolicySchema(current.schemaVersion, "1.6"),
                        }));
                      }
                    }}
                  />
                  <span>
                    <code>{attribute.name}</code>
                    <small>{t(attribute.help)}</small>
                  </span>
                </label>
              ))}
            </div>
            <h5>{t("Labels de negocio")}</h5>
            <div className="dimension-picker">
              {dimensionFields.map((field) => (
                <label className="check-line" key={field.attribute}>
                  <input
                    type="checkbox"
                    checked={(eventMetric.dimensions || []).includes(field.attribute)}
                    onChange={() =>
                      updateEventMetric(metricIndex, {
                        ...eventMetric,
                        dimensions: (eventMetric.dimensions || []).includes(field.attribute)
                          ? eventMetric.dimensions.filter(
                              (item) => item !== field.attribute,
                            )
                          : [...(eventMetric.dimensions || []), field.attribute],
                      })
                    }
                  />
                  <code>{field.attribute}</code>
                </label>
              ))}
              {!dimensionFields.length && (
                <small>
                  {t("En Datos, marca un campo como “Usar como label” y controla sus valores con ENUM, RANGE o BOOLEAN.")}
                </small>
              )}
            </div>
            {!!unavailableDimensions.length && (
              <div className="warning-box compact-warning">
                <span>
                  {t("Labels no disponibles")}: <code>{unavailableDimensions.join(", ")}</code>
                </span>
                <button
                  type="button"
                  className="ghost small"
                  onClick={() =>
                    updateEventMetric(metricIndex, {
                      ...eventMetric,
                      dimensions: (eventMetric.dimensions || []).filter(
                        (dimension) => !unavailableDimensions.includes(dimension),
                      ),
                    })
                  }
                >
                  {t("Quitar labels no disponibles")}
                </button>
              </div>
            )}

            <details className="policy-advanced-options">
              <summary>{t("Opciones avanzadas de la métrica")}</summary>
              <div className="row">
                <label>
                  {t("Unidad")}
                  <input
                    value={eventMetric.unit}
                    onChange={(event) =>
                      updateEventMetric(metricIndex, {
                        ...eventMetric,
                        unit: event.target.value,
                      })
                    }
                  />
                </label>
                <label>
                  {t("Descripción")}
                  <input
                    value={eventMetric.description}
                    onChange={(event) =>
                      updateEventMetric(metricIndex, {
                        ...eventMetric,
                        description: event.target.value,
                      })
                    }
                  />
                </label>
              </div>
              {intent === "DISTRIBUTION" && (
                <label>
                  {t("Buckets explícitos")}
                  <input
                    value={(eventMetric.buckets || []).join(",")}
                    onChange={(event) =>
                      updateEventMetric(metricIndex, {
                        ...eventMetric,
                        buckets: event.target.value
                          .split(",")
                          .map(Number)
                          .filter(Number.isFinite),
                      })
                    }
                  />
                </label>
              )}
            </details>
          </div>
        );
      })}
    </div>
  );
}

function BodyEventPoliciesEditor({
  policy,
  setPolicy,
  nameErrors,
  direction,
  onEditLegacy,
}) {
  const { t } = useI18n();
  const updateEvent = (index, value) =>
    setPolicy((current) => ({
      ...current,
      bodyEventPolicies: current.bodyEventPolicies.map((item, itemIndex) =>
        itemIndex === index ? value : item,
      ),
    }));

  const duplicateEventNames = duplicateTelemetryEventNames(policy);
  const legacyCount = legacyHTTPConfigurationCount(policy, direction);

  return (
    <section className="editor-section">
      <div className="section-heading">
        <div>
          <p className="eyebrow">{t("REGLAS HTTP")}</p>
          <h2>{t("Cuándo ocurre, qué datos usar y qué telemetría emitir")}</h2>
        </div>
        <button
          type="button"
          className="ghost"
          onClick={() =>
            setPolicy((current) => {
              const eventName = nextHTTPEventName(current.bodyEventPolicies);
              return {
                ...current,
                schemaVersion: ensurePolicySchema(current.schemaVersion, "1.5"),
                bodyEventPolicies: [
                  ...current.bodyEventPolicies,
                  newBodyEventPolicy(direction, eventName),
                ],
              };
            })
          }
        >
          {t("+ agregar regla HTTP")}
        </button>
      </div>
      <p className="hint">
        {t("Una regla puede combinar request y response del mismo intercambio. Define condiciones, extrae sólo los datos necesarios y decide si van a spans, logs o métricas. Las condiciones se combinan con AND y nunca se exportan headers ni bodies completos.")}
      </p>
      <HttpRuleQuickGuide t={t} />

      {legacyCount > 0 && (
        <div className="warning-box legacy-http-warning">
          <div>
            <b>{t("Configuración HTTP heredada conservada")}</b>
            <p>
              {t("Esta policy contiene")} {legacyCount}{" "}
              {t(legacyCount === 1 ? "captura o métrica" : "capturas o métricas")}{" "}
              {t("del editor anterior. No se borran ni se modifican desde este formulario unificado.")}
            </p>
          </div>
          <button type="button" className="ghost small" onClick={onEditLegacy}>
            {t("Editar en JSON")}
          </button>
        </div>
      )}

      {!policy.bodyEventPolicies.some(
        (eventPolicy) => normalizeHTTPDirection(eventPolicy.direction) === direction,
      ) && (
        <div className="empty-state compact-empty-state">
          <b>{t("No hay reglas HTTP para esta dirección.")}</b>
          <p>{t("Agrega una regla y completa el flujo Cuándo → Datos → Salidas.")}</p>
        </div>
      )}

      {policy.bodyEventPolicies.map((eventPolicy, eventIndex) => ({ eventPolicy, eventIndex }))
        .filter(({ eventPolicy }) => normalizeHTTPDirection(eventPolicy.direction) === direction)
        .map(({ eventPolicy, eventIndex }) => (
        <article className="policy-card" key={eventPolicy.id}>
          <button
            type="button"
            className="remove"
            onClick={() =>
              setPolicy((current) => removeHTTPEventAt(current, eventIndex))
            }
          >
            {t("Eliminar")}
          </button>

          <div className="row">
            <label>
              {t("Nombre de la regla")}
              <input
                value={eventPolicy.ruleName}
                onChange={(event) =>
                  updateEvent(eventIndex, {
                    ...eventPolicy,
                    ruleName: event.target.value,
                  })
                }
              />
            </label>
            <span className="field-direction">
              {direction === "INCOMING"
                ? t("HTTP entrante")
                : t("HTTP saliente · RestClient, Apache HttpClient u OkHttp")}
            </span>
          </div>

          <details className="policy-advanced-options">
            <summary>{t("Opciones avanzadas de la regla")}</summary>
            <label>
              {t("Identificador interno")}
              <input
                placeholder="http-event"
                className={duplicateEventNames.includes(eventPolicy.eventName) ? "invalid" : ""}
                value={eventPolicy.eventName}
                onChange={(event) =>
                  setPolicy((current) =>
                    renameHTTPEventAt(current, eventIndex, event.target.value),
                  )
                }
              />
              <small>
                {t("Enlaza internamente las métricas con esta regla; no se exporta por sí solo.")}
              </small>
              {duplicateEventNames.includes(eventPolicy.eventName) && (
                <small className="error">
                  {t("Debe ser único en todo el documento, incluso en reglas deshabilitadas.")}
                </small>
              )}
            </label>
          </details>

          <details className="policy-advanced-options">
            <summary>{t("Atributos estáticos y límites de body")}</summary>
            <div className="section-heading small-heading">
              <div>
                <h4>{t("Atributos estáticos")}</h4>
                <small>
                  {t("Son opcionales y ningún nombre o valor se añade implícitamente.")}
                </small>
              </div>
              <button
                type="button"
                className="ghost small"
                onClick={() =>
                  updateEvent(eventIndex, {
                    ...eventPolicy,
                    staticAttributes: [
                      ...(eventPolicy.staticAttributes || []),
                      {
                        attribute: "",
                        value: "",
                        type: "STRING",
                        destinations: ["SPAN", "LOG"],
                      },
                    ],
                  })
                }
              >
                {t("+ atributo estático")}
              </button>
            </div>

          {(eventPolicy.staticAttributes || [])
            .map((attribute, attributeIndex) => ({ attribute, attributeIndex }))
            .filter(({ attribute }) => attribute.attribute !== "event.name")
            .map(({ attribute, attributeIndex }) => (
            <div className="nested-card" key={`${eventPolicy.id}-static-${attributeIndex}`}>
              <div className="body-field-row">
                <input
                  aria-label={t("Nombre del atributo estático")}
                  placeholder="event.type"
                  value={attribute.attribute}
                  onChange={(event) => {
                    const attributeName = event.target.value;
                    if (attributeName === "event.name") {
                      updateEvent(
                        eventIndex,
                        withEventNameOutput(
                          eventPolicy,
                          attribute.value,
                          attribute.destinations || [],
                        ),
                      );
                      return;
                    }
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      staticAttributes: eventPolicy.staticAttributes.map((item, index) =>
                        index === attributeIndex
                          ? { ...item, attribute: attributeName }
                          : item,
                      ),
                    });
                  }}
                />
                <input
                  aria-label={t("Valor del atributo estático")}
                  placeholder="transfer-submitted"
                  value={attribute.value}
                  onChange={(event) =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      staticAttributes: eventPolicy.staticAttributes.map((item, index) =>
                        index === attributeIndex ? { ...item, value: event.target.value } : item,
                      ),
                    })
                  }
                />
                <select
                  aria-label={t("Tipo del atributo estático")}
                  value={attribute.type}
                  onChange={(event) =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      staticAttributes: eventPolicy.staticAttributes.map((item, index) =>
                        index === attributeIndex ? { ...item, type: event.target.value } : item,
                      ),
                    })
                  }
                >
                  <option>STRING</option>
                  <option>DOUBLE</option>
                  <option>LONG</option>
                  <option>BOOLEAN</option>
                </select>
                <button
                  type="button"
                  className="icon-button"
                  aria-label={t("Quitar atributo estático")}
                  onClick={() =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      staticAttributes: eventPolicy.staticAttributes.filter(
                        (_, index) => index !== attributeIndex,
                      ),
                    })
                  }
                >
                  ×
                </button>
              </div>
              <div className="destinations body-destinations">
                {[
                  ["SPAN", "Añadir al span"],
                  ["LOG", "Añadir al log"],
                ].map(([destination, label]) => (
                  <label key={destination}>
                    <input
                      type="checkbox"
                      checked={(attribute.destinations || []).includes(destination)}
                      onChange={() => {
                        const destinations = (attribute.destinations || []).includes(destination)
                          ? attribute.destinations.filter((item) => item !== destination)
                          : [...(attribute.destinations || []), destination];
                        updateEvent(eventIndex, {
                          ...eventPolicy,
                          staticAttributes: eventPolicy.staticAttributes.map((item, index) =>
                            index === attributeIndex ? { ...item, destinations } : item,
                          ),
                        });
                      }}
                    />
                    {t(label)}
                  </label>
                ))}
              </div>
            </div>
          ))}

          {httpEventUsesBody(eventPolicy) && (
          <div className="row compact">
            <label>
              {t("Content-Type request")}
              <select
                value={eventPolicy.requestContentType}
                onChange={(event) =>
                  updateEvent(eventIndex, {
                    ...eventPolicy,
                    requestContentType: event.target.value,
                  })
                }
              >
                <option>application/json</option>
                <option>application/*+json</option>
              </select>
            </label>
            <label>
              {t("Content-Type response")}
              <select
                value={eventPolicy.responseContentType}
                onChange={(event) =>
                  updateEvent(eventIndex, {
                    ...eventPolicy,
                    responseContentType: event.target.value,
                  })
                }
              >
                <option>application/json</option>
                <option>application/*+json</option>
              </select>
            </label>
            <label>
              {t("Límite por body (bytes)")}
              <input
                type="number"
                min="1024"
                max="262144"
                value={eventPolicy.maxBodyBytes}
                onChange={(event) =>
                  updateEvent(eventIndex, {
                    ...eventPolicy,
                    maxBodyBytes: Number(event.target.value),
                  })
                }
              />
            </label>
          </div>
          )}
          {!httpEventUsesBody(eventPolicy) && (
            <p className="hint">
              {t("Los límites de body aparecerán cuando uses Request body o Response body.")}
            </p>
          )}
          </details>

          <div className="section-heading small-heading">
            <div>
              <h4>{t("1 · Cuándo: condiciones AND")}</h4>
              <small>
                {t("Path y método son obligatorios; cualquier dato disponible del request o response puede confirmar el resultado.")}
              </small>
            </div>
            <button
              type="button"
              className="ghost small"
              onClick={() =>
                updateEvent(eventIndex, {
                  ...eventPolicy,
                  conditions: [
                    ...eventPolicy.conditions,
                    bodyCondition("RESPONSE_BODY", [""], ""),
                  ],
                })
              }
            >
              {t("+ condición")}
            </button>
          </div>

          {!!eventPolicy.conditions.length && (
            <div className="condition-row condition-row-head" aria-hidden="true">
              <span>{t("Fuente")}</span>
              <span>{t("Ruta, header o query")}</span>
              <span>{t("Operador")}</span>
              <span>{t("Valor(es)")}</span>
              <span />
            </div>
          )}

          {eventPolicy.conditions.map((condition, conditionIndex) => {
            const selector = httpSourceSelector(condition.source);
            return (
              <div className="condition-row" key={`${eventPolicy.id}-condition-${conditionIndex}`}>
                <select
                  aria-label={t("Fuente de condición")}
                  value={condition.source}
                  onChange={(event) => {
                    const source = event.target.value;
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      conditions: eventPolicy.conditions.map((item, index) =>
                        index === conditionIndex
                          ? {
                              ...item,
                              source,
                              path: httpSourceSelector(source).disabled ? "" : item.path,
                            }
                          : item,
                      ),
                    });
                    if (source === "REQUEST_PATH_PARAM") {
                      setPolicy((current) => ({
                        ...current,
                        schemaVersion: ensurePolicySchema(current.schemaVersion, "1.5"),
                      }));
                    } else if (["REQUEST_HEADER", "RESPONSE_HEADER", "REQUEST_QUERY"].includes(source)) {
                      setPolicy((current) => ({
                        ...current,
                        schemaVersion: ensurePolicySchema(current.schemaVersion, "1.4"),
                      }));
                    }
                  }}
                >
                  {httpConditionSourceOptions.map((source) => (
                    <option key={source.id} value={source.id}>{t(source.label)}</option>
                  ))}
                </select>
                <input
                  aria-label={t(selector.label)}
                  placeholder={t(selector.placeholder)}
                  disabled={selector.disabled}
                  value={condition.path}
                  onChange={(event) =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      conditions: eventPolicy.conditions.map((item, index) =>
                        index === conditionIndex
                          ? { ...item, path: event.target.value }
                          : item,
                      ),
                    })
                  }
                />
                <select
                  aria-label={t("Operador")}
                  value={condition.operator}
                  onChange={(event) =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      conditions: eventPolicy.conditions.map((item, index) =>
                        index === conditionIndex
                          ? { ...item, operator: event.target.value }
                          : item,
                      ),
                    })
                  }
                >
                  <option value="EQUALS">equals</option>
                  <option value="IN">in</option>
                </select>
                <input
                  aria-label={t("Valores")}
                  placeholder="200,201"
                  value={(condition.values || []).join(",")}
                  onChange={(event) =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      conditions: eventPolicy.conditions.map((item, index) =>
                        index === conditionIndex
                          ? {
                              ...item,
                              values: event.target.value
                                .split(",")
                                .map((value) => value.trim())
                                .filter(Boolean),
                            }
                          : item,
                      ),
                    })
                  }
                />
                <button
                  type="button"
                  className="icon-button"
                  aria-label={t("Quitar condición")}
                  onClick={() =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      conditions: eventPolicy.conditions.filter(
                        (_, index) => index !== conditionIndex,
                      ),
                    })
                  }
                >
                  ×
                </button>
              </div>
            );
          })}

          <div className="section-heading small-heading">
            <div>
              <h4>{t("2 · Datos capturados")}</h4>
              <small>
                {t("Cada selector crea sólo el atributo indicado; el dato original se descarta.")}
              </small>
            </div>
            <button
              type="button"
              className="ghost small"
              onClick={() =>
                updateEvent(eventIndex, {
                  ...eventPolicy,
                  fields: [...eventPolicy.fields, bodyField()],
                })
              }
            >
              {t("+ campo")}
            </button>
          </div>

          {!!eventPolicy.fields.length && (
            <div className="body-field-head" aria-hidden="true">
              <span>{t("Fuente")}</span>
              <span>{t("Selector (ruta JSON, header o query)")}</span>
              <span>{t("Atributo OTel resultante")}</span>
              <span>{t("Tipo")}</span>
              <span />
            </div>
          )}

          {eventPolicy.fields.map((field, fieldIndex) => (
            <div className="nested-card" key={`${eventPolicy.id}-field-${fieldIndex}`}>
              <div className="body-field-row">
                <select
                  aria-label={t("Fuente HTTP")}
                  value={field.source}
                  onChange={(event) => {
                    const source = event.target.value;
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      fields: eventPolicy.fields.map((item, index) =>
                        index === fieldIndex
                          ? { ...item, source }
                          : item,
                      ),
                    });
                    if (source === "REQUEST_PATH_PARAM") {
                      setPolicy((current) => ({
                        ...current,
                        schemaVersion: ensurePolicySchema(current.schemaVersion, "1.5"),
                      }));
                    } else if (["REQUEST_HEADER", "RESPONSE_HEADER", "REQUEST_QUERY"].includes(source)) {
                      setPolicy((current) => ({
                        ...current,
                        schemaVersion: ensurePolicySchema(current.schemaVersion, "1.4"),
                      }));
                    }
                  }}
                >
                  {httpEventSourceOptions.map((source) => (
                    <option key={source.id} value={source.id}>{t(source.label)}</option>
                  ))}
                </select>
                <input
                  aria-label={t(httpSourceSelector(field.source).label)}
                  placeholder={t(httpSourceSelector(field.source).placeholder)}
                  value={field.path}
                  onChange={(event) =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      fields: eventPolicy.fields.map((item, index) =>
                        index === fieldIndex ? { ...item, path: event.target.value } : item,
                      ),
                    })
                  }
                />
                <input
                  aria-label={t("Atributo OTel")}
                  placeholder="customer.segment"
                  value={field.attribute}
                  onChange={(event) =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      fields: eventPolicy.fields.map((item, index) =>
                        index === fieldIndex
                          ? { ...item, attribute: event.target.value }
                          : item,
                      ),
                    })
                  }
                />
                <select
                  aria-label={t("Tipo de campo")}
                  value={field.type}
                  onChange={(event) =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      fields: eventPolicy.fields.map((item, index) =>
                        index === fieldIndex ? { ...item, type: event.target.value } : item,
                      ),
                    })
                  }
                >
                  <option>STRING</option>
                  <option>DOUBLE</option>
                  <option>LONG</option>
                  <option>BOOLEAN</option>
                </select>
                <button
                  type="button"
                  className="icon-button"
                  aria-label={t("Quitar campo")}
                  onClick={() =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      fields: eventPolicy.fields.filter(
                        (_, index) => index !== fieldIndex,
                      ),
                    })
                  }
                >
                  ×
                </button>
              </div>
              <div className="destinations body-destinations">
                {[
                  ["SPAN", "Añadir al span"],
                  ["LOG", "Añadir al log"],
                  ["METRIC", "Usar como label"],
                ].map(([destination, label]) => (
                  <label key={destination}>
                    <input
                      type="checkbox"
                      checked={(field.destinations || []).includes(destination)}
                      onChange={() => {
                        const selected = (field.destinations || []).includes(destination)
                          ? field.destinations.filter((item) => item !== destination)
                          : [...(field.destinations || []), destination];
                        updateEvent(eventIndex, {
                          ...eventPolicy,
                          fields: eventPolicy.fields.map((item, index) =>
                            index === fieldIndex
                              ? { ...item, destinations: selected }
                              : item,
                          ),
                        });
                      }}
                    />
                    {t(label)}
                  </label>
                ))}
              </div>
              {(field.destinations || []).includes("METRIC") && (
                <ValuePolicyEditor
                  value={field.valuePolicy || bounded()}
                  onChange={(valuePolicy) =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      fields: eventPolicy.fields.map((item, index) =>
                        index === fieldIndex ? { ...item, valuePolicy } : item,
                      ),
                    })
                  }
                />
              )}
            </div>
          ))}

          <details className="policy-advanced-options">
            <summary>
              {t("Datos avanzados: campos calculados")}
              {(eventPolicy.derivedFields || []).length > 0
                ? ` (${eventPolicy.derivedFields.length})`
                : ""}
            </summary>
            <div className="section-heading small-heading">
              <small>
                {t("Combina campos numéricos ya extraídos con +, -, *, / y paréntesis. Se evalúan en orden y nunca se ejecuta código.")}
              </small>
              <button
                type="button"
                className="ghost small"
                disabled={!eventPolicy.fields.some((field) =>
                  ["DOUBLE", "LONG"].includes(field.type),
                )}
                onClick={() =>
                  updateEvent(eventIndex, {
                    ...eventPolicy,
                    derivedFields: [
                      ...(eventPolicy.derivedFields || []),
                      derivedField(),
                    ],
                  })
                }
              >
                {t("+ campo calculado")}
              </button>
            </div>

          {!!(eventPolicy.derivedFields || []).length && (
            <div className="body-field-head derived" aria-hidden="true">
              <span>{t("Atributo OTel resultante")}</span>
              <span>{t("Expresión con atributos capturados")}</span>
              <span>{t("Tipo")}</span>
              <span />
            </div>
          )}

          {(eventPolicy.derivedFields || []).map((field, fieldIndex) => {
            const availableFields = [
              ...eventPolicy.fields,
              ...(eventPolicy.derivedFields || []).slice(0, fieldIndex),
            ].filter((candidate) => ["DOUBLE", "LONG"].includes(candidate.type));
            return (
              <div
                className="nested-card"
                key={`${eventPolicy.id}-derived-${fieldIndex}`}
              >
                <div className="body-field-row">
                  <input
                    aria-label={t("Atributo calculado OTel")}
                    placeholder="transaction.total"
                    value={field.attribute}
                    onChange={(event) =>
                      updateEvent(eventIndex, {
                        ...eventPolicy,
                        derivedFields: eventPolicy.derivedFields.map((item, index) =>
                          index === fieldIndex
                            ? { ...item, attribute: event.target.value }
                            : item,
                        ),
                      })
                    }
                  />
                  <input
                    className="expression-input"
                    aria-label={t("Expresión aritmética")}
                    placeholder="order.quantity * order.unit_price"
                    value={field.expression}
                    onChange={(event) =>
                      updateEvent(eventIndex, {
                        ...eventPolicy,
                        derivedFields: eventPolicy.derivedFields.map((item, index) =>
                          index === fieldIndex
                            ? { ...item, expression: event.target.value }
                            : item,
                        ),
                      })
                    }
                  />
                  <select aria-label={t("Tipo calculado")} value="DOUBLE" disabled>
                    <option>DOUBLE</option>
                  </select>
                  <button
                    type="button"
                    className="icon-button"
                    aria-label={t("Quitar campo calculado")}
                    onClick={() =>
                      updateEvent(eventIndex, {
                        ...eventPolicy,
                        derivedFields: eventPolicy.derivedFields.filter(
                          (_, index) => index !== fieldIndex,
                        ),
                      })
                    }
                  >
                    ×
                  </button>
                </div>
                <small className="hint">
                  {t("Disponibles")}: {availableFields.map((item) => item.attribute).join(", ")}
                </small>
                <div className="destinations body-destinations">
                  {[
                    ["SPAN", "Añadir al span"],
                    ["LOG", "Añadir al log"],
                    ["METRIC", "Usar como label"],
                  ].map(([destination, label]) => (
                    <label key={destination}>
                      <input
                        type="checkbox"
                        checked={(field.destinations || []).includes(destination)}
                        onChange={() => {
                          const selected = (field.destinations || []).includes(destination)
                            ? field.destinations.filter((item) => item !== destination)
                            : [...(field.destinations || []), destination];
                          updateEvent(eventIndex, {
                            ...eventPolicy,
                            derivedFields: eventPolicy.derivedFields.map((item, index) =>
                              index === fieldIndex
                                ? { ...item, destinations: selected }
                                : item,
                            ),
                          });
                        }}
                      />
                      {t(label)}
                    </label>
                  ))}
                </div>
                {(field.destinations || []).includes("METRIC") && (
                  <ValuePolicyEditor
                    value={field.valuePolicy || rangePolicy()}
                    onChange={(valuePolicy) =>
                      updateEvent(eventIndex, {
                        ...eventPolicy,
                        derivedFields: eventPolicy.derivedFields.map((item, index) =>
                          index === fieldIndex ? { ...item, valuePolicy } : item,
                        ),
                      })
                    }
                  />
                )}
              </div>
            );
          })}
          </details>

          <div className="section-heading small-heading">
            <div>
              <h4>{t("3 · Salidas: spans y logs")}</h4>
              <small>
                {t("Los datos marcados se añaden sólo a la señal elegida. Puedes asignar un nombre al evento y emitir un log correlacionado opcional.")}
              </small>
            </div>
          </div>
          <div className="nested-card event-name-output">
            <label>
              {t("Nombre del evento (opcional)")}
              <input
                value={eventNameOutput(eventPolicy).value}
                placeholder="cambistapp.exchange"
                onChange={(event) => {
                  const current = eventNameOutput(eventPolicy);
                  const value = event.target.value;
                  updateEvent(
                    eventIndex,
                    withEventNameOutput(
                      eventPolicy,
                      value,
                      value && !current.destinations.length
                        ? ["SPAN"]
                        : current.destinations,
                    ),
                  );
                }}
              />
              <small>
                {t("Se serializa explícitamente como el atributo OTel")} <code>event.name</code>.
              </small>
            </label>
            <div className="destinations body-destinations">
              {[
                ["SPAN", "Añadir al span"],
                ["LOG", "Añadir al log"],
              ].map(([destination, label]) => {
                const output = eventNameOutput(eventPolicy);
                return (
                  <label key={destination}>
                    <input
                      type="checkbox"
                      disabled={
                        !output.value
                        || (output.destinations.includes(destination)
                          && output.destinations.length === 1)
                      }
                      checked={output.destinations.includes(destination)}
                      onChange={() =>
                        updateEvent(
                          eventIndex,
                          withEventNameOutput(
                            eventPolicy,
                            output.value,
                            output.destinations.includes(destination)
                              ? output.destinations.filter((item) => item !== destination)
                              : [...output.destinations, destination],
                          ),
                        )
                      }
                    />
                    {t(label)}
                  </label>
                );
              })}
            </div>
            {eventNameOutput(eventPolicy).value
              && !eventNameOutput(eventPolicy).destinations.length && (
              <small className="error">
                {t("Selecciona al menos un destino para event.name.")}
              </small>
            )}
          </div>
          <label className="check-line">
            <input
              type="checkbox"
              checked={eventPolicy.log.enabled}
              onChange={() =>
                updateEvent(eventIndex, {
                  ...eventPolicy,
                  log: { ...eventPolicy.log, enabled: !eventPolicy.log.enabled },
                })
              }
            />
            {t("Emitir un log OTel correlacionado cuando toda la regla coincida")}
          </label>
          {eventPolicy.log.enabled && (
            <div className="row">
              <label>
                {t("Severidad del log")}
                <select
                  value={eventPolicy.log.severity}
                  onChange={(event) =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      log: { ...eventPolicy.log, severity: event.target.value },
                    })
                  }
                >
                  <option>TRACE</option>
                  <option>DEBUG</option>
                  <option>INFO</option>
                  <option>WARN</option>
                  <option>ERROR</option>
                </select>
              </label>
              <label>
                {t("Mensaje del log")}
                <input
                  value={eventPolicy.log.body}
                  onChange={(event) =>
                    updateEvent(eventIndex, {
                      ...eventPolicy,
                      log: { ...eventPolicy.log, body: event.target.value },
                    })
                  }
                />
              </label>
            </div>
          )}
          <HTTPEventMetricsEditor
            policy={policy}
            setPolicy={setPolicy}
            eventPolicy={eventPolicy}
            nameErrors={nameErrors}
            direction={direction}
          />
        </article>
      ))}
    </section>
  );
}

function MethodPoliciesEditor({ policy, setPolicy, nameErrors }) {
  const { t } = useI18n();
  const updateMethod = (index, value) =>
    setPolicy((current) => ({
      ...current,
      methodPolicies: current.methodPolicies.map((item, itemIndex) =>
        itemIndex === index ? value : item,
      ),
    }));

  return (
    <section className="editor-section">
      <div className="section-heading">
        <div>
          <p className="eyebrow">{t("MÉTODO JAVA")}</p>
          <h2>{t("Argumentos, retornos y métricas nuevas")}</h2>
        </div>
        <button
          type="button"
          className="ghost"
          onClick={() =>
            setPolicy((current) => ({
              ...current,
              methodPolicies: [...current.methodPolicies, newMethodPolicy()],
            }))
          }
        >
          {t("+ método manual")}
        </button>
      </div>
      <p className="hint">
        {t("La clase y el método cambian sin reinicio sólo dentro de packages autorizados al iniciar el agente. Las capturas marcadas METRIC forman los labels de los instrumentos del método. Las variables locales no son observables.")}
      </p>

      {policy.methodPolicies.map((methodPolicy, methodIndex) => (
        <article className="policy-card" key={methodPolicy.id}>
          <button
            type="button"
            className="remove"
            onClick={() =>
              setPolicy((current) => ({
                ...current,
                methodPolicies: current.methodPolicies.filter(
                  (_, index) => index !== methodIndex,
                ),
              }))
            }
          >
            {t("Eliminar")}
          </button>

          <div className="row">
            <label>
              {t("Package permitido")}
              <input
                placeholder="com.example.application"
                value={methodPolicy.packagePrefix}
                onChange={(event) =>
                  updateMethod(methodIndex, {
                    ...methodPolicy,
                    packagePrefix: event.target.value,
                  })
                }
              />
            </label>
            <label>
              {t("Clase completa")}
              <input
                placeholder="com.example.application.PriceCalculator"
                value={methodPolicy.className}
                onChange={(event) =>
                  updateMethod(methodIndex, {
                    ...methodPolicy,
                    className: event.target.value,
                  })
                }
              />
            </label>
            <label>
              {t("Método")}
              <input
                placeholder="calculate"
                value={methodPolicy.methodName}
                onChange={(event) =>
                  updateMethod(methodIndex, {
                    ...methodPolicy,
                    methodName: event.target.value,
                  })
                }
              />
            </label>
          </div>

          <div className="section-heading small-heading">
            <div>
              <h4>{t("Valores capturados y labels")}</h4>
              <small>{t("SPAN y LOG conservan el valor; METRIC exige cardinalidad acotada.")}</small>
            </div>
            <button
              type="button"
              className="ghost small"
              onClick={() =>
                updateMethod(methodIndex, {
                  ...methodPolicy,
                  captures: [...methodPolicy.captures, capture()],
                })
              }
            >
              {t("+ captura manual")}
            </button>
          </div>

          {methodPolicy.captures.map((item, captureIndex) => (
            <div className="capture-card" key={`${methodPolicy.id}-${captureIndex}`}>
              <div className="capture-grid">
                <label>
                  {t("Fuente")}
                  <select
                    value={item.source}
                    onChange={(event) => {
                      const source = event.target.value;
                      const captures = methodPolicy.captures.map((current, index) =>
                        index === captureIndex
                          ? {
                              ...current,
                              source,
                              argumentIndex: source === "ARGUMENT" ? 0 : -1,
                            }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, captures });
                    }}
                  >
                    <option value="ARGUMENT">{t("Argumento")}</option>
                    <option value="RETURN">{t("Retorno")}</option>
                    <option value="DURATION">{t("Duración")}</option>
                    <option value="CONSTANT">{t("Constante")}</option>
                  </select>
                </label>
                <label>
                  {t("Índice argumento")}
                  <input
                    type="number"
                    disabled={item.source !== "ARGUMENT"}
                    value={item.argumentIndex}
                    onChange={(event) => {
                      const captures = methodPolicy.captures.map((current, index) =>
                        index === captureIndex
                          ? { ...current, argumentIndex: Number(event.target.value) }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, captures });
                    }}
                  />
                </label>
                <label>
                  {t("Ruta / propiedad")}
                  <input
                    placeholder="amount"
                    value={item.path}
                    onChange={(event) => {
                      const captures = methodPolicy.captures.map((current, index) =>
                        index === captureIndex
                          ? { ...current, path: event.target.value }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, captures });
                    }}
                  />
                </label>
                <label>
                  {t("Atributo OTel / label")}
                  <input
                    placeholder="custom.amount.range"
                    value={item.attribute}
                    onChange={(event) => {
                      const captures = methodPolicy.captures.map((current, index) =>
                        index === captureIndex
                          ? { ...current, attribute: event.target.value }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, captures });
                    }}
                  />
                </label>
                <label>
                  {t("Tipo")}
                  <select
                    value={item.type}
                    onChange={(event) => {
                      const captures = methodPolicy.captures.map((current, index) =>
                        index === captureIndex
                          ? { ...current, type: event.target.value }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, captures });
                    }}
                  >
                    <option>STRING</option>
                    <option>DOUBLE</option>
                    <option>LONG</option>
                    <option>BOOLEAN</option>
                  </select>
                </label>
              </div>

              <div className="destinations">
                {["SPAN", "METRIC", "LOG"].map((destination) => (
                  <label key={destination}>
                    <input
                      type="checkbox"
                      checked={item.destinations.includes(destination)}
                      onChange={() => {
                        const captures = methodPolicy.captures.map(
                          (current, index) =>
                            index === captureIndex
                              ? {
                                  ...current,
                                  destinations: current.destinations.includes(
                                    destination,
                                  )
                                    ? current.destinations.filter(
                                        (value) => value !== destination,
                                      )
                                    : [...current.destinations, destination],
                                }
                              : current,
                        );
                        updateMethod(methodIndex, { ...methodPolicy, captures });
                      }}
                    />
                    {destination}
                  </label>
                ))}
              </div>

              {item.destinations.includes("METRIC") && (
                <ValuePolicyEditor
                  value={item.valuePolicy}
                  onChange={(valuePolicy) => {
                    const captures = methodPolicy.captures.map((current, index) =>
                      index === captureIndex
                        ? { ...current, valuePolicy }
                        : current,
                    );
                    updateMethod(methodIndex, { ...methodPolicy, captures });
                  }}
                />
              )}

              <button
                type="button"
                className="remove inline"
                onClick={() =>
                  updateMethod(methodIndex, {
                    ...methodPolicy,
                    captures: methodPolicy.captures.filter(
                      (_, index) => index !== captureIndex,
                    ),
                  })
                }
              >
                {t("Quitar captura")}
              </button>
            </div>
          ))}

          <div className="section-heading small-heading">
            <div>
              <h4>{t("Nuevos instrumentos")}</h4>
              <small>
                {t("El valor puede venir de argumento, retorno, duración o constante.")}
              </small>
            </div>
            <button
              type="button"
              className="ghost small"
              onClick={() =>
                updateMethod(methodIndex, {
                  ...methodPolicy,
                  metrics: [...methodPolicy.metrics, metric()],
                })
              }
            >
              {t("+ instrumento")}
            </button>
          </div>

          {methodPolicy.metrics.map((item, metricIndex) => (
            <div className="nested-card" key={`${methodPolicy.id}-metric-${metricIndex}`}>
              <div className="row">
                <label>
                  {t("Nombre")}
                  <input
                    className={nameErrors.includes(item.name) ? "invalid" : ""}
                    value={item.name}
                    onChange={(event) => {
                      const metrics = methodPolicy.metrics.map((current, index) =>
                        index === metricIndex
                          ? { ...current, name: event.target.value }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, metrics });
                    }}
                  />
                </label>
                <label>
                  {t("Instrumento")}
                  <select
                    value={item.instrument}
                    onChange={(event) => {
                      const instrument = event.target.value;
                      const metrics = methodPolicy.metrics.map((current, index) =>
                        index === metricIndex
                          ? {
                              ...current,
                              instrument,
                              buckets:
                                instrument === "HISTOGRAM" ? defaultBuckets : [],
                            }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, metrics });
                    }}
                  >
                    <option>COUNTER</option>
                    <option>HISTOGRAM</option>
                    <option>UP_DOWN_COUNTER</option>
                  </select>
                </label>
                <label>
                  {t("Unidad")}
                  <input
                    value={item.unit}
                    onChange={(event) => {
                      const metrics = methodPolicy.metrics.map((current, index) =>
                        index === metricIndex
                          ? { ...current, unit: event.target.value }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, metrics });
                    }}
                  />
                </label>
              </div>
              <label>
                {t("Descripción")}
                <input
                  value={item.description}
                  onChange={(event) => {
                    const metrics = methodPolicy.metrics.map((current, index) =>
                      index === metricIndex
                        ? { ...current, description: event.target.value }
                        : current,
                    );
                    updateMethod(methodIndex, { ...methodPolicy, metrics });
                  }}
                />
              </label>
              <div className="row">
                <label>
                  {t("Fuente del valor")}
                  <select
                    value={item.value.source}
                    onChange={(event) => {
                      const source = event.target.value;
                      const metrics = methodPolicy.metrics.map((current, index) =>
                        index === metricIndex
                          ? {
                              ...current,
                              value: {
                                ...current.value,
                                source,
                                argumentIndex: source === "ARGUMENT" ? 0 : -1,
                              },
                            }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, metrics });
                    }}
                  >
                    <option>ARGUMENT</option>
                    <option>RETURN</option>
                    <option>DURATION</option>
                    <option>CONSTANT</option>
                  </select>
                </label>
                <label>
                  {t("Índice argumento")}
                  <input
                    type="number"
                    disabled={item.value.source !== "ARGUMENT"}
                    value={item.value.argumentIndex}
                    onChange={(event) => {
                      const metrics = methodPolicy.metrics.map((current, index) =>
                        index === metricIndex
                          ? {
                              ...current,
                              value: {
                                ...current.value,
                                argumentIndex: Number(event.target.value),
                              },
                            }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, metrics });
                    }}
                  />
                </label>
                <label>
                  {t("Ruta / propiedad")}
                  <input
                    value={item.value.path}
                    onChange={(event) => {
                      const metrics = methodPolicy.metrics.map((current, index) =>
                        index === metricIndex
                          ? {
                              ...current,
                              value: { ...current.value, path: event.target.value },
                            }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, metrics });
                    }}
                  />
                </label>
                <label>
                  {t("Constante")}
                  <input
                    type="number"
                    value={item.value.constant}
                    onChange={(event) => {
                      const metrics = methodPolicy.metrics.map((current, index) =>
                        index === metricIndex
                          ? {
                              ...current,
                              value: {
                                ...current.value,
                                constant: Number(event.target.value),
                              },
                            }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, metrics });
                    }}
                  />
                </label>
              </div>
              {item.instrument === "HISTOGRAM" && (
                <label>
                  {t("Buckets explícitos")}
                  <input
                    value={item.buckets.join(",")}
                    onChange={(event) => {
                      const metrics = methodPolicy.metrics.map((current, index) =>
                        index === metricIndex
                          ? {
                              ...current,
                              buckets: event.target.value
                                .split(",")
                                .map(Number)
                                .filter(Number.isFinite),
                            }
                          : current,
                      );
                      updateMethod(methodIndex, { ...methodPolicy, metrics });
                    }}
                  />
                </label>
              )}
              <button
                type="button"
                className="remove inline"
                onClick={() => {
                  const metrics = methodPolicy.metrics.filter(
                    (_, index) => index !== metricIndex,
                  );
                  updateMethod(methodIndex, { ...methodPolicy, metrics });
                }}
              >
                {t("Quitar instrumento")}
              </button>
            </div>
          ))}

          <label className="check-line">
            <input
              type="checkbox"
              checked={methodPolicy.log.enabled}
              onChange={(event) =>
                updateMethod(methodIndex, {
                  ...methodPolicy,
                  log: { ...methodPolicy.log, enabled: event.target.checked },
                })
              }
            />
            {t("Emitir un log OTel correlacionado con las capturas marcadas LOG")}
          </label>
          {methodPolicy.log.enabled && (
            <div className="row">
              <label>
                {t("Severidad")}
                <select
                  value={methodPolicy.log.severity}
                  onChange={(event) =>
                    updateMethod(methodIndex, {
                      ...methodPolicy,
                      log: { ...methodPolicy.log, severity: event.target.value },
                    })
                  }
                >
                  <option>TRACE</option>
                  <option>DEBUG</option>
                  <option>INFO</option>
                  <option>WARN</option>
                  <option>ERROR</option>
                </select>
              </label>
              <label>
                {t("Mensaje")}
                <input
                  value={methodPolicy.log.body}
                  onChange={(event) =>
                    updateMethod(methodIndex, {
                      ...methodPolicy,
                      log: { ...methodPolicy.log, body: event.target.value },
                    })
                  }
                />
              </label>
            </div>
          )}
        </article>
      ))}
    </section>
  );
}

const denylistKinds = [
  {
    kind: "HEADER",
    label: "Headers HTTP",
    placeholder: "authorization\ncookie\nx-api-key",
    help: "Coincidencia exacta, sin distinguir mayúsculas y minúsculas.",
  },
  {
    kind: "BODY_PATH",
    label: "Paths JSON de request/response",
    placeholder: "password\ncustomer.email\ncustomer.accountNumber",
    help: "Usa paths JSON sin $. Bloquear un padre bloquea sus descendientes.",
  },
  {
    kind: "QUERY_PARAM",
    label: "Query params HTTP",
    placeholder: "access_token\napi_key\npassword",
    help: "Coincidencia exacta y sensible a mayúsculas; aplica a REQUEST_QUERY.",
  },
  {
    kind: "PATH_PARAM",
    label: "Path params HTTP",
    placeholder: "customerId\naccountId",
    help: "Coincidencia exacta con el nombre lógico declarado en la plantilla del path.",
  },
  {
    kind: "MESSAGE_PROPERTY",
    label: "Properties JMS",
    placeholder: "customerId\naccountNumber",
    help: "Coincidencia exacta con el nombre de la propiedad JMS; los message headers usan la denylist de headers.",
  },
  {
    kind: "METHOD_PATH",
    label: "Paths de argumentos/retornos",
    placeholder: "password\ncustomer.email\naccount.number",
    help: "Se compara con el object path configurado en la captura del método.",
  },
];

function SecurityView({
  entries,
  actor,
  setActor,
  onReload,
  setNotice,
}) {
  const { t } = useI18n();
  const serialize = (kind) =>
    entries
      .filter((entry) => entry.Kind === kind)
      .map((entry) => entry.Value)
      .join("\n");
  const [draft, setDraft] = useState(() =>
    Object.fromEntries(denylistKinds.map(({ kind }) => [kind, serialize(kind)])),
  );
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!dirty) {
      setDraft(
        Object.fromEntries(
          denylistKinds.map(({ kind }) => [kind, serialize(kind)]),
        ),
      );
    }
  }, [entries, dirty]);

  const save = async () => {
    const payload = denylistKinds.flatMap(({ kind }) =>
      unique(
        (draft[kind] || "")
          .split("\n")
          .map((value) => value.trim())
          .filter(Boolean),
      ).map((Value) => ({ Kind: kind, Value })),
    );
    setSaving(true);
    try {
      const response = await fetch("/api/security/denylist", {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          "x-actor": actor,
        },
        credentials: "same-origin",
        body: JSON.stringify(payload),
      });
      const message = await response.text();
      if (!response.ok) throw new Error(message.trim());
      setDirty(false);
      setNotice(
        t("Denylist guardada. Las siguientes publicaciones y rollbacks se validarán contra esta versión."),
      );
      await onReload();
    } catch (error) {
      setNotice(`${t("Error")}: ${error.message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <section className="panel">
      <div className="panel-title">
        <div>
          <p className="eyebrow">{t("SEGURIDAD CENTRAL")}</p>
          <h2>{t("Denylist del Control Plane")}</h2>
          <p className="explanation">
            {t("El servidor rechaza cualquier policy que intente leer una entrada bloqueada. La extensión recibe únicamente policies ya aprobadas y no contiene clasificación de datos sensibles.")}
          </p>
        </div>
      </div>

      <div className="security-grid">
        {denylistKinds.map(({ kind, label, placeholder, help }) => (
          <label key={kind}>
            {t(label)}
            <textarea
              className="code"
              rows="10"
              placeholder={t(placeholder)}
              value={draft[kind] || ""}
              onChange={(event) => {
                setDraft((current) => ({
                  ...current,
                  [kind]: event.target.value,
                }));
                setDirty(true);
              }}
            />
            <small>{t(help)} {t("Una entrada por línea.")}</small>
          </label>
        ))}
      </div>

      <label className="publication-fields">
        {t("Identidad auditada")}
        <input value={actor} readOnly />
      </label>
      <button
        type="button"
        className="primary"
        disabled={!dirty || saving}
        onClick={save}
      >
        {saving ? t("Validando…") : t("Validar y guardar denylist")}
      </button>
      <p className="hint">
        {t("Si una policy activa viola la nueva lista, el cambio se rechaza. Retira primero esa captura de la policy y vuelve a publicar.")}
      </p>
    </section>
  );
}

function AgentsView({ agents, collectorBases, onReload }) {
  const { t, formatDate } = useI18n();
  const [query, setQuery] = useState("");
  const [services, setServices] = useState([]);
  const [kinds, setKinds] = useState([]);
  const [transports, setTransports] = useState([]);
  const [availability, setAvailability] = useState([]);
  const [effectiveStatuses, setEffectiveStatuses] = useState([]);
  const rows = useMemo(
    () => projectFleetAgents(agents, collectorBases),
    [agents, collectorBases],
  );
  const filterOptions = useMemo(() => ({
    services: fleetFilterValues(rows, (row) => row.agent.Service)
      .map((value) => ({ value, label: value })),
    kinds: fleetFilterValues(rows, (row) => row.agent.Kind)
      .map((value) => ({
        value,
        label: value === "collector"
            ? t("Collector")
            : value === "java-extension"
            ? "Java extension"
            : value,
      })),
    transports: fleetFilterValues(rows, (row) => row.agent.Transport)
      .map((value) => ({
        value,
        label: value === "http-poll"
          ? "HTTP polling"
          : value === "websocket"
            ? "WebSocket"
            : value,
      })),
    availability: fleetFilterValues(rows, (row) => row.availability)
      .map((value) => ({ value, label: t(statusMeta(value, "connection")[0]) })),
    effectiveStatuses: fleetFilterValues(rows, (row) => row.effectiveStatus)
      .map((value) => ({ value, label: t(statusMeta(value, "config")[0]) })),
  }), [rows, t]);
  const visibleRows = useMemo(
    () => filterFleetAgentRows(rows, {
      query,
      services,
      kinds,
      transports,
      availability,
      effectiveStatuses,
    }),
    [
      rows,
      query,
      services,
      kinds,
      transports,
      availability,
      effectiveStatuses,
    ],
  );

  return (
    <section className="panel">
      <div className="panel-title">
        <div>
          <p className="eyebrow">FLEET</p>
          <h2>{t("Clientes OpAMP")}</h2>
          <p className="explanation">
            <b>{t("Disponibilidad")}</b> {t("y")} <b>{t("configuración")}</b>{" "}
            {t("son estados diferentes. “Aplicada” significa que el cliente validó la última versión recibida. La lista y el contador de conectados se actualizan automáticamente cada")}{" "}
            {controlPlaneRefreshIntervalMs / 1000} {t("segundos")}.
          </p>
        </div>
        <button className="ghost" onClick={onReload}>
          {t("Actualizar")}
        </button>
      </div>
      <div className="table-filters fleet-filters">
        <label>
          {t("Buscar clientes")}
          <input
            type="search"
            placeholder={t("Servicio, instance ID, configuración o atributo")}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>
        <MultiSelectFilter
          label={t("Servicio")}
          options={filterOptions.services}
          values={services}
          onChange={setServices}
        />
        <MultiSelectFilter
          label={t("Tipo")}
          options={filterOptions.kinds}
          values={kinds}
          onChange={setKinds}
        />
        <MultiSelectFilter
          label={t("Transporte")}
          options={filterOptions.transports}
          values={transports}
          onChange={setTransports}
        />
        <MultiSelectFilter
          label={t("Disponibilidad")}
          options={filterOptions.availability}
          values={availability}
          onChange={setAvailability}
        />
        <MultiSelectFilter
          label={t("Estado efectivo")}
          options={filterOptions.effectiveStatuses}
          values={effectiveStatuses}
          onChange={setEffectiveStatuses}
        />
      </div>
      <p className="fleet-filter-result" role="status" aria-live="polite">
        {visibleRows.length} {t("de")} {rows.length} {t("clientes")}
      </p>
      <div className="table">
        <div className="tr head">
          <span>{t("Servicio / instance ID")}</span>
          <span>{t("Tipo / transporte")}</span>
          <span>{t("Disponibilidad")}</span>
          <span>{t("Estado efectivo")}</span>
          <span>{t("Configuración / fallback")}</span>
          <span>{t("Atributos reportados")}</span>
        </div>
        {visibleRows.map(({
          agent,
          collectorMode,
          reportedVersions,
          javaPolicies,
          availability: agentAvailability,
          effectiveStatus,
        }) => (
          <div className="tr" key={agent.UID}>
            <span>
              <b>{agent.Service}</b>
              <small>{agent.UID}</small>
            </span>
            <span>
              {agent.Kind}
              <small>
                {agent.Transport === "http-poll"
                  ? `HTTP · ${agent.PollIntervalSeconds}s`
                  : "WebSocket"}
              </small>
            </span>
            <span>
              <StatusBadge status={agentAvailability} type="connection" />
              <small>
                {t("Infraestructura")}: {agent.InfrastructureStatus === "UNKNOWN"
                  ? t("no verificada")
                  : agent.InfrastructureStatus || t("no reportada")}
              </small>
            </span>
            <span>
              <StatusBadge
                status={effectiveStatus}
                type="config"
              />
            </span>
            <span>
              <b>
                {collectorMode?.effectiveLabel ||
                  (agent.Kind === "java-extension"
                    ? javaPolicies.length
                      ? `${javaPolicies.length} ${t(javaPolicies.length === 1 ? "policy activa" : "policies activas")}`
                      : t("Sin policies activas")
                    : agent.ConfigID
                      ? `${agent.ConfigID} · v${agent.Version}`
                      : t("Sin configuración"))}
              </b>
              {agent.Kind === "java-extension" && javaPolicies.length > 0 && (
                <small title={javaPolicies.map(({ id, version }) => `${id} · v${version}`).join(" · ")}>
                  {javaPolicies.map(({ id, version }) => `${id} · v${version}`).join(" · ")}
                </small>
              )}
              {collectorMode && <small>{t("Fallback")}: {collectorMode.fallbackLabel}</small>}
              {collectorMode && (reportedVersions.supervisor || reportedVersions.collector) && (
                <small>
                  {[
                    reportedVersions.supervisor && `Supervisor ${reportedVersions.supervisor}`,
                    reportedVersions.collector && `Collector ${reportedVersions.collector}`,
                  ].filter(Boolean).join(" · ")}
                </small>
              )}
              <small>{formatDate(agent.LastSeen)}</small>
            </span>
            <span>
              <AgentAttributesButton agent={agent} />
            </span>
          </div>
        ))}
        {!rows.length && <div className="empty">{t("Esperando clientes OpAMP…")}</div>}
        {rows.length > 0 && !visibleRows.length && (
          <div className="empty">{t("No hay clientes que coincidan con los filtros.")}</div>
        )}
      </div>
    </section>
  );
}

function AgentAttributesButton({ agent }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const dialogTitleId = useId();
  const dialogDescriptionId = useId();
  const triggerRef = useRef(null);
  const closeRef = useRef(null);
  const attributes = useMemo(
    () => reportedAttributeEntries(agent.Attributes),
    [agent.Attributes],
  );

  useEffect(() => {
    if (!open || !attributes.length) {
      return undefined;
    }

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeRef.current?.focus();

    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setOpen(false);
      } else if (event.key === "Tab") {
        // The close control is intentionally the only focusable element in this dialog.
        event.preventDefault();
        closeRef.current?.focus();
      }
    };
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      triggerRef.current?.focus();
    };
  }, [open, attributes.length]);

  if (!attributes.length) {
    return <small className="agent-attributes-empty">{t("Sin atributos")}</small>;
  }

  return (
    <>
      <button
        ref={triggerRef}
        type="button"
        className="ghost small agent-attributes-trigger"
        aria-haspopup="dialog"
        aria-expanded={open}
        aria-label={`${t("Ver atributos")} (${attributes.length}) · ${agent.Service}`}
        onClick={() => setOpen(true)}
      >
        <span aria-hidden="true">{t("Ver atributos")} ({attributes.length})</span>
      </button>
      {open && (
        <div
          className="agent-attributes-backdrop"
          role="presentation"
          onMouseDown={() => setOpen(false)}
        >
          <section
            className="agent-attributes-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby={dialogTitleId}
            aria-describedby={dialogDescriptionId}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="agent-attributes-heading">
              <div>
                <p className="eyebrow">{t("CLIENTE OPAMP")}</p>
                <h2 id={dialogTitleId}>{t("Atributos reportados")}</h2>
                <p id={dialogDescriptionId}>
                  <b>{agent.Service}</b>
                  <span>{agent.UID}</span>
                </p>
              </div>
              <button
                ref={closeRef}
                type="button"
                className="ghost"
                onClick={() => setOpen(false)}
              >
                {t("Cerrar")}
              </button>
            </div>
            <dl className="agent-attributes-list">
              {attributes.map(([key, value]) => (
                <div key={key}>
                  <dt>{key}</dt>
                  <dd>{formatReportedAttributeValue(value)}</dd>
                </div>
              ))}
            </dl>
          </section>
        </div>
      )}
    </>
  );
}

function PolicyDocumentButton({ body, target, label }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const buttonLabel = label || documentButtonLabel(target);
  let formatted = body || "";
  if (target === "java-extension" || target === "collector-base") {
    try {
      formatted = JSON.stringify(JSON.parse(formatted), null, 2);
    } catch {
      // Preserve the original document when it is not valid JSON.
    }
  }
  return (
    <>
      <button type="button" className="ghost small" onClick={() => setOpen(true)}>
        {t(buttonLabel)}
      </button>
      {open && (
        <div className="document-popover-backdrop" role="presentation" onMouseDown={() => setOpen(false)}>
          <section
            className="document-popover"
            role="dialog"
            aria-modal="true"
            aria-label={
              target === "collector"
                ? t("Configuración YAML")
                : target === "collector-base"
                  ? t("Configuración base inmutable")
                  : "Policy JSON"
            }
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="panel-title">
              <div>
                <p className="eyebrow">
                  {t(target === "collector-base" ? "BASE INMUTABLE" : "DOCUMENTO INMUTABLE")}
                </p>
                <h2>
                  {target === "collector"
                    ? "Collector YAML"
                    : target === "collector-base"
                      ? t("Descriptor del ConfigMap base")
                      : "Policy JSON"}
                </h2>
              </div>
              <button type="button" className="ghost" onClick={() => setOpen(false)}>
                {t("Cerrar")}
              </button>
            </div>
            <pre>{formatted}</pre>
          </section>
        </div>
      )}
    </>
  );
}

function SelectorDetailsButton({ selector, coverage, destinationLabel = "destinos" }) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const details = selectorDetails(selector);
  const selectorMatched = coverage?.desiredMatched ?? coverage?.matched ?? 0;
  return (
    <>
      <div className="selector-table-summary">
        <span className={`scope-chip ${details.exact ? "exact" : "dynamic"}`}>
          {t(details.scopeLabel)}
        </span>
        <small>{t(details.summary)}</small>
        {coverage && (
          <small className="selector-live-coverage">
            {t(`${selectorMatched} vivo(s) coincide(n) · ${coverage.applied || 0} aplicada(s)`)}
            {coverage.removalMatched
              ? ` · ${t(`${coverage.removalMatched} retiro(s) en seguimiento`)}`
              : ""}
          </small>
        )}
        <button
          type="button"
          className="ghost small"
          onClick={() => setOpen(true)}
          aria-label={`${t("Ver selectores")} · ${destinationLabel}`}
        >
          {t("Ver selectores")}
        </button>
      </div>
      {open && (
        <div
          className="document-popover-backdrop"
          role="presentation"
          onMouseDown={() => setOpen(false)}
        >
          <section
            className="document-popover selector-popover"
            role="dialog"
            aria-modal="true"
            aria-label={`${t("Selectores")} · ${destinationLabel}`}
            onMouseDown={(event) => event.stopPropagation()}
          >
            <div className="panel-title">
              <div>
                <p className="eyebrow">{t("ALCANCE DE PUBLICACIÓN")}</p>
                <h2>{t("Selectores aplicados")}</h2>
                <p className="explanation">
                  {t("La cobertura viva se calcula sólo con clientes actualmente en línea que cumplen todos estos criterios.")}
                </p>
              </div>
              <button type="button" className="ghost" onClick={() => setOpen(false)}>
                {t("Cerrar")}
              </button>
            </div>
            <dl className="selector-details-list">
              <div>
                <dt>{t("Modalidad")}</dt>
                <dd>
                  <span className={`scope-chip ${details.exact ? "exact" : "dynamic"}`}>
                    {t(details.scopeLabel)}
                  </span>
                  {details.exact
                    ? ` ${t("Sólo las instancias indicadas; una réplica nueva no hereda este alcance.")}`
                    : ` ${t("Las réplicas nuevas que coincidan también reciben la configuración.")}`}
                </dd>
              </div>
              <div>
                <dt>{t("Servicios")}</dt>
                <dd>{details.services.join(", ") || t("Sin restricción")}</dd>
              </div>
              <div>
                <dt>Resource attributes</dt>
                <dd>
                  {details.attributes.length
                    ? details.attributes.map(([key, value]) => (
                      <code className="selector-value" key={key}>{key}={value}</code>
                    ))
                    : t("Sin restricción")}
                </dd>
              </div>
              <div>
                <dt>{t("InstanceUID exactos")}</dt>
                <dd>
                  {details.instanceUIDs.length
                    ? details.instanceUIDs.map((uid) => (
                      <code className="selector-value" key={uid}>{uid}</code>
                    ))
                    : t("Sin restricción")}
                </dd>
              </div>
              {coverage && (
                <div>
                  <dt>{t("Cobertura actual")}</dt>
                  <dd>
                    {t(`${coverage.applied || 0}/${selectorMatched} destino(s) vivo(s) coincidente(s) confirmaron la versión.`)}
                    {coverage.removalMatched
                      ? ` ${t(`${coverage.removalMatched} destino(s) adicional(es) se siguen hasta confirmar el retiro.`)}`
                      : ""}
                    {coverage.degraded
                      ? ` ${t(`${coverage.degraded} señal(es) degradada(s) no cuentan.`)}`
                      : ""}
                    {coverage.historical
                      ? ` ${t(`${coverage.historical} registro(s) histórico(s) no cuentan.`)}`
                      : ""}
                    {coverage.unknown
                      ? ` ${t(`${coverage.unknown} destino(s) tienen estado desconocido.`)}`
                      : ""}
                  </dd>
                </div>
              )}
            </dl>
          </section>
        </div>
      )}
    </>
  );
}

function DeploymentsView({
  deployments,
  versions,
  collectorBases,
  busy,
  onPolicyLifecycle,
  onCollectorLifecycle,
  onReload,
}) {
  const { t, formatDate } = useI18n();
  const [policyQuery, setPolicyQuery] = useState("");
  const [policyStatuses, setPolicyStatuses] = useState([]);
  const [selectedPolicyServices, setSelectedPolicyServices] = useState([]);
  const [detailQuery, setDetailQuery] = useState("");
  const [detailStatuses, setDetailStatuses] = useState([]);
  const [detailTargets, setDetailTargets] = useState([]);
  const [detailPolicies, setDetailPolicies] = useState([]);
  const [collectorQuery, setCollectorQuery] = useState("");
  const [collectorStatuses, setCollectorStatuses] = useState([]);
  const [selectedCollectorServices, setSelectedCollectorServices] = useState([]);
  const managedPolicies = useMemo(
    () => buildManagedPolicies(versions, deployments),
    [versions, deployments],
  );
  const policyServices = useMemo(
    () => unique(managedPolicies.flatMap((policy) => policy.services)).sort(),
    [managedPolicies],
  );
  const managedCollectors = useMemo(
    () => buildManagedCollectorConfigs(versions, deployments, collectorBases),
    [versions, deployments, collectorBases],
  );
  const collectorServices = useMemo(
    () => unique(managedCollectors.flatMap((config) => config.services)).sort(),
    [managedCollectors],
  );
  const visibleCollectors = useMemo(
    () => filterManagedCollectorConfigs(managedCollectors, {
      query: collectorQuery,
      status: collectorStatuses,
      service: selectedCollectorServices,
    }),
    [managedCollectors, collectorQuery, collectorStatuses, selectedCollectorServices],
  );
  const visiblePolicies = useMemo(
    () => filterManagedPolicies(managedPolicies, {
      query: policyQuery,
      status: policyStatuses,
      service: selectedPolicyServices,
    }),
    [managedPolicies, policyQuery, policyStatuses, selectedPolicyServices],
  );
  const detailPolicyOptions = useMemo(
    () => unique(deployments.map((record) => record.ConfigID)).sort(),
    [deployments],
  );
  const visibleDestinations = useMemo(() => {
    const needle = detailQuery.trim().toLowerCase();
    return sortDestinationRecords(deployments.filter((record) => {
      const status = coverageStatusForDisplay(record) || deploymentRecordStatus(record);
      if (!matchesAnySelection(detailStatuses, status)) return false;
      if (!matchesAnySelection(detailTargets, record.Target)) return false;
      if (!matchesAnySelection(detailPolicies, record.ConfigID)) return false;
      if (!needle) return true;
      return [
        record.ConfigID,
        record.Version,
        record.Service,
        record.AgentUID,
        record.PublishedBy,
        ...Object.entries(record.AgentAttributes || {}).map(
          ([key, value]) => `${key}=${value}`,
        ),
      ].some((value) => String(value || "").toLowerCase().includes(needle));
    }));
  }, [deployments, detailQuery, detailStatuses, detailTargets, detailPolicies]);
  const applied = deployments.filter(
    (record) =>
      deploymentCoverage(record).counts && deploymentRecordStatus(record) === "APPLIED",
  ).length;
  const activePolicies = managedPolicies.filter((policy) => policy.active).length;
  const activeCollectors = managedCollectors.filter((config) => config.active).length;

  return (
    <>
      <section className="summary collector-management-summary">
        <div><small>{t("Policies activas")}</small><strong>{activePolicies}</strong></div>
        <div><small>{t("Configs Collector administradas")}</small><strong>{activeCollectors}</strong></div>
        <div><small>{t("Destinos en línea y aplicados")}</small><strong>{applied}</strong></div>
        <div>
          <small>{t("Actualización")}</small>
          <strong>{controlPlaneRefreshIntervalMs / 1000}s</strong>
        </div>
      </section>
      <section className="panel collector-configs-panel">
        <div className="panel-title">
          <div>
            <p className="eyebrow">{t("CONFIGURACIONES COLLECTOR")}</p>
            <h2>{t("Configuración administrada y fallback")}</h2>
            <p className="explanation">
              {t("La configuración remota puede retirarse. El Supervisor vuelve entonces a su base NOP inmutable del ConfigMap; esa base nunca se elimina desde el Control Plane.")}
            </p>
          </div>
          <button type="button" className="ghost" onClick={onReload}>{t("Actualizar")}</button>
        </div>
        <div className="table-filters three">
          <label>
            {t("Buscar configuración")}
            <input
              type="search"
              placeholder={t("ID, Supervisor, base, autor o selector")}
              value={collectorQuery}
              onChange={(event) => setCollectorQuery(event.target.value)}
            />
          </label>
          <MultiSelectFilter
            label={t("Estado")}
            options={translatedOptions(t, collectorStatusFilterOptions)}
            values={collectorStatuses}
            onChange={setCollectorStatuses}
          />
          <MultiSelectFilter
            label={t("Supervisor")}
            options={collectorServices.map((service) => ({ value: service, label: service }))}
            values={selectedCollectorServices}
            onChange={setSelectedCollectorServices}
          />
        </div>
        <div className="data-table-wrap">
          <table className="data-table collector-configs-table">
            <thead>
              <tr>
                <th>{t("Configuración / versión")}</th>
                <th>{t("Supervisors")}</th>
                <th>{t("Selectores")}</th>
                <th>{t("Fallback inmutable")}</th>
                <th>{t("Live status")}</th>
                <th>{t("Documento")}</th>
                <th>{t("Acciones")}</th>
              </tr>
            </thead>
            <tbody>
              {visibleCollectors.map((config) => (
                <tr key={config.id}>
                  <td>
                    <b>{config.id}</b>
                    <small>
                      v{policyVersionNumber(config.latestVersion)} · {config.versions.length}{" "}
                      {t(config.versions.length === 1 ? "versión" : "versiones")}
                      {config.active ? ` · ${t("Administrada")}` : ` · ${t("Retirada")}`}
                    </small>
                  </td>
                  <td>
                    <b>{config.services.join(", ") || t("Todos los compatibles")}</b>
                    <small>{config.records.length} {t("destino(s) observado(s)")}</small>
                  </td>
                  <td>
                    <SelectorDetailsButton
                      selector={config.selector}
                      coverage={config.destinationSummary}
                      destinationLabel={config.id}
                    />
                  </td>
                  <td>
                    {config.fallbackBases.length ? config.fallbackBases.map((base) => (
                      <span className="collector-base-reference" key={base.ID}>
                        <b>{base.ID}</b>
                        <small>{base.Source} · Inmutable · {base.Behavior}</small>
                      </span>
                    )) : <small>{t("Base todavía no reportada")}</small>}
                  </td>
                  <td>
                    <StatusBadge status={config.destinationSummary.status} type="deployment" />
                    <small>{t(collectorSummaryText(config.destinationSummary))}</small>
                  </td>
                  <td>
                    <PolicyDocumentButton
                      body={config.lastContentVersion.Body}
                      target="collector"
                      label={t("Ver YAML")}
                    />
                  </td>
                  <td>
                    {config.active ? (
                      <button
                        type="button"
                        className="ghost small danger on"
                        disabled={busy}
                        onClick={() => onCollectorLifecycle(config)}
                      >
                        {t(config.actionLabel)}
                      </button>
                    ) : (
                      <small>{t("La base es sólo lectura")}</small>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!visibleCollectors.length && (
          <div className="empty">{t("No hay configuraciones Collector administradas que coincidan.")}</div>
        )}
      </section>
      <section className="panel">
        <div className="panel-title">
          <div>
            <p className="eyebrow">{t("GESTIÓN POR POLICY")}</p>
            <h2>{t("Policies por microservicio")}</h2>
            <p className="explanation">
              {t("Cada fila representa una policy independiente. Un microservicio puede aparecer en varias filas; el estado indica qué versión confirma cada destino en este momento.")}
            </p>
          </div>
          <button type="button" className="ghost" onClick={onReload}>{t("Actualizar")}</button>
        </div>
        <div className="table-filters three">
          <label>
            {t("Buscar policy")}
            <input
              type="search"
              placeholder={t("Nombre, microservicio, autor o selector")}
              value={policyQuery}
              onChange={(event) => setPolicyQuery(event.target.value)}
            />
          </label>
          <MultiSelectFilter
            label={t("Estado")}
            options={translatedOptions(t, policyStatusFilterOptions)}
            values={policyStatuses}
            onChange={setPolicyStatuses}
          />
          <MultiSelectFilter
            label={t("Microservicio")}
            options={policyServices.map((service) => ({ value: service, label: service }))}
            values={selectedPolicyServices}
            onChange={setSelectedPolicyServices}
          />
        </div>
        <div className="data-table-wrap">
          <table className="data-table policies-table">
            <thead>
              <tr>
                <th>{t("Policy / versión")}</th>
                <th>{t("Microservicios")}</th>
                <th>{t("Selectores")}</th>
                <th>{t("Live status")}</th>
                <th>{t("Documento")}</th>
                <th>{t("Acciones")}</th>
              </tr>
            </thead>
            <tbody>
              {visiblePolicies.map((policy) => {
                const documentVersion = policy.lastContentVersion || policy.latestVersion;
                return (
                  <tr key={policy.id}>
                    <td>
                      <b>{policy.id}</b>
                      <small>
                        v{policyVersionNumber(policy.latestVersion)} · {policy.versionCount} {t(policy.versionCount === 1 ? "versión" : "versiones")}
                        {policy.active ? ` · ${t("Activa")}` : ` · ${t("Retirada")}`}
                      </small>
                    </td>
                    <td>
                      <b>{policy.services.join(", ") || t("Todos los compatibles")}</b>
                      <small>{policy.records.length} {t("destino(s) observado(s)")}</small>
                    </td>
                    <td>
                      <SelectorDetailsButton
                        selector={policy.selector}
                        coverage={policy.destinationSummary}
                        destinationLabel={policy.id}
                      />
                    </td>
                    <td>
                      <StatusBadge status={policy.destinationSummary.status} type="deployment" />
                      <small>{t(managedPolicyDestinationSummary(policy.destinationSummary))}</small>
                    </td>
                    <td>
                      <PolicyDocumentButton
                        body={documentVersion?.Body}
                        target="java-extension"
                      />
                    </td>
                    <td>
                      <div className="table-actions policy-management-actions">
                        <button
                          type="button"
                          className="ghost small"
                          onClick={() => setDetailPolicies([policy.id])}
                        >
                          {t("Ver destinos")}
                        </button>
                        {policy.active && (
                          <button
                            type="button"
                            className={policy.action === "DEACTIVATE" ? "ghost small danger on" : "ghost small"}
                            disabled={busy}
                            aria-label={
                              policy.action === "REVERT"
                                ? `Revertir versión anterior de ${policy.id}: ${policy.actionLabel}`
                                : `${policy.actionLabel}: ${policy.id}`
                            }
                            onClick={() => onPolicyLifecycle(policy)}
                          >
                            {t(policy.actionLabel)}
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {!visiblePolicies.length && <div className="empty">{t("No hay policies que coincidan.")}</div>}
      </section>

      <section className="panel policy-destinations-panel">
        <div className="panel-title">
          <div>
            <p className="eyebrow">{t("ESTADO POR DESTINO")}</p>
            <h2>{t("Confirmación viva de cada agente")}</h2>
            <p className="explanation">
              {t("Un selector estable por servicio o resource attributes alcanza también réplicas futuras. Un InstanceUID exacto sólo alcanza ese proceso.")}
            </p>
          </div>
          {!!detailPolicies.length && (
            <button type="button" className="ghost" onClick={() => setDetailPolicies([])}>
              {t("Ver todas")}
            </button>
          )}
        </div>
        <div className="table-filters four">
          <label>
            {t("Buscar destino")}
            <input
              type="search"
              placeholder={t("Servicio, pod, UID, autor o atributo")}
              value={detailQuery}
              onChange={(event) => setDetailQuery(event.target.value)}
            />
          </label>
          <MultiSelectFilter
            label={t("Policy / configuración")}
            allLabel={t("Todas")}
            options={detailPolicyOptions.map((id) => ({ value: id, label: id }))}
            values={detailPolicies}
            onChange={setDetailPolicies}
          />
          <MultiSelectFilter
            label={t("Estado vivo")}
            options={translatedOptions(t, destinationStatusFilterOptions)}
            values={detailStatuses}
            onChange={setDetailStatuses}
          />
          <MultiSelectFilter
            label={t("Tipo")}
            options={translatedOptions(t, targetFilterOptions)}
            values={detailTargets}
            onChange={setDetailTargets}
          />
        </div>
        <div className="data-table-wrap">
          <table className="data-table deployments-table">
            <thead>
              <tr>
                <th>{t("Policy o configuración / versión")}</th>
                <th>{t("Destino")}</th>
                <th>{t("Alcance")}</th>
                <th>{t("Confirmación")}</th>
                <th>{t("Live status")}</th>
                <th>{t("Documento")}</th>
              </tr>
            </thead>
            <tbody>
              {visibleDestinations.map((record) => {
                const live = deploymentRecordStatus(record);
                const coverageStatus = coverageStatusForDisplay(record);
                const displayedStatus = coverageStatus || live;
                const confirmation = deploymentConfirmation(record, live);
                const dynamic = !(record.Selector?.InstanceUIDs || []).length;
                return (
                  <tr key={`${record.ConfigID}-${record.Version}-${record.AgentUID}`}>
                    <td>
                      <b>{record.ConfigID} · v{record.Version}</b>
                      <small>
                        {record.Target} · {record.PublishedBy} · {formatDate(record.PublishedAt)}
                      </small>
                    </td>
                    <td>
                      <b>{record.Service}</b>
                      <small title={record.AgentUID}>{record.AgentUID}</small>
                    </td>
                    <td>
                      <span className={`scope-chip ${dynamic ? "dynamic" : "exact"}`}>
                        {t(dynamic ? "Dinámico" : "InstanceUID exacto")}
                      </span>
                      <small>
                        {(record.Selector?.Services || []).join(", ") ||
                          Object.entries(record.Selector?.Attributes || {})
                            .map(([key, value]) => `${key}=${value}`).join(" · ") ||
                          t("Todos los compatibles")}
                      </small>
                    </td>
                    <td>
                      {confirmation.confirmed
                        ? formatDate(confirmation.at)
                        : t("Sin confirmación")}
                      {confirmation.source === "LIVE_REPORT" && (
                        <small>{t("Confirmado por el último reporte vivo")}</small>
                      )}
                      <small>{t("Visto")}: {formatDate(record.LastObservedAt)}</small>
                    </td>
                    <td>
                      <StatusBadge status={displayedStatus} type="deployment" />
                      <small>
                        {coverageStatus
                          ? `${t("Última confirmación de configuración")}: ${t(statusMeta(live, "deployment")[0])}`
                          : `${t("Cobertura viva")} · ${record.ConnectionStatus}`}
                      </small>
                    </td>
                    <td>
                      <PolicyDocumentButton body={record.Body} target={record.Target} />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {!visibleDestinations.length && (
          <div className="empty">{t("No hay destinos que coincidan con los filtros.")}</div>
        )}
      </section>
    </>
  );
}

function HistoryView({
  storage,
  versions,
  agents,
  collectorBases,
  deployments,
  auditEvents,
  actor,
  setActor,
  busy,
  onLoad,
  onPolicyLifecycle,
  onCollectorLifecycle,
  onRestoreCollector,
}) {
  const { t, formatDate } = useI18n();
  const [query, setQuery] = useState("");
  const [targetFilters, setTargetFilters] = useState([]);
  const [statusFilters, setStatusFilters] = useState([]);
  const managedPolicyMap = useMemo(
    () => new Map(
      buildManagedPolicies(versions, []).map((policy) => [policy.id, policy]),
    ),
    [versions],
  );
  const managedCollectorMap = useMemo(
    () => new Map(
      buildManagedCollectorConfigs(versions, deployments, collectorBases)
        .map((config) => [config.id, config]),
    ),
    [versions, deployments, collectorBases],
  );
  const visibleVersions = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return versions.filter((version) => {
      const deactivated = isDeactivatedPolicyVersion(version);
      const managedCollector = version.Target === "collector"
        ? managedCollectorMap.get(version.configId)
        : null;
      const deployment = deactivated
        ? { status: managedCollector?.destinationSummary.status || "DEACTIVATED" }
        : deploymentStatusForVersion(version, agents);
      if (!matchesAnySelection(targetFilters, version.Target)) return false;
      if (!matchesAnySelection(statusFilters, deployment.status)) return false;
      return !needle || [
        version.configId,
        version.Version,
        version.Target,
        version.CreatedBy,
        version.Hash,
        publicationActionLabel(version.Action),
      ].some((value) => String(value || "").toLowerCase().includes(needle));
    });
  }, [versions, agents, managedCollectorMap, query, targetFilters, statusFilters]);
  return (
    <>
      <section className="summary storage-summary">
        <div>
          <small>{t("Persistencia")}</small>
          <strong>{storage.driver}</strong>
        </div>
        <div>
          <small>{t("Estado")}</small>
          <strong>{storage.status}</strong>
        </div>
        <div>
          <small>{t("Modelo")}</small>
          <strong>{t("Versionado + audit")}</strong>
        </div>
      </section>
      <section className="panel collector-bases-panel">
        <div className="panel-title">
          <div>
            <p className="eyebrow">{t("INVENTARIO REPORTADO")}</p>
            <h2>{t("Bases locales de Supervisor")}</h2>
            <p className="explanation">
              {t("Cada Supervisor es propietario de su binario y de su base NOP inmutable. El Control Plane sólo muestra los metadatos reportados y no distribuye ni versiona esos artefactos.")}
            </p>
          </div>
        </div>
        <div className="data-table-wrap">
          <table className="data-table collector-bases-table">
            <thead>
              <tr>
                <th>{t("Base")}</th>
                <th>{t("Origen")}</th>
                <th>{t("Supervisors")}</th>
                <th>{t("Comportamiento")}</th>
                <th>{t("Descriptor")}</th>
              </tr>
            </thead>
            <tbody>
              {collectorBases.map((rawBase) => {
                const base = normalizeCollectorBase(rawBase);
                return (
                  <tr key={base.ID}>
                    <td>
                      <b>{base.ID}</b>
                      <small>{t("Reportada por Supervisor")}</small>
                    </td>
                    <td>
                      <b>{base.Source}</b>
                      <small>{t("Revisión del artefacto")} {base.Revision || t("no reportada")}</small>
                    </td>
                    <td>
                      <b>{base.Services.join(", ") || t("Asignación por AgentUID")}</b>
                      <small>{base.AgentUIDs.length ? `${base.AgentUIDs.length} ${t("instancia(s)")}` : t("Todas las réplicas del servicio")}</small>
                    </td>
                    <td>
                      <span className="scope-chip immutable">{t(base.Immutable ? "Inmutable" : "Reportada")}</span>
                      <small>{base.Behavior}</small>
                    </td>
                    <td>
                      <PolicyDocumentButton
                        body={JSON.stringify(base, null, 2)}
                        target="collector-base"
                        label={t("Ver descriptor")}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {!collectorBases.length && (
          <div className="empty">{t("Ningún Supervisor ha reportado una base local.")}</div>
        )}
      </section>
      <section className="panel">
        <div className="panel-title">
          <div>
            <p className="eyebrow">{t("CONFIGURACIONES")}</p>
            <h2>{t("Versiones inmutables")}</h2>
            <p className="explanation">
              {t("Inmutable significa que una versión guardada nunca se sobrescribe ni se elimina. Publicar, restaurar o retirar crea la siguiente versión y conserva las anteriores para auditoría.")}
            </p>
            <ul className="lifecycle-help">
              <li>{t("Policy activa con una versión anterior: restaura ese contenido como una versión nueva.")}</li>
              <li>{t("Policy activa sin predecesora: se puede retirar y deja de formar parte del PolicySet.")}</li>
              <li>{t("Collector: una versión histórica se restaura como nueva; retirar la activa vuelve a la base NOP local.")}</li>
            </ul>
            <small className="hint">
              {t("La acción aparece en la fila correspondiente. Guardada no significa aplicada: el estado sólo cambia cuando cada destino confirma por OpAMP.")}
            </small>
          </div>
          <label>
            {t("Identidad auditada")}
            <input value={actor} readOnly />
          </label>
        </div>
        <div className="table-filters three">
          <label>
            {t("Buscar")}
            <input
              type="search"
              placeholder={t("ID, versión, autor o hash")}
              value={query}
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          <MultiSelectFilter
            label={t("Tipo")}
            options={translatedOptions(t, targetFilterOptions)}
            values={targetFilters}
            onChange={setTargetFilters}
          />
          <MultiSelectFilter
            label={t("Estado actual")}
            options={translatedOptions(t, versionStatusFilterOptions)}
            values={statusFilters}
            onChange={setStatusFilters}
          />
        </div>
        <div className="versions">
          {visibleVersions.map((version) => {
            const deactivated = isDeactivatedPolicyVersion(version);
            const managedCollector = version.Target === "collector"
              ? managedCollectorMap.get(version.configId)
              : null;
            const deployment = deactivated
              ? { status: managedCollector?.destinationSummary.status || "DEACTIVATED" }
              : deploymentStatusForVersion(version, agents);
            const managedPolicy = managedPolicyMap.get(version.configId);
            return (
              <div
                className="version-row"
                key={`${version.configId}-${version.Version}`}
              >
                <span>
                  <b>{version.configId}</b>
                  <small>
                    {version.Target} · {t(publicationActionLabel(version.Action))} ·{" "}
                    {version.CreatedBy || "local-admin"} · {version.Hash.slice(0, 10)}
                  </small>
                </span>
                <strong>v{version.Version}</strong>
                <span className="version-deployment">
                  <StatusBadge status={deployment.status} type="deployment" />
                  <small>
                    {deactivated
                      ? version.Target === "collector"
                        ? t(collectorSummaryText(managedCollector?.destinationSummary))
                        : t("No se entrega a ningún destino.")
                      : t(deploymentStatusSummary(deployment))}
                  </small>
                </span>
                <time>{formatDate(version.UpdatedAt)}</time>
                <div className="version-actions">
                  <PolicyDocumentButton body={version.Body} target={version.Target} label={t("Ver")} />
                  {version.Body && (
                    <button className="ghost small" onClick={() => onLoad(version)}>
                      {t("Cargar en editor")}
                    </button>
                  )}
                  {version.Target === "java-extension" &&
                    version.IsLatest && managedPolicy?.active && (
                      <button
                        className={managedPolicy.action === "DEACTIVATE" ? "ghost small danger on" : "ghost small"}
                        disabled={busy}
                        aria-label={
                          managedPolicy.action === "REVERT"
                            ? `Revertir versión anterior de ${managedPolicy.id}: ${managedPolicy.actionLabel}`
                            : `${managedPolicy.actionLabel}: ${managedPolicy.id}`
                        }
                        onClick={() => onPolicyLifecycle(managedPolicy)}
                      >
                        {t(managedPolicy.actionLabel)}
                      </button>
                    )}
                  {version.Target === "collector" && !version.IsLatest && (
                    <button
                      className="ghost small"
                      disabled={busy}
                      onClick={() => onRestoreCollector(version)}
                    >
                      {t("Restaurar como nueva versión")}
                    </button>
                  )}
                  {version.Target === "collector" &&
                    version.IsLatest && managedCollector?.active && (
                      <button
                        className="ghost small danger on"
                        disabled={busy}
                        onClick={() => onCollectorLifecycle(managedCollector)}
                      >
                        {t(managedCollector.actionLabel)}
                      </button>
                    )}
                </div>
              </div>
            );
          })}
          {!visibleVersions.length && (
            <div className="empty">{t("No hay versiones que coincidan con los filtros.")}</div>
          )}
        </div>
      </section>
      <section className="panel audit-panel">
        <p className="eyebrow">{t("AUDITORÍA POSTGRESQL")}</p>
        <h2>{t("Últimas acciones")}</h2>
        <div className="audit-list">
          {auditEvents.map((event) => (
            <div key={event.AuditID}>
              <b>{t(publicationActionLabel(event.Action))}</b>
              <span>
                {event.ConfigID} · v{event.Version}
              </span>
              <span>{event.Actor}</span>
              <time>{formatDate(event.CreatedAt)}</time>
            </div>
          ))}
          {!auditEvents.length && <div className="empty">{t("Sin eventos de auditoría.")}</div>}
        </div>
      </section>
    </>
  );
}

function LoginView({ onAuthenticated }) {
  const { t } = useI18n();
  const [username, setUsername] = useState("o11y-admin");
  const [password, setPassword] = useState("");
  const resetToken = useMemo(
    () => passwordResetToken(window.location.search, window.location.hash),
    [],
  );
  const [mode, setMode] = useState(resetToken ? "reset" : "login");
  const [recoveryIdentifier, setRecoveryIdentifier] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [providers, setProviders] = useState([]);
  const [recoveryEnabled, setRecoveryEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState(
    () => new URLSearchParams(window.location.search).get("auth_error") || "",
  );
  const activeProviders = providers
    .map((provider) => normalizeProvider(provider))
    .filter((provider) => provider.id && provider.startUrl && providerLoginEnabled(provider));

  useEffect(() => {
    if (resetToken) {
      window.history.replaceState({}, "", window.location.pathname);
    }
    fetch("/api/auth/public-providers", { cache: "no-store" })
      .then((response) => response.ok ? response.json() : Promise.reject())
      .then((payload) => setProviders(payload.providers || []))
      .catch(() => setProviders([]));
    fetch("/api/auth/password-recovery/status", { cache: "no-store" })
      .then((response) => response.ok ? response.json() : Promise.reject())
      .then((payload) => setRecoveryEnabled(payload.enabled === true))
      .catch(() => setRecoveryEnabled(false));
  }, [resetToken]);

  const login = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ Username: username, Password: password }),
      });
      const message = await response.text();
      if (!response.ok) throw new Error(message.trim() || t("No se pudo autenticar."));
      const session = JSON.parse(message);
      onAuthenticated(session.identity);
    } catch (loginError) {
      setError(loginError.message);
    } finally {
      setBusy(false);
    }
  };

  const requestRecovery = async (event) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const response = await fetch("/api/auth/password/forgot", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ usernameOrEmail: recoveryIdentifier.trim() }),
      });
      const body = await response.text();
      if (!response.ok) throw new Error(body.trim() || t("No se pudo procesar la solicitud."));
      setMessage(
        t("Si la cuenta existe y tiene correo configurado, recibirás un enlace para restablecer la contraseña."),
      );
    } catch (recoveryError) {
      setError(recoveryError.message);
    } finally {
      setBusy(false);
    }
  };

  const resetPassword = async (event) => {
    event.preventDefault();
    setError("");
    setMessage("");
    const errors = validatePasswordChange({
      currentPassword: "recovery-token",
      newPassword,
      confirmPassword,
    }).filter((entry) => !entry.includes("diferente de la actual"));
    if (errors.length) {
      setError(errors.map((entry) => t(entry)).join(" "));
      return;
    }
    setBusy(true);
    try {
      const response = await fetch("/api/auth/password/reset", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ token: resetToken, newPassword }),
      });
      const body = await response.text();
      if (!response.ok) throw new Error(body.trim() || t("El enlace no es válido o ya venció."));
      window.history.replaceState({}, "", "/");
      setNewPassword("");
      setConfirmPassword("");
      setMode("login");
      setMessage(t("Contraseña actualizada. Ya puedes iniciar sesión."));
    } catch (resetError) {
      setError(resetError.message);
    } finally {
      setBusy(false);
    }
  };

  const showLogin = () => {
    setMode("login");
    setError("");
    setMessage("");
  };

  return (
    <div className="login-backdrop">
      <form
        className="login-card"
        onSubmit={mode === "login" ? login : mode === "forgot" ? requestRecovery : resetPassword}
      >
        <div className="brand login-brand">
          <span>◈</span>
          <div><b>o11y</b><small>Control Plane</small></div>
        </div>
        <LanguageSelector compact />
        <p className="eyebrow">{t("AUTENTICACIÓN")}</p>
        <h1>
          {mode === "login" && t("Accede al Control Plane")}
          {mode === "forgot" && t("Recupera tu contraseña")}
          {mode === "reset" && t("Define una nueva contraseña")}
        </h1>
        {mode === "login" && (
          <>
            <label>
              {t("Usuario")}
              <input value={username} autoComplete="username" onChange={(event) => setUsername(event.target.value)} />
            </label>
            <label>
              {t("Contraseña")}
              <input type="password" autoComplete="current-password" value={password} onChange={(event) => setPassword(event.target.value)} />
            </label>
          </>
        )}
        {mode === "forgot" && (
          <>
            <p className="explanation">
              {t("Ingresa tu usuario o correo. Si la cuenta local tiene un correo asociado, recibirás un enlace temporal.")}
            </p>
            <label>
              {t("Usuario o correo")}
              <input
                value={recoveryIdentifier}
                autoComplete="username email"
                onChange={(event) => setRecoveryIdentifier(event.target.value)}
              />
            </label>
          </>
        )}
        {mode === "reset" && (
          <>
            <label>
              {t("Nueva contraseña")}
              <input type="password" maxLength="72" autoComplete="new-password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} />
            </label>
            <label>
              {t("Confirmar contraseña")}
              <input type="password" maxLength="72" autoComplete="new-password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} />
            </label>
            <small className="password-help">{t("Mínimo 12 caracteres y máximo 72 bytes.")}</small>
          </>
        )}
        {error && <div className="warning-box">{error}</div>}
        {message && <div className="notice login-notice">{message}</div>}
        <button
          className="primary"
          disabled={busy ||
            (mode === "login" && (!username || !password)) ||
            (mode === "forgot" && !recoveryIdentifier.trim()) ||
            (mode === "reset" && (!newPassword || !confirmPassword))}
        >
          {busy
            ? t("Procesando…")
            : mode === "login"
              ? t("Ingresar")
              : mode === "forgot"
                ? t("Enviar enlace")
                : t("Cambiar contraseña")}
        </button>
        {mode === "login" ? (
          <>
            {recoveryEnabled && (
              <button type="button" className="login-link" onClick={() => {
                setMode("forgot");
                setError("");
                setMessage("");
              }}>
                {t("¿Olvidaste tu contraseña?")}
              </button>
            )}
            {!!activeProviders.length && <div className="login-divider"><span>{t("o usa tu organización")}</span></div>}
            <div className="login-providers">
              {activeProviders.map((provider) => (
                <button
                  key={provider.id}
                  type="button"
                  className="sso-button"
                  title={`${t("AUTENTICACIÓN")} ${provider.protocol}`}
                  onClick={() => { window.location.assign(provider.startUrl); }}
                >
                  <span className={`provider-mark ${provider.id} ${provider.protocol.toLowerCase()}`}>
                    {provider.id === "microsoft" ? "⊞" : provider.id === "google" ? "G" : provider.protocol === "SAML" ? "S" : "◇"}
                  </span>
                  {provider.label}
                </button>
              ))}
            </div>
          </>
        ) : (
          <button type="button" className="login-link" onClick={showLogin}>
            {t("← Volver al inicio de sesión")}
          </button>
        )}
      </form>
    </div>
  );
}

function ProfileView({ identity, onIdentityUpdated }) {
  const { t } = useI18n();
  const [profile, setProfile] = useState(() => normalizeProfile({}, identity));
  const [persistedEmail, setPersistedEmail] = useState("");
  const [emailPassword, setEmailPassword] = useState("");
  const [profileBusy, setProfileBusy] = useState(false);
  const [passwordBusy, setPasswordBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [passwordDraft, setPasswordDraft] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: "",
  });

  useEffect(() => {
    let active = true;
    fetch("/api/auth/profile", { cache: "no-store", credentials: "same-origin" })
      .then(async (response) => {
        const body = await response.text();
        if (!response.ok) throw new Error(body.trim() || t("No se pudo cargar el perfil."));
        return body ? JSON.parse(body) : {};
      })
      .then((payload) => {
        if (active) {
          const loaded = normalizeProfile(payload, identity);
          setProfile(loaded);
          setPersistedEmail(loaded.email);
        }
      })
      .catch((error) => {
        if (active) setNotice(`${t("No se pudo cargar el perfil")}: ${error.message}`);
      });
    return () => { active = false; };
  }, [identity?.Username, identity?.username]);

  const saveProfile = async (event) => {
    event.preventDefault();
    const errors = validateProfile(profile);
    if (errors.length) {
      setNotice(errors.map((error) => t(error)).join(" "));
      return;
    }
    const emailChanged = profile.email.trim().toLowerCase() !== persistedEmail.trim().toLowerCase();
    if (emailChanged && !emailPassword) {
      setNotice(t("Ingresa tu contraseña actual para cambiar el correo de recuperación."));
      return;
    }
    setProfileBusy(true);
    setNotice("");
    try {
      const response = await fetch("/api/auth/profile", {
        method: "PUT",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(profilePayload(profile, emailChanged ? emailPassword : "")),
      });
      const body = await response.text();
      if (!response.ok) throw new Error(body.trim() || t("No se pudo actualizar el perfil."));
      const updated = normalizeProfile(body ? JSON.parse(body) : profile, identity);
      setProfile(updated);
      setPersistedEmail(updated.email);
      setEmailPassword("");
      onIdentityUpdated?.({ ...identity, ...updated });
      setNotice(t("Datos personales actualizados."));
    } catch (error) {
      setNotice(`${t("No se pudo guardar el perfil")}: ${error.message}`);
    } finally {
      setProfileBusy(false);
    }
  };

  const changePassword = async (event) => {
    event.preventDefault();
    const errors = validatePasswordChange(passwordDraft);
    if (errors.length) {
      setNotice(errors.map((error) => t(error)).join(" "));
      return;
    }
    setPasswordBusy(true);
    setNotice("");
    try {
      const response = await fetch("/api/auth/password/change", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          currentPassword: passwordDraft.currentPassword,
          newPassword: passwordDraft.newPassword,
        }),
      });
      const body = await response.text();
      if (!response.ok) throw new Error(body.trim() || t("No se pudo cambiar la contraseña."));
      setPasswordDraft({ currentPassword: "", newPassword: "", confirmPassword: "" });
      setNotice(t("Contraseña actualizada y sesión renovada."));
    } catch (error) {
      setNotice(`${t("No se pudo cambiar la contraseña")}: ${error.message}`);
    } finally {
      setPasswordBusy(false);
    }
  };

  const localIdentity = !profile.provider || profile.provider === "local";

  return (
    <div className="settings-content profile-layout">
      <section className="panel">
        <p className="eyebrow">{t("MI CUENTA")}</p>
        <h2>{t("Datos personales")}</h2>
        <p className="explanation">
          {t("Estos datos identifican tus cambios en el Control Plane y permiten recuperar el acceso por correo.")}
        </p>
        {notice && <div className="notice account-notice">{notice}</div>}
        <form onSubmit={saveProfile}>
          <label>
            {t("Usuario")}
            <input value={profile.username} readOnly />
          </label>
          <div className="row">
            <label>
              {t("Nombre")}
              <input disabled={!localIdentity} value={profile.firstName} autoComplete="given-name" onChange={(event) => setProfile((current) => ({ ...current, firstName: event.target.value }))} />
            </label>
            <label>
              {t("Apellidos")}
              <input disabled={!localIdentity} value={profile.lastName} autoComplete="family-name" onChange={(event) => setProfile((current) => ({ ...current, lastName: event.target.value }))} />
            </label>
          </div>
          <label>
            {t("Correo electrónico")}
            <input disabled={!localIdentity} type="email" value={profile.email} autoComplete="email" onChange={(event) => setProfile((current) => ({ ...current, email: event.target.value }))} />
            {localIdentity && <small>{t("Se utiliza para recuperar la contraseña.")}</small>}
          </label>
          {localIdentity && profile.email.trim().toLowerCase() !== persistedEmail.trim().toLowerCase() && (
            <label>
              {t("Contraseña actual para cambiar el correo")}
              <input type="password" autoComplete="current-password" value={emailPassword} onChange={(event) => setEmailPassword(event.target.value)} />
            </label>
          )}
          <div className="account-meta">
            <span><small>{t("Proveedor")}</small><b>{profile.provider || "local"}</b></span>
            <span><small>{t("Roles")}</small><b>{profile.roles?.join(", ") || t("Sin rol")}</b></span>
          </div>
          {!localIdentity && (
            <div className="validation-box">
              {t("Nombre, apellidos, correo y credenciales se administran en")} <b>{profile.provider}</b>.
            </div>
          )}
          <button type="submit" className="primary account-action" disabled={profileBusy || !localIdentity}>
            {profileBusy ? t("Guardando…") : t("Guardar perfil")}
          </button>
        </form>
      </section>

      <section className="panel">
        <p className="eyebrow">{t("CREDENCIALES")}</p>
        <h2>{t("Cambiar contraseña")}</h2>
        {localIdentity ? (
          <form onSubmit={changePassword}>
            <label>
              {t("Contraseña actual")}
              <input type="password" autoComplete="current-password" value={passwordDraft.currentPassword} onChange={(event) => setPasswordDraft((current) => ({ ...current, currentPassword: event.target.value }))} />
            </label>
            <label>
              {t("Nueva contraseña")}
              <input type="password" maxLength="72" autoComplete="new-password" value={passwordDraft.newPassword} onChange={(event) => setPasswordDraft((current) => ({ ...current, newPassword: event.target.value }))} />
            </label>
            <label>
              {t("Confirmar nueva contraseña")}
              <input type="password" maxLength="72" autoComplete="new-password" value={passwordDraft.confirmPassword} onChange={(event) => setPasswordDraft((current) => ({ ...current, confirmPassword: event.target.value }))} />
            </label>
            <p className="hint">{t("Usa al menos 12 caracteres y hasta 72 bytes. La sesión se renueva al guardar.")}</p>
            <button type="submit" className="primary account-action" disabled={passwordBusy}>
              {passwordBusy ? t("Actualizando…") : t("Cambiar contraseña")}
            </button>
          </form>
        ) : (
          <div className="validation-box">
            {t("Tu acceso pertenece a")} <b>{profile.provider}</b>. {t("Cambia la contraseña en ese proveedor de identidad.")}
          </div>
        )}
      </section>
    </div>
  );
}

function AccessView({ model, onReload }) {
  const { t } = useI18n();
  const providers = (model?.providers || [])
    .map((provider) => normalizeProvider(provider, model))
    .filter((provider) => provider.id);
  const configurations = (model?.configurations || [])
    .map((provider) => normalizeProvider(provider, model))
    .filter((provider) => provider.id);
  const roles = model?.roles || {};
  const assignableRoles = model?.assignableRoles || Object.keys(roles);
  const identityPermissions = model?.identity?.permissions || model?.identity?.Permissions || [];
  const identityRoles = model?.identity?.roles || model?.identity?.Roles || [];
  const canManageProviders = identityPermissions.includes("*") ||
    identityPermissions.includes("auth.admin") ||
    identityRoles.some((role) => ["admin", "security-admin"].includes(role));
  const [drafts, setDrafts] = useState({});
  const [newDraft, setNewDraft] = useState(null);
  const [busyProvider, setBusyProvider] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    setDrafts((current) => Object.fromEntries(configurations.map((provider) => {
      if (current[provider.id]?._dirty) return [provider.id, current[provider.id]];
      return [provider.id, {
        ...provider,
        clientSecret: "",
        _dirty: false,
      }];
    })));
  }, [model]);

  const updateDraft = (providerID, field, value) => {
    if (providerID === "__new__") {
      setNewDraft((current) => ({ ...current, [field]: value, _dirty: true }));
      return;
    }
    setDrafts((current) => ({
      ...current,
      [providerID]: { ...current[providerID], [field]: value, _dirty: true },
    }));
  };

  const updateMapping = (providerID, index, field, value) => {
    const update = (draft) => ({
      ...draft,
      _dirty: true,
      roleMappings: (draft.roleMappings || []).map((mapping, mappingIndex) =>
        mappingIndex === index ? { ...mapping, [field]: value } : mapping),
    });
    if (providerID === "__new__") setNewDraft(update);
    else setDrafts((current) => ({ ...current, [providerID]: update(current[providerID]) }));
  };

  const addMapping = (providerID) => {
    const update = (draft) => ({
      ...draft,
      _dirty: true,
      roleMappings: [...(draft.roleMappings || []), { externalRole: "", localRole: "viewer" }],
    });
    if (providerID === "__new__") setNewDraft(update);
    else setDrafts((current) => ({ ...current, [providerID]: update(current[providerID]) }));
  };

  const removeMapping = (providerID, index) => {
    const update = (draft) => ({
      ...draft,
      _dirty: true,
      roleMappings: (draft.roleMappings || []).filter((_, mappingIndex) => mappingIndex !== index),
    });
    if (providerID === "__new__") setNewDraft(update);
    else setDrafts((current) => ({ ...current, [providerID]: update(current[providerID]) }));
  };

  const persistProvider = async (providerID, draft) => {
    const errors = validateProviderDraft(draft);
    const actualID = providerID === "__new__" ? (draft.id || "").trim() : providerID;
    if (!/^[a-z][a-z0-9-]{0,62}$/.test(actualID)) {
      errors.unshift(t("El ID debe tener entre 1 y 63 caracteres, iniciar con una letra y usar sólo minúsculas, números o guiones."));
    }
    if (providerID === "__new__" && configurations.some((provider) => provider.id === actualID)) {
      errors.unshift(t("Ya existe un proveedor con ese ID."));
    }
    if (errors.length) throw new Error(errors.map((error) => t(error)).join(" "));

    const response = await fetch(`/api/auth/providers/${encodeURIComponent(actualID)}`, {
      method: "PUT",
      credentials: "same-origin",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(providerPayload(draft)),
    });
    const message = await response.text();
    if (!response.ok) throw new Error(message.trim() || t("No se pudo guardar el proveedor."));

    return actualID;
  };

  const saveProvider = async (providerID) => {
    setBusyProvider(providerID);
    try {
      const draft = providerID === "__new__" ? newDraft : drafts[providerID];
      await persistProvider(providerID, draft);
      setNotice(t("Proveedor guardado como CONFIGURADO. Valídalo antes de habilitar el login."));
      if (providerID === "__new__") setNewDraft(null);
      else setDrafts((current) => ({
        ...current,
        [providerID]: { ...current[providerID], _dirty: false },
      }));
      await onReload();
    } catch (error) {
      setNotice(`${t("No se pudo guardar el proveedor")}: ${error.message}`);
    } finally {
      setBusyProvider("");
    }
  };

  const validateProvider = async (providerID) => {
    setBusyProvider(providerID);
    try {
      const draft = providerID === "__new__" ? newDraft : drafts[providerID];
      const actualID = await persistProvider(providerID, draft);
      if (providerID === "__new__") setNewDraft(null);
      else setDrafts((current) => ({
        ...current,
        [providerID]: { ...current[providerID], _dirty: false },
      }));
      const response = await fetch(
        `/api/auth/providers/${encodeURIComponent(actualID)}/preflight`,
        { method: "POST", credentials: "same-origin" },
      );
      const message = await response.text();
      if (!response.ok) throw new Error(message.trim() || t("La validación operativa falló."));
      let result = {};
      try {
        result = message ? JSON.parse(message) : {};
      } catch {
        result = { message };
      }
      setNotice(result.message || result.validationMessage || t("Proveedor VALIDADO y disponible en el login."));
      await onReload();
    } catch (error) {
      setNotice(`${t("El proveedor quedó en ERROR")}: ${error.message}`);
      await onReload();
    } finally {
      setBusyProvider("");
    }
  };

  const removeProvider = async (providerID) => {
    if (providerID === "__new__") {
      setNewDraft(null);
      return;
    }
    if (!window.confirm(t("¿Eliminar este proveedor de identidad? Dejará de aparecer en el login."))) return;
    setBusyProvider(providerID);
    try {
      const response = await fetch(`/api/auth/providers/${encodeURIComponent(providerID)}`, {
        method: "DELETE",
        credentials: "same-origin",
      });
      const message = await response.text();
      if (!response.ok) throw new Error(message.trim());
      setNotice(t("Proveedor eliminado; ya no aparecerá en el login."));
      await onReload();
    } catch (error) {
      setNotice(`${t("No se pudo eliminar el proveedor")}: ${error.message}`);
    } finally {
      setBusyProvider("");
    }
  };

  const addProvider = () => setNewDraft({
    id: "",
    label: t("Continuar con SSO"),
    protocol: "OIDC",
    status: "INACTIVE",
    issuer: "",
    clientId: "",
    clientSecret: "",
    secretConfigured: false,
    userClaim: "preferred_username",
    roleClaim: "roles",
    spEntityId: "",
    metadataUrl: "",
    metadataXml: "",
    nameIdAttribute: "",
    userAttribute: "mail",
    roleAttribute: "groups",
    callbackUrl: "",
    roleMappings: [{ externalRole: "", localRole: "viewer" }],
    _dirty: true,
  });

  const copyText = async (value, description) => {
    try {
      await navigator.clipboard.writeText(value);
      setNotice(`${description} ${t("copiada.")}`);
    } catch {
      setNotice(`${t("No se pudo copiar")} ${description.toLowerCase()}.`);
    }
  };

  const copySPMetadata = async (metadataURL) => {
    try {
      const response = await fetch(metadataURL, { credentials: "same-origin" });
      const metadata = await response.text();
      if (!response.ok) throw new Error(metadata.trim());
      await navigator.clipboard.writeText(metadata);
      setNotice(t("Metadata XML del SP copiada."));
    } catch (error) {
      setNotice(`${t("No se pudo copiar la metadata SP")}: ${error.message || t("error del navegador")}`);
    }
  };

  const renderConfiguration = (provider, providerID, isNew = false) => {
    const draft = isNew ? newDraft : drafts[providerID];
    if (!draft) return null;
    const effectiveID = isNew ? (draft.id || "nuevo-proveedor") : providerID;
    const effectiveProvider = { ...provider, ...draft, id: effectiveID };
    const acsOrCallback = callbackURL(
      effectiveProvider,
      window.location.origin,
    );
    const metadataURL = provider.spMetadataUrl ||
      `${window.location.origin}/api/auth/saml/${encodeURIComponent(effectiveID)}/metadata`;
    const configuredLocalRoles = (draft.roleMappings || []).map((mapping) => mapping.localRole).filter(Boolean);
    const visibleRoleNames = [...new Set([...assignableRoles, ...configuredLocalRoles])];
    const providerManageable = configuredLocalRoles.every((role) => assignableRoles.includes(role));

    return (
      <article className="provider-configuration" key={providerID}>
        <div className="provider-configuration-title">
          <div>
            <b>{draft.label || (isNew ? t("Nuevo proveedor") : providerID)}</b>
            <small>{isNew ? t("Define un ID estable; no depende del nombre mostrado.") : providerID}</small>
          </div>
          <div className="provider-title-status">
            {draft._dirty && <span className="unsaved-chip">{t("Cambios sin guardar")}</span>}
            <StatusBadge status={isNew ? "INACTIVE" : provider.status} type="config" />
          </div>
        </div>

        <div className="row">
          <label>
            {t("ID estable")}
            <input
              value={isNew ? draft.id : providerID}
              disabled={!isNew}
              placeholder="sso-corporativo"
              onChange={(event) => updateDraft(providerID, "id", event.target.value.toLowerCase().replace(/[^a-z0-9-]/g, ""))}
            />
          </label>
          <label>
            {t("Protocolo")}
            <select value={draft.protocol} onChange={(event) => updateDraft(providerID, "protocol", event.target.value)}>
              <option value="OIDC">OpenID Connect (OIDC)</option>
              <option value="SAML">SAML 2.0</option>
            </select>
          </label>
        </div>
        <label>
          {t("Texto del botón de login")}
          <input value={draft.label || ""} onChange={(event) => updateDraft(providerID, "label", event.target.value)} />
        </label>

        {draft.protocol === "OIDC" ? (
          <>
            <div className="row">
              <label>
                Issuer OIDC
                <input placeholder="https://idp.example.com" value={draft.issuer || ""} onChange={(event) => updateDraft(providerID, "issuer", event.target.value)} />
              </label>
              <label>
                {t("Callback URL")}
                <input value={acsOrCallback} readOnly />
              </label>
            </div>
            <div className="row">
              <label>
                Client ID
                <input value={draft.clientId || ""} onChange={(event) => updateDraft(providerID, "clientId", event.target.value)} />
              </label>
              <label>
                Client secret
                <input
                  type="password"
                  autoComplete="new-password"
                  placeholder={draft.credentialsUnavailable
                    ? t("La clave cambió; ingresa un secret nuevo")
                    : draft.secretConfigured
                      ? t("Configurado; deja vacío para conservarlo")
                      : t("Requerido")}
                  value={draft.clientSecret || ""}
                  onChange={(event) => updateDraft(providerID, "clientSecret", event.target.value)}
                />
              </label>
            </div>
            {draft.credentialsUnavailable && (
              <div className="warning-box provider-validation">
                {t("La credencial cifrada ya no está disponible. Ingresa un client secret nuevo y guarda; no es necesario eliminar el proveedor.")}
              </div>
            )}
            <div className="row">
              <label>
                {t("Claim de usuario")}
                <input placeholder="preferred_username" value={draft.userClaim || ""} onChange={(event) => updateDraft(providerID, "userClaim", event.target.value)} />
              </label>
              <label>
                {t("Claim de roles o grupos")}
                <input placeholder="roles" value={draft.roleClaim || ""} onChange={(event) => updateDraft(providerID, "roleClaim", event.target.value)} />
              </label>
            </div>
          </>
        ) : (
          <>
            <div className="row">
              <label>
                SP Entity ID
                <input placeholder="urn:o11y:control-plane" value={draft.spEntityId || ""} onChange={(event) => updateDraft(providerID, "spEntityId", event.target.value)} />
              </label>
              <label>
                {t("ACS URL (calculada)")}
                <input value={acsOrCallback} readOnly />
              </label>
            </div>
            <div className="saml-service-actions">
              <button type="button" className="ghost small" onClick={() => copyText(acsOrCallback, "ACS URL")}>{t("Copiar ACS")}</button>
              {!isNew && (
                <>
                  <button type="button" className="ghost small" onClick={() => copySPMetadata(metadataURL)}>{t("Copiar metadata SP")}</button>
                  <a className="button-link ghost small" href={metadataURL} download>
                    {t("Descargar metadata SP")}
                  </a>
                </>
              )}
            </div>
            <div className="row">
              <label>
                {t("URL de metadata del IdP")}
                <input placeholder="https://idp.example.com/metadata" value={draft.metadataUrl || ""} onChange={(event) => updateDraft(providerID, "metadataUrl", event.target.value)} />
              </label>
              <label>
                {t("Atributo alternativo de usuario (opcional)")}
                <input placeholder="uid" value={draft.nameIdAttribute || ""} onChange={(event) => updateDraft(providerID, "nameIdAttribute", event.target.value)} />
              </label>
            </div>
            <label>
              {t("Metadata XML del IdP (alternativa a la URL)")}
              <textarea
                className="saml-metadata"
                placeholder="<EntityDescriptor ...>"
                value={draft.metadataXml || ""}
                onChange={(event) => updateDraft(providerID, "metadataXml", event.target.value)}
              />
            </label>
            <div className="row">
              <label>
                {t("Atributo de usuario")}
                <input placeholder="mail" value={draft.userAttribute || ""} onChange={(event) => updateDraft(providerID, "userAttribute", event.target.value)} />
              </label>
              <label>
                {t("Atributo de roles o grupos")}
                <input placeholder="groups" value={draft.roleAttribute || ""} onChange={(event) => updateDraft(providerID, "roleAttribute", event.target.value)} />
              </label>
            </div>
          </>
        )}

        <div className="provider-mappings-heading">
          <div>
            <h4>{t("Mapeo de roles externo → local")}</h4>
            <small>{t("Si ningún rol coincide, el inicio de sesión se rechaza.")}</small>
          </div>
          <button type="button" className="ghost small" onClick={() => addMapping(providerID)}>{t("+ mapeo")}</button>
        </div>
        <div className="provider-mappings">
          {(draft.roleMappings || []).map((mapping, index) => (
            <div className="provider-mapping-row" key={`${providerID}-mapping-${index}`}>
              <label>
                {t("Rol o grupo externo")}
                <input value={mapping.externalRole} placeholder="observability-admins" onChange={(event) => updateMapping(providerID, index, "externalRole", event.target.value)} />
              </label>
              <label>
                {t("Rol local")}
                <select value={mapping.localRole} onChange={(event) => updateMapping(providerID, index, "localRole", event.target.value)}>
                  {visibleRoleNames.map((role) => (
                    <option key={role} value={role} disabled={!assignableRoles.includes(role)}>
                      {role}{assignableRoles.includes(role) ? "" : t(" (requiere permisos superiores)")}
                    </option>
                  ))}
                </select>
              </label>
              <button type="button" className="remove mapping-remove" aria-label={t("Eliminar mapeo")} onClick={() => removeMapping(providerID, index)}>×</button>
            </div>
          ))}
          {!(draft.roleMappings || []).length && <small className="empty-inline">{t("Sin mapeos explícitos.")}</small>}
        </div>

        {provider.validationMessage && (
          <div className={provider.status === "ERROR" ? "warning-box provider-validation" : "validation-box"}>
            {t(provider.validationMessage)}
          </div>
        )}
        {!providerManageable && (
          <div className="warning-box provider-validation">
            {t("Este proveedor asigna permisos superiores a los tuyos. Sólo un administrador con esos permisos puede modificarlo, validarlo o eliminarlo.")}
          </div>
        )}
        <div className="form-actions provider-actions">
          <button type="button" className="primary small" disabled={busyProvider === providerID || !providerManageable} onClick={() => saveProvider(providerID)}>
            {busyProvider === providerID ? t("Guardando…") : t("Guardar configuración")}
          </button>
          <button type="button" className="ghost small validate-provider" disabled={busyProvider === providerID || !providerManageable} onClick={() => validateProvider(providerID)}>
            {t("Probar y validar")}
          </button>
          <button type="button" className="ghost small danger" disabled={busyProvider === providerID || !providerManageable} onClick={() => removeProvider(providerID)}>
            {isNew ? t("Cancelar") : t("Eliminar")}
          </button>
        </div>
      </article>
    );
  };

  return (
    <>
      <section className="summary">
        <div><small>{t("Proveedores")}</small><strong>{providers.length}</strong></div>
        <div><small>{t("Roles locales")}</small><strong>{Object.keys(roles).length}</strong></div>
        <div><small>{t("Sesión web")}</small><strong>HttpOnly</strong></div>
      </section>
      <section className="panel">
        <p className="eyebrow">AUTHN / AUTHZ</p>
        <h2>{t("Proveedores y permisos efectivos")}</h2>
        <p className="explanation">
          {t("OIDC usa Authorization Code con PKCE y SAML usa un Service Provider nativo. Guardar deja el proveedor en CONFIGURADO; sólo una prueba satisfactoria lo marca VALIDADO y habilita su botón de login.")}
        </p>
        {notice && <div className="notice access-notice">{notice}</div>}
        <div className="access-providers">
          {providers.map((provider) => (
            <article className="nested-card" key={provider.id}>
              <b>{provider.label}</b>
              <StatusBadge status={provider.status} type="config" />
              <small>{provider.protocol}</small>
            </article>
          ))}
          {!providers.length && <div className="empty">{t("No hay proveedores externos activos.")}</div>}
        </div>
        {!!configurations.length && (
          <div className="provider-configurations">
            <div className="section-heading small-heading">
              <div>
                <h3>{t("Configuración de login externo")}</h3>
                <small>
                  {t("Sólo admin y security-admin pueden editar. Los secretos se cifran antes de persistirse y nunca se devuelven al navegador.")}
                </small>
              </div>
              {!newDraft && (
                <button type="button" className="primary small add-provider" onClick={addProvider}>
                  {t("+ Agregar proveedor")}
                </button>
              )}
            </div>
            {newDraft && renderConfiguration({ status: "INACTIVE", validationMessage: "" }, "__new__", true)}
            {configurations.map((provider) => renderConfiguration(provider, provider.id))}
          </div>
        )}
        {!configurations.length && canManageProviders && (
          <div className="provider-configurations">
            <button type="button" className="primary small add-provider" onClick={addProvider}>{t("+ Agregar proveedor")}</button>
            {newDraft && renderConfiguration({ status: "INACTIVE", validationMessage: "" }, "__new__", true)}
          </div>
        )}
        <div className="data-table-wrap">
          <table className="data-table">
            <thead><tr><th>{t("Rol local")}</th><th>{t("Permisos predefinidos")}</th></tr></thead>
            <tbody>
              {Object.entries(roles).map(([role, permissions]) => (
                <tr key={role}>
                  <td><b>{role}</b></td>
                  <td><code>{permissions.join(" · ")}</code></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}

function UsersView({ currentIdentity }) {
  const { t } = useI18n();
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState({});
  const [query, setQuery] = useState("");
  const [draft, setDraft] = useState(null);
  const [creating, setCreating] = useState(false);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");

  const loadUsers = async () => {
    setBusy(true);
    try {
      const [usersResponse, rolesResponse] = await Promise.all([
        fetch("/api/auth/users", { cache: "no-store", credentials: "same-origin" }),
        fetch("/api/auth/roles", { cache: "no-store", credentials: "same-origin" }),
      ]);
      const usersBody = await usersResponse.text();
      const rolesBody = await rolesResponse.text();
      if (!usersResponse.ok) throw new Error(usersBody.trim() || t("No se pudieron cargar los usuarios."));
      if (!rolesResponse.ok) throw new Error(rolesBody.trim() || t("No se pudieron cargar los roles."));
      const usersPayload = usersBody ? JSON.parse(usersBody) : [];
      const rolesPayload = rolesBody ? JSON.parse(rolesBody) : {};
      setUsers((Array.isArray(usersPayload) ? usersPayload : usersPayload.users || []).map(normalizeUser));
      setRoles(rolesPayload.roles || rolesPayload);
    } catch (error) {
      setNotice(`${t("No se pudo cargar la gestión de usuarios")}: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => { loadUsers(); }, []);

  const visibleUsers = users.filter((user) => {
    const value = `${user.username} ${user.firstName} ${user.lastName} ${user.email} ${user.roles.join(" ")}`.toLowerCase();
    return value.includes(query.trim().toLowerCase());
  });

  const startCreate = () => {
    setCreating(true);
    setDraft({
      username: "",
      firstName: "",
      lastName: "",
      email: "",
      roles: ["viewer"],
      active: true,
      password: "",
    });
    setNotice("");
  };

  const saveUser = async (event) => {
    event.preventDefault();
    const errors = validateUser(draft, creating);
    if (errors.length) {
      setNotice(errors.map((error) => t(error)).join(" "));
      return;
    }
    setBusy(true);
    setNotice("");
    try {
      const username = userPayload(draft, creating).username;
      const response = await fetch(
        creating ? "/api/auth/users" : `/api/auth/users/${encodeURIComponent(username)}`,
        {
          method: creating ? "POST" : "PUT",
          credentials: "same-origin",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(userPayload(draft, creating)),
        },
      );
      const body = await response.text();
      if (!response.ok) throw new Error(body.trim() || t("No se pudo guardar el usuario."));
      setDraft(null);
      setCreating(false);
      setNotice(creating ? t("Usuario creado.") : t("Usuario actualizado."));
      await loadUsers();
    } catch (error) {
      setNotice(`${t("No se pudo guardar el usuario")}: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

  const removeUser = async (user) => {
    if (!window.confirm(t("¿Desactivar al usuario {username}?", { username: user.username }))) return;
    setBusy(true);
    try {
      const response = await fetch(`/api/auth/users/${encodeURIComponent(user.username)}`, {
        method: "DELETE",
        credentials: "same-origin",
      });
      const body = await response.text();
      if (!response.ok) throw new Error(body.trim() || t("No se pudo eliminar el usuario."));
      setNotice(t("Usuario desactivado."));
      await loadUsers();
    } catch (error) {
      setNotice(`${t("No se pudo desactivar el usuario")}: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

  const requestPasswordReset = async (user) => {
    setBusy(true);
    try {
      const response = await fetch(
        `/api/auth/users/${encodeURIComponent(user.username)}/password-reset`,
        { method: "POST", credentials: "same-origin" },
      );
      const body = await response.text();
      if (!response.ok) throw new Error(body.trim() || t("No se pudo generar la recuperación."));
      setNotice(
        t("Si {username} tiene un correo válido y el envío está habilitado, recibirá el enlace de recuperación.", { username: user.username }),
      );
    } catch (error) {
      setNotice(`${t("No se pudo solicitar la recuperación")}: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

  const roleOptions = Array.isArray(roles)
    ? roles.map((role) => typeof role === "string"
      ? { id: role, assignable: true }
      : { id: role.id || role.name, assignable: role.assignable !== false })
      .filter((role) => role.id)
    : Object.keys(roles).map((role) => ({ id: role, assignable: true }));
  const currentUsername = currentIdentity?.username || currentIdentity?.Username || "";

  const canEditUser = (user) => !user.root && user.roles.every((assignedRole) => (
    roleOptions.find((role) => role.id === assignedRole)?.assignable !== false
  ));

  return (
    <section className="panel">
      <div className="panel-title">
        <div>
          <p className="eyebrow">{t("USUARIOS LOCALES")}</p>
          <h2>{t("Usuarios y asignación de roles")}</h2>
          <p className="explanation">
            {t("Las identidades externas reciben sus roles mediante el mapeo del proveedor. Aquí se administran únicamente las cuentas locales.")}
          </p>
        </div>
        <button type="button" className="primary small settings-add" onClick={startCreate} disabled={busy || creating}>
          {t("+ Nuevo usuario")}
        </button>
      </div>
      {notice && <div className="notice account-notice">{notice}</div>}

      {draft && (
        <form className="subpanel user-editor" onSubmit={saveUser}>
          <div className="section-heading small-heading">
            <div><b>{creating ? t("Crear usuario local") : t("Editar {username}", { username: draft.username })}</b></div>
            <button type="button" className="ghost small" onClick={() => { setDraft(null); setCreating(false); }}>{t("Cancelar")}</button>
          </div>
          <div className="row">
            <label>
              {t("Usuario")}
              <input
                value={draft.username}
                readOnly={!creating}
                autoComplete="off"
                onChange={(event) => setDraft((current) => ({ ...current, username: event.target.value.toLowerCase() }))}
              />
            </label>
            {creating && (
              <label>
                {t("Contraseña inicial")}
                <input type="password" maxLength="72" autoComplete="new-password" value={draft.password || ""} onChange={(event) => setDraft((current) => ({ ...current, password: event.target.value }))} />
              </label>
            )}
          </div>
          <div className="row">
            <label>
              {t("Nombre")}
              <input value={draft.firstName} onChange={(event) => setDraft((current) => ({ ...current, firstName: event.target.value }))} />
            </label>
            <label>
              {t("Apellidos")}
              <input value={draft.lastName} onChange={(event) => setDraft((current) => ({ ...current, lastName: event.target.value }))} />
            </label>
          </div>
          <label>
            {t("Correo electrónico")}
            <input type="email" value={draft.email} onChange={(event) => setDraft((current) => ({ ...current, email: event.target.value }))} />
            <small>{t("Se utiliza para recuperar la contraseña.")}</small>
          </label>
          <div className="role-picker">
            <span>{t("Roles locales")}</span>
            <div className="chips">
              {roleOptions.map((role) => (
                <label className="selector-chip" key={role.id}>
                  <input
                    type="checkbox"
                    checked={draft.roles.includes(role.id)}
                    disabled={draft.root || !role.assignable}
                    onChange={(event) => setDraft((current) => ({
                      ...current,
                      roles: event.target.checked
                        ? [...current.roles, role.id]
                        : current.roles.filter((entry) => entry !== role.id),
                    }))}
                  />
                  {role.id}
                </label>
              ))}
            </div>
          </div>
          <label className="toggle-line">
            <input type="checkbox" disabled={draft.root || draft.username === currentUsername} checked={draft.active} onChange={(event) => setDraft((current) => ({ ...current, active: event.target.checked }))} />
            {t("Cuenta activa")}
          </label>
          <button type="submit" className="primary account-action" disabled={busy}>
            {busy ? t("Guardando…") : creating ? t("Crear usuario") : t("Guardar cambios")}
          </button>
        </form>
      )}

      <label className="settings-search">
        {t("Buscar usuarios")}
        <input placeholder={t("Usuario, nombre, correo o rol")} value={query} onChange={(event) => setQuery(event.target.value)} />
      </label>
      <div className="data-table-wrap">
        <table className="data-table users-table">
          <thead>
            <tr><th>{t("Usuario")}</th><th>{t("Datos personales")}</th><th>{t("Roles")}</th><th>{t("Estado")}</th><th>{t("Acciones")}</th></tr>
          </thead>
          <tbody>
            {visibleUsers.map((user) => (
              <tr key={user.username}>
                <td>
                  <b>{user.username}</b>
                  {user.root && <small className="root-badge">{t("Cuenta raíz")}</small>}
                </td>
                <td>
                  <b>{`${user.firstName} ${user.lastName}`.trim() || t("Sin nombre")}</b>
                  <small>{user.email || t("Sin correo de recuperación")}</small>
                </td>
                <td><code>{user.roles.join(" · ")}</code></td>
                <td><StatusBadge status={user.active ? "ACTIVE" : "INACTIVE"} type="config" /></td>
                <td>
                  <div className="table-actions">
                    <button
                      type="button"
                      className="ghost small"
                      disabled={!canEditUser(user)}
                      title={user.root ? t("La cuenta raíz se modifica desde Mi perfil") : !canEditUser(user) ? t("No puedes delegar todos los roles de esta cuenta") : undefined}
                      onClick={() => { setDraft({ ...user }); setCreating(false); }}
                    >
                      {t("Editar")}
                    </button>
                    <button
                      type="button"
                      className="ghost small"
                      disabled={user.root || !user.email || busy}
                      title={user.root ? t("La cuenta raíz usa Recuperar contraseña en el inicio de sesión") : undefined}
                      onClick={() => requestPasswordReset(user)}
                    >
                      {t("Recuperar acceso")}
                    </button>
                    <button
                      type="button"
                      className="ghost small danger"
                      disabled={user.root || user.username === currentUsername || !user.active || busy}
                      title={user.root ? t("La cuenta raíz no puede desactivarse") : undefined}
                      onClick={() => removeUser(user)}
                    >
                      {user.active ? t("Desactivar") : t("Desactivado")}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!visibleUsers.length && <div className="empty">{busy ? t("Cargando usuarios…") : t("No hay usuarios que coincidan.")}</div>}
    </section>
  );
}

function EmailSettingsView({ editable }) {
  const { t } = useI18n();
  const [settings, setSettings] = useState(() => normalizeEmailSettings());
  const [testRecipient, setTestRecipient] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");

  const loadSettings = async () => {
    setBusy(true);
    try {
      const response = await fetch("/api/settings/email", {
        cache: "no-store",
        credentials: "same-origin",
      });
      const body = await response.text();
      if (!response.ok) throw new Error(body.trim() || t("No se pudo cargar la configuración de correo."));
      setSettings(normalizeEmailSettings(body ? JSON.parse(body) : {}));
    } catch (error) {
      setNotice(`${t("No se pudo cargar la configuración de correo")}: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => { loadSettings(); }, []);

  const updateProviderField = (provider, field, value) => {
    setSettings((current) => ({
      ...current,
      [provider]: { ...current[provider], [field]: value },
    }));
  };

  const save = async (event) => {
    event.preventDefault();
    const errors = validateEmailSettings(settings);
    if (errors.length) {
      setNotice(errors.map((error) => t(error)).join(" "));
      return;
    }
    if (settings.clearSecrets && !window.confirm(
      t("¿Eliminar las credenciales guardadas de todos los proveedores de correo?"),
    )) return;
    setBusy(true);
    setNotice("");
    try {
      const response = await fetch("/api/settings/email", {
        method: "PUT",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(emailSettingsPayload(settings)),
      });
      const body = await response.text();
      if (!response.ok) throw new Error(body.trim() || t("No se pudo guardar la configuración."));
      setSettings(normalizeEmailSettings(body ? JSON.parse(body) : settings));
      setNotice(t("Configuración de correo guardada. Los secretos nuevos ya no se muestran."));
    } catch (error) {
      setNotice(`${t("No se pudo guardar el correo")}: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

  const test = async () => {
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(testRecipient.trim())) {
      setNotice(t("Ingresa un destinatario válido para la prueba."));
      return;
    }
    setBusy(true);
    setNotice("");
    try {
      const response = await fetch("/api/settings/email/test", {
        method: "POST",
        credentials: "same-origin",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ to: testRecipient.trim().toLowerCase() }),
      });
      const body = await response.text();
      if (!response.ok) throw new Error(body.trim() || t("No se pudo enviar el correo de prueba."));
      const result = body ? JSON.parse(body) : {};
      setNotice(t("Correo de prueba enviado mediante {provider}.", { provider: result.provider || settings.provider }));
    } catch (error) {
      setNotice(`${t("Falló el envío de prueba")}: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

  const secretHint = (configured) => configured
    ? t("Configurado; deja vacío para conservarlo")
    : t("Requerido");

  return (
    <section className="panel email-settings">
      <p className="eyebrow">{t("NOTIFICACIONES")}</p>
      <h2>{t("Envío de correos")}</h2>
      <p className="explanation">
        {t("Se usa para recuperar contraseñas y enviar avisos de seguridad. Los secretos se cifran y nunca regresan al navegador.")}
      </p>
      {!editable && (
        <div className="validation-box">{t("Tienes acceso de lectura. Se requiere")} <code>settings.email.edit</code> {t("para modificar o probar el envío.")}</div>
      )}
      {settings.credentialsUnavailable && (
        <div className="warning-box">
          {t("Las credenciales guardadas no pueden descifrarse con la clave actual. Ingresa credenciales nuevas y guarda; las anteriores serán reemplazadas de forma segura.")}
        </div>
      )}
      {notice && <div className="notice account-notice">{notice}</div>}
      <form onSubmit={save}>
        <fieldset className="settings-fieldset" disabled={!editable}>
        <label className="toggle-line feature-toggle">
          <input type="checkbox" checked={settings.enabled} onChange={(event) => setSettings((current) => ({ ...current, enabled: event.target.checked }))} />
          <span><b>{t("Habilitar envío de correos")}</b><small>{t("Necesario para recuperación de contraseña.")}</small></span>
        </label>
        <div className="row">
          <label>
            {t("Proveedor")}
            <select value={settings.provider} onChange={(event) => setSettings((current) => ({ ...current, provider: event.target.value }))}>
              <option value="SMTP">{t("Servidor SMTP")}</option>
              <option value="AWS_SES">Amazon SES</option>
              <option value="AZURE_ACS">Azure Communication Services</option>
            </select>
          </label>
          <label>
            {t("Estado")}
            <input value={settings.enabled ? t("Habilitado") : t("Deshabilitado")} readOnly />
          </label>
        </div>
        <div className="row">
          <label>
            {t("Nombre del remitente")}
            <input value={settings.fromName} onChange={(event) => setSettings((current) => ({ ...current, fromName: event.target.value }))} />
          </label>
          <label>
            {t("Dirección del remitente")}
            <input type="email" placeholder="o11y@example.com" value={settings.fromAddress} onChange={(event) => setSettings((current) => ({ ...current, fromAddress: event.target.value }))} />
          </label>
        </div>

        {settings.provider === "SMTP" && (
          <div className="provider-fields">
            <div className="row">
              <label>Host SMTP<input value={settings.smtp.host} onChange={(event) => updateProviderField("smtp", "host", event.target.value)} /></label>
              <label>{t("Puerto")}<input type="number" min="1" max="65535" value={settings.smtp.port} onChange={(event) => updateProviderField("smtp", "port", event.target.value)} /></label>
            </div>
            <div className="row">
              <label>{t("Usuario")}<input autoComplete="off" value={settings.smtp.username} onChange={(event) => updateProviderField("smtp", "username", event.target.value)} /></label>
              <label>{t("Contraseña")}<input type="password" autoComplete="new-password" placeholder={secretHint(settings.secretsConfigured.smtpPassword)} value={settings.smtp.password} onChange={(event) => updateProviderField("smtp", "password", event.target.value)} /></label>
            </div>
            <label>
              {t("Seguridad de transporte")}
              <select value={settings.smtp.tlsMode} onChange={(event) => updateProviderField("smtp", "tlsMode", event.target.value)}>
                <option value="STARTTLS">STARTTLS</option>
                <option value="TLS">{t("TLS directo")}</option>
                <option value="NONE">{t("Sin TLS")}</option>
              </select>
            </label>
          </div>
        )}

        {settings.provider === "AWS_SES" && (
          <div className="provider-fields">
            <div className="row">
              <label>{t("Región")}<input placeholder="us-east-1" value={settings.awsSes.region} onChange={(event) => updateProviderField("awsSes", "region", event.target.value)} /></label>
              <label>Access key ID<input autoComplete="off" value={settings.awsSes.accessKeyId} onChange={(event) => updateProviderField("awsSes", "accessKeyId", event.target.value)} /></label>
            </div>
            <div className="row">
              <label>Secret access key<input type="password" autoComplete="new-password" placeholder={secretHint(settings.secretsConfigured.awsSecretAccessKey)} value={settings.awsSes.secretAccessKey} onChange={(event) => updateProviderField("awsSes", "secretAccessKey", event.target.value)} /></label>
              <label>Session token ({t("opcional")})<input type="password" autoComplete="new-password" placeholder={settings.secretsConfigured.awsSessionToken ? t("Configurado; deja vacío para conservarlo") : t("Opcional")} value={settings.awsSes.sessionToken} onChange={(event) => updateProviderField("awsSes", "sessionToken", event.target.value)} /></label>
            </div>
            <label>{t("Endpoint alternativo (opcional)")}<input placeholder="https://email.us-east-1.amazonaws.com" value={settings.awsSes.endpoint} onChange={(event) => updateProviderField("awsSes", "endpoint", event.target.value)} /></label>
          </div>
        )}

        {settings.provider === "AZURE_ACS" && (
          <div className="provider-fields">
            <label>Endpoint ACS<input placeholder="https://example.communication.azure.com" value={settings.azureAcs.endpoint} onChange={(event) => updateProviderField("azureAcs", "endpoint", event.target.value)} /></label>
            <div className="row">
              <label>Access key<input type="password" autoComplete="new-password" placeholder={secretHint(settings.secretsConfigured.azureAccessKey)} value={settings.azureAcs.accessKey} onChange={(event) => updateProviderField("azureAcs", "accessKey", event.target.value)} /></label>
              <label>API version<input value={settings.azureAcs.apiVersion} onChange={(event) => updateProviderField("azureAcs", "apiVersion", event.target.value)} /></label>
            </div>
          </div>
        )}
        {(settings.credentialsUnavailable || Object.values(settings.secretsConfigured || {}).some(Boolean)) && (
          <label className="toggle-line clear-secrets">
            <input type="checkbox" disabled={settings.credentialsUnavailable} checked={settings.clearSecrets === true} onChange={(event) => setSettings((current) => ({ ...current, clearSecrets: event.target.checked }))} />
            <span><b>{t("Eliminar credenciales guardadas")}</b><small>{t("Se solicitará confirmación al guardar.")}</small></span>
          </label>
        )}
        <button type="submit" className="primary account-action" disabled={busy}>
          {busy ? t("Guardando…") : t("Guardar correo")}
        </button>
        </fieldset>
      </form>

      <div className="email-test">
        <label>
          {t("Destinatario de prueba")}
          <input type="email" placeholder="tu-correo@example.com" value={testRecipient} onChange={(event) => setTestRecipient(event.target.value)} />
          <small>{t("La prueba utiliza la última configuración guardada, incluso si todavía está deshabilitada.")}</small>
        </label>
        <button type="button" className="ghost" onClick={test} disabled={busy || !editable}>
          {t("Enviar prueba")}
        </button>
      </div>
    </section>
  );
}

function NetworkSettingsView() {
  const { t } = useI18n();
  const [network, setNetwork] = useState(null);
  const [busy, setBusy] = useState(true);
  const [error, setError] = useState("");

  const loadNetwork = async () => {
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/system/network", {
        cache: "no-store",
        credentials: "same-origin",
      });
      const body = await response.text();
      if (!response.ok) {
        throw new Error(body.trim() || t("No se pudo consultar la configuración de red."));
      }
      setNetwork(normalizeNetworkSettings(body ? JSON.parse(body) : {}));
    } catch (loadError) {
      setError(loadError.message || t("No se pudo consultar la configuración de red."));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => { loadNetwork(); }, []);

  const source = publicUrlSourceDetails(network?.publicUrlSource);
  const proxy = proxyModeDetails(network?.proxyMode);
  const displayValue = (value) => value || t("No configurado");

  return (
    <section className="panel network-settings">
      <div className="network-heading">
        <div>
          <p className="eyebrow">{t("DIAGNÓSTICO DE RED")}</p>
          <h2>{t("Red y acceso")}</h2>
          <p className="explanation">
            {t("Muestra las direcciones efectivas que usa el Control Plane y cómo interpreta el tráfico recibido desde proxies o balanceadores.")}
          </p>
        </div>
        <button type="button" className="ghost" onClick={loadNetwork} disabled={busy}>
          {busy ? t("Consultando…") : t("Actualizar")}
        </button>
      </div>

      <div className="validation-box network-readonly-notice">
        {t("Esta vista es de sólo lectura. Los cambios se realizan en las variables y manifiestos del despliegue; después se debe reiniciar el Control Plane.")}
      </div>

      {error && (
        <div className="warning-box network-error" role="alert">
          <b>{t("No se pudo cargar el diagnóstico.")}</b>
          <span>{error}</span>
        </div>
      )}

      {!network && !error && <div className="empty">{t("Consultando configuración efectiva…")}</div>}

      {network && (
        <>
          {!network.publicUrlValid && (
            <div className="warning-box network-error">
              <b>{t("La URL pública no es válida.")}</b>
              <span>{t("Los callbacks de autenticación y enlaces externos pueden fallar.")}</span>
            </div>
          )}

          <dl className="network-overview">
            <div className="network-value-card network-value-wide">
              <dt>{t("URL pública")}</dt>
              <dd><code>{displayValue(network.publicUrl)}</code></dd>
              <small>
                <span className={`network-state ${network.publicUrlValid ? "good" : "bad"}`}>
                  {network.publicUrlValid ? t("Válida") : t("Inválida")}
                </span>
                {t("Origen externo de la UI y callbacks.")}
              </small>
            </div>
            <div className="network-value-card network-value-wide">
              <dt>{t("Endpoint OpAMP público")}</dt>
              <dd><code>{displayValue(network.opampPublicUrl)}</code></dd>
              <small>{t("Dirección que deben usar agentes y Supervisors.")}</small>
            </div>
            <div className="network-value-card">
              <dt>{t("Modo de proxy")}</dt>
              <dd>{t(proxy.label)}</dd>
              <small>{t(proxy.detail)}</small>
            </div>
            <div className="network-value-card">
              <dt>{t("Fuente de URL pública")}</dt>
              <dd>
                <code>{t(source.label)}</code>
                {source.legacy && <span className="network-state legacy">Legacy</span>}
              </dd>
              <small>{t(source.detail)}</small>
            </div>
          </dl>

          <div className="network-details-grid">
            <article>
              <h3>{t("Listeners internos")}</h3>
              <dl>
                <div><dt>HTTP / UI</dt><dd><code>{displayValue(network.httpListenAddress)}</code></dd></div>
                <div><dt>OpAMP</dt><dd><code>{displayValue(network.opampListenAddress)}</code></dd></div>
              </dl>
              <small>{t("Son direcciones de escucha internas, no URLs para clientes externos.")}</small>
            </article>

            <article>
              <h3>{t("Proxies confiables")}</h3>
              {network.trustedProxyCidrs.length ? (
                <div className="network-cidr-list">
                  {network.trustedProxyCidrs.map((cidr) => <code key={cidr}>{cidr}</code>)}
                </div>
              ) : (
                <div className="empty compact">{t("Ningún CIDR configurado.")}</div>
              )}
              <small>{t("Fuera de estos rangos no se confía en headers forwarded.")}</small>
            </article>

            <article>
              <h3>{t("Publicación bajo subpath")}</h3>
              <p>
                <span className={`network-state ${network.subpathSupported ? "good" : "neutral"}`}>
                  {network.subpathSupported ? t("Compatible") : t("No compatible")}
                </span>
              </p>
              <small>
                {network.subpathSupported
                  ? t("La aplicación puede publicarse bajo una ruta base.")
                  : t("Publica la aplicación en la raíz del dominio; el proxy no debe agregar un prefijo de ruta.")}
              </small>
            </article>
          </div>
        </>
      )}
    </section>
  );
}

function SettingsView({
  identity,
  accessModel,
  securityDenylist,
  actor,
  onReload,
}) {
  const { t } = useI18n();
  const mayManageSecurity = canManageSecurity(identity);
  const mayManageEmail = canManageEmail(identity);
  const mayEditEmail = canEditEmail(identity);
  const mayViewNetwork = canViewNetwork(identity);
  const [section, setSection] = useState(
    mayManageSecurity ? "security" : mayManageEmail ? "email" : "network",
  );
  const [securitySection, setSecuritySection] = useState("providers");
  const [notice, setNotice] = useState("");

  if (!mayManageSecurity && !mayManageEmail && !mayViewNetwork) {
    return (
      <section className="panel">
        <p className="eyebrow">{t("CONFIGURACIÓN")}</p>
        <h2>{t("Acceso restringido")}</h2>
        <div className="warning-box">{t("Tu rol no tiene permisos para modificar la configuración del sistema.")}</div>
      </section>
    );
  }

  return (
    <>
      <div className="settings-tabs" role="tablist" aria-label={t("Configuración del sistema")}>
        {mayManageSecurity && (
          <button type="button" role="tab" aria-selected={section === "security"} className={section === "security" ? "active" : ""} onClick={() => setSection("security")}>
            <span>◇</span><b>{t("Seguridad")}</b><small>{t("Accesos, roles y capturas")}</small>
          </button>
        )}
        {mayManageEmail && (
          <button type="button" role="tab" aria-selected={section === "email"} className={section === "email" ? "active" : ""} onClick={() => setSection("email")}>
            <span>✉</span><b>{t("Correo")}</b><small>SMTP, AWS SES o Azure ACS</small>
          </button>
        )}
        {mayViewNetwork && (
          <button type="button" role="tab" aria-selected={section === "network"} className={section === "network" ? "active" : ""} onClick={() => setSection("network")}>
            <span>⌁</span><b>{t("Red y acceso")}</b><small>{t("URLs, proxy y listeners")}</small>
          </button>
        )}
      </div>

      {section === "security" && mayManageSecurity && (
        <>
          <div className="settings-subtabs" role="tablist" aria-label={t("Opciones de seguridad")}>
            <button type="button" role="tab" aria-selected={securitySection === "providers"} className={securitySection === "providers" ? "active" : ""} onClick={() => setSecuritySection("providers")}>{t("Proveedores SSO y roles")}</button>
            <button type="button" role="tab" aria-selected={securitySection === "users"} className={securitySection === "users" ? "active" : ""} onClick={() => setSecuritySection("users")}>{t("Usuarios locales")}</button>
            <button type="button" role="tab" aria-selected={securitySection === "governance"} className={securitySection === "governance" ? "active" : ""} onClick={() => setSecuritySection("governance")}>{t("Gobierno de capturas")}</button>
          </div>
          {securitySection === "providers" && <AccessView model={accessModel} onReload={onReload} />}
          {securitySection === "users" && <UsersView currentIdentity={identity} />}
          {securitySection === "governance" && (
            <SecurityView
              entries={securityDenylist}
              actor={actor}
              setActor={() => {}}
              onReload={onReload}
              setNotice={setNotice}
            />
          )}
          {notice && <div className="notice settings-global-notice">{notice}</div>}
        </>
      )}
      {section === "email" && mayManageEmail && <EmailSettingsView editable={mayEditEmail} />}
      {section === "network" && mayViewNetwork && <NetworkSettingsView />}
    </>
  );
}

function App() {
  const { t } = useI18n();
  const queryParameters = useMemo(
    () => new URLSearchParams(window.location.search),
    [],
  );
  const initialTab = tabFromLocation(window.location);
  const initialTarget = queryParameters.get("target") === "collector"
    ? "collector"
    : "java-extension";
  const requestedStep = Number(queryParameters.get("step"));
  const initialStep = requestedStep >= 1 && requestedStep <= workflowSteps.length
    ? requestedStep
    : 1;
  const restoredDraft = useMemo(() => readPolicyDraft(window.localStorage), []);
  const useRestoredTarget = !queryParameters.has("target") && restoredDraft?.target;
  const useRestoredStep = !queryParameters.has("step") && restoredDraft?.activeStep;

  const [agents, setAgents] = useState([]);
  const [collectorBases, setCollectorBases] = useState([]);
  const [deployments, setDeployments] = useState([]);
  const [configs, setConfigs] = useState({});
  const [securityDenylist, setSecurityDenylist] = useState([]);
  const [reserved, setReserved] = useState([]);
  const [auditEvents, setAuditEvents] = useState([]);
  const [storage, setStorage] = useState({
    driver: "PostgreSQL",
    status: "unknown",
  });
  const [tab, setTab] = useState(initialTab);
  const [configId, setConfigId] = useState(restoredDraft?.configId || "");
  const [target, setTarget] = useState(useRestoredTarget || initialTarget);
  const [baseVersionKey, setBaseVersionKey] = useState(restoredDraft?.baseVersionKey || "");
  const [authIdentity, setAuthIdentity] = useState(null);
  const [loginRequired, setLoginRequired] = useState(true);
  const [accessModel, setAccessModel] = useState(null);
  const [actor, setActor] = useState("local-admin");
  const [policy, setPolicy] = useState(() =>
    restoredDraft?.policy ? normalizePolicy(restoredDraft.policy) : emptyPolicy(),
  );
  const [editorMode, setEditorMode] = useState(restoredDraft?.editorMode || "form");
  const [editorFocus, setEditorFocus] = useState(
    normalizeTelemetryEditorFocus(restoredDraft?.editorFocus),
  );
  const [rawPolicyBody, setRawPolicyBody] = useState(
    restoredDraft?.rawPolicyBody || JSON.stringify(emptyPolicy(), null, 2),
  );
  const [collectorBody, setCollectorBody] = useState(
    restoredDraft?.collectorBody ||
      "# Escribe o carga una configuración completa del OpenTelemetry Collector\n",
  );
  const [collectorValidation, setCollectorValidation] = useState(null);
  const [collectorValidationBusy, setCollectorValidationBusy] = useState(false);
  const [reportedConfigKey, setReportedConfigKey] = useState("");
  const [selectedAgentIds, setSelectedAgentIds] = useState(
    restoredDraft?.selectedAgentIds || [],
  );
  const [selectedServices, setSelectedServices] = useState(
    restoredDraft?.selectedServices || [],
  );
  const [selectorAttributes, setSelectorAttributes] = useState(
    restoredDraft?.selectorAttributes || [],
  );
  const [agentQuery, setAgentQuery] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [activeStep, setActiveStep] = useState(useRestoredStep || initialStep);
  const [draftRecoveryVisible, setDraftRecoveryVisible] = useState(Boolean(restoredDraft));
  const [menuCollapsed, setMenuCollapsed] = useState(
    () => window.localStorage.getItem("o11y.sidebar.collapsed") === "true",
  );
  const loadGate = useRef(createLatestRequestGate());
  const liveLoadGate = useRef(createLatestRequestGate());
  const profileMenuRef = useRef(null);

  const navigateToTab = (destination, { replace = false } = {}) => {
    const nextTab = tabFromLocation({ pathname: urlForTab(destination) });
    const nextURL = urlForTab(nextTab, window.location.search);
    if (`${window.location.pathname}${window.location.search}` !== nextURL) {
      window.history[replace ? "replaceState" : "pushState"]({}, "", nextURL);
    }
    setTab(nextTab);
  };

  useEffect(() => {
    navigateToTab(initialTab, { replace: true });
    const restoreTabFromHistory = () => setTab(tabFromLocation(window.location));
    window.addEventListener("popstate", restoreTabFromHistory);
    return () => window.removeEventListener("popstate", restoreTabFromHistory);
  }, []);

  useEffect(() => {
    window.localStorage.setItem(
      "o11y.sidebar.collapsed",
      String(menuCollapsed),
    );
  }, [menuCollapsed]);

  useEffect(() => {
    if (!authIdentity) return;
    const owner = authIdentity.username || authIdentity.Username || "";
    if (!owner) return;
    writePolicyDraft(
      window.localStorage,
      {
        owner,
        savedAt: new Date().toISOString(),
        configId,
        target,
        baseVersionKey,
        policy,
        editorMode,
        editorFocus,
        rawPolicyBody,
        collectorBody,
        selectedAgentIds,
        selectedServices,
        selectorAttributes,
        activeStep,
      },
    );
  }, [
    configId,
    target,
    baseVersionKey,
    policy,
    editorMode,
    editorFocus,
    rawPolicyBody,
    collectorBody,
    selectedAgentIds,
    selectedServices,
    selectorAttributes,
    activeStep,
    authIdentity,
  ]);

  const replaceCollectorBody = (value) => {
    setCollectorBody(value);
    setCollectorValidation(null);
  };

  const resetPolicyDraftState = (message = "") => {
    setBaseVersionKey("");
    setConfigId("");
    setSelectedAgentIds([]);
    setSelectedServices([]);
    setSelectorAttributes([]);
    setPolicy(emptyPolicy());
    setRawPolicyBody(JSON.stringify(emptyPolicy(), null, 2));
    replaceCollectorBody(
      "# Escribe una configuración completa del OpenTelemetry Collector\n",
    );
    setReportedConfigKey("");
    setNotice(message);
    setActiveStep(1);
  };

  const isolatePolicyDraft = (identity) => {
    const username = identity?.username || identity?.Username || "";
    const stored = readPolicyDraft(window.localStorage);
    if (!username || (stored?.owner && stored.owner !== username)) {
      clearPolicyDraft(window.localStorage);
      setDraftRecoveryVisible(false);
      resetPolicyDraftState();
    }
  };

  const requireLogin = () => {
    clearPolicyDraft(window.localStorage);
    setDraftRecoveryVisible(false);
    resetPolicyDraftState();
    setLoginRequired(true);
    setAuthIdentity(null);
  };

  const load = async () => {
    const sequence = loadGate.current.begin();
    try {
      const protectedOptions = {
        cache: "no-store",
        credentials: "same-origin",
      };
      const responses = await Promise.all([
        fetch("/api/agents", protectedOptions),
        fetch("/api/configs", protectedOptions),
        fetch("/api/metric-names", protectedOptions),
        fetch("/api/audit", protectedOptions),
        fetch("/api/storage", protectedOptions),
        fetch("/api/security/denylist", protectedOptions),
        fetch("/api/deployments", protectedOptions),
        fetch("/api/auth/session", protectedOptions),
        fetch("/api/auth/providers", protectedOptions),
        fetch("/api/collector-base-configs", protectedOptions),
      ]);
      if (!loadGate.current.isCurrent(sequence)) return;
      if (responses.some((response) => response.status === 401)) {
        requireLogin();
        return;
      }
      if (responses.some((response) => !response.ok)) {
        throw new Error("Control Plane API unavailable");
      }
      const [
        agentData,
        configData,
        metricData,
        auditData,
        storageData,
        securityData,
        deploymentData,
        identityData,
        accessData,
        collectorBaseData,
      ] = await Promise.all(responses.map((response) => response.json()));
      if (!loadGate.current.isCurrent(sequence)) return;
      setAgents(agentData);
      setCollectorBases(collectorBaseData);
      setConfigs(configData);
      setReserved(metricData);
      setAuditEvents(auditData);
      setStorage(storageData);
      setSecurityDenylist(securityData);
      setDeployments(deploymentData);
      isolatePolicyDraft(identityData);
      setAuthIdentity(identityData);
      setAccessModel(accessData);
      setActor(identityData.Username || identityData.username || "authenticated-user");
      setLoginRequired(false);
    } catch {
      if (!loadGate.current.isCurrent(sequence)) return;
      setNotice(t("No se pudo consultar el Control Plane."));
    }
  };

  const loadLiveState = async () => {
    const sequence = liveLoadGate.current.begin();
    try {
      const protectedOptions = {
        cache: "no-store",
        credentials: "same-origin",
      };
      const responses = await Promise.all([
        fetch("/api/agents", protectedOptions),
        fetch("/api/configs", protectedOptions),
        fetch("/api/deployments", protectedOptions),
        fetch("/api/collector-base-configs", protectedOptions),
      ]);
      if (!liveLoadGate.current.isCurrent(sequence)) return;
      if (responses.some((response) => response.status === 401)) {
        requireLogin();
        return;
      }
      if (responses.some((response) => !response.ok)) return;
      const [agentData, configData, deploymentData, collectorBaseData] =
        await Promise.all(responses.map((response) => response.json()));
      if (!liveLoadGate.current.isCurrent(sequence)) return;
      setAgents(agentData);
      setConfigs(configData);
      setDeployments(deploymentData);
      setCollectorBases(collectorBaseData);
    } catch {
      // Preserve the last good live state. Manual refresh still reports errors.
    }
  };

  useEffect(() => {
    let refreshInProgress = false;
    let initialized = false;
    let disposed = false;
    let timer;

    const refresh = async () => {
      if (!initialized || refreshInProgress) return;
      refreshInProgress = true;
      try {
        await loadLiveState();
      } finally {
        refreshInProgress = false;
      }
    };

    const refreshWhenVisible = () => {
      if (!document.hidden) refresh();
    };

    const start = async () => {
      await load();
      if (disposed) return;
      initialized = true;
      timer = setInterval(refreshWhenVisible, controlPlaneRefreshIntervalMs);
    };

    start();
    window.addEventListener("focus", refreshWhenVisible);
    document.addEventListener("visibilitychange", refreshWhenVisible);

    return () => {
      disposed = true;
      if (timer) clearInterval(timer);
      liveLoadGate.current.invalidate();
      window.removeEventListener("focus", refreshWhenVisible);
      document.removeEventListener("visibilitychange", refreshWhenVisible);
    };
  }, []);

  const authenticated = (identity) => {
    isolatePolicyDraft(identity);
    setAuthIdentity(identity);
    setActor(identity.Username || identity.username || "authenticated-user");
    setLoginRequired(false);
    load();
  };

  const logout = async () => {
    loadGate.current.invalidate();
    liveLoadGate.current.invalidate();
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "same-origin",
      });
    } finally {
      clearPolicyDraft(window.localStorage);
      setDraftRecoveryVisible(false);
      resetPolicyDraftState();
      setAuthIdentity(null);
      setLoginRequired(true);
    }
  };

  const currentVersions = useMemo(
    () => flattenStoredVersions(configs),
    [configs],
  );

  const targetVersions = currentVersions.filter(
    (version) => version.Target === target,
  );
  const managedPolicies = useMemo(
    () => buildManagedPolicies(currentVersions, deployments),
    [currentVersions, deployments],
  );
  const managedCollectors = useMemo(
    () => buildManagedCollectorConfigs(currentVersions, deployments, collectorBases),
    [currentVersions, deployments, collectorBases],
  );

  const policyNames = [
    ...policy.metricPolicies.map((item) => item.name),
    ...policy.eventMetricPolicies.map((item) => item.name),
    ...policy.messagingMetricPolicies.map((item) => item.name),
    ...policy.methodPolicies.flatMap((item) =>
      item.metrics.map((metricItem) => metricItem.name),
    ),
  ];

  const nameErrors =
    target === "java-extension" && editorMode === "form"
      ? policyNames.filter(
          (name, index) =>
            !name ||
            policyNames.indexOf(name) !== index ||
            reserved.some((item) => item.name === name && item.owner !== configId),
        )
      : [];

  const compatibleTargetAgents = agents.filter(
    (agent) =>
      agent.Kind === target &&
      (target !== "collector" || agent.RemoteConfig),
  );
  const targetAgents = compatibleTargetAgents.filter(isConnectedTarget);
  const unavailableTargetCount =
    compatibleTargetAgents.length - targetAgents.length;

  const reportedCollectorConfigs = targetAgents.flatMap((agent) =>
    Object.entries(agent.EffectiveConfig || {}).map(([name, file]) => ({
      key: `${agent.UID}::${name}`,
      agent,
      name,
      file,
    })),
  );

  const selector = {
    InstanceUIDs: selectedAgentIds,
    Services: selectedServices,
    Attributes: Object.fromEntries(
      selectorAttributes
        .filter((attribute) => attribute.key && attribute.value)
        .map((attribute) => [attribute.key, attribute.value]),
    ),
  };

  const matchesSelector = (agent) =>
    (!selector.InstanceUIDs.length || selector.InstanceUIDs.includes(agent.UID)) &&
    (!selector.Services.length || selector.Services.includes(agent.Service)) &&
    Object.entries(selector.Attributes).every(
      ([key, value]) => agent.Attributes?.[key] === value,
    );

  const matchingTargetAgents = targetAgents.filter(matchesSelector);

  const body =
    target === "collector"
      ? collectorBody
      : editorMode === "raw"
        ? rawPolicyBody
        : JSON.stringify(policy, null, 2);

  let rawPolicyValid = true;
  let policyForClientValidation = policy;
  if (target === "java-extension" && editorMode === "raw") {
    try {
      policyForClientValidation = JSON.parse(rawPolicyBody);
    } catch {
      rawPolicyValid = false;
    }
  }
  const policySchemaRequired = target === "java-extension" && rawPolicyValid
    ? requiredPolicySchema(policyForClientValidation)
    : "1.3";
  const incompatibleSchemaTargets = target === "java-extension"
    ? matchingTargetAgents.filter(
        (agent) => !agentSupportsPolicySchema(agent, policySchemaRequired),
      )
    : [];
  const denyViolations = target === "java-extension" && rawPolicyValid
    ? policyCaptureDenyViolations(policyForClientValidation, securityDenylist)
    : [];
  const wireContractErrors = target === "java-extension" && rawPolicyValid
    ? policyWireContractErrors(policyForClientValidation)
    : [];
  const invalidPolicyHeaders = target === "java-extension" && rawPolicyValid
    ? [
        ...(Array.isArray(policyForClientValidation.requestHeaders)
          ? policyForClientValidation.requestHeaders
          : []).map((item) => item.name),
        ...(Array.isArray(policyForClientValidation.responseHeaders)
          ? policyForClientValidation.responseHeaders
          : []).map((item) => item.name),
        ...(Array.isArray(policyForClientValidation.metricPolicies)
          ? policyForClientValidation.metricPolicies
          : []).flatMap((item) =>
          (Array.isArray(item.customAttributes) ? item.customAttributes : [])
            .map((attribute) => attribute.header),
        ),
      ].filter((name) => !String(name || "").trim())
    : [];
  const collectorValidationCurrent =
    target !== "collector" ||
    (collectorValidation?.valid && collectorValidation.body === collectorBody);
  const reservedCollectorBaseID = target === "collector" && collectorBases
    .map((base) => normalizeCollectorBase(base).ID)
    .includes(configId.trim());
  const configurationReady = Boolean(body.trim()) &&
    nameErrors.length === 0 && invalidPolicyHeaders.length === 0 &&
    denyViolations.length === 0 && wireContractErrors.length === 0 &&
    rawPolicyValid && collectorValidationCurrent &&
    !reservedCollectorBaseID;

  const publicationBlockers = [
    !configId.trim() && "Define un ID de configuración en el paso Origen.",
    !body.trim() && "La configuración está vacía.",
    nameErrors.length > 0 && "Hay nombres de métricas vacíos, repetidos o reservados.",
    invalidPolicyHeaders.length > 0 && "Hay capturas HTTP con un header vacío.",
    denyViolations.length > 0 &&
      "La policy intenta capturar datos bloqueados por la denylist del Control Plane.",
    wireContractErrors.length > 0 && wireContractErrors[0],
    incompatibleSchemaTargets.length > 0 &&
      `La policy requiere schema ${policySchemaRequired}; ${incompatibleSchemaTargets.length} destino(s) coincidente(s) no reportan una versión compatible en o11y.policy.schema.`,
    reservedCollectorBaseID &&
      "Ese ID pertenece a un ConfigMap base inmutable; usa otro ID para la configuración administrada.",
    !rawPolicyValid && "El JSON de la policy no tiene una sintaxis válida.",
    target === "collector" &&
      !collectorValidationCurrent &&
      "Valida el YAML actual con otelcol-contrib antes de publicarlo.",
    matchingTargetAgents.length === 0 &&
      "No hay destinos conectados que coincidan con los selectores.",
  ].filter(Boolean);

  const changeTarget = (value) => {
    setTarget(value);
    setBaseVersionKey("");
    setConfigId("");
    setSelectedAgentIds([]);
    setSelectedServices([]);
    setSelectorAttributes([]);
    setAgentQuery("");
    setReportedConfigKey("");
    setCollectorValidation(null);
    setNotice("");
    setActiveStep(1);
  };

  const chooseConfigurationType = (option) => {
    if (option.target !== target) {
      changeTarget(option.target);
    }
    if (option.target === "java-extension") {
      setEditorFocus(option.editorFocus || "http-incoming");
    }
  };

  const startBlank = () => {
    resetPolicyDraftState(t("Editor reiniciado. No se publicó ningún cambio."));
  };

  const loadVersion = (version) => {
    setConfigId(version.ID || version.configId);
    setTarget(version.Target);
    setBaseVersionKey(`${version.configId || version.ID}::${version.Version}`);
    setSelectedAgentIds(version.Selector?.InstanceUIDs || []);
    setSelectedServices(version.Selector?.Services || []);
    setSelectorAttributes(
      Object.entries(version.Selector?.Attributes || {}).map(([key, value]) => ({
        key,
        value,
      })),
    );
    if (version.Target === "java-extension") {
      setRawPolicyBody(version.Body);
      try {
        const loadedPolicy = normalizePolicy(JSON.parse(version.Body));
        setPolicy(loadedPolicy);
        const hasIncomingHTTP = [
          ...loadedPolicy.requestHeaders,
          ...loadedPolicy.responseHeaders,
          ...loadedPolicy.metricPolicies,
          ...loadedPolicy.bodyEventPolicies,
        ].some((item) => normalizeHTTPDirection(item.direction) === "INCOMING");
        const hasOutgoingHTTP = [
          ...loadedPolicy.requestHeaders,
          ...loadedPolicy.responseHeaders,
          ...loadedPolicy.metricPolicies,
          ...loadedPolicy.bodyEventPolicies,
        ].some((item) => normalizeHTTPDirection(item.direction) === "OUTGOING");
        const firstMessagingFamily = loadedPolicy.messagingEventPolicies.length
          ? messagingFamilyForScope(loadedPolicy.messagingEventPolicies[0].scope)
          : "";
        if (hasIncomingHTTP) {
          setEditorFocus("http-incoming");
        } else if (loadedPolicy.methodPolicies.length) {
          setEditorFocus("method");
        } else if (hasOutgoingHTTP) {
          setEditorFocus("http-outgoing");
        } else if (firstMessagingFamily) {
          setEditorFocus(firstMessagingFamily);
        } else {
          setEditorFocus("http-incoming");
        }
      } catch {
        setEditorMode("raw");
        setNotice(t("La versión se cargó en modo JSON porque no pudo abrirse como formulario."));
      }
    } else {
      replaceCollectorBody(version.Body);
    }
    navigateToTab("policy");
    setActiveStep(2);
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  const loadSelectedVersion = () => {
    const selected = targetVersions.find(
      (version) => `${version.configId}::${version.Version}` === baseVersionKey,
    );
    if (selected) loadVersion(selected);
  };

  const loadReportedCollectorConfig = () => {
    const selected = reportedCollectorConfigs.find(
      (item) => item.key === reportedConfigKey,
    );
    if (!selected) return;
    const sanitized = sanitizeEffectiveCollectorConfig(selected.file.Body);
    const origin = String(selected.agent.EffectiveConfigOrigin || "MANAGED").toUpperCase();
    replaceCollectorBody(sanitized.body);
    setConfigId((current) => current.trim() || collectorConfigId(selected.agent));
    setBaseVersionKey("");
    setNotice(
      `${t(origin === "BASE" ? "Base inmutable" : "Configuración administrada")} ${t("reportada por")} ${selected.agent.Service} ${t("cargada como borrador.")} ` +
        `${sanitized.removed.length ? `${t("Se retiró automáticamente")}: ${sanitized.removed.join(", ")}. ` : ""}` +
        t("El documento de origen no fue modificado y aún no se publicó ningún cambio."),
    );
    setActiveStep(2);
  };

  const loadCollectorFile = async (event) => {
    const input = event.currentTarget;
    const file = input.files?.[0];
    if (!file) return;
    if (file.size > 1024 * 1024) {
      setNotice(t("El YAML local no puede superar 1 MiB."));
      input.value = "";
      return;
    }
    try {
      const content = await file.text();
      if (!content.trim()) {
        throw new Error(t("el archivo está vacío"));
      }
      replaceCollectorBody(content);
      setBaseVersionKey("");
      setReportedConfigKey("");
      setNotice(
        `${t("YAML local")} ${file.name} ${t("cargado en el editor. Aún no se publicó ningún cambio.")}`,
      );
      setActiveStep(2);
    } catch (error) {
      setNotice(`${t("No se pudo cargar el YAML local")}: ${error.message}`);
    } finally {
      input.value = "";
    }
  };

  const switchEditorMode = (nextMode) => {
    if (nextMode === editorMode) return;
    if (nextMode === "raw") {
      setRawPolicyBody(JSON.stringify(policy, null, 2));
      setEditorMode("raw");
      return;
    }
    try {
      setPolicy(normalizePolicy(JSON.parse(rawPolicyBody)));
      setEditorMode("form");
      setNotice("");
    } catch {
      setNotice(t("El JSON debe ser válido antes de volver al formulario."));
    }
  };

  const validateCollectorBody = async () => {
    const bodyBeingValidated = collectorBody;
    setCollectorValidationBusy(true);
    setCollectorValidation(null);
    setNotice(t("Validando YAML con otelcol-contrib…"));
    try {
      const response = await fetch("/api/configs/validate", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-actor": actor,
        },
        credentials: "same-origin",
        body: JSON.stringify({ Body: bodyBeingValidated }),
      });
      const message = await response.text();
      let result;
      try {
        result = JSON.parse(message);
      } catch {
        result = { valid: false, output: message.trim() };
      }
      setCollectorValidation({ ...result, body: bodyBeingValidated });
      if (!response.ok || !result.valid) {
        throw new Error(result.output || t("El Collector rechazó el YAML."));
      }
      setNotice(
        `${t("YAML válido con otelcol-contrib")} ${result.validatorVersion}. ${t("Ya puedes seleccionar destinos.")}`,
      );
    } catch (error) {
      setNotice(`${t("YAML inválido")}: ${error.message}`);
    } finally {
      setCollectorValidationBusy(false);
    }
  };

  const publish = async () => {
    setBusy(true);
    setNotice(t("Validando y publicando…"));
    try {
      const response = await fetch("/api/configs", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-actor": actor,
        },
        credentials: "same-origin",
        body: JSON.stringify({
          ID: configId,
          Target: target,
          Body: body,
          Selector: selector,
        }),
      });
      const message = await response.text();
      if (!response.ok) {
        let errorMessage = message.trim();
        try {
          errorMessage = JSON.parse(message).output || errorMessage;
        } catch {
          // Plain-text validation errors are already readable.
        }
        throw new Error(errorMessage);
      }
      const saved = JSON.parse(message);
      setNotice(
        `${t("Versión")} ${saved.Version} ${t("guardada y enviada. Aún no está aplicada: espera la confirmación individual de los destinos coincidentes.")}`,
      );
      await load();
    } catch (error) {
      setNotice(`${t("Error")}: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

  const restoreCollectorVersion = async (version) => {
    if (
      !window.confirm(t(`¿Restaurar ${version.configId} v${version.Version} como una versión nueva?`))
    ) {
      return;
    }
    setBusy(true);
    setNotice(t("Creando una restauración auditable del Collector…"));
    try {
      const response = await fetch(
        `/api/configs/${encodeURIComponent(version.configId)}/versions/${version.Version}/rollback`,
        {
          method: "POST",
          headers: {
            "x-actor": actor,
          },
          credentials: "same-origin",
        },
      );
      const message = await response.text();
      if (!response.ok) throw new Error(message.trim());
      const saved = JSON.parse(message);
      setNotice(
        `${t("Configuración restaurada como")} ${saved.ID} v${saved.Version}; ${t("la versión original no fue alterada.")}`,
      );
      await load();
    } catch (error) {
      setNotice(`${t("Error")}: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

  const managePolicyLifecycle = async (managedPolicy) => {
    const confirmation = policyLifecycleConfirmation(managedPolicy);
    if (!confirmation || !window.confirm(t(confirmation))) return;

    setBusy(true);
    setNotice(
      managedPolicy.action === "DEACTIVATE"
        ? `${t("Retirando")} ${managedPolicy.id} ${t("de sus destinos…")}`
        : `${t("Creando una nueva versión de")} ${managedPolicy.id} ${t("desde la versión anterior…")}`,
    );
    try {
      const response = await fetch(policyLifecycleEndpoint(managedPolicy.id), {
        method: "POST",
        headers: {
          "x-actor": actor,
        },
        credentials: "same-origin",
      });
      const message = await response.text();
      if (!response.ok) throw new Error(message.trim());
      const saved = JSON.parse(message);
      if (managedPolicy.action === "DEACTIVATE") {
        setNotice(
          `${managedPolicy.id} ${t("fue retirada de sus destinos como")} v${saved.Version}. ${t("El historial se conserva.")}`,
        );
      } else {
        setNotice(
          `${managedPolicy.id} ${t("volvió al contenido de")} v${policyVersionNumber(managedPolicy.previousVersion)} ${t("mediante la nueva")} v${saved.Version}.`,
        );
      }
      await load();
    } catch (error) {
      setNotice(`${t("Error")}: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };

  const manageCollectorLifecycle = async (managedCollector) => {
    const confirmation = collectorDeactivateConfirmation(managedCollector);
    if (!confirmation || !window.confirm(t(confirmation))) return;

    setBusy(true);
    setNotice(`${t("Retirando")} ${managedCollector.id} ${t("y solicitando la base NOP…")}`);
    try {
      const response = await fetch(collectorDeactivateEndpoint(managedCollector.id), {
        method: "POST",
        headers: {
          "x-actor": actor,
        },
        credentials: "same-origin",
      });
      const message = await response.text();
      if (!response.ok) throw new Error(message.trim());
      const saved = JSON.parse(message);
      setNotice(
        `${managedCollector.id} ${t("fue retirada como")} v${saved.Version}. ` +
        t("Espera la confirmación BASE_APPLIED de cada Supervisor; los ConfigMap base y el historial permanecen intactos."),
      );
      await load();
    } catch (error) {
      setNotice(`${t("Error")}: ${error.message}`);
    } finally {
      setBusy(false);
    }
  };


  const navItems = [
    { id: "policy", label: t("Editor OTel"), icon: "◆" },
    {
      id: "agents",
      label: t("Agentes"),
      icon: "◎",
      count: agents.filter(isConnectedTarget).length,
    },
    {
      id: "deployments",
      label: t("Gestión remota"),
      icon: "⇢",
      count:
        managedPolicies.filter((policy) => policy.active).length +
        managedCollectors.filter((config) => config.active).length,
    },
    {
      id: "history",
      label: t("Versiones"),
      icon: "↺",
      count: currentVersions.length,
    },
  ];

  const pageTitle = t({
    policy: "Editor OTel",
    agents: "Fleet de agentes",
    deployments: "Policies y configuraciones",
    history: "Historial",
    profile: "Mi perfil",
    settings: "Configuración",
  }[tab]);

  const settingsAvailable = canManageSecurity(authIdentity) ||
    canManageEmail(authIdentity) || canViewNetwork(authIdentity);
  const username = authIdentity?.username || authIdentity?.Username || t("servidor disponible");
  const displayName = [authIdentity?.firstName, authIdentity?.lastName].filter(Boolean).join(" ") || username;
  const avatarLabel = displayName
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("") || "U";

  const openAccountPage = (destination) => {
    navigateToTab(destination);
    if (profileMenuRef.current) profileMenuRef.current.open = false;
  };

  if (loginRequired) {
    return <LoginView onAuthenticated={authenticated} />;
  }

  return (
    <div className={`shell ${menuCollapsed ? "sidebar-collapsed" : ""}`}>
      <aside>
        <button
          type="button"
          className="sidebar-toggle"
          aria-label={t(menuCollapsed ? "Expandir menú" : "Colapsar menú")}
          title={t(menuCollapsed ? "Expandir menú" : "Colapsar menú")}
          onClick={() => setMenuCollapsed((current) => !current)}
        >
          <span aria-hidden="true">{menuCollapsed ? "›" : "‹"}</span>
        </button>
        <div className="brand">
          <span>◈</span>
          <div className="brand-copy">
            <b>o11y</b>
            <small>OpAMP Control</small>
          </div>
        </div>
        <nav>
          {navItems.map(({ id, label, icon, count }) => (
            <button
              key={id}
              className={tab === id ? "active" : ""}
              onClick={() => navigateToTab(id)}
              aria-label={
                id === "agents" ? `${label}: ${count} ${t("conectados")}` : label
              }
              title={
                id === "agents"
                  ? `${count} ${t("conectados")} · ${t("Actualización")} ${
                      controlPlaneRefreshIntervalMs / 1000
                    } s`
                  : menuCollapsed
                    ? label
                    : undefined
              }
            >
              <span className="nav-icon" aria-hidden="true">{icon}</span>
              <span className="nav-label">{label}</span>
              {Number.isInteger(count) && <i>{count}</i>}
            </button>
          ))}
        </nav>
        <div className="protocol">
          <div className="protocol-heading">
            <span className="pulse" />
            <span>{t("OpAMP HTTP polling")}</span>
          </div>
          <small>{t("Agentes y Supervisors: HTTP · 10s")}</small>
          <small>{t("PostgreSQL")}: {storage.status}</small>
        </div>
      </aside>

      <main>
        <header>
          <div>
            <p className="eyebrow">{t("CONTROL PLANE")}</p>
            <h1>{pageTitle}</h1>
          </div>
          <div className="session-status">
            <LanguageSelector compact />
            {settingsAvailable && (
              <button
                type="button"
                className={`settings-gear ${tab === "settings" ? "active" : ""}`}
                aria-label={t("Abrir configuración")}
                title={t("Configuración")}
                onClick={() => navigateToTab("settings")}
              >
                ⚙
              </button>
            )}
            <details className="profile-menu" ref={profileMenuRef}>
              <summary aria-label={`${t("Menú")} · ${displayName}`}>
                <span className="profile-avatar" aria-hidden="true">{avatarLabel}</span>
                <span className="profile-summary-copy"><b>{displayName}</b><small>{username}</small></span>
                <span className="profile-chevron" aria-hidden="true">⌄</span>
              </summary>
              <div className="profile-popover">
                <div className="profile-popover-heading">
                  <span className="profile-avatar large" aria-hidden="true">{avatarLabel}</span>
                  <span><b>{displayName}</b><small>{identityRoles(authIdentity).join(", ") || t("Sin rol")}</small></span>
                </div>
                <button type="button" onClick={() => openAccountPage("profile")}><span>◉</span> {t("Mi perfil")}</button>
                {settingsAvailable && <button type="button" onClick={() => openAccountPage("settings")}><span>⚙</span> {t("Configuración")}</button>}
                <button type="button" className="profile-logout" onClick={logout}><span>↪</span> {t("Salir")}</button>
              </div>
            </details>
          </div>
        </header>

        {tab === "policy" && (
          <>
            <section className="summary">
              <div>
                <small>
                  {t("Destinos conectados")}
                  {unavailableTargetCount > 0
                    ? ` · ${unavailableTargetCount} ${t("sin señal OpAMP excluidos")}`
                    : ""}
                </small>
                <strong>{targetAgents.length}</strong>
              </div>
              <div>
                <small>{t("Métricas en editor")}</small>
                <strong>{target === "java-extension" ? policyNames.length : "—"}</strong>
              </div>
              <div>
                <small>{t("Capturas bloqueadas por deny")}</small>
                <strong>{target === "java-extension" ? denyViolations.length : "—"}</strong>
              </div>
            </section>

            {draftRecoveryVisible && (
              <section className="notice policy-draft-recovery" role="status">
                <div>
                  <b>{t("Borrador local restaurado")}</b>
                  <span>
                    {t("Se recuperaron el formulario, los selectores y el paso anterior. No se publicó ninguna versión.")}
                  </span>
                </div>
                <div className="table-actions">
                  <button type="button" className="ghost small" onClick={() => setDraftRecoveryVisible(false)}>
                    {t("Continuar con borrador")}
                  </button>
                  <button
                    type="button"
                    className="ghost small danger on"
                    onClick={() => {
                      clearPolicyDraft(window.localStorage);
                      setDraftRecoveryVisible(false);
                      resetPolicyDraftState(t("Borrador local descartado. No se publicó ningún cambio."));
                    }}
                  >
                    {t("Descartar")}
                  </button>
                </div>
              </section>
            )}

            <div
              className={`columns policy-columns ${
                activeStep === 4 ? "review-step" : "single-step"
              }`}
            >
              <section className="panel editor">
                <PolicyStepper
                  activeStep={activeStep}
                  setActiveStep={setActiveStep}
                />

                {notice && <div className="notice workflow-notice">{notice}</div>}

                {activeStep === 1 && (
                  <section className="workflow-content">
                    <div className="panel-title">
                      <div>
                        <p className="eyebrow">{t("PASO 1 · ORIGEN")}</p>
                        <h2>{t("Carga o inicia una configuración")}</h2>
                      </div>
                    </div>

                    <ConfigurationTypeChooser
                      target={target}
                      editorFocus={editorFocus}
                      onChoose={chooseConfigurationType}
                    />

                    <div className="row configuration-source version-source">
                      <StoredVersionPicker
                        versions={targetVersions}
                        value={baseVersionKey}
                        onChange={setBaseVersionKey}
                        t={t}
                      />
                      <div className="load-actions">
                        <button
                          type="button"
                          className="ghost"
                          disabled={!baseVersionKey}
                          onClick={loadSelectedVersion}
                        >
                          {t("Cargar versión")}
                        </button>
                        <button type="button" className="ghost" onClick={startBlank}>
                          {t("Nueva en blanco")}
                        </button>
                      </div>
                    </div>

                    {target === "collector" && (
                      <div className="reported-config-loader">
                        <label>
                          {t("YAML efectivo reportado por un Supervisor")}
                          <select
                            value={reportedConfigKey}
                            onChange={(event) => setReportedConfigKey(event.target.value)}
                          >
                            <option value="">{t("Selecciona un Supervisor…")}</option>
                            {reportedCollectorConfigs.map((item) => (
                              <option key={item.key} value={item.key}>
                                {String(item.agent.EffectiveConfigOrigin || "MANAGED").toUpperCase() === "BASE"
                                  ? "BASE · "
                                  : "ADMINISTRADA · "}
                                {item.agent.Service} · {item.name || "config.yaml"}
                              </option>
                            ))}
                          </select>
                        </label>
                        <button
                          type="button"
                          className="ghost"
                          disabled={!reportedConfigKey}
                          onClick={loadReportedCollectorConfig}
                        >
                          {t("Importar EffectiveConfig")}
                        </button>
                        {!reportedCollectorConfigs.length && (
                          <small>
                            {t("No hay un Supervisor conectado que reporte EffectiveConfig.")}
                          </small>
                        )}
                        <label className="local-config-loader">
                          {t("O cargar YAML desde este equipo")}
                          <input
                            type="file"
                            accept=".yaml,.yml,text/yaml,application/yaml,application/x-yaml"
                            onChange={loadCollectorFile}
                          />
                          <small>
                            {t("Se lee localmente en el navegador; no requiere un Supervisor conectado y no se publica hasta el paso final.")}
                          </small>
                        </label>
                      </div>
                    )}

                    <label>
                      {t("ID de configuración")}
                      <input
                        placeholder={
                          target === "collector"
                            ? "central-collector-config"
                            : "java-telemetry-policy"
                        }
                        value={configId}
                        onChange={(event) => setConfigId(event.target.value)}
                      />
                    </label>
                    <p className="hint">
                      {t("El ID agrupa el historial de versiones. Cargar o importar sólo abre el documento; todavía no lo publica.")}
                    </p>
                    {reservedCollectorBaseID && (
                      <p className="error">
                        {t("Este ID identifica un ConfigMap base inmutable. Usa un ID distinto para publicar una configuración administrada.")}
                      </p>
                    )}
                    <StepNavigation
                      activeStep={activeStep}
                      setActiveStep={setActiveStep}
                      nextDisabled={!configId.trim()}
                    />
                  </section>
                )}

                {activeStep === 2 && (
                  <section className="workflow-content">
                    <div className="panel-title">
                      <div>
                        <p className="eyebrow">{t("PASO 2 · EDICIÓN")}</p>
                        <h2>
                          {target === "java-extension"
                            ? t("Define capturas e instrumentos")
                            : t("Edita la configuración del Collector")}
                        </h2>
                      </div>
                    </div>

                    {target === "java-extension" ? (
                      <>
                        <div className="editor-mode">
                          <span>{t("Modo de edición")}</span>
                          <button
                            type="button"
                            className={editorMode === "form" ? "active" : ""}
                            onClick={() => switchEditorMode("form")}
                          >
                            {t("Formulario guiado")}
                          </button>
                          <button
                            type="button"
                            className={editorMode === "raw" ? "active" : ""}
                            onClick={() => switchEditorMode("raw")}
                          >
                            JSON
                          </button>
                        </div>

                        {editorMode === "raw" ? (
                          <label>
                            {t("Policy JSON completa")}
                            <textarea
                              className="code extra-large"
                              value={rawPolicyBody}
                              onChange={(event) => setRawPolicyBody(event.target.value)}
                            />
                            {!rawPolicyValid && (
                              <small className="error">{t("El JSON todavía no es válido.")}</small>
                            )}
                          </label>
                        ) : (
                          <>
                            <PolicyFlowNavigator
                              policy={policy}
                              editorFocus={editorFocus}
                              setEditorFocus={setEditorFocus}
                            />
                            {["http-incoming", "http-outgoing"].includes(editorFocus) && (
                              <BodyEventPoliciesEditor
                                policy={policy}
                                setPolicy={setPolicy}
                                nameErrors={nameErrors}
                                direction={telemetryDirectionForFocus(editorFocus)}
                                onEditLegacy={() => switchEditorMode("raw")}
                              />
                            )}
                            {editorFocus === "method" && (
                              <MethodPoliciesEditor
                                policy={policy}
                                setPolicy={setPolicy}
                                nameErrors={nameErrors}
                              />
                            )}
                            {["kafka", "jms"].includes(editorFocus) && (
                              <MessagingPoliciesEditor
                                policy={policy}
                                setPolicy={setPolicy}
                                nameErrors={nameErrors}
                                family={editorFocus}
                              />
                            )}
                          </>
                        )}
                      </>
                    ) : (
                      <>
                        <p className="hint">
                          {t("Edita el documento completo. La validación usa el mismo otelcol-contrib 0.156.0 y el backend vuelve a ejecutarla de forma obligatoria antes de guardar o enviar la versión.")}
                        </p>
                        <textarea
                          className="code extra-large"
                          value={collectorBody}
                          onChange={(event) => replaceCollectorBody(event.target.value)}
                        />
                        <div className="collector-validation-actions">
                          <button
                            type="button"
                            className="ghost"
                            disabled={collectorValidationBusy || !collectorBody.trim()}
                            onClick={validateCollectorBody}
                          >
                            {collectorValidationBusy
                              ? t("Validando…")
                              : t("Validar YAML con Collector")}
                          </button>
                          <small>
                            {t("No crea versiones, no envía cambios y no reinicia Collectors.")}
                          </small>
                        </div>
                        {collectorValidation && (
                          <div
                            className={
                              collectorValidation.valid
                                ? "safe collector-validation-result"
                                : "warning-box collector-validation-result"
                            }
                          >
                            <b>
                              {collectorValidation.valid
                                ? t("YAML válido")
                                : t("YAML rechazado")}
                            </b>
                            <span>
                              otelcol-contrib {collectorValidation.validatorVersion || ""}
                            </span>
                            {collectorValidation.output && (
                              <pre>{collectorValidation.output}</pre>
                            )}
                          </div>
                        )}
                      </>
                    )}

                    <StepNavigation
                      activeStep={activeStep}
                      setActiveStep={setActiveStep}
                      nextDisabled={!configurationReady}
                    />
                  </section>
                )}

                {activeStep === 3 && (
                  <section className="workflow-content">
                    <div className="panel-title">
                      <div>
                        <p className="eyebrow">{t("PASO 3 · DESTINOS")}</p>
                        <h2>{t("Comprueba quién recibirá esta versión")}</h2>
                      </div>
                    </div>
                    <TargetSelector
                      agents={targetAgents}
                      query={agentQuery}
                      setQuery={setAgentQuery}
                      selectedAgentIds={selectedAgentIds}
                      setSelectedAgentIds={setSelectedAgentIds}
                      selectedServices={selectedServices}
                      setSelectedServices={setSelectedServices}
                      selectorAttributes={selectorAttributes}
                      setSelectorAttributes={setSelectorAttributes}
                    />
                    {incompatibleSchemaTargets.length > 0 && (
                      <div className="warning-box" role="alert">
                        <b>{t("Destinos incompatibles con schema")} {policySchemaRequired}</b>
                        <span>
                          {incompatibleSchemaTargets.map((agent) =>
                            `${agent.Service} (${agent.UID})`).join(", ")}
                        </span>
                        <small>
                          {t("Actualiza la extensión o ajusta el selector. El backend no enviará esta policy a un agente que reporte un máximo menor.")}
                        </small>
                      </div>
                    )}
                    <StepNavigation
                      activeStep={activeStep}
                      setActiveStep={setActiveStep}
                      nextDisabled={
                        matchingTargetAgents.length === 0 || incompatibleSchemaTargets.length > 0
                      }
                    />
                  </section>
                )}

                {activeStep === 4 && (
                  <section className="workflow-content">
                    <div className="panel-title">
                      <div>
                        <p className="eyebrow">{t("PASO 4 · REVISIÓN")}</p>
                        <h2>{t("Valida el alcance y publica")}</h2>
                      </div>
                    </div>

                    <div className="review-summary">
                      <div>
                        <small>ID</small>
                        <b>{configId || t("Sin definir")}</b>
                      </div>
                      <div>
                        <small>{t("Tipo")}</small>
                        <b>{target === "collector" ? "Collector YAML" : "Java policy"}</b>
                      </div>
                      <div>
                        <small>{t("Destinos conectados coincidentes")}</small>
                        <b>{matchingTargetAgents.length} {t("de")} {targetAgents.length}</b>
                      </div>
                      <div>
                        <small>{t("Schema requerido")}</small>
                        <b>{target === "java-extension" ? policySchemaRequired : "—"}</b>
                      </div>
                      <div>
                        <small>{t("Selectores")}</small>
                        <b>
                          {selectedAgentIds.length + selectedServices.length +
                            Object.keys(selector.Attributes).length || t("Todos conectados")}
                        </b>
                      </div>
                    </div>

                    <div className="review-details">
                      <span>
                        <b>{t("Servicios")}:</b>{" "}
                        {selectedServices.length
                          ? selectedServices.join(", ")
                          : t("todos los conectados compatibles")}
                      </span>
                      <span>
                        <b>{t("Instancias exactas")}:</b>{" "}
                        {selectedAgentIds.length || t("sin restricción")}
                      </span>
                      <span>
                        <b>Resource attributes:</b>{" "}
                        {Object.entries(selector.Attributes).length
                          ? Object.entries(selector.Attributes)
                              .map(([key, value]) => `${key}=${value}`)
                              .join(", ")
                          : t("sin restricción")}
                      </span>
                    </div>

                    <button
                      type="button"
                      className="ghost review-back"
                      onClick={() => setActiveStep(3)}
                    >
                      {t("← Volver a destinos")}
                    </button>

                    <label className="publication-fields">
                      {t("Identidad auditada")}
                      <input value={actor} readOnly />
                    </label>
                    <button
                      className="primary publish-button"
                      disabled={
                        busy ||
                        !configurationReady ||
                        publicationBlockers.length > 0
                      }
                      onClick={publish}
                    >
                      {busy ? t("Publicando…") : t("Validar y enviar a destinos")}
                    </button>
                    {!busy && publicationBlockers.length > 0 && (
                      <div className="warning-box publication-blockers">
                        <b>{t("No se puede publicar todavía")}</b>
                        <ul>
                          {publicationBlockers.map((blocker) => (
                            <li key={blocker}>{t(blocker)}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </section>
                )}
              </section>

              {activeStep === 4 && (
                <section className="panel preview">
                  <p className="eyebrow">REMOTE CONFIG</p>
                  <h2>{t("Vista previa efectiva")}</h2>
                  <pre>{body}</pre>
                  {target === "java-extension" && denyViolations.length > 0 && (
                    <div className="warning-box">
                      <b>{t("Publicación bloqueada")}</b>
                      <span>
                        {t("El Control Plane rechazará")}: <code>{denyViolations
                          .map((violation) => `${violation.kind}:${violation.value}`)
                          .join(", ")}</code>
                      </span>
                    </div>
                  )}
                  <div className="safe">
                    <b>{t("Policy independiente, PolicySet atómico")}</b>
                    <span>
                      {t("Cada policy mantiene su historial. El agente recibe en una sola configuración efectiva todas las policies activas que coinciden con sus selectores.")}
                    </span>
                  </div>
                  <div className="safe">
                    <b>{t("Instrumentos inmutables")}</b>
                    <span>
                      {t("Después de crear un nombre no se puede cambiar tipo, unidad ni buckets. Para cambiar su identidad usa otro nombre.")}
                    </span>
                  </div>
                </section>
              )}
            </div>
          </>
        )}

        {tab === "agents" && (
          <AgentsView
            agents={agents}
            collectorBases={collectorBases}
            onReload={load}
          />
        )}

        {tab === "deployments" && (
          <DeploymentsView
            deployments={deployments}
            versions={currentVersions}
            collectorBases={collectorBases}
            busy={busy}
            onPolicyLifecycle={managePolicyLifecycle}
            onCollectorLifecycle={manageCollectorLifecycle}
            onReload={load}
          />
        )}

        {tab === "history" && (
          <HistoryView
            storage={storage}
            versions={currentVersions}
            agents={agents}
            collectorBases={collectorBases}
            deployments={deployments}
            auditEvents={auditEvents}
            actor={actor}
            setActor={setActor}
            busy={busy}
            onLoad={loadVersion}
            onPolicyLifecycle={managePolicyLifecycle}
            onCollectorLifecycle={manageCollectorLifecycle}
            onRestoreCollector={restoreCollectorVersion}
          />
        )}

        {tab === "profile" && (
          <ProfileView
            identity={authIdentity}
            onIdentityUpdated={setAuthIdentity}
          />
        )}

        {tab === "settings" && (
          <SettingsView
            identity={authIdentity}
            accessModel={accessModel}
            securityDenylist={securityDenylist}
            actor={actor}
            onReload={load}
          />
        )}
      </main>
    </div>
  );
}

createRoot(document.getElementById("root")).render(
  <I18nProvider>
    <App />
  </I18nProvider>,
);
