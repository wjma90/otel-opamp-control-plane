export const telemetryEventCategories = [
  {
    id: "http-incoming",
    direction: "INCOMING",
    title: "HTTP entrante",
    description: "Request y response del servidor: headers, query, JSON, spans, logs y métricas.",
  },
  {
    id: "method",
    direction: null,
    title: "Método Java",
    description: "Argumentos y retorno disponibles dentro de una misma invocación.",
  },
  {
    id: "http-outgoing",
    direction: "OUTGOING",
    title: "HTTP saliente",
    description: "Request y response de clientes HTTP soportados por la extensión.",
  },
  {
    id: "kafka",
    direction: null,
    title: "Kafka",
    description: "Producer o consumer: topic, key, headers y payload JSON.",
  },
  {
    id: "jms",
    direction: null,
    title: "JMS",
    description: "Producer o consumer: queue/topic, properties y payload JSON.",
  },
];

export const normalizeTelemetryEditorFocus = (value) => {
  if (["method", "http-outgoing", "kafka", "jms"].includes(value)) return value;
  // Borradores previos usaban `http` y `business-event` como tabs separados.
  return "http-incoming";
};

export const telemetryDirectionForFocus = (focus) =>
  focus === "http-outgoing" ? "OUTGOING" : "INCOMING";

const normalizeHTTPDirection = (direction) =>
  String(direction || "INCOMING").trim().toUpperCase() || "INCOMING";

export const legacyHTTPConfigurationCount = (policy = {}, direction = "INCOMING") => {
  const expectedDirection = normalizeHTTPDirection(direction);
  const headers = [
    ...(Array.isArray(policy.requestHeaders) ? policy.requestHeaders : []),
    ...(Array.isArray(policy.responseHeaders) ? policy.responseHeaders : []),
  ];
  const metrics = Array.isArray(policy.metricPolicies) ? policy.metricPolicies : [];
  return [...headers, ...metrics].filter(
    (item) => normalizeHTTPDirection(item?.direction) === expectedDirection,
  ).length;
};

export const legacyHTTPHeaderCount = (policy = {}, direction = "INCOMING") => {
  const expectedDirection = normalizeHTTPDirection(direction);
  return [
    ...(Array.isArray(policy.requestHeaders) ? policy.requestHeaders : []),
    ...(Array.isArray(policy.responseHeaders) ? policy.responseHeaders : []),
  ].filter(
    (item) => normalizeHTTPDirection(item?.direction) === expectedDirection,
  ).length;
};

export const createHTTPDurationMetricPolicy = (
  direction = "INCOMING",
  id = `http-metric-${Date.now()}`,
) => ({
  id,
  enabled: true,
  direction: normalizeHTTPDirection(direction),
  value: {
    source: "DURATION",
    argumentIndex: -1,
    path: "",
    constant: 1,
  },
  name: "",
  instrument: "HISTOGRAM",
  unit: "s",
  description: "Duración de los intercambios HTTP",
  standardAttributes: [],
  customAttributes: [],
  buckets: [
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
  ],
});

export const normalizeHTTPMetricPolicy = (metric = {}) => ({
  ...metric,
  direction: normalizeHTTPDirection(metric.direction),
  value: {
    source: "DURATION",
    argumentIndex: -1,
    path: "",
    constant: 1,
    ...(metric.value || {}),
  },
  standardAttributes: Array.isArray(metric.standardAttributes)
    ? metric.standardAttributes
    : [],
  customAttributes: (Array.isArray(metric.customAttributes)
    ? metric.customAttributes
    : []).map((attribute) => ({
    source: "REQUEST_HEADER",
    argumentIndex: -1,
    path: "",
    constant: 1,
    header: "",
    attribute: "",
    destinations: [],
    ...attribute,
    valuePolicy: {
      type: "ENUM",
      allowed: ["VALUE_A", "VALUE_B"],
      fallback: "OTHER",
      ranges: [],
      ...(attribute?.valuePolicy || {}),
    },
  })),
  buckets: Array.isArray(metric.buckets) ? metric.buckets : [],
});

export const httpEventUsesBody = (eventPolicy = {}) =>
  [...(eventPolicy.conditions || []), ...(eventPolicy.fields || [])].some(
    (item) => item?.source === "REQUEST_BODY" || item?.source === "RESPONSE_BODY",
  );

export const eventMetricIntent = (eventMetric = {}) => {
  if (eventMetric.instrument === "HISTOGRAM") return "DISTRIBUTION";
  return eventMetric.valueField ? "TOTAL" : "COUNT";
};

export const configureEventMetricIntent = (
  eventMetric,
  intent,
  defaultNumericField = "",
) => {
  if (intent === "COUNT") {
    return {
      ...eventMetric,
      instrument: "COUNTER",
      valueField: "",
      buckets: [],
    };
  }
  if (intent === "TOTAL") {
    return {
      ...eventMetric,
      instrument: "COUNTER",
      valueField: eventMetric.valueField || defaultNumericField,
      buckets: [],
    };
  }
  if (intent === "DISTRIBUTION") {
    return {
      ...eventMetric,
      instrument: "HISTOGRAM",
      valueField: eventMetric.valueField || defaultNumericField,
      buckets: eventMetric.buckets?.length
        ? eventMetric.buckets
        : [100, 500, 1000, 3000, 10000],
    };
  }
  return eventMetric;
};

export const eventNameOutput = (eventPolicy = {}) => {
  const attribute = (eventPolicy.staticAttributes || []).find(
    (item) => item?.attribute === "event.name",
  );
  return {
    value: String(attribute?.value || ""),
    destinations: (attribute?.destinations || []).filter(
      (destination) => destination === "SPAN" || destination === "LOG",
    ),
  };
};

export const withEventNameOutput = (eventPolicy = {}, value = "", destinations = []) => {
  const normalizedValue = String(value);
  const normalizedDestinations = destinations.filter(
    (destination) => destination === "SPAN" || destination === "LOG",
  );
  let replaced = false;
  const staticAttributes = [];
  for (const attribute of eventPolicy.staticAttributes || []) {
    if (attribute?.attribute !== "event.name") {
      staticAttributes.push(attribute);
      continue;
    }
    if (normalizedValue && !replaced) {
      staticAttributes.push({
        ...attribute,
        attribute: "event.name",
        value: normalizedValue,
        type: "STRING",
        destinations: normalizedDestinations,
      });
      replaced = true;
    }
  }
  if (normalizedValue && !replaced) {
    staticAttributes.push({
      attribute: "event.name",
      value: normalizedValue,
      type: "STRING",
      destinations: normalizedDestinations,
    });
  }
  return { ...eventPolicy, staticAttributes };
};

export const normalizeHTTPEventPolicy = (eventPolicy = {}) => {
  const normalized = {
    ...eventPolicy,
    direction: normalizeHTTPDirection(eventPolicy.direction),
    conditions: Array.isArray(eventPolicy.conditions) ? eventPolicy.conditions : [],
    staticAttributes: Array.isArray(eventPolicy.staticAttributes)
      ? eventPolicy.staticAttributes
      : [],
    fields: Array.isArray(eventPolicy.fields) ? eventPolicy.fields : [],
    derivedFields: Array.isArray(eventPolicy.derivedFields) ? eventPolicy.derivedFields : [],
    log: {
      enabled: false,
      severity: "INFO",
      body: "HTTP rule matched",
      ...(eventPolicy.log || {}),
    },
  };
  const output = eventNameOutput(normalized);
  return withEventNameOutput(normalized, output.value, output.destinations);
};

export const normalizeHTTPEventMetric = (eventMetric = {}) => ({
  ...eventMetric,
  dimensions: Array.isArray(eventMetric.dimensions) ? eventMetric.dimensions : [],
  standardAttributes: Array.isArray(eventMetric.standardAttributes)
    ? eventMetric.standardAttributes
    : [],
  buckets: Array.isArray(eventMetric.buckets) ? eventMetric.buckets : [],
});

export const httpEventMetricStandardAttributes = (direction = "INCOMING") => [
  {
    name: "http.request.method",
    help: "Método HTTP conocido.",
  },
  ...(
    direction === "INCOMING"
      ? [{
        name: "http.route",
        help: "Plantilla de ruta coincidente; nunca se sustituye por la URL concreta.",
      }]
      : []
  ),
  {
    name: "http.response.status_code",
    help: "Código de respuesta cuando la operación produjo uno.",
  },
  {
    name: "error.type",
    help: "Se omite en operaciones exitosas. En errores contiene el código HTTP, timeout o la clase de excepción.",
  },
];

export const httpMetricStandardAttributes = (direction = "INCOMING") => [
  ...httpEventMetricStandardAttributes(direction),
  {
    name: "url.scheme",
    help: "Esquema HTTP o HTTPS conocido por la instrumentación.",
  },
  {
    name: "network.protocol.name",
    help: "Nombre estable del protocolo cuando está disponible.",
  },
  {
    name: "network.protocol.version",
    help: "Versión del protocolo cuando está disponible.",
  },
];

export const duplicateHTTPEventNames = (policy = {}) => {
  const seen = new Set();
  const duplicates = new Set();
  for (const eventPolicy of Array.isArray(policy.bodyEventPolicies)
    ? policy.bodyEventPolicies
    : []) {
    const eventName = String(eventPolicy?.eventName || "");
    if (!eventName) continue;
    if (seen.has(eventName)) duplicates.add(eventName);
    seen.add(eventName);
  }
  return [...duplicates];
};

export const nextHTTPEventName = (events = [], base = "http-event") => {
  const used = new Set(events.map((eventPolicy) => String(eventPolicy?.eventName || "")));
  if (!used.has(base)) return base;
  let suffix = 2;
  while (used.has(`${base}-${suffix}`)) suffix += 1;
  return `${base}-${suffix}`;
};

export const fieldsForHTTPEvent = (policy = {}, eventName, direction) => {
  const candidates = (Array.isArray(policy.bodyEventPolicies)
    ? policy.bodyEventPolicies
    : []).filter(
    (eventPolicy) =>
      eventPolicy?.enabled &&
      String(eventPolicy.direction || "INCOMING").toUpperCase() === direction &&
      eventPolicy.eventName === eventName,
  );
  if (candidates.length !== 1) return [];
  return [
    ...(candidates[0].fields || []),
    ...(candidates[0].derivedFields || []),
  ];
};

export const removeHTTPEventAt = (policy, eventIndex) => {
  const target = policy.bodyEventPolicies?.[eventIndex];
  if (!target) return policy;
  const bodyEventPolicies = policy.bodyEventPolicies.filter(
    (_, index) => index !== eventIndex,
  );
  const eventNameStillDeclared = bodyEventPolicies.some(
    (eventPolicy) => eventPolicy.eventName === target.eventName,
  );
  return {
    ...policy,
    bodyEventPolicies,
    eventMetricPolicies: eventNameStillDeclared
      ? policy.eventMetricPolicies
      : (policy.eventMetricPolicies || []).filter(
        (eventMetric) => eventMetric.eventName !== target.eventName,
      ),
  };
};

export const renameHTTPEventAt = (policy, eventIndex, eventName) => {
  const target = policy.bodyEventPolicies?.[eventIndex];
  if (!target) return policy;
  const previous = target.eventName;
  const previousOwners = policy.bodyEventPolicies.filter(
    (eventPolicy) => eventPolicy.eventName === previous,
  ).length;
  return {
    ...policy,
    bodyEventPolicies: policy.bodyEventPolicies.map((eventPolicy, index) =>
      index === eventIndex ? { ...eventPolicy, eventName } : eventPolicy,
    ),
    eventMetricPolicies: (policy.eventMetricPolicies || []).map((eventMetric) =>
      eventMetric.eventName === previous && previousOwners === 1
        ? { ...eventMetric, eventName }
        : eventMetric,
    ),
  };
};

export const httpEventSourceOptions = [
  { id: "REQUEST_HEADER", label: "Request header" },
  { id: "REQUEST_QUERY", label: "Request query param" },
  { id: "REQUEST_PATH_PARAM", label: "Request path param" },
  { id: "REQUEST_BODY", label: "Request body JSON" },
  { id: "RESPONSE_HEADER", label: "Response header" },
  { id: "RESPONSE_BODY", label: "Response body JSON" },
];

export const httpConditionSourceOptions = [
  { id: "REQUEST_PATH", label: "Request path" },
  { id: "REQUEST_METHOD", label: "HTTP method" },
  ...httpEventSourceOptions.slice(0, 4),
  { id: "RESPONSE_STATUS", label: "Response status" },
  ...httpEventSourceOptions.slice(4),
];

const sourceSelectorMetadata = {
  REQUEST_HEADER: {
    label: "Nombre del request header",
    placeholder: "x-client-type",
  },
  RESPONSE_HEADER: {
    label: "Nombre del response header",
    placeholder: "x-rate-type",
  },
  REQUEST_QUERY: {
    label: "Nombre del query param",
    placeholder: "campaign_id",
  },
  REQUEST_PATH_PARAM: {
    label: "Nombre lógico del path param",
    placeholder: "accountId",
  },
  REQUEST_BODY: {
    label: "Ruta JSON del request body",
    placeholder: "customer.segment",
  },
  RESPONSE_BODY: {
    label: "Ruta JSON del response body",
    placeholder: "status",
  },
};

export const httpSourceSelector = (source) =>
  sourceSelectorMetadata[source] || {
    label: "No aplica",
    placeholder: "No aplica",
    disabled: true,
  };

export const httpEventUsesExtendedSources = (policy = {}) =>
  (policy.bodyEventPolicies || []).some((eventPolicy) =>
    [...(eventPolicy.conditions || []), ...(eventPolicy.fields || [])].some((item) =>
      ["REQUEST_HEADER", "RESPONSE_HEADER", "REQUEST_QUERY"].includes(item.source),
    ),
  );

export const httpEventUsesPathParameters = (policy = {}) =>
  (policy.bodyEventPolicies || []).some((eventPolicy) =>
    [...(eventPolicy.conditions || []), ...(eventPolicy.fields || [])].some((item) =>
      item.source === "REQUEST_PATH_PARAM"
      || (
        item.source === "REQUEST_PATH"
        && (item.values || []).some((value) =>
          /\{[A-Za-z_][A-Za-z0-9_.-]{0,127}\}/.test(value),
        )
      )),
  );

export const policyUsesPassthroughValuePolicy = (policy = {}) => {
  const valuePolicies = [
    ...(policy.metricPolicies || []).flatMap((metric) =>
      (metric.customAttributes || []).map((attribute) => attribute.valuePolicy),
    ),
    ...(policy.methodPolicies || []).flatMap((method) =>
      (method.captures || []).map((capture) => capture.valuePolicy),
    ),
    ...(policy.bodyEventPolicies || []).flatMap((eventPolicy) => [
      ...(eventPolicy.fields || []).map((field) => field.valuePolicy),
      ...(eventPolicy.derivedFields || []).map((field) => field.valuePolicy),
    ]),
    ...(policy.messagingEventPolicies || []).flatMap((eventPolicy) =>
      (eventPolicy.fields || []).map((field) => field.valuePolicy),
    ),
  ];
  return valuePolicies.some((valuePolicy) => valuePolicy?.type === "PASSTHROUGH");
};

export const requiredPolicySchema = (policy = {}) =>
  policyUsesPassthroughValuePolicy(policy)
    ? "1.7"
    : (policy.eventMetricPolicies || []).some(
    (metric) => (metric.standardAttributes || []).length > 0,
  )
    ? "1.6"
    : httpEventUsesPathParameters(policy)
    || (policy.messagingEventPolicies || []).length
    || (policy.messagingMetricPolicies || []).length
    ? "1.5"
    : httpEventUsesExtendedSources(policy)
      ? "1.4"
      : String(policy.schemaVersion || "1.3");

export const policySchemaRank = (value) => {
  const match = String(value || "").trim().match(/^(\d+)\.(\d+)$/);
  if (!match) return -1;
  return Number(match[1]) * 1_000 + Number(match[2]);
};

export const ensurePolicySchema = (current, required) =>
  policySchemaRank(current) >= policySchemaRank(required) ? current : required;

export const agentSupportsPolicySchema = (agent = {}, required = "1.3") => {
  const advertisedEntry = Object.entries(agent.Attributes || {}).find(
    ([key]) => String(key).trim().toLowerCase() === "o11y.policy.schema",
  );
  const advertised = String(advertisedEntry?.[1] || "").trim();
  const requiredRank = policySchemaRank(required);
  if (requiredRank < 0) return false;
  if (requiredRank <= policySchemaRank("1.3")) return true;
  return policySchemaRank(advertised) >= requiredRank;
};
