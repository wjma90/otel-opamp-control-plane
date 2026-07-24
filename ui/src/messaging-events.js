import {
  configureEventMetricIntent,
  eventMetricIntent,
  eventNameOutput,
  withEventNameOutput,
} from "./telemetry-events.js";

const array = (value) => Array.isArray(value) ? value : [];

export const messagingScopeOptions = {
  kafka: [
    { id: "KAFKA_PRODUCER", label: "Kafka producer" },
    { id: "KAFKA_CONSUMER", label: "Kafka consumer" },
  ],
  jms: [
    { id: "JMS_PRODUCER", label: "JMS producer" },
    { id: "JMS_CONSUMER", label: "JMS consumer" },
  ],
};

export const messagingSourceOptions = [
  { id: "DESTINATION", label: "Destino (topic o queue)" },
  { id: "MESSAGE_KEY", label: "Message key" },
  { id: "MESSAGE_HEADER", label: "Message header" },
  { id: "MESSAGE_PROPERTY", label: "JMS property", jmsOnly: true },
  { id: "PAYLOAD", label: "Payload JSON" },
];

export const messagingSourcesForFamily = (family) =>
  messagingSourceOptions.filter((source) => family === "jms" || !source.jmsOnly);

const selectorMetadata = {
  DESTINATION: { label: "No aplica", placeholder: "No aplica", disabled: true },
  MESSAGE_KEY: { label: "No aplica", placeholder: "No aplica", disabled: true },
  MESSAGE_HEADER: { label: "Nombre del message header", placeholder: "event.type" },
  MESSAGE_PROPERTY: { label: "Nombre de la propiedad JMS", placeholder: "eventType" },
  PAYLOAD: { label: "Ruta JSON del payload", placeholder: "customer.segment" },
};

export const messagingSourceSelector = (source) =>
  selectorMetadata[source] || selectorMetadata.DESTINATION;

export const normalizeMessagingEventPolicy = (eventPolicy = {}) => ({
  ...eventPolicy,
  scope: String(eventPolicy.scope || "KAFKA_PRODUCER").trim().toUpperCase(),
  conditions: array(eventPolicy.conditions),
  staticAttributes: array(eventPolicy.staticAttributes),
  fields: array(eventPolicy.fields),
  log: {
    enabled: false,
    severity: "INFO",
    body: "Messaging rule matched",
    ...(eventPolicy.log || {}),
  },
});

export const normalizeMessagingMetric = (metric = {}) => ({
  ...metric,
  dimensions: array(metric.dimensions),
  buckets: array(metric.buckets),
});

export const messagingFamilyForScope = (scope) =>
  String(scope || "").startsWith("JMS_") ? "jms" : "kafka";

export const fieldsForMessagingEvent = (policy = {}, eventName) => {
  const candidates = array(policy.messagingEventPolicies).filter(
    (eventPolicy) => eventPolicy?.enabled && eventPolicy.eventName === eventName,
  );
  return candidates.length === 1 ? array(candidates[0].fields) : [];
};

export const duplicateTelemetryEventNames = (policy = {}) => {
  const seen = new Set();
  const duplicates = new Set();
  for (const eventPolicy of [
    ...array(policy.bodyEventPolicies),
    ...array(policy.messagingEventPolicies),
  ]) {
    const eventName = String(eventPolicy?.eventName || "");
    if (!eventName) continue;
    if (seen.has(eventName)) duplicates.add(eventName);
    seen.add(eventName);
  }
  return [...duplicates];
};

export const nextMessagingEventName = (policy = {}, base = "messaging-event") => {
  const used = new Set([
    ...array(policy.bodyEventPolicies),
    ...array(policy.messagingEventPolicies),
  ].map((eventPolicy) => String(eventPolicy?.eventName || "")));
  if (!used.has(base)) return base;
  let suffix = 2;
  while (used.has(`${base}-${suffix}`)) suffix += 1;
  return `${base}-${suffix}`;
};

export const removeMessagingEventAt = (policy, eventIndex) => {
  const target = policy.messagingEventPolicies?.[eventIndex];
  if (!target) return policy;
  const messagingEventPolicies = policy.messagingEventPolicies.filter(
    (_, index) => index !== eventIndex,
  );
  const eventNameStillDeclared = messagingEventPolicies.some(
    (eventPolicy) => eventPolicy.eventName === target.eventName,
  );
  return {
    ...policy,
    messagingEventPolicies,
    messagingMetricPolicies: eventNameStillDeclared
      ? policy.messagingMetricPolicies
      : array(policy.messagingMetricPolicies).filter(
        (metric) => metric.eventName !== target.eventName,
      ),
  };
};

export const renameMessagingEventAt = (policy, eventIndex, eventName) => {
  const target = policy.messagingEventPolicies?.[eventIndex];
  if (!target) return policy;
  const previous = target.eventName;
  const previousOwners = policy.messagingEventPolicies.filter(
    (eventPolicy) => eventPolicy.eventName === previous,
  ).length;
  return {
    ...policy,
    messagingEventPolicies: policy.messagingEventPolicies.map((eventPolicy, index) =>
      index === eventIndex ? { ...eventPolicy, eventName } : eventPolicy,
    ),
    messagingMetricPolicies: array(policy.messagingMetricPolicies).map((metric) =>
      metric.eventName === previous && previousOwners === 1
        ? { ...metric, eventName }
        : metric,
    ),
  };
};

export {
  configureEventMetricIntent,
  eventMetricIntent,
  eventNameOutput,
  withEventNameOutput,
};
