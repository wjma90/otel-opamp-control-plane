import { duplicateTelemetryEventNames } from "./messaging-events.js";

export const normalizeHeaderName = (value) =>
  String(value || "").trim().toLowerCase();

export const normalizeBodyPath = (value) =>
  String(value || "").trim().replace(/^\$\.?/, "");

const pathsOverlap = (captured, blocked) =>
  captured === blocked ||
  captured === "" ||
  blocked === "" ||
  captured.startsWith(`${blocked}.`) ||
  captured.startsWith(`${blocked}[`) ||
  blocked.startsWith(`${captured}.`) ||
  blocked.startsWith(`${captured}[`);

const array = (value) => Array.isArray(value) ? value : [];

export const policyCaptureDenyViolations = (policy = {}, entries = []) => {
  const denied = {
    HEADER: entries
      .filter((entry) => entry.Kind === "HEADER")
      .map((entry) => normalizeHeaderName(entry.Value)),
    BODY_PATH: entries
      .filter((entry) => entry.Kind === "BODY_PATH")
      .map((entry) => normalizeBodyPath(entry.Value)),
    QUERY_PARAM: entries
      .filter((entry) => entry.Kind === "QUERY_PARAM")
      .map((entry) => String(entry.Value || "").trim()),
    METHOD_PATH: entries
      .filter((entry) => entry.Kind === "METHOD_PATH")
      .map((entry) => String(entry.Value || "").trim()),
    PATH_PARAM: entries
      .filter((entry) => entry.Kind === "PATH_PARAM")
      .map((entry) => String(entry.Value || "").trim()),
    MESSAGE_PROPERTY: entries
      .filter((entry) => entry.Kind === "MESSAGE_PROPERTY")
      .map((entry) => String(entry.Value || "").trim()),
  };
  const violations = [];
  const add = (kind, value, owner) => {
    const canonical = kind === "HEADER"
      ? normalizeHeaderName(value)
      : kind === "BODY_PATH"
        ? normalizeBodyPath(value)
        : String(value || "").trim();
    if (!denied[kind].some((blocked) =>
      ["HEADER", "QUERY_PARAM", "PATH_PARAM", "MESSAGE_PROPERTY"].includes(kind)
        ? canonical === blocked
        : pathsOverlap(canonical, blocked))) {
      return;
    }
    violations.push({ kind, value: canonical || "<root>", owner });
  };

  for (const header of array(policy.requestHeaders)) {
    add("HEADER", header.name, "requestHeaders");
  }
  for (const header of array(policy.responseHeaders)) {
    add("HEADER", header.name, "responseHeaders");
  }
  for (const metric of array(policy.metricPolicies)) {
    if (metric.enabled === false) continue;
    for (const attribute of array(metric.customAttributes)) {
      add("HEADER", attribute.header, metric.id || metric.name || "httpMetric");
    }
  }

  for (const event of array(policy.bodyEventPolicies)) {
    if (event.enabled === false) continue;
    for (const condition of array(event.conditions)) {
      if (["REQUEST_BODY", "RESPONSE_BODY"].includes(condition.source)) {
        add("BODY_PATH", condition.path, event.id || event.eventName || "bodyEvent");
      } else if (["REQUEST_HEADER", "RESPONSE_HEADER"].includes(condition.source)) {
        add("HEADER", condition.path, event.id || event.eventName || "httpEvent");
      } else if (condition.source === "REQUEST_QUERY") {
        add("QUERY_PARAM", condition.path, event.id || event.eventName || "httpEvent");
      } else if (condition.source === "REQUEST_PATH_PARAM") {
        add("PATH_PARAM", condition.path, event.id || event.eventName || "httpEvent");
      }
    }
    for (const field of array(event.fields)) {
      if (["REQUEST_BODY", "RESPONSE_BODY"].includes(field.source)) {
        add("BODY_PATH", field.path, event.id || event.eventName || "httpEvent");
      } else if (["REQUEST_HEADER", "RESPONSE_HEADER"].includes(field.source)) {
        add("HEADER", field.path, event.id || event.eventName || "httpEvent");
      } else if (field.source === "REQUEST_QUERY") {
        add("QUERY_PARAM", field.path, event.id || event.eventName || "httpEvent");
      } else if (field.source === "REQUEST_PATH_PARAM") {
        add("PATH_PARAM", field.path, event.id || event.eventName || "httpEvent");
      }
    }
  }

  for (const event of array(policy.messagingEventPolicies)) {
    if (event.enabled === false) continue;
    for (const selector of [...array(event.conditions), ...array(event.fields)]) {
      const owner = event.id || event.eventName || "messagingEvent";
      if (selector.source === "MESSAGE_HEADER") {
        add("HEADER", selector.path, owner);
      } else if (selector.source === "MESSAGE_PROPERTY") {
        add("MESSAGE_PROPERTY", selector.path, owner);
      } else if (selector.source === "PAYLOAD") {
        add("BODY_PATH", selector.path, owner);
      }
    }
  }

  for (const method of array(policy.methodPolicies)) {
    if (method.enabled === false) continue;
    for (const capture of array(method.captures)) {
      if (["ARGUMENT", "RETURN"].includes(capture.source)) {
        add("METHOD_PATH", capture.path, method.id || method.methodName || "method");
      }
    }
    for (const metric of array(method.metrics)) {
      if (["ARGUMENT", "RETURN"].includes(metric.value?.source)) {
        add("METHOD_PATH", metric.value?.path, method.id || method.methodName || "method");
      }
    }
  }

  return violations.filter((violation, index, values) =>
    values.findIndex((candidate) =>
      candidate.kind === violation.kind &&
      candidate.value === violation.value &&
      candidate.owner === violation.owner) === index);
};

const has = (value, field) =>
  value !== null && typeof value === "object" &&
  Object.prototype.hasOwnProperty.call(value, field);

const valueSourceContractErrors = (value, owner) => {
  if (value === null || typeof value !== "object") return [];
  if (value.source === "ARGUMENT" && !has(value, "argumentIndex")) {
    return [`${owner} requiere argumentIndex explícito para source=ARGUMENT.`];
  }
  if (value.source === "CONSTANT" && !has(value, "constant")) {
    return [`${owner} requiere constant explícito para source=CONSTANT.`];
  }
  return [];
};

export const httpEventHasOutput = (policy = {}, event = {}) => {
  if (event === null || typeof event !== "object" || Array.isArray(event)) return false;
  if (event.enabled === false) return true;
  if (event.log?.enabled) return true;
  const attributes = [
    ...array(event.staticAttributes),
    ...array(event.fields),
    ...array(event.derivedFields),
  ];
  if (attributes.some((attribute) => array(attribute?.destinations).includes("SPAN"))) {
    return true;
  }
  const eventName = String(event.eventName || "");
  return Boolean(eventName) && array(policy.eventMetricPolicies).some(
    (metric) => metric?.enabled === true && metric?.eventName === eventName,
  );
};

export const messagingEventHasOutput = (policy = {}, event = {}) => {
  if (event === null || typeof event !== "object" || Array.isArray(event)) return false;
  if (event.enabled === false) return true;
  if (event.log?.enabled) return true;
  const attributes = [...array(event.staticAttributes), ...array(event.fields)];
  if (attributes.some((attribute) => array(attribute?.destinations).includes("SPAN"))) {
    return true;
  }
  const eventName = String(event.eventName || "");
  return Boolean(eventName) && array(policy.messagingMetricPolicies).some(
    (metric) => metric?.enabled === true && metric?.eventName === eventName,
  );
};

export const policyWireContractErrors = (policy) => {
  if (policy === null || typeof policy !== "object" || Array.isArray(policy)) {
    return ["La policy debe ser un objeto JSON."];
  }
  const errors = [];
  const policyCollections = [
    "metricPolicies",
    "methodPolicies",
    "bodyEventPolicies",
    "eventMetricPolicies",
    "messagingEventPolicies",
    "messagingMetricPolicies",
  ];
  for (const collection of policyCollections) {
    if (policy[collection] !== undefined && !Array.isArray(policy[collection])) {
      errors.push(`${collection} debe ser un arreglo.`);
      continue;
    }
    for (const [index, item] of array(policy[collection]).entries()) {
      if (!has(item, "enabled") || typeof item.enabled !== "boolean") {
        errors.push(`${collection}[${index}] requiere enabled boolean explícito.`);
      }
    }
  }

  for (const [index, metric] of array(policy.metricPolicies).entries()) {
    errors.push(...valueSourceContractErrors(metric?.value, `metricPolicies[${index}].value`));
  }
  for (const [methodIndex, method] of array(policy.methodPolicies).entries()) {
    for (const [captureIndex, capture] of array(method?.captures).entries()) {
      errors.push(...valueSourceContractErrors(
        capture,
        `methodPolicies[${methodIndex}].captures[${captureIndex}]`,
      ));
    }
    for (const [metricIndex, metric] of array(method?.metrics).entries()) {
      errors.push(...valueSourceContractErrors(
        metric?.value,
        `methodPolicies[${methodIndex}].metrics[${metricIndex}].value`,
      ));
    }
  }
  for (const eventName of duplicateTelemetryEventNames(policy)) {
    errors.push(
      `eventName debe ser único entre bodyEventPolicies y messagingEventPolicies; duplicado: ${eventName}.`,
    );
  }
  for (const [eventIndex, event] of array(policy.bodyEventPolicies).entries()) {
    if (!httpEventHasOutput(policy, event)) {
      errors.push(
        `bodyEventPolicies[${eventIndex}] no tiene una salida efectiva: `
        + "añade un atributo al span, habilita el log o crea una métrica para el evento.",
      );
    }
  }
  for (const [eventIndex, event] of array(policy.messagingEventPolicies).entries()) {
    if (!messagingEventHasOutput(policy, event)) {
      errors.push(
        `messagingEventPolicies[${eventIndex}] no tiene una salida efectiva: `
        + "añade un atributo al span, habilita el log o crea una métrica para el evento.",
      );
    }
  }
  return errors;
};
