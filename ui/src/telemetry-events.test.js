import test from "node:test";
import assert from "node:assert/strict";

import {
  agentSupportsPolicySchema,
  configureEventMetricIntent,
  createHTTPDurationMetricPolicy,
  duplicateHTTPEventNames,
  ensurePolicySchema,
  eventMetricIntent,
  eventNameOutput,
  fieldsForHTTPEvent,
  httpConditionSourceOptions,
  httpEventSourceOptions,
  httpEventUsesBody,
  httpEventMetricStandardAttributes,
  httpMetricStandardAttributes,
  httpSourceSelector,
  legacyHTTPConfigurationCount,
  legacyHTTPHeaderCount,
  normalizeTelemetryEditorFocus,
  nextHTTPEventName,
  normalizeHTTPEventMetric,
  normalizeHTTPEventPolicy,
  normalizeHTTPMetricPolicy,
  policyUsesPassthroughValuePolicy,
  policySchemaRank,
  removeHTTPEventAt,
  renameHTTPEventAt,
  requiredPolicySchema,
  telemetryEventCategories,
  withEventNameOutput,
} from "./telemetry-events.js";

test("resume configuración HTTP heredada sin mezclar direcciones", () => {
  const policy = {
    requestHeaders: [
      { name: "x-in", direction: "INCOMING" },
      { name: "x-out", direction: "OUTGOING" },
    ],
    responseHeaders: [{ name: "x-default" }],
    metricPolicies: [{ name: "legacy.metric", direction: "OUTGOING" }],
  };

  assert.equal(legacyHTTPConfigurationCount(policy, "INCOMING"), 2);
  assert.equal(legacyHTTPConfigurationCount(policy, "OUTGOING"), 2);
  assert.equal(legacyHTTPHeaderCount(policy, "INCOMING"), 2);
  assert.equal(legacyHTTPHeaderCount(policy, "OUTGOING"), 1);
});

test("crea una métrica de duración para todos los intercambios sin condiciones", () => {
  const metric = createHTTPDurationMetricPolicy("INCOMING", "http-duration-1");

  assert.equal(metric.id, "http-duration-1");
  assert.equal(metric.direction, "INCOMING");
  assert.equal(metric.value.source, "DURATION");
  assert.equal(metric.instrument, "HISTOGRAM");
  assert.equal(metric.unit, "s");
  assert.ok(metric.buckets.length > 0);
  assert.equal(Object.hasOwn(metric, "conditions"), false);
  assert.ok(
    httpMetricStandardAttributes("INCOMING")
      .some(({ name }) => name === "http.route"),
  );
  assert.equal(
    httpMetricStandardAttributes("OUTGOING")
      .some(({ name }) => name === "http.route"),
    false,
  );

  assert.deepEqual(normalizeHTTPMetricPolicy({
    direction: "outgoing",
    value: null,
    standardAttributes: null,
    customAttributes: [{
      header: "x-customer-type",
      attribute: "customer.type",
      valuePolicy: null,
    }],
    buckets: null,
  }), {
    direction: "OUTGOING",
    value: {
      source: "DURATION",
      argumentIndex: -1,
      path: "",
      constant: 1,
    },
    standardAttributes: [],
    customAttributes: [{
      source: "REQUEST_HEADER",
      argumentIndex: -1,
      path: "",
      constant: 1,
      header: "x-customer-type",
      attribute: "customer.type",
      destinations: [],
      valuePolicy: {
        type: "ENUM",
        allowed: ["VALUE_A", "VALUE_B"],
        fallback: "OTHER",
        ranges: [],
      },
    }],
    buckets: [],
  });
});

test("describe error.type como un atributo ausente en éxitos y causal en errores", () => {
  const errorType = httpEventMetricStandardAttributes("INCOMING")
    .find(({ name }) => name === "error.type");

  assert.match(errorType.help, /Se omite en operaciones exitosas/);
  assert.match(errorType.help, /código HTTP, timeout o la clase de excepción/);
});

test("presenta las métricas de evento por intención sin cambiar el contrato wire", () => {
  const count = { instrument: "COUNTER", valueField: "", buckets: [1] };
  assert.equal(eventMetricIntent(count), "COUNT");
  assert.deepEqual(configureEventMetricIntent(count, "COUNT"), {
    instrument: "COUNTER",
    valueField: "",
    buckets: [],
  });

  const total = configureEventMetricIntent(count, "TOTAL", "transaction.amount");
  assert.equal(eventMetricIntent(total), "TOTAL");
  assert.equal(total.instrument, "COUNTER");
  assert.equal(total.valueField, "transaction.amount");

  const distribution = configureEventMetricIntent(total, "DISTRIBUTION");
  assert.equal(eventMetricIntent(distribution), "DISTRIBUTION");
  assert.equal(distribution.instrument, "HISTOGRAM");
  assert.deepEqual(distribution.buckets, [100, 500, 1000, 3000, 10000]);
});

test("muestra opciones de body sólo cuando una condición o campo las necesita", () => {
  assert.equal(httpEventUsesBody({ conditions: [], fields: [] }), false);
  assert.equal(httpEventUsesBody({
    conditions: [{ source: "REQUEST_METHOD" }],
    fields: [{ source: "RESPONSE_BODY" }],
  }), true);
});

test("edita event.name explícito sin tocar otros atributos estáticos", () => {
  const policy = {
    staticAttributes: [
      { attribute: "custom.keep", value: "yes", type: "STRING", destinations: ["LOG"] },
      { attribute: "event.name", value: "old", type: "LONG", destinations: ["SPAN"] },
      { attribute: "event.name", value: "duplicate", type: "STRING", destinations: ["LOG"] },
    ],
  };

  const updated = withEventNameOutput(policy, "exchange.approved", ["SPAN", "LOG", "METRIC"]);
  assert.deepEqual(eventNameOutput(updated), {
    value: "exchange.approved",
    destinations: ["SPAN", "LOG"],
  });
  assert.equal(updated.staticAttributes[0], policy.staticAttributes[0]);
  assert.equal(updated.staticAttributes.filter((item) => item.attribute === "event.name").length, 1);
  assert.equal(updated.staticAttributes[1].type, "STRING");

  const removed = withEventNameOutput(updated, "", ["SPAN"]);
  assert.equal(eventNameOutput(removed).value, "");
  assert.deepEqual(removed.staticAttributes, [policy.staticAttributes[0]]);
});

test("normaliza reglas y métricas HTTP parciales para editar sin perder campos", () => {
  assert.deepEqual(normalizeHTTPEventPolicy({
    id: "rule-1",
    direction: "outgoing",
    conditions: null,
    staticAttributes: null,
    fields: null,
    derivedFields: null,
  }), {
    id: "rule-1",
    direction: "OUTGOING",
    conditions: [],
    staticAttributes: [],
    fields: [],
    derivedFields: [],
    log: { enabled: false, severity: "INFO", body: "HTTP rule matched" },
  });
  assert.deepEqual(normalizeHTTPEventMetric({ id: "metric-1", dimensions: null }), {
    id: "metric-1",
    dimensions: [],
    standardAttributes: [],
    buckets: [],
  });
  assert.deepEqual(normalizeHTTPEventPolicy({
    staticAttributes: [{
      attribute: "event.name",
      value: "",
      type: "STRING",
      destinations: ["SPAN"],
    }],
  }).staticAttributes, []);
});

test("expone una macro de eventos con HTTP, método y mensajería", () => {
  assert.deepEqual(
    telemetryEventCategories.map(({ id }) => id),
    ["http-incoming", "method", "http-outgoing", "kafka", "jms"],
  );
  assert.deepEqual(
    httpEventSourceOptions.map(({ id }) => id),
    [
      "REQUEST_HEADER",
      "REQUEST_QUERY",
      "REQUEST_PATH_PARAM",
      "REQUEST_BODY",
      "RESPONSE_HEADER",
      "RESPONSE_BODY",
    ],
  );
  assert.ok(httpConditionSourceOptions.some(({ id }) => id === "RESPONSE_STATUS"));
  assert.equal(httpSourceSelector("REQUEST_HEADER").label, "Nombre del request header");
  assert.equal(httpSourceSelector("REQUEST_PATH").disabled, true);
});

test("migra tabs de borradores antiguos sin alterar el JSON wire", () => {
  assert.equal(normalizeTelemetryEditorFocus("http"), "http-incoming");
  assert.equal(normalizeTelemetryEditorFocus("business-event"), "http-incoming");
  assert.equal(normalizeTelemetryEditorFocus("http-outgoing"), "http-outgoing");
  assert.equal(normalizeTelemetryEditorFocus("method"), "method");
  assert.equal(normalizeTelemetryEditorFocus("kafka"), "kafka");
  assert.equal(normalizeTelemetryEditorFocus("jms"), "jms");
});

test("eleva a 1.4 sólo al usar headers o query en un evento correlacionado", () => {
  assert.equal(requiredPolicySchema({ schemaVersion: "1.3", bodyEventPolicies: [] }), "1.3");
  assert.equal(requiredPolicySchema({
    schemaVersion: "1.3",
    bodyEventPolicies: [{ conditions: [{ source: "REQUEST_QUERY" }], fields: [] }],
  }), "1.4");
  assert.equal(agentSupportsPolicySchema({ Attributes: {} }, "1.4"), false);
  assert.equal(agentSupportsPolicySchema({ Attributes: { "o11y.policy.schema": "1.3" } }, "1.4"), false);
  assert.equal(agentSupportsPolicySchema({ Attributes: { "o11y.policy.schema": "1.4" } }, "1.4"), true);
  assert.equal(agentSupportsPolicySchema({ Attributes: { "o11y.policy.schema": "1.10" } }, "1.4"), true);
  assert.equal(policySchemaRank("1.10") > policySchemaRank("1.4"), true);
  assert.equal(agentSupportsPolicySchema({ Attributes: { "o11y.policy.schema": "invalid" } }, "1.4"), false);
});

test("eleva a 1.5 para path params y mensajería sin degradar un schema existente", () => {
  assert.equal(requiredPolicySchema({
    schemaVersion: "1.4",
    bodyEventPolicies: [{
      conditions: [{ source: "REQUEST_PATH", values: ["/customers/{customerId}"] }],
      fields: [],
    }],
  }), "1.5");
  assert.equal(requiredPolicySchema({
    schemaVersion: "1.4",
    bodyEventPolicies: [{
      conditions: [{ source: "REQUEST_PATH", values: ["/accounts/{customer-id}/limits/{limit.type}"] }],
      fields: [],
    }],
  }), "1.5");
  assert.equal(requiredPolicySchema({
    schemaVersion: "1.4",
    bodyEventPolicies: [{ conditions: [], fields: [{ source: "REQUEST_PATH_PARAM" }] }],
  }), "1.5");
  assert.equal(requiredPolicySchema({
    schemaVersion: "1.4",
    messagingEventPolicies: [{ enabled: true }],
  }), "1.5");
  assert.equal(ensurePolicySchema("1.5", "1.4"), "1.5");
  assert.equal(ensurePolicySchema("1.3", "1.5"), "1.5");
});

test("eleva a 1.6 y ofrece sólo atributos contextuales válidos para métricas HTTP", () => {
  assert.equal(requiredPolicySchema({
    schemaVersion: "1.5",
    eventMetricPolicies: [{
      standardAttributes: ["http.request.method", "http.route"],
    }],
  }), "1.6");
  assert.deepEqual(
    httpEventMetricStandardAttributes("INCOMING").map(({ name }) => name),
    [
      "http.request.method",
      "http.route",
      "http.response.status_code",
      "error.type",
    ],
  );
  assert.equal(
    httpEventMetricStandardAttributes("OUTGOING").some(
      ({ name }) => name === "http.route",
    ),
    false,
  );
  assert.deepEqual(
    normalizeHTTPEventMetric({ standardAttributes: null }).standardAttributes,
    [],
  );
});

test("eleva a 1.7 cuando una dimensión declara cardinalidad sin control", () => {
  const policy = {
    schemaVersion: "1.6",
    metricPolicies: [{
      customAttributes: [{
        valuePolicy: {
          type: "PASSTHROUGH",
          allowed: [],
          fallback: "",
          ranges: [],
        },
      }],
    }],
  };

  assert.equal(policyUsesPassthroughValuePolicy(policy), true);
  assert.equal(requiredPolicySchema(policy), "1.7");
  assert.equal(
    agentSupportsPolicySchema(
      { Attributes: { "o11y.policy.schema": "1.6" } },
      requiredPolicySchema(policy),
    ),
    false,
  );
});

test("genera eventName nuevos y detecta duplicados sin depender de enabled", () => {
  const events = [
    { enabled: true, eventName: "http-event" },
    { enabled: false, eventName: "http-event" },
    { enabled: false, eventName: "http-event-2" },
  ];
  assert.deepEqual(duplicateHTTPEventNames({ bodyEventPolicies: events }), ["http-event"]);
  assert.equal(nextHTTPEventName(events), "http-event-3");
});

test("campos, renombre y eliminación no resuelven un eventName ambiguo", () => {
  const policy = {
    bodyEventPolicies: [
      {
        enabled: true,
        direction: "INCOMING",
        eventName: "duplicate",
        fields: [{ attribute: "first" }],
      },
      {
        enabled: true,
        direction: "INCOMING",
        eventName: "duplicate",
        fields: [{ attribute: "second" }],
      },
    ],
    eventMetricPolicies: [{ eventName: "duplicate", name: "custom.event.count" }],
  };

  assert.deepEqual(fieldsForHTTPEvent(policy, "duplicate", "INCOMING"), []);
  const renamed = renameHTTPEventAt(policy, 0, "renamed");
  assert.equal(renamed.eventMetricPolicies[0].eventName, "duplicate");
  const removed = removeHTTPEventAt(policy, 0);
  assert.equal(removed.eventMetricPolicies[0].eventName, "duplicate");

  const unique = {
    ...policy,
    bodyEventPolicies: [policy.bodyEventPolicies[0]],
  };
  assert.equal(renameHTTPEventAt(unique, 0, "renamed").eventMetricPolicies[0].eventName, "renamed");
  assert.deepEqual(removeHTTPEventAt(unique, 0).eventMetricPolicies, []);
});
