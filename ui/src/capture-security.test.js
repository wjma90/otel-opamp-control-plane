import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  normalizeHeaderName,
  policyCaptureDenyViolations,
  policyWireContractErrors,
} from "./capture-security.js";

test("normaliza headers igual que el Control Plane", () => {
  assert.equal(normalizeHeaderName(" Authorization "), "authorization");
});

test("bloquea paths iguales, descendientes, ancestros y root sin afectar hermanos", () => {
  const entries = [
    { Kind: "BODY_PATH", Value: "customer.email" },
    { Kind: "HEADER", Value: "authorization" },
    { Kind: "QUERY_PARAM", Value: "access_token" },
    { Kind: "METHOD_PATH", Value: "account.number" },
    { Kind: "PATH_PARAM", Value: "customerId" },
    { Kind: "MESSAGE_PROPERTY", Value: "accountNumber" },
  ];
  const policy = {
    bodyEventPolicies: [{
      enabled: true,
      id: "event",
      conditions: [],
      fields: [
        { path: "customer", source: "REQUEST_BODY" },
        { path: "order.id", source: "REQUEST_BODY" },
        { path: "Authorization", source: "REQUEST_HEADER" },
        { path: "access_token", source: "REQUEST_QUERY" },
        { path: "customerId", source: "REQUEST_PATH_PARAM" },
      ],
    }],
    methodPolicies: [{
      enabled: true,
      id: "method",
      captures: [
        { source: "ARGUMENT", path: "" },
        { source: "RETURN", path: "profile.name" },
      ],
      metrics: [],
    }],
    messagingEventPolicies: [{
      enabled: true,
      id: "messaging",
      conditions: [
        { source: "MESSAGE_HEADER", path: "Authorization" },
        { source: "PAYLOAD", path: "customer.email" },
      ],
      fields: [{ source: "MESSAGE_PROPERTY", path: "accountNumber" }],
    }],
  };

  assert.deepEqual(policyCaptureDenyViolations(policy, entries), [
    { kind: "BODY_PATH", value: "customer", owner: "event" },
    { kind: "HEADER", value: "authorization", owner: "event" },
    { kind: "QUERY_PARAM", value: "access_token", owner: "event" },
    { kind: "PATH_PARAM", value: "customerId", owner: "event" },
    { kind: "HEADER", value: "authorization", owner: "messaging" },
    { kind: "BODY_PATH", value: "customer.email", owner: "messaging" },
    { kind: "MESSAGE_PROPERTY", value: "accountNumber", owner: "messaging" },
    { kind: "METHOD_PATH", value: "<root>", owner: "method" },
  ]);
});

test("ignora headers y reglas deshabilitadas", () => {
  const entries = [{ Kind: "HEADER", Value: "authorization" }];
  const policy = {
    metricPolicies: [{
      enabled: false,
      customAttributes: [{ header: " Authorization " }],
    }],
  };
  assert.deepEqual(policyCaptureDenyViolations(policy, entries), []);

  assert.equal(policyCaptureDenyViolations({
    metricPolicies: [{
      customAttributes: [{ header: " Authorization " }],
    }],
  }, entries).length, 1);
});

test("el modo JSON valida la denylist contra el documento editado", () => {
  const source = readFileSync(new URL("./main.jsx", import.meta.url), "utf8");
  assert.match(
    source,
    /policyForClientValidation\s*=\s*JSON\.parse\(rawPolicyBody\)/,
  );
  assert.match(
    source,
    /policyCaptureDenyViolations\(policyForClientValidation, securityDenylist\)/,
  );
});

test("un JSON con shape inválido no rompe la validación preventiva", () => {
  assert.doesNotThrow(() => policyCaptureDenyViolations({
    requestHeaders: {},
    responseHeaders: "invalid",
    metricPolicies: {},
    bodyEventPolicies: null,
    methodPolicies: { captures: [] },
  }, [{ Kind: "HEADER", Value: "authorization" }]));
  assert.doesNotThrow(() => policyWireContractErrors({ bodyEventPolicies: [null] }));
});

test("exige defaults semánticos explícitos en el contrato wire", () => {
  assert.deepEqual(policyWireContractErrors({
    metricPolicies: [{
      value: { source: "CONSTANT" },
    }],
    methodPolicies: [{
      enabled: true,
      captures: [{ source: "ARGUMENT" }],
      metrics: [{ value: { source: "CONSTANT" } }],
    }],
    bodyEventPolicies: [{ enabled: true }],
    eventMetricPolicies: [{ enabled: true }],
  }), [
    "metricPolicies[0] requiere enabled boolean explícito.",
    "metricPolicies[0].value requiere constant explícito para source=CONSTANT.",
    "methodPolicies[0].captures[0] requiere argumentIndex explícito para source=ARGUMENT.",
    "methodPolicies[0].metrics[0].value requiere constant explícito para source=CONSTANT.",
    "bodyEventPolicies[0] no tiene una salida efectiva: añade un atributo al span, habilita el log o crea una métrica para el evento.",
  ]);
});

test("rechaza eventos HTTP no-op y acepta una métrica count como salida", () => {
  const event = {
    enabled: true,
    eventName: "exchange-approved",
    log: { enabled: false },
    fields: [{ destinations: ["METRIC"] }],
  };
  assert.deepEqual(policyWireContractErrors({ bodyEventPolicies: [event] }), [
    "bodyEventPolicies[0] no tiene una salida efectiva: añade un atributo al span, habilita el log o crea una métrica para el evento.",
  ]);
  assert.deepEqual(policyWireContractErrors({
    bodyEventPolicies: [event],
    eventMetricPolicies: [{
      enabled: true,
      eventName: "exchange-approved",
      instrument: "COUNTER",
      valueField: "",
    }],
  }), []);
  assert.deepEqual(policyWireContractErrors({
    bodyEventPolicies: [event],
    eventMetricPolicies: [{ eventName: "exchange-approved" }],
  }), [
    "eventMetricPolicies[0] requiere enabled boolean explícito.",
    "bodyEventPolicies[0] no tiene una salida efectiva: añade un atributo al span, habilita el log o crea una métrica para el evento.",
  ]);
  assert.deepEqual(policyWireContractErrors({
    bodyEventPolicies: [{ ...event, fields: [{ destinations: ["SPAN"] }] }],
  }), []);
});

test("eventName es único entre HTTP y mensajería aunque una regla esté deshabilitada", () => {
  for (const bodyEventPolicies of [
    [
      { enabled: true, eventName: "exchange-approved", log: { enabled: true } },
      { enabled: false, eventName: "exchange-approved" },
    ],
    [
      { enabled: false, eventName: "exchange-approved" },
      { enabled: false, eventName: "exchange-approved" },
    ],
  ]) {
    assert.deepEqual(policyWireContractErrors({ bodyEventPolicies }), [
      "eventName debe ser único entre bodyEventPolicies y messagingEventPolicies; duplicado: exchange-approved.",
    ]);
  }

  assert.deepEqual(policyWireContractErrors({
    bodyEventPolicies: [
      { enabled: false, eventName: "exchange-requested" },
      { enabled: false, eventName: "exchange-approved" },
    ],
  }), []);

  assert.deepEqual(policyWireContractErrors({
    bodyEventPolicies: [{ enabled: false, eventName: "exchange-approved" }],
    messagingEventPolicies: [{ enabled: false, eventName: "exchange-approved" }],
  }), [
    "eventName debe ser único entre bodyEventPolicies y messagingEventPolicies; duplicado: exchange-approved.",
  ]);
});

test("exige enabled y una salida efectiva para reglas y métricas de mensajería", () => {
  const event = {
    enabled: true,
    eventName: "message-observed",
    fields: [{ destinations: ["METRIC"] }],
    staticAttributes: [],
    log: { enabled: false },
  };
  assert.deepEqual(policyWireContractErrors({ messagingEventPolicies: [event] }), [
    "messagingEventPolicies[0] no tiene una salida efectiva: añade un atributo al span, habilita el log o crea una métrica para el evento.",
  ]);
  assert.deepEqual(policyWireContractErrors({
    messagingEventPolicies: [event],
    messagingMetricPolicies: [{
      enabled: true,
      eventName: "message-observed",
      instrument: "COUNTER",
    }],
  }), []);
  assert.deepEqual(policyWireContractErrors({
    messagingEventPolicies: [{ ...event, fields: [{ destinations: ["SPAN"] }] }],
    messagingMetricPolicies: [{ eventName: "message-observed" }],
  }), [
    "messagingMetricPolicies[0] requiere enabled boolean explícito.",
  ]);
});
