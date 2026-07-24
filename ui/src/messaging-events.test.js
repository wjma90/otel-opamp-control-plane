import test from "node:test";
import assert from "node:assert/strict";

import {
  duplicateTelemetryEventNames,
  fieldsForMessagingEvent,
  messagingFamilyForScope,
  messagingSourcesForFamily,
  messagingSourceSelector,
  nextMessagingEventName,
  normalizeMessagingEventPolicy,
  normalizeMessagingMetric,
  removeMessagingEventAt,
  renameMessagingEventAt,
} from "./messaging-events.js";

test("separa scopes y fuentes Kafka/JMS sin ofrecer properties JMS a Kafka", () => {
  assert.equal(messagingFamilyForScope("KAFKA_CONSUMER"), "kafka");
  assert.equal(messagingFamilyForScope("JMS_PRODUCER"), "jms");
  assert.equal(
    messagingSourcesForFamily("kafka").some(({ id }) => id === "MESSAGE_PROPERTY"),
    false,
  );
  assert.equal(
    messagingSourcesForFamily("jms").some(({ id }) => id === "MESSAGE_PROPERTY"),
    true,
  );
  assert.equal(messagingSourceSelector("DESTINATION").disabled, true);
  assert.equal(messagingSourceSelector("PAYLOAD").label, "Ruta JSON del payload");
});

test("normaliza documentos parciales sin inventar semántica de negocio", () => {
  assert.deepEqual(normalizeMessagingEventPolicy({
    id: "event-1",
    scope: "jms_consumer",
    conditions: null,
    staticAttributes: null,
    fields: null,
  }), {
    id: "event-1",
    scope: "JMS_CONSUMER",
    conditions: [],
    staticAttributes: [],
    fields: [],
    log: {
      enabled: false,
      severity: "INFO",
      body: "Messaging rule matched",
    },
  });
  assert.deepEqual(normalizeMessagingMetric({ id: "metric-1" }), {
    id: "metric-1",
    dimensions: [],
    buckets: [],
  });
});

test("eventName es único entre HTTP, Kafka y JMS aunque esté deshabilitado", () => {
  const policy = {
    bodyEventPolicies: [{ enabled: false, eventName: "operation-observed" }],
    messagingEventPolicies: [{ enabled: true, eventName: "operation-observed" }],
  };
  assert.deepEqual(duplicateTelemetryEventNames(policy), ["operation-observed"]);
  assert.equal(nextMessagingEventName(policy, "operation-observed"), "operation-observed-2");
});

test("renombra y elimina métricas sólo cuando el eventName tiene un dueño único", () => {
  const policy = {
    bodyEventPolicies: [],
    messagingEventPolicies: [{
      enabled: true,
      eventName: "message-observed",
      fields: [{ attribute: "messaging.operation.type" }],
    }],
    messagingMetricPolicies: [{
      enabled: true,
      eventName: "message-observed",
      name: "domain.messaging.count",
    }],
  };
  assert.equal(
    fieldsForMessagingEvent(policy, "message-observed")[0].attribute,
    "messaging.operation.type",
  );
  assert.equal(
    renameMessagingEventAt(policy, 0, "renamed").messagingMetricPolicies[0].eventName,
    "renamed",
  );
  assert.deepEqual(removeMessagingEventAt(policy, 0).messagingMetricPolicies, []);

  const ambiguous = {
    ...policy,
    messagingEventPolicies: [
      policy.messagingEventPolicies[0],
      { ...policy.messagingEventPolicies[0], id: "event-2" },
    ],
  };
  assert.equal(fieldsForMessagingEvent(ambiguous, "message-observed").length, 0);
  assert.equal(
    renameMessagingEventAt(ambiguous, 0, "renamed").messagingMetricPolicies[0].eventName,
    "message-observed",
  );
});
