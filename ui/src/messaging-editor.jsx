import React from "react";

import { MetricUnitHelp } from "./components/MetricUnitHelp.jsx";
import { NormalizedInput } from "./components/NormalizedInput.jsx";
import { useI18n } from "./i18n.js";
import { ensurePolicySchema } from "./telemetry-events.js";
import {
  configureEventMetricIntent,
  duplicateTelemetryEventNames,
  eventMetricIntent,
  eventNameOutput,
  messagingFamilyForScope,
  messagingScopeOptions,
  messagingSourcesForFamily,
  messagingSourceSelector,
  nextMessagingEventName,
  removeMessagingEventAt,
  renameMessagingEventAt,
  withEventNameOutput,
} from "./messaging-events.js";

const bounded = () => ({
  type: "ENUM",
  allowed: ["VALUE_A", "VALUE_B"],
  ranges: [],
  fallback: "OTHER",
});

const rangePolicy = () => ({
  type: "RANGE",
  allowed: [],
  ranges: [
    { max: 100, label: "0-100" },
    { max: 1000, label: "100-1000" },
    { max: null, label: "1000+" },
  ],
  fallback: "OTHER",
});

const newCondition = (source = "DESTINATION") => ({
  source,
  path: "",
  operator: "EQUALS",
  values: [""],
});

const newField = () => ({
  source: "PAYLOAD",
  path: "",
  attribute: "",
  type: "STRING",
  destinations: ["SPAN"],
  valuePolicy: bounded(),
});

const newEvent = (scope, eventName) => ({
  id: `messaging-event-${Date.now()}`,
  enabled: true,
  ruleName: scope.startsWith("JMS_") ? "Regla JMS" : "Regla Kafka",
  scope,
  conditions: [newCondition()],
  eventName,
  staticAttributes: [],
  maxPayloadBytes: 65536,
  fields: [],
  log: {
    enabled: false,
    severity: "INFO",
    body: "Messaging telemetry event matched",
  },
});

const newMetric = (eventName) => ({
  id: `messaging-metric-${Date.now()}`,
  enabled: true,
  eventName,
  name: "",
  instrument: "COUNTER",
  unit: "1",
  description: "",
  valueField: "",
  dimensions: [],
  buckets: [],
});

const unique = (values) => [...new Set(values.filter(Boolean))];

function ValuePolicyEditor({ value, onChange, onRequireSchema }) {
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
              fallback: type === "PASSTHROUGH"
                ? ""
                : type === "BOOLEAN"
                  ? "false"
                  : "OTHER",
            });
            if (type === "PASSTHROUGH") onRequireSchema?.("1.7");
          }}
        >
          <option value="ENUM">{t("Lista permitida")}</option>
          <option value="RANGE">{t("Rangos")}</option>
          <option value="BOOLEAN">{t("Booleano")}</option>
          <option value="PASSTHROUGH">{t("Sin control (cualquier valor)")}</option>
        </select>
      </label>
      {value.type === "ENUM" && (
        <label>
          {t("Valores permitidos")}
          <NormalizedInput
            value={(value.allowed || []).join(",")}
            onChange={(event) => onChange({
              ...value,
              allowed: event.target.value.split(",").map((item) => item.trim()).filter(Boolean),
            })}
          />
        </label>
      )}
      {value.type === "RANGE" && (
        <label>
          {t("Rangos `máximo:label`")}
          <NormalizedInput
            value={rangesText}
            onChange={(event) => onChange({
              ...value,
              ranges: event.target.value.split(",").map((item) => {
                const [maximum, label] = item.split(":");
                return {
                  max: maximum?.trim() === "*" ? null : Number(maximum),
                  label: label?.trim() || "",
                };
              }).filter((item) => item.label && (item.max === null || Number.isFinite(item.max))),
            })}
          />
        </label>
      )}
      {value.type !== "PASSTHROUGH" && (
        <label>
          {t("Fallback")}
          <input
            value={value.fallback}
            onChange={(event) => onChange({ ...value, fallback: event.target.value })}
          />
        </label>
      )}
      {value.type === "PASSTHROUGH" && (
        <div className="warning-box compact-warning">
          {t("Se conservará cualquier valor capturado. Puede crear una cantidad no acotada de series; úsalo sólo cuando aceptes ese costo.")}
        </div>
      )}
    </div>
  );
}

function MessagingMetricsEditor({ policy, setPolicy, eventPolicy, nameErrors }) {
  const { t } = useI18n();
  const fields = eventPolicy.fields || [];
  const numericFields = fields.filter((field) => ["DOUBLE", "LONG"].includes(field.type));
  const dimensionFields = fields.filter((field) =>
    (field.destinations || []).includes("METRIC"));
  const metrics = (policy.messagingMetricPolicies || [])
    .map((metric, index) => ({ metric, index }))
    .filter(({ metric }) => metric.eventName === eventPolicy.eventName);
  const updateMetric = (index, value) => setPolicy((current) => ({
    ...current,
    schemaVersion: "1.5",
    messagingMetricPolicies: current.messagingMetricPolicies.map((item, itemIndex) =>
      itemIndex === index ? value : item),
  }));

  return (
    <div className="http-rule-output">
      <div className="section-heading small-heading">
        <div>
          <h4>{t("3 · Salidas: métricas")}</h4>
          <small>{t("Cuenta mensajes coincidentes, suma un campo numérico no negativo o registra su distribución.")}</small>
        </div>
        <button
          type="button"
          className="ghost small"
          onClick={() => setPolicy((current) => ({
            ...current,
            schemaVersion: "1.5",
            messagingMetricPolicies: [
              ...current.messagingMetricPolicies,
              newMetric(eventPolicy.eventName),
            ],
          }))}
        >
          {t("+ agregar métrica")}
        </button>
      </div>
      {!metrics.length && (
        <p className="hint">{t("Opcional. La extensión crea la métrica por producer o consumer; el Collector sólo la transporta.")}</p>
      )}
      {metrics.map(({ metric, index }) => {
        const intent = eventMetricIntent(metric);
        const numericOptions = unique([
          metric.valueField,
          ...numericFields.map((field) => field.attribute),
        ]);
        return (
          <div className="nested-card event-metric-card" key={metric.id}>
            <button
              type="button"
              className="remove inline"
              onClick={() => setPolicy((current) => ({
                ...current,
                messagingMetricPolicies: current.messagingMetricPolicies.filter(
                  (_, metricIndex) => metricIndex !== index,
                ),
              }))}
            >
              {t("Eliminar métrica")}
            </button>
            <div className="row">
              <label>
                {t("Nombre OTel")}
                <input
                  className={!String(metric.name || "").trim() || nameErrors.includes(metric.name)
                    ? "invalid"
                    : ""}
                  value={metric.name}
                  placeholder="domain.messaging.operation"
                  onChange={(event) => updateMetric(index, { ...metric, name: event.target.value })}
                />
              </label>
              <label>
                {t("Qué medir")}
                <select
                  value={intent}
                  onChange={(event) => updateMetric(
                    index,
                    configureEventMetricIntent(
                      metric,
                      event.target.value,
                      numericFields[0]?.attribute || "",
                    ),
                  )}
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
                    value={metric.valueField}
                    onChange={(event) => updateMetric(index, {
                      ...metric,
                      valueField: event.target.value,
                    })}
                  >
                    {numericOptions.map((field) => (
                      <option key={field} value={field}>{field}</option>
                    ))}
                  </select>
                  {!numericFields.length && (
                    <small className="error">{t("Añade primero un dato numérico DOUBLE o LONG.")}</small>
                  )}
                </label>
              )}
            </div>
            <h5>{t("Labels de la métrica")}</h5>
            <div className="dimension-picker">
              {dimensionFields.map((field) => (
                <label className="check-line" key={field.attribute}>
                  <input
                    type="checkbox"
                    checked={(metric.dimensions || []).includes(field.attribute)}
                    onChange={() => updateMetric(index, {
                      ...metric,
                      dimensions: (metric.dimensions || []).includes(field.attribute)
                        ? metric.dimensions.filter((item) => item !== field.attribute)
                        : [...(metric.dimensions || []), field.attribute],
                    })}
                  />
                  <code>{field.attribute}</code>
                </label>
              ))}
              {!dimensionFields.length && (
                <small>{t("En Datos, marca un campo como “Usar como label” y controla su cardinalidad o elige Sin control.")}</small>
              )}
            </div>
            <details className="policy-advanced-options">
              <summary>{t("Opciones avanzadas de la métrica")}</summary>
              <div className="row">
                <label>
                  {t("Unidad")}
                  <input
                    value={metric.unit}
                    onChange={(event) => updateMetric(index, { ...metric, unit: event.target.value })}
                  />
                  <MetricUnitHelp unit={metric.unit} />
                </label>
                <label>
                  {t("Descripción")}
                  <input
                    value={metric.description}
                    onChange={(event) => updateMetric(index, {
                      ...metric,
                      description: event.target.value,
                    })}
                  />
                </label>
              </div>
              {intent === "DISTRIBUTION" && (
                <label>
                  {t("Buckets explícitos")}
                  <NormalizedInput
                    value={(metric.buckets || []).join(",")}
                    onChange={(event) => updateMetric(index, {
                      ...metric,
                      buckets: event.target.value.split(",").map(Number).filter(Number.isFinite),
                    })}
                  />
                  <MetricUnitHelp unit={metric.unit} buckets />
                </label>
              )}
            </details>
          </div>
        );
      })}
    </div>
  );
}

export function MessagingPoliciesEditor({ policy, setPolicy, nameErrors, family }) {
  const { t } = useI18n();
  const scopeOptions = messagingScopeOptions[family] || messagingScopeOptions.kafka;
  const sourceOptions = messagingSourcesForFamily(family);
  const duplicateNames = duplicateTelemetryEventNames(policy);
  const events = (policy.messagingEventPolicies || [])
    .map((eventPolicy, eventIndex) => ({ eventPolicy, eventIndex }))
    .filter(({ eventPolicy }) => messagingFamilyForScope(eventPolicy.scope) === family);
  const updateEvent = (index, value) => setPolicy((current) => ({
    ...current,
    schemaVersion: "1.5",
    messagingEventPolicies: current.messagingEventPolicies.map((item, itemIndex) =>
      itemIndex === index ? value : item),
  }));

  return (
    <section className="editor-section">
      <div className="section-heading">
        <div>
          <p className="eyebrow">{t(family === "jms" ? "REGLAS JMS" : "REGLAS KAFKA")}</p>
          <h2>{t("Observa una operación de mensajería y decide qué telemetría emitir")}</h2>
        </div>
        <button
          type="button"
          className="ghost"
          onClick={() => setPolicy((current) => {
            const eventName = nextMessagingEventName(current, `${family}-event`);
            return {
              ...current,
              schemaVersion: "1.5",
              messagingEventPolicies: [
                ...current.messagingEventPolicies,
                newEvent(scopeOptions[0].id, eventName),
              ],
            };
          })}
        >
          {t(family === "jms" ? "+ agregar regla JMS" : "+ agregar regla Kafka")}
        </button>
      </div>
      <p className="hint">
        {t("Producer y consumer son operaciones independientes. Cada regla combina sus condiciones con AND y puede usar destino, key, headers, properties JMS o payload JSON.")}
      </p>
      {!events.length && (
        <div className="empty-state compact-empty-state">
          <b>{t("No hay reglas para esta tecnología.")}</b>
          <p>{t("Agrega una regla y completa Cuándo → Datos → Salidas.")}</p>
        </div>
      )}

      {events.map(({ eventPolicy, eventIndex }) => {
        const output = eventNameOutput(eventPolicy);
        return (
          <article className="policy-card" key={eventPolicy.id}>
            <button
              type="button"
              className="remove"
              onClick={() => setPolicy((current) => removeMessagingEventAt(current, eventIndex))}
            >
              {t("Eliminar")}
            </button>
            <div className="row">
              <label>
                {t("Nombre de la regla")}
                <input
                  value={eventPolicy.ruleName}
                  onChange={(event) => updateEvent(eventIndex, {
                    ...eventPolicy,
                    ruleName: event.target.value,
                  })}
                />
              </label>
              <label>
                {t("Operación observada")}
                <select
                  value={eventPolicy.scope}
                  onChange={(event) => updateEvent(eventIndex, {
                    ...eventPolicy,
                    scope: event.target.value,
                    conditions: eventPolicy.conditions.filter(
                      (condition) => !(
                        event.target.value.startsWith("KAFKA_")
                        && condition.source === "MESSAGE_PROPERTY"
                      ),
                    ),
                    fields: eventPolicy.fields.filter(
                      (field) => !(
                        event.target.value.startsWith("KAFKA_")
                        && field.source === "MESSAGE_PROPERTY"
                      ),
                    ),
                  })}
                >
                  {scopeOptions.map((scope) => (
                    <option value={scope.id} key={scope.id}>{t(scope.label)}</option>
                  ))}
                </select>
              </label>
            </div>

            <details className="policy-advanced-options">
              <summary>{t("Opciones avanzadas de la regla")}</summary>
              <div className="row compact">
                <label>
                  {t("Identificador interno")}
                  <input
                    className={duplicateNames.includes(eventPolicy.eventName) ? "invalid" : ""}
                    value={eventPolicy.eventName}
                    onChange={(event) => setPolicy((current) =>
                      renameMessagingEventAt(current, eventIndex, event.target.value))}
                  />
                  <small>{t("Enlaza internamente las métricas con la regla; no se exporta por sí solo.")}</small>
                </label>
                <label>
                  {t("Límite de payload JSON (bytes)")}
                  <input
                    type="number"
                    min="1024"
                    max="262144"
                    value={eventPolicy.maxPayloadBytes}
                    onChange={(event) => updateEvent(eventIndex, {
                      ...eventPolicy,
                      maxPayloadBytes: Number(event.target.value),
                    })}
                  />
                </label>
              </div>
              {duplicateNames.includes(eventPolicy.eventName) && (
                <small className="error">{t("Debe ser único entre reglas HTTP, Kafka y JMS, incluso deshabilitadas.")}</small>
              )}
            </details>

            <div className="section-heading small-heading">
              <div>
                <h4>{t("1 · Cuándo: condiciones AND")}</h4>
                <small>{t("Destino es obligatorio. Las demás condiciones afinan la coincidencia de esta operación.")}</small>
              </div>
              <button
                type="button"
                className="ghost small"
                onClick={() => updateEvent(eventIndex, {
                  ...eventPolicy,
                  conditions: [...eventPolicy.conditions, newCondition("PAYLOAD")],
                })}
              >
                {t("+ condición")}
              </button>
            </div>
            {!!eventPolicy.conditions.length && (
              <div className="condition-row condition-row-head" aria-hidden="true">
                <span>{t("Fuente")}</span>
                <span>{t("Selector")}</span>
                <span>{t("Operador")}</span>
                <span>{t("Valor(es)")}</span>
                <span />
              </div>
            )}
            {eventPolicy.conditions.map((condition, conditionIndex) => {
              const selector = messagingSourceSelector(condition.source);
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
                            ? { ...item, source, path: messagingSourceSelector(source).disabled ? "" : item.path }
                            : item),
                      });
                    }}
                  >
                    {sourceOptions.map((source) => (
                      <option key={source.id} value={source.id}>{t(source.label)}</option>
                    ))}
                  </select>
                  <input
                    aria-label={t(selector.label)}
                    placeholder={t(selector.placeholder)}
                    disabled={selector.disabled}
                    value={condition.path}
                    onChange={(event) => updateEvent(eventIndex, {
                      ...eventPolicy,
                      conditions: eventPolicy.conditions.map((item, index) =>
                        index === conditionIndex ? { ...item, path: event.target.value } : item),
                    })}
                  />
                  <select
                    aria-label={t("Operador")}
                    value={condition.operator}
                    onChange={(event) => updateEvent(eventIndex, {
                      ...eventPolicy,
                      conditions: eventPolicy.conditions.map((item, index) =>
                        index === conditionIndex ? { ...item, operator: event.target.value } : item),
                    })}
                  >
                    <option value="EQUALS">equals</option>
                    <option value="IN">in</option>
                  </select>
                  <NormalizedInput
                    aria-label={t("Valores")}
                    placeholder={condition.source === "DESTINATION" ? "orders" : "VALUE_A,VALUE_B"}
                    value={(condition.values || []).join(",")}
                    onChange={(event) => updateEvent(eventIndex, {
                      ...eventPolicy,
                      conditions: eventPolicy.conditions.map((item, index) =>
                        index === conditionIndex ? {
                          ...item,
                          values: event.target.value.split(",").map((value) => value.trim()).filter(Boolean),
                        } : item),
                    })}
                  />
                  <button
                    type="button"
                    className="icon-button"
                    aria-label={t("Quitar condición")}
                    onClick={() => updateEvent(eventIndex, {
                      ...eventPolicy,
                      conditions: eventPolicy.conditions.filter((_, index) => index !== conditionIndex),
                    })}
                  >×</button>
                </div>
              );
            })}

            <div className="section-heading small-heading">
              <div>
                <h4>{t("2 · Datos capturados")}</h4>
                <small>{t("Extrae únicamente el selector indicado y descarta el mensaje original.")}</small>
              </div>
              <button
                type="button"
                className="ghost small"
                onClick={() => updateEvent(eventIndex, {
                  ...eventPolicy,
                  fields: [...eventPolicy.fields, newField()],
                })}
              >{t("+ campo")}</button>
            </div>
            {!!eventPolicy.fields.length && (
              <div className="body-field-head" aria-hidden="true">
                <span>{t("Fuente")}</span>
                <span>{t("Selector")}</span>
                <span>{t("Atributo OTel resultante")}</span>
                <span>{t("Tipo")}</span>
                <span />
              </div>
            )}
            {eventPolicy.fields.map((field, fieldIndex) => {
              const selector = messagingSourceSelector(field.source);
              return (
                <div className="nested-card" key={`${eventPolicy.id}-field-${fieldIndex}`}>
                  <div className="body-field-row">
                    <select
                      aria-label={t("Fuente de mensajería")}
                      value={field.source}
                      onChange={(event) => {
                        const source = event.target.value;
                        updateEvent(eventIndex, {
                          ...eventPolicy,
                          fields: eventPolicy.fields.map((item, index) =>
                            index === fieldIndex ? {
                              ...item,
                              source,
                              path: messagingSourceSelector(source).disabled ? "" : item.path,
                            } : item),
                        });
                      }}
                    >
                      {sourceOptions.map((source) => (
                        <option key={source.id} value={source.id}>{t(source.label)}</option>
                      ))}
                    </select>
                    <input
                      aria-label={t(selector.label)}
                      placeholder={t(selector.placeholder)}
                      disabled={selector.disabled}
                      value={field.path}
                      onChange={(event) => updateEvent(eventIndex, {
                        ...eventPolicy,
                        fields: eventPolicy.fields.map((item, index) =>
                          index === fieldIndex ? { ...item, path: event.target.value } : item),
                      })}
                    />
                    <input
                      aria-label={t("Atributo OTel")}
                      placeholder="messaging.operation.type"
                      value={field.attribute}
                      onChange={(event) => updateEvent(eventIndex, {
                        ...eventPolicy,
                        fields: eventPolicy.fields.map((item, index) =>
                          index === fieldIndex ? { ...item, attribute: event.target.value } : item),
                      })}
                    />
                    <select
                      aria-label={t("Tipo de campo")}
                      value={field.type}
                      onChange={(event) => updateEvent(eventIndex, {
                        ...eventPolicy,
                        fields: eventPolicy.fields.map((item, index) =>
                          index === fieldIndex ? { ...item, type: event.target.value } : item),
                      })}
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
                      onClick={() => updateEvent(eventIndex, {
                        ...eventPolicy,
                        fields: eventPolicy.fields.filter((_, index) => index !== fieldIndex),
                      })}
                    >×</button>
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
                            const destinations = (field.destinations || []).includes(destination)
                              ? field.destinations.filter((item) => item !== destination)
                              : [...(field.destinations || []), destination];
                            updateEvent(eventIndex, {
                              ...eventPolicy,
                              fields: eventPolicy.fields.map((item, index) =>
                                index === fieldIndex ? { ...item, destinations } : item),
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
                      onRequireSchema={(schemaVersion) =>
                        setPolicy((current) => ({
                          ...current,
                          schemaVersion: ensurePolicySchema(
                            current.schemaVersion,
                            schemaVersion,
                          ),
                        }))
                      }
                      onChange={(valuePolicy) => updateEvent(eventIndex, {
                        ...eventPolicy,
                        fields: eventPolicy.fields.map((item, index) =>
                          index === fieldIndex ? { ...item, valuePolicy } : item),
                      })}
                    />
                  )}
                </div>
              );
            })}

            <div className="section-heading small-heading">
              <div>
                <h4>{t("3 · Salidas: spans y logs")}</h4>
                <small>{t("Los datos marcados se añaden sólo a la señal elegida.")}</small>
              </div>
            </div>
            <div className="nested-card event-name-output">
              <label>
                {t("Nombre del evento (opcional)")}
                <input
                  value={output.value}
                  placeholder="domain.messaging.event"
                  onChange={(event) => {
                    const value = event.target.value;
                    updateEvent(eventIndex, withEventNameOutput(
                      eventPolicy,
                      value,
                      value && !output.destinations.length ? ["SPAN"] : output.destinations,
                    ));
                  }}
                />
                <small>{t("Se serializa explícitamente como el atributo OTel")} <code>event.name</code>.</small>
              </label>
              <div className="destinations body-destinations">
                {[["SPAN", "Añadir al span"], ["LOG", "Añadir al log"]].map(
                  ([destination, label]) => (
                    <label key={destination}>
                      <input
                        type="checkbox"
                        disabled={!output.value || (
                          output.destinations.includes(destination)
                          && output.destinations.length === 1
                        )}
                        checked={output.destinations.includes(destination)}
                        onChange={() => updateEvent(eventIndex, withEventNameOutput(
                          eventPolicy,
                          output.value,
                          output.destinations.includes(destination)
                            ? output.destinations.filter((item) => item !== destination)
                            : [...output.destinations, destination],
                        ))}
                      />
                      {t(label)}
                    </label>
                  ),
                )}
              </div>
            </div>
            <label className="check-line">
              <input
                type="checkbox"
                checked={eventPolicy.log.enabled}
                onChange={() => updateEvent(eventIndex, {
                  ...eventPolicy,
                  log: { ...eventPolicy.log, enabled: !eventPolicy.log.enabled },
                })}
              />
              {t("Emitir un log OTel correlacionado cuando toda la regla coincida")}
            </label>
            {eventPolicy.log.enabled && (
              <div className="row">
                <label>
                  {t("Severidad del log")}
                  <select
                    value={eventPolicy.log.severity}
                    onChange={(event) => updateEvent(eventIndex, {
                      ...eventPolicy,
                      log: { ...eventPolicy.log, severity: event.target.value },
                    })}
                  >
                    <option>TRACE</option><option>DEBUG</option><option>INFO</option>
                    <option>WARN</option><option>ERROR</option>
                  </select>
                </label>
                <label>
                  {t("Mensaje del log")}
                  <input
                    value={eventPolicy.log.body}
                    onChange={(event) => updateEvent(eventIndex, {
                      ...eventPolicy,
                      log: { ...eventPolicy.log, body: event.target.value },
                    })}
                  />
                </label>
              </div>
            )}
            <MessagingMetricsEditor
              policy={policy}
              setPolicy={setPolicy}
              eventPolicy={eventPolicy}
              nameErrors={nameErrors}
            />
          </article>
        );
      })}
    </section>
  );
}
