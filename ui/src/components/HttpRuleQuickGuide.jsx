import React from "react";

const FieldExample = ({ source, path, attribute, destinations, t }) => (
  <div className="http-guide-field" role="row">
    <code role="cell">{t(source)}</code>
    <span role="cell">{path}</span>
    <b role="cell">{attribute}</b>
    <small role="cell">{destinations.map((item) => t(item)).join(" + ")}</small>
  </div>
);

export function HttpRuleQuickGuide({ t }) {
  return (
    <details className="http-rule-quick-guide">
      <summary>{t("Guía rápida: ejemplo CambistApp con span, log y métrica")}</summary>
      <div className="http-rule-guide-content">
        <p>
          {t("La regla se lee de arriba hacia abajo: primero decide cuándo coincide, luego extrae datos con nombres OTel y finalmente elige a qué señales enviarlos.")}
        </p>
        <ol>
          <li>
            <b>{t("Cuándo")}</b>: <code>POST /api/exchanges</code>, response status
            <code> 200,201</code> y, opcionalmente, response body
            <code> status=APPROVED</code>.
          </li>
          <li>
            <b>{t("Datos")}</b>: {t("cada fila relaciona una fuente y ruta con un atributo OTel; nunca exporta el body o header completo.")}
          </li>
        </ol>
        <div className="http-guide-fields" role="table" aria-label={t("Ejemplo de datos capturados")}>
          <div className="http-guide-field headings" role="row">
            <span role="columnheader">{t("Fuente")}</span>
            <span role="columnheader">{t("Ruta o header")}</span>
            <span role="columnheader">{t("Atributo OTel")}</span>
            <span role="columnheader">{t("Salidas")}</span>
          </div>
          <FieldExample
            source="Header de response"
            path="x-customer-type"
            attribute="cambistapp.customer.type"
            destinations={["Span", "Log", "Label de métrica"]}
            t={t}
          />
          <FieldExample
            source="Body de request"
            path="channel"
            attribute="client.channel"
            destinations={["Span", "Log", "Label de métrica"]}
            t={t}
          />
          <FieldExample
            source="Body de request"
            path="amount"
            attribute="exchange.amount"
            destinations={["Span", "Log", "Valor de métrica"]}
            t={t}
          />
          <FieldExample
            source="Body de response"
            path="status"
            attribute="exchange.status"
            destinations={["Span", "Log", "Label de métrica"]}
            t={t}
          />
        </div>
        <p>
          <b>{t("Salidas")}</b>: {t("marca «Añadir al span» para enriquecer la traza, «Añadir al log» para copiar el dato al log correlacionado y «Label de métrica» sólo para valores acotados. event.name identifica el evento en spans y logs; el nombre de la métrica se define en su propio bloque.")}
        </p>
      </div>
    </details>
  );
}
