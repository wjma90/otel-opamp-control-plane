import React, { useMemo, useState } from "react";

import { publicationActionLabel } from "../deployment-status.js";
import {
  filterStoredVersions,
  storedVersionSelectorSummary,
} from "../version-source.js";

const versionKey = (version) => `${version.configId}::${version.Version}`;

const selectorText = (version, t) => {
  const selector = storedVersionSelectorSummary(version);
  const parts = [];
  if (selector.services.length) {
    parts.push(`${t("Servicios")}: ${selector.services.join(", ")}`);
  }
  if (selector.instances.length) {
    parts.push(`InstanceUID: ${selector.instances.join(", ")}`);
  }
  if (selector.attributes.length) {
    parts.push(`${t("Atributos")}: ${selector.attributes.join(", ")}`);
  }
  return parts.join(" · ") || t("Sin restricción");
};

export function StoredVersionPicker({ versions, value, onChange, t }) {
  const [query, setQuery] = useState("");
  const matches = useMemo(
    () => filterStoredVersions(versions, query),
    [versions, query],
  );
  const selected = versions.find((version) => versionKey(version) === value);
  const options = selected && !matches.some((version) => versionKey(version) === value)
    ? [selected, ...matches]
    : matches;

  return (
    <div className="stored-version-picker">
      <label>
        {t("Buscar versión guardada")}
        <input
          type="search"
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder={t("Nombre, vN, servicio, InstanceUID o atributo key=value")}
        />
      </label>
      <label>
        {t("Versión guardada en PostgreSQL")}
        <select value={value} onChange={(event) => onChange(event.target.value)}>
          <option value="">{t("Selecciona una versión…")}</option>
          {options.map((version) => (
            <option key={versionKey(version)} value={versionKey(version)}>
              {version.configId} · v{version.Version} · {t(publicationActionLabel(version.Action))}
            </option>
          ))}
        </select>
      </label>
      <small className="stored-version-match-count" aria-live="polite">
        {matches.length === versions.length
          ? `${versions.length} ${t("versiones disponibles")}`
          : `${matches.length} ${t("de")} ${versions.length} ${t("versiones coincidentes")}`}
      </small>
      {query && matches.length === 0 && (
        <p className="empty-inline">{t("No hay versiones que coincidan con la búsqueda.")}</p>
      )}
      {selected && (
        <div className="stored-version-selection">
          <b>{selected.configId} · v{selected.Version}</b>
          <span>{selectorText(selected, t)}</span>
        </div>
      )}
    </div>
  );
}
