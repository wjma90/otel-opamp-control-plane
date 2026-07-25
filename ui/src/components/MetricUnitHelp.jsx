import React from "react";

import { useI18n } from "../i18n.js";
import { displayMetricUnit } from "../metric-unit.js";

export function MetricUnitHelp({ unit, buckets = false }) {
  const { t } = useI18n();
  const displayedUnit = displayMetricUnit(unit);

  if (buckets) {
    return (
      <small>
        {displayedUnit ? (
          <>
            {t("Unidad en")} <code>{displayedUnit}</code>;{" "}
            {t("cada bucket representa un límite de la unidad.")}
          </>
        ) : (
          t("Define primero la unidad; cada bucket representa un límite expresado en ella.")
        )}
      </small>
    );
  }

  return (
    <small>
      {t("Se exporta literalmente en OTLP. Las llaves, como {PEN}, son una anotación UCUM; no una variable ni un campo.")}
    </small>
  );
}
