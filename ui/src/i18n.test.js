import assert from "node:assert/strict";
import test from "node:test";

import {
  defaultLocale,
  formatDateTime,
  localeStorageKey,
  normalizeLocale,
  readStoredLocale,
  translate,
  translatedOptions,
  translationKeys,
} from "./i18n.js";

test("Spanish is the default and unsupported locales fall back safely", () => {
  assert.equal(defaultLocale, "es");
  assert.equal(normalizeLocale("es-PE"), "es");
  assert.equal(normalizeLocale("EN_us"), "en");
  assert.equal(normalizeLocale("fr"), "es");
  assert.equal(readStoredLocale({ getItem: () => null }), "es");
  assert.equal(readStoredLocale({ getItem: () => "en" }), "en");
  assert.equal(readStoredLocale({ getItem: () => { throw new Error("denied"); } }), "es");
  assert.equal(localeStorageKey, "o11y.ui.locale");
});

test("translator uses English catalog, interpolates variables and falls back to source", () => {
  assert.equal(translate("es", "Idioma"), "Idioma");
  assert.equal(translate("en", "Idioma"), "Language");
  assert.equal(translate("en", "Untranslated wire value"), "Untranslated wire value");
  assert.equal(translate("en", "Restaurar contenido de v7"), "Restore content from v7");
  assert.equal(
    translate("en", "Guía rápida: ejemplo HTTP con span, log y métrica"),
    "Quick guide: HTTP example with span, log, and metric",
  );
  assert.equal(
    translate("en", "2/3 destino(s) vivo(s) coincidente(s) aplicada(s)"),
    "2/3 matching live target(s) applied",
  );
  assert.equal(translate("en", "{count} conectados", { count: 3 }), "3 conectados");
  assert.deepEqual(
    translatedOptions((value) => translate("en", value), [{ value: "ACTIVE", label: "Activa" }]),
    [{ value: "ACTIVE", label: "Active" }],
  );
});

test("every key has a non-empty English value and dates follow the selected locale", () => {
  assert.ok(translationKeys.length > 100);
  for (const key of translationKeys) {
    assert.ok(translate("en", key).trim(), `missing English translation for ${key}`);
  }
  const value = "2026-07-21T17:30:45Z";
  assert.match(formatDateTime("en", value), /7\/21\/26|7\/21\/2026/);
  assert.match(formatDateTime("es", value), /21\/0?7\/(?:26|2026)/);
  assert.equal(formatDateTime("en", "not-a-date"), "—");
});
