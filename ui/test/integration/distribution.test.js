import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const projectDirectory = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../..",
);
const distributionDirectory = path.join(projectDirectory, "dist");

const assetPath = (html, expression, description) => {
  const match = html.match(expression);
  assert.ok(match, `${description} must be referenced by dist/index.html`);
  assert.ok(match[1].startsWith("/assets/"), `${description} must use the Vite assets directory`);
  return path.join(distributionDirectory, match[1].slice(1));
};

test("production bundle exposes the concise OTel Editor label", async () => {
  const html = await readFile(path.join(distributionDirectory, "index.html"), "utf8");
  assert.match(html, /<title>O11Y Control Plane<\/title>/);
  const script = await readFile(
    assetPath(html, /<script[^>]+src="([^"]+\.js)"/, "JavaScript bundle"),
    "utf8",
  );
  const stylesheet = await readFile(
    assetPath(html, /<link[^>]+href="([^"]+\.css)"/, "stylesheet"),
    "utf8",
  );

  assert.doesNotMatch(script, /\/api\/capture-inventory/);
  assert.doesNotMatch(script, /Inventario de capturas/);
  assert.match(script, /Editor OTel/);
  assert.match(script, /OTel Editor/);
  assert.doesNotMatch(script, /Studio de configuración/);
  assert.doesNotMatch(script, /Policy studio/);
  assert.match(script, /Eventos de telemetría/);
  assert.match(script, /HTTP entrante/);
  assert.match(script, /Método Java/);
  assert.match(script, /HTTP saliente/);
  assert.match(script, /Request query param/);
  assert.match(script, /Cuándo ocurre, qué datos usar y qué telemetría emitir/);
  assert.match(script, /Guía rápida: ejemplo HTTP con span, log y métrica/);
  assert.match(script, /Quick guide: HTTP example with span, log, and metric/);
  assert.match(script, /POST \/api\/orders/);
  assert.match(script, /customer\.type/);
  assert.match(script, /order\.amount/);
  assert.match(script, /order\.status/);
  assert.match(script, /order\.approved/);
  assert.doesNotMatch(script, /CambistApp/i);
  assert.match(script, /Contar coincidencias/);
  assert.match(script, /Total acumulado de un campo no negativo/);
  assert.match(script, /Distribución de un campo/);
  assert.match(script, /Añadir al span/);
  assert.match(script, /Añadir al log/);
  assert.match(script, /Usar como label/);
  assert.match(script, /event\.name/);
  assert.match(script, /OpAMP HTTP polling/);
  assert.doesNotMatch(script, /OpAMP HTTP \+ WebSocket/);
  assert.doesNotMatch(script, /1 · MODO DIRECTO/);
  assert.doesNotMatch(script, /2 · MÉTRICAS HTTP/);
  assert.doesNotMatch(script, /3 · MODO CORRELACIONADO/);
  assert.doesNotMatch(script, /Métricas derivadas del evento HTTP/);
  assert.doesNotMatch(script, /crear business event/i);
  assert.match(script, /\/api\/system\/network/);
  assert.match(script, /Red y acceso/);
  assert.match(script, /Publicación bajo subpath/);
  assert.match(script, /Esta vista es de sólo lectura/);
  assert.match(script, /Atributos reportados/);
  assert.match(script, /Reported attributes/);
  assert.match(script, /CLIENTE OPAMP/);
  assert.match(script, /Buscar clientes/);
  assert.match(script, /Servicio, instance ID, configuración o atributo/);
  assert.match(script, /No hay clientes que coincidan con los filtros/);
  assert.match(script, /multi-select-filter-trigger/);
  assert.match(script, /seleccionados/);
  assert.match(script, /Sin criterios disponibles/);
  assert.match(script, /Bases locales de Supervisor/);
  assert.match(script, /Gestión remota/);
  assert.match(script, /Buscar versión guardada/);
  assert.match(script, /Change language/);
  assert.match(script, /o11y\.supervisor\.version/);
  assert.match(script, /o11y\.collector\.version/);
  assert.doesNotMatch(script, /\/api\/catalog(?:["'/?]|$)/);
  assert.doesNotMatch(script, /\/api\/captures(?:["'/?]|$)/);
  assert.doesNotMatch(script, /\/api\/collector-bootstrap-profiles/);
  assert.doesNotMatch(script, /Bootstrap y configuraciones base/);
  assert.doesNotMatch(script, /perfil de bootstrap/i);
  assert.ok(stylesheet.length > 1_000, "the production stylesheet must not be empty");
  assert.match(stylesheet, /agent-attributes-dialog/);
  assert.match(stylesheet, /fleet-filters/);
  assert.match(stylesheet, /fleet-filter-result/);
  assert.match(stylesheet, /multi-select-filter-panel/);
  assert.match(stylesheet, /policy-flow\.four-steps/);
  assert.doesNotMatch(html, /https?:\/\//, "HTML must not load cross-origin assets");
  assert.doesNotMatch(stylesheet, /https?:\/\//, "CSS must not load cross-origin assets");
  assert.match(stylesheet, /@font-face/, "fonts must be bundled for the strict CSP");

  const fontAssets = [
    ...new Set(
      [...stylesheet.matchAll(/url\((?:["']?)(\/assets\/[^)"']+\.woff2)(?:["']?)\)/g)]
        .map((match) => match[1]),
    ),
  ];
  assert.ok(fontAssets.length >= 6, "all selected font weights must be local WOFF2 assets");
  assert.ok(fontAssets.some((asset) => asset.includes("dm-sans")));
  assert.ok(fontAssets.some((asset) => asset.includes("space-mono")));
  await Promise.all(fontAssets.map((asset) =>
    readFile(path.join(distributionDirectory, asset.slice(1))),
  ));
});
