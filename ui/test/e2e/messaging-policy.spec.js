import { expect, test } from "@playwright/test";

const identity = {
  username: "messaging-policy-editor",
  provider: "local",
  roles: ["admin"],
  permissions: ["*"],
};

const json = (body) => ({
  status: 200,
  contentType: "application/json",
  body: JSON.stringify(body),
});

test("Policy Studio authors a schema 1.5 Kafka event without losing the wire contract", async ({ page }) => {
  const responses = new Map([
    ["/api/agents", []],
    ["/api/configs", {}],
    ["/api/metric-names", []],
    ["/api/audit", []],
    ["/api/storage", { driver: "PostgreSQL", status: "ready" }],
    ["/api/security/denylist", []],
    ["/api/deployments", []],
    ["/api/auth/session", identity],
    ["/api/auth/providers", {
      identity,
      providers: [],
      roles: {},
      assignableRoles: [],
      roleMappings: {},
      configurations: [],
    }],
    ["/api/collector-base-configs", []],
  ]);

  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill(json(responses.get(path) ?? {}));
  });

  await page.goto("/?tab=policy");
  await page.getByRole("textbox", { name: "ID de configuración" })
    .fill("cambistapp-kafka-telemetry");
  await page.getByRole("button", { name: /Continuar: Edición/ }).click();
  await page.getByRole("tab", { name: "Kafka" }).click();
  await expect(page.getByRole("heading", {
    name: "Observa una operación de mensajería y decide qué telemetría emitir",
  })).toBeVisible();

  await page.getByRole("button", { name: "+ agregar regla Kafka" }).click();
  const rule = page.locator("article.policy-card").last();
  await rule.getByRole("textbox", { name: "Valores" }).fill("cambistapp.exchange.completed");
  await rule.getByRole("button", { name: "+ campo" }).click();
  await rule.getByRole("textbox", { name: "Ruta JSON del payload" }).fill("sourceAmount");
  await rule.getByRole("textbox", { name: "Atributo OTel", exact: true })
    .fill("exchange.source.amount");
  await rule.getByRole("combobox", { name: "Tipo de campo" }).selectOption("DOUBLE");

  await page.getByRole("button", { name: "JSON", exact: true }).click();
  const wire = page.getByRole("textbox", { name: "Policy JSON completa" });
  await expect(wire).toContainText('"schemaVersion": "1.5"');
  await expect(wire).toContainText('"scope": "KAFKA_PRODUCER"');
  await expect(wire).toContainText('"source": "PAYLOAD"');
  await expect(wire).toContainText('"attribute": "exchange.source.amount"');
});
