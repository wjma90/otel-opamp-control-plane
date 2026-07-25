import { expect, test } from "@playwright/test";

const identity = {
  username: "global-http-metric",
  provider: "local",
  roles: ["admin"],
  permissions: ["*"],
};

const json = (body) => ({
  status: 200,
  contentType: "application/json",
  body: JSON.stringify(body),
});

test("creates an unconditional HTTP duration metric with an uncontrolled header label", async ({
  page,
}) => {
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

  await page.goto("/policy-studio");
  await page.getByRole("textbox", { name: "ID de configuración" })
    .fill("global-http-duration");
  await page.getByRole("button", { name: /Continuar: Edición/ }).click();
  await page.getByRole("tab", { name: "HTTP entrante" }).click();
  await page.getByRole("button", { name: "+ métrica para todo HTTP" }).click();

  const metric = page.locator(".http-global-metric-card");
  await metric.getByRole("textbox", { name: "Nombre OTel" })
    .fill("custom.http.server.request.duration");
  await metric.getByText("http.route", { exact: true }).click();
  await metric.getByRole("button", { name: "+ label de negocio" }).click();
  await metric.getByRole("textbox", { name: "Request header" })
    .fill("x-customer-type");
  await metric.getByRole("textbox", { name: "Atributo OTel / label" })
    .fill("customer.type");
  await metric.getByRole("combobox", { name: "Control de cardinalidad" })
    .selectOption("PASSTHROUGH");

  await expect(metric.getByText(/cantidad no acotada de series/)).toBeVisible();
  await page.getByRole("button", { name: "JSON", exact: true }).click();

  const body = page.getByRole("textbox", { name: "Policy JSON completa" });
  await expect(body).toContainText('"schemaVersion": "1.7"');
  await expect(body).toContainText('"source": "DURATION"');
  await expect(body).toContainText('"type": "PASSTHROUGH"');
  await expect(body).not.toContainText('"conditions"');
});
