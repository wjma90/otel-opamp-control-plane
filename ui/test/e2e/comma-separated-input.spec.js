import { expect, test } from "@playwright/test";

const identity = {
  username: "comma-input-regression",
  provider: "local",
  roles: ["admin"],
  permissions: ["*"],
};

const json = (body) => ({
  status: 200,
  contentType: "application/json",
  body: JSON.stringify(body),
});

test("HTTP response statuses accept a comma while typing an IN list", async ({ page }) => {
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
    .fill("http-status-list");
  await page.getByRole("button", { name: /Continuar: Edición/ }).click();
  await page.getByRole("tab", { name: "HTTP entrante" }).click();
  await page.getByRole("button", { name: "+ agregar regla HTTP" }).click();

  const rule = page.locator("article.policy-card").last();
  const statusValues = rule.locator(".condition-row").nth(2)
    .getByRole("textbox", { name: "Valores" });

  await statusValues.fill("");
  await statusValues.pressSequentially("200,201");
  await expect(statusValues).toHaveValue("200,201");

  await statusValues.press("Tab");
  await expect(statusValues).toHaveValue("200,201");

  await page.getByRole("button", { name: "JSON", exact: true }).click();
  await expect(page.getByRole("textbox", { name: "Policy JSON completa" }))
    .toContainText('"values": [\n          "200",\n          "201"\n        ]');
});
