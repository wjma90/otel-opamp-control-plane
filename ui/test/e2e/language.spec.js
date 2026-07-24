import { expect, test } from "@playwright/test";

const identity = {
  username: "language-test",
  provider: "local",
  roles: ["admin"],
  permissions: ["*"],
};

const json = (body) => ({
  status: 200,
  contentType: "application/json",
  body: JSON.stringify(body),
});

test("Spanish is the default and the selected language persists", async ({ page }) => {
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

  await page.goto("/?tab=agents");
  await expect(page.getByRole("heading", { name: "Clientes OpAMP" })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "es");

  await page.getByRole("combobox", { name: "Cambiar idioma" }).selectOption("en");
  await expect(page.getByRole("heading", { name: "OpAMP clients" })).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("lang", "en");

  await page.reload();
  await expect(page.getByRole("heading", { name: "OpAMP clients" })).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Change language" })).toHaveValue("en");
});
