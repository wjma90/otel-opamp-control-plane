import { expect, test } from "@playwright/test";

const identity = {
  username: "browser-smoke",
  provider: "local",
  roles: ["admin"],
  permissions: ["*"],
};

const json = (body) => ({
  status: 200,
  contentType: "application/json",
  body: JSON.stringify(body),
});

const destination = (target, id, uid) => ({
  ConfigID: id,
  Version: 1,
  Target: target,
  AgentUID: uid,
  Service: `${target}-service`,
  Selector: { Services: [`${target}-service`], Attributes: {} },
  PublishedBy: "browser-smoke",
  PublishedAt: "2026-07-23T12:00:00Z",
  AppliedAt: "2026-07-23T12:01:00Z",
  LastObservedAt: "2026-07-23T12:02:00Z",
  ConnectionStatus: "ONLINE",
  CountsForLiveCoverage: true,
  CurrentConfigID: id,
  CurrentConfigVersion: 1,
  CurrentConfigStatus: "APPLIED",
  ObservedStatus: "APPLIED",
  Body: target === "collector" ? "receivers: {}\n" : "{}",
});

test("the production bundle renders the authenticated Fleet without browser errors", async ({ page }) => {
  const pageErrors = [];
  const consoleErrors = [];
  const externalRequests = [];

  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("console", (message) => {
    if (message.type() === "error") consoleErrors.push(message.text());
  });
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.origin !== "http://127.0.0.1:4173") externalRequests.push(url.href);
  });

  const responses = new Map([
    ["/api/agents", []],
    ["/api/configs", {}],
    ["/api/metric-names", []],
    ["/api/audit", []],
    ["/api/storage", { driver: "PostgreSQL", status: "ready" }],
    ["/api/security/denylist", []],
    ["/api/deployments", [
      destination("collector", "gateway-config", "collector-1"),
      destination("java-extension", "exchange-policy", "java-1"),
    ]],
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

  await page.goto("/agents");
  await page.waitForLoadState("networkidle");

  await expect(page).toHaveTitle("O11Y Control Plane");
  expect(pageErrors, "uncaught browser errors").toEqual([]);
  expect(consoleErrors, "console errors").toEqual([]);
  expect(externalRequests, "cross-origin runtime requests").toEqual([]);

  await expect(page.getByRole("heading", { name: "Clientes OpAMP" })).toBeVisible();
  await expect(page.getByText("Esperando clientes OpAMP…")).toBeVisible();
  await expect(page.locator("#root")).not.toBeEmpty();
  await expect(page.getByRole("button", { name: "Editor OTel" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Studio de configuración" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Policy studio" })).toHaveCount(0);

  await page.reload();
  await expect(page).toHaveURL(/\/agents$/);
  await expect(page.getByRole("heading", { name: "Clientes OpAMP" })).toBeVisible();

  await page.getByRole("button", { name: "Editor OTel" }).click();
  await expect(page).toHaveURL(/\/policy-studio$/);
  await expect(page.getByRole("heading", { name: "Editor OTel" })).toBeVisible();

  await page.reload();
  await expect(page).toHaveURL(/\/policy-studio$/);
  await expect(page.getByRole("heading", { name: "Editor OTel" })).toBeVisible();

  await page.getByRole("button", { name: "Agentes" }).click();
  await expect(page).toHaveURL(/\/agents$/);

  await page.getByRole("button", { name: "Gestión remota" }).click();
  await expect(page).toHaveURL(/\/remote-management$/);
  await expect(page.getByRole("heading", { name: "Policies y configuraciones" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Ver configuración" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Ver policy" })).toBeVisible();

  await page.reload();
  await expect(page).toHaveURL(/\/remote-management$/);
  await expect(page.getByRole("heading", { name: "Policies y configuraciones" })).toBeVisible();

  await page.goBack();
  await expect(page).toHaveURL(/\/agents$/);
  await expect(page.getByRole("heading", { name: "Clientes OpAMP" })).toBeVisible();
});
