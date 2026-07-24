import { expect, test } from "@playwright/test";

const identity = {
  username: "version-search",
  provider: "local",
  roles: ["admin"],
  permissions: ["*"],
};

const json = (body) => ({
  status: 200,
  contentType: "application/json",
  body: JSON.stringify(body),
});

const version = (number, service, attributes = {}) => ({
  Version: number,
  Target: "java-extension",
  Action: "PUBLISHED",
  Body: "{}",
  UpdatedAt: `2026-07-${18 + number}T10:00:00Z`,
  Selector: {
    Services: [service],
    InstanceUIDs: [],
    Attributes: attributes,
  },
});

test("saved PostgreSQL versions can be searched by name, version and selector", async ({ page }) => {
  const responses = new Map([
    ["/api/agents", []],
    ["/api/configs", {
      "cambistapp-approved": [
        version(1, "exchange-service"),
        version(2, "exchange-service", {
          "deployment.environment.name": "local",
        }),
      ],
      "rates-policy": [version(1, "rates-service")],
    }],
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

  const search = page.getByRole("searchbox", { name: "Buscar versión guardada" });
  const versions = page.getByRole("combobox", {
    name: "Versión guardada en PostgreSQL",
  });

  await expect(versions.locator("option:not([value=''])")).toHaveCount(3);
  await search.fill("cambistapp v2 deployment.environment.name=local");
  await expect(versions.locator("option:not([value=''])")).toHaveCount(1);
  await expect(versions.locator("option:not([value=''])")).toContainText(
    "cambistapp-approved · v2",
  );

  await versions.selectOption("cambistapp-approved::2");
  await expect(page.getByText("Servicios: exchange-service")).toBeVisible();
  await expect(page.getByText("Atributos: deployment.environment.name=local")).toBeVisible();
});
