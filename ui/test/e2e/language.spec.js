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

  const sidebar = page.locator("aside");
  const remoteManagement = page.getByRole("button", { name: "Remote management" });
  const remoteManagementLabel = remoteManagement.locator(".nav-label");
  const protocolDetail = page.getByText(
    "Agents and Supervisors: HTTP · 10s",
    { exact: true },
  );
  await expect(remoteManagement).toBeVisible();
  await expect(protocolDetail).toBeVisible();
  await remoteManagement.click();
  await expect(remoteManagement).toHaveClass(/\bactive\b/);

  const layout = await page.evaluate(() => {
    const sidebarElement = document.querySelector("aside");
    const remoteElement = [...document.querySelectorAll("nav button")]
      .find((button) => button.textContent.includes("Remote management"));
    const remoteLabelElement = remoteElement?.querySelector(".nav-label");
    const protocolElement = [...document.querySelectorAll(".protocol small")]
      .find((element) => element.textContent.includes("Agents and Supervisors"));
    const sidebarBounds = sidebarElement.getBoundingClientRect();
    const remoteBounds = remoteElement.getBoundingClientRect();

    return {
      sidebarWidth: sidebarBounds.width,
      remoteContained: remoteBounds.right <= sidebarBounds.right,
      remoteLabelFits:
        remoteLabelElement.scrollWidth <= remoteLabelElement.clientWidth,
      protocolFits: protocolElement.scrollWidth <= protocolElement.clientWidth,
      protocolWhiteSpace: getComputedStyle(protocolElement).whiteSpace,
    };
  });

  await expect(sidebar).toHaveCSS("width", "288px");
  await expect(remoteManagementLabel).toHaveText("Remote management");
  expect(layout).toEqual({
    sidebarWidth: 288,
    remoteContained: true,
    remoteLabelFits: true,
    protocolFits: true,
    protocolWhiteSpace: "nowrap",
  });

  await page.getByRole("button", { name: /^Agents:/ }).click();
  await page.reload();
  await expect(page.getByRole("heading", { name: "OpAMP clients" })).toBeVisible();
  await expect(page.getByRole("combobox", { name: "Change language" })).toHaveValue("en");
});
