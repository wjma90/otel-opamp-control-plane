import { expect, test } from "@playwright/test";
import { readFileSync } from "node:fs";

const requiredEnvironment = (name) => {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required for the deployed Control Plane smoke test`);
  }
  return value;
};

const username = requiredEnvironment("O11Y_E2E_USERNAME");
const password = requiredEnvironment("O11Y_E2E_PASSWORD");
const kubernetesCollectorConfig = readFileSync(
  new URL(
    "../../../cmd/server/testdata/collector-kubernetes-infra.yaml",
    import.meta.url,
  ),
  "utf8",
);

const isGoogleResource = (requestURL) => {
  const hostname = new URL(requestURL).hostname.toLowerCase();
  return hostname === "googleapis.com" ||
    hostname.endsWith(".googleapis.com") ||
    hostname === "gstatic.com" ||
    hostname.endsWith(".gstatic.com") ||
    hostname === "googleusercontent.com" ||
    hostname.endsWith(".googleusercontent.com");
};

const observeBrowserFailures = (page) => {
  const pageErrors = [];
  const consoleErrors = [];
  const googleResources = [];
  const state = { authenticated: false };

  page.on("pageerror", (error) => pageErrors.push(error.message));
  page.on("console", (message) => {
    const text = message.text();
    if (
      message.type() === "error" &&
      (state.authenticated || text.includes("Content Security Policy"))
    ) {
      consoleErrors.push(text);
    }
  });
  page.on("request", (request) => {
    if (isGoogleResource(request.url())) googleResources.push(request.url());
  });

  return {
    markAuthenticated: () => {
      state.authenticated = true;
    },
    assertClean: () => {
      expect(pageErrors, "uncaught browser errors").toEqual([]);
      expect(consoleErrors, "console errors").toEqual([]);
      expect(googleResources, "Google-hosted runtime resources").toEqual([]);
    },
  };
};

const login = async (page, path) => {
  const documentResponse = await page.goto(path, {
    waitUntil: "domcontentloaded",
  });
  expect(documentResponse?.ok(), "the deployed UI document must be reachable").toBeTruthy();

  await expect(page).toHaveTitle("O11Y Control Plane");
  await expect(page.getByRole("heading", { name: "Accede al Control Plane" })).toBeVisible();
  await page.getByLabel("Usuario", { exact: true }).fill(username);
  await page.getByLabel("Contraseña", { exact: true }).fill(password);

  const [loginResponse] = await Promise.all([
    page.waitForResponse((response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/api/auth/login"),
    page.getByRole("button", { name: "Ingresar", exact: true }).click(),
  ]);
  expect(
    loginResponse.ok(),
    `local login returned HTTP ${loginResponse.status()}`,
  ).toBeTruthy();
};

test("the deployed Control Plane logs in and renders Fleet without browser failures", async ({ page }) => {
  const browser = observeBrowserFailures(page);
  await login(page, "/?tab=agents");
  browser.markAuthenticated();

  await expect(page.getByRole("heading", { name: "Clientes OpAMP" })).toBeVisible();
  // Fleet polls continuously, so this page intentionally never reaches networkidle.
  await page.waitForTimeout(1_000);

  await expect(page.locator("#root")).not.toBeEmpty();
  browser.assertClean();
});

test("the deployed Control Plane renders an empty remote-management state", async ({ page }) => {
  const browser = observeBrowserFailures(page);
  await login(page, "/remote-management");
  browser.markAuthenticated();

  await expect(page.getByRole("heading", {
    name: "Policies y configuraciones",
  })).toBeVisible();
  await expect(page.getByText(
    "No hay configuraciones Collector administradas que coincidan.",
  )).toBeVisible();
  await expect(page.getByText("No hay policies que coincidan.")).toBeVisible();
  await expect(page.locator("#root")).not.toBeEmpty();
  browser.assertClean();
});

test("the deployed UI validates Kubernetes infrastructure Collector YAML", async ({ page }) => {
  const browser = observeBrowserFailures(page);
  await login(page, "/policy-studio");
  browser.markAuthenticated();

  await expect(page.getByRole("heading", {
    name: "Editor OTel",
  })).toBeVisible();
  await page.locator(".scope-card").filter({ hasText: "Collector" }).click();
  await page.getByLabel("ID de configuración").fill("e2e-kubernetes-infra");
  await page.getByRole("button", { name: /Continuar: Edición/ }).click();
  await page.locator("textarea.code.extra-large").fill(kubernetesCollectorConfig);

  const [validationResponse] = await Promise.all([
    page.waitForResponse((response) =>
      response.request().method() === "POST" &&
      new URL(response.url()).pathname === "/api/configs/validate"),
    page.getByRole("button", {
      name: "Validar YAML con Collector",
      exact: true,
    }).click(),
  ]);
  expect(
    validationResponse.ok(),
    `Collector validation returned HTTP ${validationResponse.status()}`,
  ).toBeTruthy();
  await expect(page.getByText("YAML válido", { exact: true })).toBeVisible();
  await expect(page.getByText("otelcol-contrib 0.156.0", { exact: true })).toBeVisible();
  browser.assertClean();
});
