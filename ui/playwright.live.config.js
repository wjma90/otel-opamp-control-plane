import { defineConfig, devices } from "@playwright/test";

const requiredEnvironment = (name) => {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required for the deployed Control Plane smoke test`);
  }
  return value;
};

const configuredURL = requiredEnvironment("O11Y_E2E_BASE_URL");
const parsedURL = new URL(configuredURL);
if (!new Set(["http:", "https:"]).has(parsedURL.protocol)) {
  throw new Error("O11Y_E2E_BASE_URL must use http or https");
}

export default defineConfig({
  testDir: "./test/e2e-live",
  fullyParallel: false,
  forbidOnly: true,
  retries: 0,
  workers: 1,
  reporter: "line",
  outputDir: "test-results/live",
  use: {
    baseURL: parsedURL.href,
    screenshot: "only-on-failure",
    trace: "off",
    video: "off",
  },
  projects: [
    {
      name: "deployed-chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
