import { expect, test } from "@playwright/test";

const identity = {
  username: "refresh-regression",
  provider: "local",
  roles: ["admin"],
  permissions: ["*"],
};

const json = (body) => ({
  status: 200,
  contentType: "application/json",
  body: JSON.stringify(body),
});

const agent = (uid, service, lastSeen, policyVersions) => ({
  UID: uid,
  Service: service,
  Kind: "java-extension",
  Transport: "http-poll",
  PollIntervalSeconds: 10,
  LiveStatus: "ONLINE",
  ConfigStatus: "APPLIED",
  ConfigID: "java-policy-set",
  Version: 0,
  PolicyVersions: policyVersions,
  LastSeen: lastSeen,
  Attributes: {
    "service.name": service,
    "k8s.pod.uid": uid,
  },
});

const destination = (uid, service, lastObservedAt) => ({
  ConfigID: "stable-policy",
  Version: 1,
  Target: "java-extension",
  Service: service,
  AgentUID: uid,
  PublishedBy: "refresh-regression",
  PublishedAt: "2026-07-21T12:00:00Z",
  LastObservedAt: lastObservedAt,
  ConnectionStatus: "ONLINE",
  ConfigStatus: "APPLIED",
  Selector: {
    Services: [service],
    InstanceUIDs: [],
    Attributes: {},
  },
  AgentAttributes: {
    "service.name": service,
    "k8s.pod.uid": uid,
  },
  Body: "{}",
});

test("Fleet keeps its visual order and focused search during live refresh", async ({ page }) => {
  let agentRequests = 0;
  let deploymentRequests = 0;

  const alpha = agent(
    "alpha-pod-uid",
    "alpha-service",
    "2026-07-21T12:00:01Z",
    {
      "alpha-amounts": 2,
      "alpha-errors": 3,
    },
  );
  const zulu = agent(
    "zulu-pod-uid",
    "zulu-service",
    "2026-07-21T12:00:02Z",
    {},
  );
  const alphaDestination = destination(
    alpha.UID,
    alpha.Service,
    "2026-07-21T12:00:01Z",
  );
  const zuluDestination = destination(
    zulu.UID,
    zulu.Service,
    "2026-07-21T12:00:02Z",
  );

  const responses = new Map([
    ["/api/configs", {}],
    ["/api/metric-names", []],
    ["/api/audit", []],
    ["/api/storage", { driver: "PostgreSQL", status: "ready" }],
    ["/api/security/denylist", []],
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
    if (path === "/api/agents") {
      agentRequests += 1;
      const body = agentRequests % 2 === 1
        ? [zulu, alpha]
        : [alpha, zulu];
      await route.fulfill(json(body));
      return;
    }
    if (path === "/api/deployments") {
      deploymentRequests += 1;
      const body = deploymentRequests % 2 === 1
        ? [zuluDestination, alphaDestination]
        : [alphaDestination, zuluDestination];
      await route.fulfill(json(body));
      return;
    }
    await route.fulfill(json(responses.get(path) ?? {}));
  });

  await page.goto("/?tab=agents");

  const fleet = page.locator("section.panel").filter({
    has: page.getByRole("heading", { name: "Clientes OpAMP" }),
  });
  const services = fleet.locator(".table .tr:not(.head) > span:first-child > b");
  const search = page.getByRole("searchbox", { name: "Buscar clientes" });

  await expect(services).toHaveText(["alpha-service", "zulu-service"]);
  const alphaRow = fleet.locator(".table .tr:not(.head)").filter({
    hasText: "alpha-service",
  });
  const zuluRow = fleet.locator(".table .tr:not(.head)").filter({
    hasText: "zulu-service",
  });
  await expect(alphaRow.locator("> span:nth-child(5) > b")).toHaveText("2 policies activas");
  await expect(alphaRow.locator("> span:nth-child(5) > small").first()).toHaveText(
    "alpha-amounts · v2 · alpha-errors · v3",
  );
  await expect(zuluRow.locator("> span:nth-child(5) > b")).toHaveText("Sin policies activas");
  await expect(fleet.getByText("java-policy-set · v0")).toHaveCount(0);

  await search.fill("service");
  await search.focus();
  await expect(search).toBeFocused();

  await expect.poll(() => agentRequests, {
    message: "the automatic refresh should poll agents again",
    timeout: 7_000,
  }).toBeGreaterThanOrEqual(2);
  await expect.poll(() => deploymentRequests, {
    message: "the automatic refresh should poll deployments again",
    timeout: 7_000,
  }).toBeGreaterThanOrEqual(2);

  await expect(search).toHaveValue("service");
  await expect(search).toBeFocused();
  await expect(services).toHaveText(["alpha-service", "zulu-service"]);
});
