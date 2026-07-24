import assert from "node:assert/strict";
import test from "node:test";
import { tabFromLocation, urlForTab } from "./navigation.js";

test("maps every stable path to its Control Plane view", () => {
  assert.equal(tabFromLocation({ pathname: "/policy-studio" }), "policy");
  assert.equal(tabFromLocation({ pathname: "/agents/" }), "agents");
  assert.equal(tabFromLocation({ pathname: "/remote-management" }), "deployments");
  assert.equal(tabFromLocation({ pathname: "/versions" }), "history");
  assert.equal(tabFromLocation({ pathname: "/profile" }), "profile");
  assert.equal(tabFromLocation({ pathname: "/settings" }), "settings");
});

test("keeps legacy query links and safely defaults unknown paths", () => {
  assert.equal(tabFromLocation({ pathname: "/", search: "?tab=agents" }), "agents");
  assert.equal(tabFromLocation({ pathname: "/", search: "?tab=security" }), "settings");
  assert.equal(tabFromLocation({ pathname: "/not-a-view" }), "policy");
});

test("creates canonical URLs and only preserves Policy Studio state", () => {
  assert.equal(
    urlForTab("policy", "?tab=agents&target=collector&step=3"),
    "/policy-studio?target=collector&step=3",
  );
  assert.equal(urlForTab("agents", "?target=collector&step=3"), "/agents");
  assert.equal(urlForTab("deployments"), "/remote-management");
  assert.equal(urlForTab("unknown"), "/policy-studio");
});
