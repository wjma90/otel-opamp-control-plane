import assert from "node:assert/strict";
import test from "node:test";
import {
  canViewNetwork,
  normalizeNetworkSettings,
  proxyModeDetails,
  publicUrlSourceDetails,
} from "./network-settings.js";

test("normalizes the canonical network diagnostics contract", () => {
  assert.deepEqual(normalizeNetworkSettings({
    publicUrl: " https://o11y.example.test ",
    publicUrlSource: "SERVER_PUBLIC_URL",
    opampPublicUrl: "https://opamp.example.test/v1/opamp",
    trustedProxyCidrs: ["10.0.0.0/8", " 10.0.0.0/8 ", "192.168.0.0/16", ""],
    proxyMode: "TRUSTED",
    httpListenAddress: ":8080",
    opampListenAddress: ":4320",
    subpathSupported: false,
    publicUrlValid: true,
  }), {
    publicUrl: "https://o11y.example.test",
    publicUrlSource: "SERVER_PUBLIC_URL",
    opampPublicUrl: "https://opamp.example.test/v1/opamp",
    trustedProxyCidrs: ["10.0.0.0/8", "192.168.0.0/16"],
    proxyMode: "TRUSTED",
    httpListenAddress: ":8080",
    opampListenAddress: ":4320",
    subpathSupported: false,
    publicUrlValid: true,
  });
});

test("uses safe display defaults for an incomplete response", () => {
  const network = normalizeNetworkSettings({
    publicUrlSource: "unknown",
    proxyMode: "unknown",
    trustedProxyCidrs: "10.0.0.0/8",
    subpathSupported: "true",
    publicUrlValid: "true",
  });

  assert.equal(network.publicUrlSource, "request");
  assert.equal(network.proxyMode, "DIRECT");
  assert.deepEqual(network.trustedProxyCidrs, []);
  assert.equal(network.subpathSupported, false);
  assert.equal(network.publicUrlValid, false);
});

test("labels the legacy URL source and trusted proxy mode explicitly", () => {
  assert.deepEqual(publicUrlSourceDetails("AUTH_PUBLIC_URL"), {
    label: "AUTH_PUBLIC_URL",
    detail: "Variable heredada mantenida por compatibilidad.",
    legacy: true,
  });
  assert.equal(proxyModeDetails("TRUSTED").label, "Proxy confiable");
  assert.equal(publicUrlSourceDetails("request").label, "Solicitud entrante");
});

test("allows network diagnostics only with agents.view or wildcard", () => {
  assert.equal(canViewNetwork({ permissions: ["agents.view"] }), true);
  assert.equal(canViewNetwork({ Permissions: ["*"] }), true);
  assert.equal(canViewNetwork({ permissions: ["settings.email.view"] }), false);
});
