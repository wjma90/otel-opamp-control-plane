import assert from "node:assert/strict";
import test from "node:test";
import {
  callbackURL,
  createLatestRequestGate,
  normalizeProvider,
  providerLoginEnabled,
  providerPayload,
  providerProtocol,
  providerStatus,
  roleMappingsPayload,
  validateProviderDraft,
} from "./auth-providers.js";

test("ignores an authentication response superseded by a newer load", () => {
  const gate = createLatestRequestGate();
  const requestBeforeLogin = gate.begin();
  const requestAfterLogin = gate.begin();
  assert.equal(gate.isCurrent(requestBeforeLogin), false);
  assert.equal(gate.isCurrent(requestAfterLogin), true);
  gate.invalidate();
  assert.equal(gate.isCurrent(requestAfterLogin), false);
});

test("normalizes explicit OIDC and SAML protocols", () => {
  assert.equal(providerProtocol({ protocol: "oidc" }), "OIDC");
  assert.equal(providerProtocol({ Protocol: "SAML" }), "SAML");
  assert.equal(providerProtocol({ protocol: "SAML/OIDC broker" }), "OIDC");
});

test("only enables login after operational validation", () => {
  assert.equal(providerStatus({ configured: true }), "CONFIGURED");
  assert.equal(providerStatus({ enabled: true }), "CONFIGURED");
  assert.equal(providerLoginEnabled({ enabled: true }), false);
  assert.equal(providerLoginEnabled({ enabled: true, status: "CONFIGURED" }), false);
  assert.equal(providerLoginEnabled({ enabled: true, status: "VALIDATED" }), true);
  assert.equal(providerLoginEnabled({ enabled: true, status: "ERROR" }), false);
});

test("calculates protocol-specific callback URLs", () => {
  assert.equal(
    callbackURL({ id: "company", protocol: "SAML" }, "https://cp.example.com/"),
    "https://cp.example.com/api/auth/saml/company/acs",
  );
  assert.equal(
    callbackURL({ id: "google", protocol: "OIDC" }, "https://cp.example.com"),
    "https://cp.example.com/api/auth/oidc/google/callback",
  );
});

test("normalizes provider fields and provider-specific role mappings", () => {
  const provider = normalizeProvider({
    ID: "company",
    Protocol: "SAML",
    Label: "Ingresar con la empresa",
    ValidationStatus: "VALIDATED",
    SPEntityID: "https://cp.example.com/saml/metadata",
    RoleMappings: { "group-observers": "viewer" },
  });
  assert.equal(provider.id, "company");
  assert.equal(provider.protocol, "SAML");
  assert.equal(provider.status, "VALIDATED");
  assert.deepEqual(provider.roleMappings, [
    { externalRole: "group-observers", localRole: "viewer" },
  ]);
});

test("surfaces an encrypted credential that must be replaced", () => {
  const provider = normalizeProvider({
    id: "company",
    protocol: "OIDC",
    credentialsUnavailable: true,
    secretConfigured: false,
  });
  assert.equal(provider.credentialsUnavailable, true);
  assert.equal(provider.secretConfigured, false);
});

test("builds a SAML provider without OIDC-only fields", () => {
  assert.deepEqual(providerPayload({
    protocol: "SAML",
    label: "Empresa",
    spEntityId: "urn:o11y:control-plane",
    metadataUrl: "https://idp.example.com/metadata",
    metadataXml: "",
    callbackUrl: "https://cp.example.com/api/auth/saml/company/acs",
    nameIdAttribute: "NameID",
    userAttribute: "mail",
    roleAttribute: "groups",
  }), {
    protocol: "SAML",
    label: "Empresa",
    roleMappings: {},
    spEntityId: "urn:o11y:control-plane",
    metadataUrl: "https://idp.example.com/metadata",
    metadataXml: "",
    nameIdAttribute: "NameID",
    userAttribute: "mail",
    roleAttribute: "groups",
  });
});

test("round-trips the provider revision for optimistic updates", () => {
  const provider = normalizeProvider({
    id: "company",
    protocol: "OIDC",
    updatedAt: "2026-07-19T12:00:00Z",
    roleMappings: { users: "viewer" },
  });
  assert.equal(provider.updatedAt, "2026-07-19T12:00:00Z");
  assert.equal(providerPayload(provider).expectedUpdatedAt, "2026-07-19T12:00:00Z");
});

test("validates required protocol-specific fields", () => {
  const samlErrors = validateProviderDraft({
    protocol: "SAML",
    label: "Empresa",
    nameIdAttribute: "NameID",
    userAttribute: "mail",
    roleAttribute: "groups",
    roleMappings: [{ externalRole: "users", localRole: "viewer" }],
  });
  assert.deepEqual(samlErrors, [
    "El SP Entity ID es obligatorio.",
    "Ingresa la URL o el XML de metadata del IdP.",
  ]);
  assert.deepEqual(validateProviderDraft({
    protocol: "OIDC",
    label: "Google",
    issuer: "https://accounts.google.com",
    clientId: "client",
    clientSecret: "secret",
    userClaim: "email",
    roleClaim: "roles",
    roleMappings: [{ externalRole: "users", localRole: "viewer" }],
  }), []);
  assert.deepEqual(validateProviderDraft({
    protocol: "OIDC",
    label: "Sin roles",
    issuer: "https://idp.example.com",
    clientId: "client",
    clientSecret: "secret",
    userClaim: "email",
    roleClaim: "groups",
    roleMappings: [],
  }), ["Agrega al menos un mapeo de rol externo a rol local."]);
});

test("drops incomplete role mapping rows", () => {
  assert.deepEqual(roleMappingsPayload([
    { externalRole: "ops", localRole: "collector-editor" },
    { externalRole: "", localRole: "viewer" },
  ]), { ops: "collector-editor" });
});
