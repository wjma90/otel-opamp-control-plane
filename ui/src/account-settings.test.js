import assert from "node:assert/strict";
import test from "node:test";
import {
  canEditEmail,
  canManageEmail,
  canManageSecurity,
  emailSettingsPayload,
  normalizeEmailSettings,
  normalizeProfile,
  normalizeUser,
  passwordResetToken,
  profilePayload,
  userPayload,
  validateEmailSettings,
  validatePasswordChange,
  validateProfile,
  validateUser,
} from "./account-settings.js";

test("normalizes profile and emits only editable personal data", () => {
  const profile = normalizeProfile({
    Username: "ana",
    FirstName: "Ana",
    LastName: "Torres",
    Email: "ANA@example.test",
  }, { Provider: "local", Roles: ["viewer"] });
  assert.equal(profile.username, "ana");
  assert.equal(profile.provider, "local");
  assert.deepEqual(profile.roles, ["viewer"]);
  assert.deepEqual(profilePayload(profile), {
    firstName: "Ana",
    lastName: "Torres",
    email: "ana@example.test",
  });
  assert.deepEqual(profilePayload(profile, "current-password"), {
    firstName: "Ana",
    lastName: "Torres",
    email: "ana@example.test",
    currentPassword: "current-password",
  });
});

test("validates profile and strong password confirmation", () => {
  assert.deepEqual(validateProfile({ firstName: "", lastName: "", email: "bad" }), [
    "El nombre es obligatorio.",
    "Los apellidos son obligatorios.",
    "Ingresa un correo electrónico válido.",
  ]);
  assert.deepEqual(validatePasswordChange({
    currentPassword: "old-password",
    newPassword: "new-password-123",
    confirmPassword: "new-password-123",
  }), []);
  assert.match(validatePasswordChange({
    currentPassword: "old-password",
    newPassword: "short",
    confirmPassword: "different",
  }).join(" "), /12 caracteres.*no coincide/);
});

test("reads reset tokens only from URL fragments", () => {
  assert.equal(passwordResetToken("", "#token=fragment-safe"), "fragment-safe");
  assert.equal(passwordResetToken("?token=legacy", "#token=preferred"), "preferred");
  assert.equal(passwordResetToken("?reset_token=abc"), "");
  assert.equal(passwordResetToken("?token=legacy"), "");
  assert.equal(passwordResetToken("?other=value"), "");
});

test("applies RBAC to security and email configuration", () => {
  assert.equal(canManageSecurity({ roles: ["security-admin"] }), true);
  assert.equal(canManageSecurity({ permissions: ["auth.admin"] }), true);
  assert.equal(canManageSecurity({ roles: ["viewer"] }), false);
  assert.equal(canManageEmail({ permissions: ["settings.email.view"] }), true);
  assert.equal(canEditEmail({ permissions: ["settings.email.view"] }), false);
  assert.equal(canEditEmail({ permissions: ["settings.email.edit"] }), true);
});

test("normalizes email secrets without exposing returned values", () => {
  const settings = normalizeEmailSettings({
    enabled: true,
    provider: "SMTP",
    smtp: { host: "mail.example.test", port: 2525, username: "mailer", password: "must-not-survive" },
    secretsConfigured: { smtpPassword: true },
  });
  assert.equal(settings.smtp.password, "");
  assert.equal(settings.secretsConfigured.smtpPassword, true);
  assert.deepEqual(validateEmailSettings({
    ...settings,
    fromName: "o11y",
    fromAddress: "o11y@example.test",
  }), []);
});

test("allows SMTP relay without AUTH credentials", () => {
  const settings = normalizeEmailSettings({
    enabled: true,
    provider: "SMTP",
    fromName: "o11y",
    fromAddress: "o11y@example.test",
    smtp: { host: "mail.example.test", port: 25, username: "", tlsMode: "TLS" },
  });
  assert.deepEqual(validateEmailSettings(settings), []);
});

test("builds provider-specific email settings and validates missing secrets", () => {
  const settings = normalizeEmailSettings({
    enabled: true,
    provider: "AWS_SES",
    fromName: "o11y",
    fromAddress: "notify@example.test",
    awsSes: { region: "us-east-1", accessKeyId: "key" },
  });
  assert.deepEqual(validateEmailSettings(settings), [
    "El secret access key de AWS es obligatorio.",
  ]);
  settings.awsSes.secretAccessKey = "secret";
  const payload = emailSettingsPayload(settings);
  assert.equal(payload.provider, "AWS_SES");
  assert.equal(payload.awsSes.secretAccessKey, "secret");
  assert.equal(payload.smtp.password, "");
});

test("normalizes and validates local users", () => {
  const user = normalizeUser({
    Username: "o11y-admin",
    FirstName: "O11y",
    LastName: "Admin",
    Email: "ADMIN@example.test",
    Roles: ["admin"],
    Root: true,
    Revision: 7,
  });
  assert.equal(user.root, true);
  assert.deepEqual(userPayload(user), {
    username: "o11y-admin",
    firstName: "O11y",
    lastName: "Admin",
    email: "admin@example.test",
    roles: ["admin"],
    active: true,
    revision: 7,
  });
  assert.deepEqual(validateUser({ ...user, password: "valid-password-123" }, true), []);
});
