const stringValue = (value, fallback = "") => {
  if (value === undefined || value === null) return fallback;
  return String(value);
};

const firstValue = (source, keys, fallback = "") => {
  for (const key of keys) {
    if (source?.[key] !== undefined && source[key] !== null) return source[key];
  }
  return fallback;
};

export const identityPermissions = (identity = {}) =>
  firstValue(identity, ["permissions", "Permissions"], []);

export const identityRoles = (identity = {}) =>
  firstValue(identity, ["roles", "Roles"], []);

export const canManageSecurity = (identity = {}) => {
  const permissions = identityPermissions(identity);
  const roles = identityRoles(identity);
  return permissions.includes("*") ||
    permissions.includes("auth.admin") ||
    roles.some((role) => ["admin", "security-admin"].includes(role));
};

export const canManageEmail = (identity = {}) => {
  const permissions = identityPermissions(identity);
  return permissions.includes("*") ||
    permissions.includes("settings.email.view") ||
    permissions.includes("settings.email.edit");
};

export const canEditEmail = (identity = {}) => {
  const permissions = identityPermissions(identity);
  return permissions.includes("*") || permissions.includes("settings.email.edit");
};

export const normalizeProfile = (profile = {}, identity = {}) => ({
  username: stringValue(firstValue(profile, ["username", "Username"],
    firstValue(identity, ["username", "Username"]))),
  firstName: stringValue(firstValue(profile, ["firstName", "FirstName"])),
  lastName: stringValue(firstValue(profile, ["lastName", "LastName"])),
  email: stringValue(firstValue(profile, ["email", "Email"])),
  provider: stringValue(firstValue(profile, ["provider", "Provider"],
    firstValue(identity, ["provider", "Provider"], "local"))),
  roles: firstValue(profile, ["roles", "Roles"], identityRoles(identity)),
  permissions: firstValue(
    profile,
    ["permissions", "Permissions"],
    identityPermissions(identity),
  ),
});

export const profilePayload = (profile = {}, currentPassword = "") => ({
  firstName: stringValue(profile.firstName).trim(),
  lastName: stringValue(profile.lastName).trim(),
  email: stringValue(profile.email).trim().toLowerCase(),
  ...(currentPassword ? { currentPassword } : {}),
});

export const validateProfile = (profile = {}) => {
  const errors = [];
  const payload = profilePayload(profile);
  if (!payload.firstName) errors.push("El nombre es obligatorio.");
  if (!payload.lastName) errors.push("Los apellidos son obligatorios.");
  if (payload.firstName.length > 120 || payload.lastName.length > 120) {
    errors.push("Nombre y apellidos admiten hasta 120 caracteres.");
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email)) {
    errors.push("Ingresa un correo electrónico válido.");
  }
  return errors;
};

export const validatePasswordChange = ({
  currentPassword = "",
  newPassword = "",
  confirmPassword = "",
} = {}) => {
  const errors = [];
  if (!currentPassword) errors.push("Ingresa tu contraseña actual.");
  if (newPassword.length < 12) {
    errors.push("La nueva contraseña debe tener al menos 12 caracteres.");
  }
  if (new TextEncoder().encode(newPassword).length > 72) {
    errors.push("La nueva contraseña admite hasta 72 bytes.");
  }
  if (newPassword && newPassword === currentPassword) {
    errors.push("La nueva contraseña debe ser diferente de la actual.");
  }
  if (newPassword !== confirmPassword) {
    errors.push("La confirmación no coincide con la nueva contraseña.");
  }
  return errors;
};

export const passwordResetToken = (search = "", hash = "") => {
  const fragment = new URLSearchParams(String(hash).replace(/^#/, ""));
  return fragment.get("token") || "";
};

export const emptyEmailSettings = () => ({
  enabled: false,
  provider: "SMTP",
  fromName: "o11y Control Plane",
  fromAddress: "",
  smtp: {
    host: "",
    port: 587,
    username: "",
    password: "",
    tlsMode: "STARTTLS",
  },
  awsSes: {
    region: "",
    accessKeyId: "",
    secretAccessKey: "",
    sessionToken: "",
    endpoint: "",
  },
  azureAcs: {
    endpoint: "",
    accessKey: "",
    apiVersion: "2025-09-01",
  },
  secretsConfigured: {
    smtpPassword: false,
    awsSecretAccessKey: false,
    awsSessionToken: false,
    azureAccessKey: false,
  },
  credentialsUnavailable: false,
  clearSecrets: false,
});

export const normalizeEmailSettings = (settings = {}) => {
  const defaults = emptyEmailSettings();
  return {
    ...defaults,
    ...settings,
    enabled: settings.enabled === true,
    provider: ["SMTP", "AWS_SES", "AZURE_ACS"].includes(settings.provider)
      ? settings.provider
      : defaults.provider,
    smtp: { ...defaults.smtp, ...(settings.smtp || {}), password: "" },
    awsSes: {
      ...defaults.awsSes,
      ...(settings.awsSes || {}),
      secretAccessKey: "",
      sessionToken: "",
    },
    azureAcs: { ...defaults.azureAcs, ...(settings.azureAcs || {}), accessKey: "" },
    secretsConfigured: {
      ...defaults.secretsConfigured,
      ...(settings.secretsConfigured || {}),
    },
    credentialsUnavailable: settings.credentialsUnavailable === true,
    clearSecrets: settings.credentialsUnavailable === true || settings.clearSecrets === true,
  };
};

export const emailSettingsPayload = (settings = {}) => {
  const normalized = normalizeEmailSettings(settings);
  return {
    enabled: normalized.enabled,
    provider: normalized.provider,
    fromName: normalized.fromName.trim(),
    fromAddress: normalized.fromAddress.trim().toLowerCase(),
    smtp: {
      host: normalized.smtp.host.trim(),
      port: Number(normalized.smtp.port) || 0,
      username: normalized.smtp.username.trim(),
      password: stringValue(settings.smtp?.password),
      tlsMode: normalized.smtp.tlsMode,
    },
    awsSes: {
      region: normalized.awsSes.region.trim(),
      accessKeyId: normalized.awsSes.accessKeyId.trim(),
      secretAccessKey: stringValue(settings.awsSes?.secretAccessKey),
      sessionToken: stringValue(settings.awsSes?.sessionToken),
      endpoint: normalized.awsSes.endpoint.trim(),
    },
    azureAcs: {
      endpoint: normalized.azureAcs.endpoint.trim(),
      accessKey: stringValue(settings.azureAcs?.accessKey),
      apiVersion: normalized.azureAcs.apiVersion.trim(),
    },
    ...(settings.updatedAt ? { expectedUpdatedAt: settings.updatedAt } : {}),
    ...(settings.clearSecrets === true ? { clearSecrets: true } : {}),
  };
};

export const validateEmailSettings = (settings = {}) => {
  const errors = [];
  const payload = emailSettingsPayload(settings);
  const preservedSecrets = settings.clearSecrets ? {} : settings.secretsConfigured || {};
  if (!payload.enabled) return errors;
  if (!payload.fromName) errors.push("El nombre del remitente es obligatorio.");
  if (payload.fromName.length > 128) errors.push("El nombre del remitente admite hasta 128 caracteres.");
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.fromAddress)) {
    errors.push("Ingresa una dirección de remitente válida.");
  }
  if (payload.provider === "SMTP") {
    if (!/^[A-Za-z0-9.-]+$/.test(payload.smtp.host)) errors.push("Ingresa un host SMTP válido.");
    if (payload.smtp.port < 1 || payload.smtp.port > 65535) {
      errors.push("El puerto SMTP debe estar entre 1 y 65535.");
    }
    if (payload.smtp.username && !payload.smtp.password &&
        !preservedSecrets.smtpPassword) {
      errors.push("La contraseña SMTP es obligatoria.");
    }
    if (!payload.smtp.username && (payload.smtp.password ||
        preservedSecrets.smtpPassword)) {
      errors.push("Ingresa el usuario SMTP o elimina también su contraseña guardada.");
    }
    if (payload.smtp.tlsMode === "NONE" &&
        !["localhost", "127.0.0.1", "::1"].includes(payload.smtp.host.toLowerCase())) {
      errors.push("SMTP sin TLS sólo se permite para pruebas locales.");
    }
  }
  if (payload.provider === "AWS_SES") {
    if (!/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(payload.awsSes.region)) {
      errors.push("Ingresa una región válida de AWS SES.");
    }
    if (!payload.awsSes.accessKeyId) errors.push("El access key ID de AWS es obligatorio.");
    if (!payload.awsSes.secretAccessKey &&
        !preservedSecrets.awsSecretAccessKey) {
      errors.push("El secret access key de AWS es obligatorio.");
    }
  }
  if (payload.provider === "AZURE_ACS") {
    if (!payload.azureAcs.endpoint) errors.push("El endpoint de Azure ACS es obligatorio.");
    if (!payload.azureAcs.accessKey && !preservedSecrets.azureAccessKey) {
      errors.push("La access key de Azure ACS es obligatoria.");
    }
    if (payload.azureAcs.apiVersion !== "2025-09-01") {
      errors.push("La API version de Azure ACS debe ser 2025-09-01.");
    }
  }
  return errors;
};

export const normalizeUser = (user = {}) => ({
  username: stringValue(firstValue(user, ["username", "Username"])),
  firstName: stringValue(firstValue(user, ["firstName", "FirstName"])),
  lastName: stringValue(firstValue(user, ["lastName", "LastName"])),
  email: stringValue(firstValue(user, ["email", "Email"])),
  roles: firstValue(user, ["roles", "Roles"], []),
  active: firstValue(user, ["active", "Active"], true) !== false,
  root: firstValue(user, ["root", "Root"], false) === true,
  createdAt: firstValue(user, ["createdAt", "CreatedAt"], ""),
  updatedAt: firstValue(user, ["updatedAt", "UpdatedAt"], ""),
  revision: Number(firstValue(user, ["revision", "Revision"], 0)) || 0,
});

export const userPayload = (user = {}, includePassword = false) => ({
  username: stringValue(user.username).trim().toLowerCase(),
  firstName: stringValue(user.firstName).trim(),
  lastName: stringValue(user.lastName).trim(),
  email: stringValue(user.email).trim().toLowerCase(),
  roles: Array.isArray(user.roles) ? user.roles.filter(Boolean) : [],
  active: user.active !== false,
  ...(includePassword ? { password: stringValue(user.password) } : {}),
  ...(!includePassword ? { revision: Number(user.revision) || 0 } : {}),
});

export const validateUser = (user = {}, includePassword = false) => {
  const payload = userPayload(user, includePassword);
  const errors = [];
  if (!/^[a-z0-9][a-z0-9._-]{2,63}$/.test(payload.username)) {
    errors.push("El usuario debe tener entre 3 y 64 caracteres: minúsculas, números, punto, guion o guion bajo.");
  }
  if (!payload.firstName) errors.push("El nombre es obligatorio.");
  if (!payload.lastName) errors.push("Los apellidos son obligatorios.");
  if (payload.firstName.length > 120 || payload.lastName.length > 120) {
    errors.push("Nombre y apellidos admiten hasta 120 caracteres.");
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(payload.email)) {
    errors.push("Ingresa un correo electrónico válido.");
  }
  if (!payload.roles.length) errors.push("Asigna al menos un rol.");
  if (!includePassword && payload.revision <= 0) {
    errors.push("Recarga el usuario antes de guardar para obtener su revisión actual.");
  }
  if (includePassword && (payload.password.length < 12 ||
      new TextEncoder().encode(payload.password).length > 72)) {
    errors.push("La contraseña inicial debe tener al menos 12 caracteres y hasta 72 bytes.");
  }
  return errors;
};
