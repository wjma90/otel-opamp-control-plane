const text = (value, fallback = "") => {
  if (value === undefined || value === null) return fallback;
  return String(value);
};

const first = (source, keys, fallback = "") => {
  for (const key of keys) {
    if (source?.[key] !== undefined && source[key] !== null) return source[key];
  }
  return fallback;
};

export const createLatestRequestGate = () => {
  let generation = 0;
  return {
    begin: () => ++generation,
    invalidate: () => { generation += 1; },
    isCurrent: (candidate) => candidate === generation,
  };
};

export const providerProtocol = (provider = {}) => {
  const value = text(first(provider, ["protocol", "Protocol", "type", "Type"], "OIDC"))
    .trim()
    .toUpperCase();
  return value.includes("SAML") && !value.includes("OIDC") ? "SAML" : "OIDC";
};

export const providerStatus = (provider = {}) => {
  const explicit = text(first(provider, [
    "status",
    "Status",
    "validationStatus",
    "ValidationStatus",
  ])).trim().toUpperCase();
  if (["VALIDATED", "CONFIGURED", "ERROR", "INACTIVE"].includes(explicit)) {
    return explicit;
  }
  if (provider.enabled === true || provider.Enabled === true ||
      provider.configured === true || provider.Configured === true) return "CONFIGURED";
  return "INACTIVE";
};

export const providerLoginEnabled = (provider = {}) =>
  (provider.enabled === true || provider.Enabled === true) && providerStatus(provider) === "VALIDATED";

export const callbackURL = (provider, origin = "") => {
  const configured = first(provider, [
    "callbackUrl",
    "callbackURL",
    "CallbackURL",
    "acsUrl",
    "acsURL",
    "ACSURL",
  ]);
  if (configured) return configured;
  const id = encodeURIComponent(text(first(provider, ["id", "ID"])).trim());
  const path = providerProtocol(provider) === "SAML"
    ? `/api/auth/saml/${id}/acs`
    : `/api/auth/oidc/${id}/callback`;
  return `${text(origin).replace(/\/$/, "")}${path}`;
};

export const normalizeRoleMappings = (value) => {
  if (Array.isArray(value)) {
    return value.map((mapping) => ({
      externalRole: text(first(mapping, ["externalRole", "ExternalRole", "external", "External"])),
      localRole: text(first(mapping, ["localRole", "LocalRole", "local", "Local"], "viewer")),
    }));
  }
  if (value && typeof value === "object") {
    return Object.entries(value).map(([externalRole, localRole]) => ({
      externalRole,
      localRole: text(localRole),
    }));
  }
  return [];
};

export const normalizeProvider = (provider = {}, model = {}) => {
  const id = text(first(provider, ["id", "ID", "providerId", "ProviderID"])).trim();
  const providerMappings = first(provider, ["roleMappings", "RoleMappings"], null)
    ?? model?.providerRoleMappings?.[id]
    ?? model?.roleMappingsByProvider?.[id]
    ?? model?.roleMappings?.[id]
    ?? {};
  return {
    id,
    label: text(first(provider, ["label", "Label"], id)),
    protocol: providerProtocol(provider),
    status: providerStatus(provider),
    validationMessage: text(first(provider, [
      "validationMessage",
      "ValidationMessage",
      "lastError",
      "LastError",
    ])),
    issuer: text(first(provider, ["issuer", "Issuer"])),
    clientId: text(first(provider, ["clientId", "ClientID"])),
    secretConfigured: first(provider, ["secretConfigured", "SecretConfigured"], false) === true,
    credentialsUnavailable: first(provider, [
      "credentialsUnavailable",
      "CredentialsUnavailable",
    ], false) === true,
    userClaim: text(first(provider, ["userClaim", "UserClaim"], "preferred_username")),
    roleClaim: text(first(provider, ["roleClaim", "RoleClaim"], "roles")),
    userAttribute: text(first(provider, ["userAttribute", "UserAttribute"], "")),
    roleAttribute: text(first(provider, ["roleAttribute", "RoleAttribute"], "")),
    spEntityId: text(first(provider, ["spEntityId", "spEntityID", "SPEntityID"])),
    metadataUrl: text(first(provider, ["metadataUrl", "metadataURL", "MetadataURL"])),
    metadataXml: text(first(provider, ["metadataXml", "metadataXML", "MetadataXML"])),
    nameIdAttribute: text(first(provider, [
      "nameIdAttribute",
      "nameIDAttribute",
      "NameIDAttribute",
    ])),
    callbackUrl: callbackURL(provider, globalThis?.window?.location?.origin || ""),
    spMetadataUrl: text(first(provider, ["spMetadataUrl", "SPMetadataURL"])),
    enabled: first(provider, ["enabled", "Enabled"], false) === true,
    updatedAt: text(first(provider, ["updatedAt", "UpdatedAt"])),
    roleMappings: normalizeRoleMappings(providerMappings),
    startUrl: text(first(provider, ["startUrl", "StartURL"])),
  };
};

export const roleMappingsPayload = (rows = []) => Object.fromEntries(
  rows
    .map((row) => [text(row.externalRole).trim(), text(row.localRole).trim()])
    .filter(([externalRole, localRole]) => externalRole && localRole),
);

export const providerPayload = (draft) => {
  const common = {
    protocol: draft.protocol,
    label: text(draft.label).trim(),
    roleMappings: roleMappingsPayload(draft.roleMappings),
    ...(draft.updatedAt ? { expectedUpdatedAt: draft.updatedAt } : {}),
  };
  if (draft.protocol === "SAML") {
    return {
      ...common,
      spEntityId: text(draft.spEntityId).trim(),
      metadataUrl: text(draft.metadataUrl).trim(),
      metadataXml: text(draft.metadataXml).trim(),
      nameIdAttribute: text(draft.nameIdAttribute).trim(),
      userAttribute: text(draft.userAttribute).trim(),
      roleAttribute: text(draft.roleAttribute).trim(),
    };
  }
  return {
    ...common,
    issuer: text(draft.issuer).trim().replace(/\/$/, ""),
    clientId: text(draft.clientId).trim(),
    clientSecret: draft.clientSecret || "",
    userClaim: text(draft.userClaim).trim(),
    roleClaim: text(draft.roleClaim).trim(),
  };
};

export const validateProviderDraft = (draft) => {
  const errors = [];
  if (!text(draft.label).trim()) errors.push("El texto del botón es obligatorio.");
  if (!Object.keys(roleMappingsPayload(draft.roleMappings)).length) {
    errors.push("Agrega al menos un mapeo de rol externo a rol local.");
  }
  if (draft.protocol === "SAML") {
    if (!text(draft.spEntityId).trim()) errors.push("El SP Entity ID es obligatorio.");
    if (!text(draft.metadataUrl).trim() && !text(draft.metadataXml).trim()) {
      errors.push("Ingresa la URL o el XML de metadata del IdP.");
    }
  } else {
    if (!text(draft.issuer).trim()) errors.push("El issuer OIDC es obligatorio.");
    if (!text(draft.clientId).trim()) errors.push("El client ID es obligatorio.");
    if (!draft.secretConfigured && !text(draft.clientSecret).trim()) {
      errors.push("El client secret es obligatorio.");
    }
  }
  if (draft.protocol === "SAML") {
    if (!text(draft.userAttribute).trim()) errors.push("El atributo de usuario es obligatorio.");
    if (!text(draft.roleAttribute).trim()) errors.push("El atributo de roles es obligatorio.");
  } else {
    if (!text(draft.userClaim).trim()) errors.push("El claim de usuario es obligatorio.");
    if (!text(draft.roleClaim).trim()) errors.push("El claim de roles es obligatorio.");
  }
  return errors;
};
