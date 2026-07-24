import { identityPermissions } from "./account-settings.js";

const stringValue = (value) => {
  if (value === undefined || value === null) return "";
  return String(value).trim();
};

const uniqueStrings = (value) => {
  if (!Array.isArray(value)) return [];
  return [...new Set(value.map(stringValue).filter(Boolean))];
};

export const canViewNetwork = (identity = {}) => {
  const permissions = identityPermissions(identity);
  return permissions.includes("*") || permissions.includes("agents.view");
};

export const normalizeNetworkSettings = (payload = {}) => ({
  publicUrl: stringValue(payload.publicUrl),
  publicUrlSource: ["SERVER_PUBLIC_URL", "AUTH_PUBLIC_URL", "request"].includes(
    payload.publicUrlSource,
  )
    ? payload.publicUrlSource
    : "request",
  opampPublicUrl: stringValue(payload.opampPublicUrl),
  trustedProxyCidrs: uniqueStrings(payload.trustedProxyCidrs),
  proxyMode: payload.proxyMode === "TRUSTED" ? "TRUSTED" : "DIRECT",
  httpListenAddress: stringValue(payload.httpListenAddress),
  opampListenAddress: stringValue(payload.opampListenAddress),
  subpathSupported: payload.subpathSupported === true,
  publicUrlValid: payload.publicUrlValid === true,
});

export const publicUrlSourceDetails = (source) => {
  switch (source) {
    case "SERVER_PUBLIC_URL":
      return {
        label: "SERVER_PUBLIC_URL",
        detail: "Configuración actual recomendada.",
        legacy: false,
      };
    case "AUTH_PUBLIC_URL":
      return {
        label: "AUTH_PUBLIC_URL",
        detail: "Variable heredada mantenida por compatibilidad.",
        legacy: true,
      };
    default:
      return {
        label: "Solicitud entrante",
        detail: "Fallback calculado desde la petición actual.",
        legacy: false,
      };
  }
};

export const proxyModeDetails = (mode) => mode === "TRUSTED"
  ? {
      label: "Proxy confiable",
      detail: "Los headers forwarded sólo se aceptan desde los CIDR configurados.",
    }
  : {
      label: "Acceso directo",
      detail: "La URL pública no depende de headers forwarded del proxy.",
    };
