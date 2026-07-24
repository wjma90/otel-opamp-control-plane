const tabPaths = Object.freeze({
  policy: "/policy-studio",
  agents: "/agents",
  deployments: "/remote-management",
  history: "/versions",
  profile: "/profile",
  settings: "/settings",
});

const pathTabs = new Map(
  Object.entries(tabPaths).map(([tab, path]) => [path, tab]),
);

const legacyTabs = new Set(Object.keys(tabPaths));

export const tabFromLocation = ({ pathname = "/", search = "" } = {}) => {
  const normalizedPath = pathname.length > 1
    ? pathname.replace(/\/+$/, "")
    : pathname;
  const pathTab = pathTabs.get(normalizedPath);
  if (pathTab) return pathTab;

  if (normalizedPath === "/") {
    const requestedTab = new URLSearchParams(search).get("tab");
    if (["security", "access"].includes(requestedTab)) return "settings";
    if (legacyTabs.has(requestedTab)) return requestedTab;
  }
  return "policy";
};

export const urlForTab = (tab, search = "") => {
  const safeTab = legacyTabs.has(tab) ? tab : "policy";
  if (safeTab !== "policy") return tabPaths[safeTab];

  const source = new URLSearchParams(search);
  const policyQuery = new URLSearchParams();
  for (const key of ["target", "step"]) {
    if (source.has(key)) policyQuery.set(key, source.get(key));
  }
  const query = policyQuery.toString();
  return `${tabPaths.policy}${query ? `?${query}` : ""}`;
};
