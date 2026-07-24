const text = (value) => String(value ?? "").trim();

const compareText = (left, right) =>
  text(left).localeCompare(text(right), undefined, {
    numeric: true,
    sensitivity: "base",
  });

const versionNumber = (version = {}) =>
  Number(version.Version ?? version.version ?? 0);

const configID = (version = {}) =>
  text(version.configId || version.ConfigID || version.ID);

const versionTimestamp = (version = {}) => {
  const value = version.UpdatedAt || version.CreatedAt;
  return value ? Date.parse(value) || 0 : 0;
};

const selectorOf = (version = {}) => version.Selector || version.selector || {};

const selectorValues = (selector = {}, upper, lower) => {
  const value = selector[upper] ?? selector[lower];
  return Array.isArray(value) ? value : [];
};

const selectorAttributes = (selector = {}) =>
  selector.Attributes || selector.attributes || {};

export const compareStoredVersions = (left = {}, right = {}) =>
  versionTimestamp(right) - versionTimestamp(left) ||
  compareText(configID(left), configID(right)) ||
  versionNumber(right) - versionNumber(left);

export const flattenStoredVersions = (configs = {}) =>
  Object.entries(configs)
    .flatMap(([id, versions]) => {
      const list = Array.isArray(versions) ? versions : [];
      const latest = list.reduce(
        (current, version) => Math.max(current, versionNumber(version)),
        0,
      );
      return list.map((version) => ({
        ...version,
        configId: id,
        IsLatest: versionNumber(version) === latest,
      }));
    })
    .sort(compareStoredVersions);

export const storedVersionSelectorSummary = (version = {}) => {
  const selector = selectorOf(version);
  const services = selectorValues(selector, "Services", "services");
  const instances = selectorValues(selector, "InstanceUIDs", "instanceUIDs");
  const attributes = Object.entries(selectorAttributes(selector))
    .sort(([left], [right]) => compareText(left, right))
    .map(([key, value]) => `${key}=${value}`);
  return { services, instances, attributes };
};

export const storedVersionSearchText = (version = {}) => {
  const selector = storedVersionSelectorSummary(version);
  return [
    configID(version),
    versionNumber(version),
    `v${versionNumber(version)}`,
    version.Target,
    version.Action,
    version.CreatedBy,
    version.Hash,
    ...selector.services,
    ...selector.instances,
    ...selector.attributes,
  ]
    .filter((value) => text(value))
    .join(" ")
    .toLowerCase();
};

export const filterStoredVersions = (versions = [], query = "") => {
  const tokens = text(query).toLowerCase().split(/\s+/).filter(Boolean);
  const sorted = [...versions].sort(compareStoredVersions);
  if (!tokens.length) return sorted;
  return sorted.filter((version) => {
    const searchText = storedVersionSearchText(version);
    return tokens.every((token) => searchText.includes(token));
  });
};

export const compareDestinationRecords = (left = {}, right = {}) =>
  compareText(left.ConfigID, right.ConfigID) ||
  Number(right.Version || 0) - Number(left.Version || 0) ||
  compareText(left.Service, right.Service) ||
  compareText(left.AgentUID, right.AgentUID);

export const sortDestinationRecords = (records = []) =>
  [...records].sort(compareDestinationRecords);
