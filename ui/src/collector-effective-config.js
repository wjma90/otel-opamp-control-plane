const yamlIndent = (line) => line.match(/^\s*/)?.[0].length || 0;

const yamlMappingBlock = (lines, path) => {
  let searchStart = 0;
  let searchEnd = lines.length;
  let parentIndent = -1;
  let block = null;

  for (const key of path) {
    block = null;
    for (let index = searchStart; index < searchEnd; index += 1) {
      const line = lines[index];
      if (!line.trim() || line.trimStart().startsWith("#")) continue;
      const indent = yamlIndent(line);
      if (indent <= parentIndent || line.trim() !== `${key}:`) continue;
      let end = index + 1;
      while (
        end < searchEnd &&
        (!lines[end].trim() || yamlIndent(lines[end]) > indent)
      ) {
        end += 1;
      }
      block = { start: index, end, indent };
      break;
    }
    if (!block) return null;
    searchStart = block.start + 1;
    searchEnd = block.end;
    parentIndent = block.indent;
  }
  return block;
};

const removeYamlMappingPath = (lines, path) => {
  const block = yamlMappingBlock(lines, path);
  if (!block) return false;
  lines.splice(block.start, block.end - block.start);
  return true;
};

const removeYamlListValue = (lines, path, value) => {
  const block = yamlMappingBlock(lines, path);
  if (!block) return false;
  let removed = false;
  for (let index = block.end - 1; index > block.start; index -= 1) {
    if (lines[index].trim() === `- ${value}`) {
      lines.splice(index, 1);
      removed = true;
    }
  }
  return removed;
};

const removeYamlNullKey = (lines, path, key) => {
  const block = yamlMappingBlock(lines, path);
  if (!block) return false;
  let removed = false;
  for (let index = block.end - 1; index > block.start; index -= 1) {
    if (lines[index].trim() === `${key}: null`) {
      lines.splice(index, 1);
      removed = true;
    }
  }
  return removed;
};

export const sanitizeEffectiveCollectorConfig = (body) => {
  const lines = String(body || "").replace(/\r\n/g, "\n").split("\n");
  const removed = [];
  if (removeYamlMappingPath(lines, ["service", "telemetry", "resource"])) {
    removed.push("service.telemetry.resource");
  }
  if (removeYamlMappingPath(lines, ["extensions", "opamp"])) {
    removed.push("extensions.opamp");
  }
  if (removeYamlListValue(lines, ["service", "extensions"], "opamp")) {
    removed.push("service.extensions[opamp]");
  }
  for (const key of ["http", "grpc"]) {
    if (removeYamlNullKey(lines, ["extensions", "health_check"], key)) {
      removed.push(`extensions.health_check.${key}=null`);
    }
  }
  return {
    body: `${lines.join("\n").trimEnd()}\n`,
    removed,
  };
};

export const collectorConfigId = (agent) => {
  const slug = (value) =>
    String(value || "")
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "");
  const cluster = slug(agent.Attributes?.["k8s.cluster.name"]);
  const role = slug(agent.Attributes?.["collector.role"]);
  const service = slug(agent.Service).replace(/-supervisor$/, "");
  return [cluster || service || "collector", role || "config", "config"]
    .filter((value, index, values) => value && values.indexOf(value) === index)
    .join("-");
};
