const optionValue = (option) =>
  typeof option === "object" && option !== null ? option.value : option;

const optionLabel = (option) =>
  typeof option === "object" && option !== null
    ? option.label ?? option.value
    : option;

const normalizedValue = (value) => String(value ?? "").trim();

export const normalizeSelection = (selection) => {
  const values = Array.isArray(selection) ? selection : [selection];
  return [...new Set(values.map(normalizedValue).filter(Boolean))];
};

export const reconcileSelection = (selection, options = []) => {
  const available = new Set(
    options.map(optionValue).map(normalizedValue).filter(Boolean),
  );
  return normalizeSelection(selection).filter((value) => available.has(value));
};

export const toggleSelection = (selection, value, checked) => {
  const normalized = normalizeSelection(selection);
  const candidate = normalizedValue(value);
  if (!candidate) return [];
  if (checked) return normalizeSelection([...normalized, candidate]);
  return normalized.filter((item) => item !== candidate);
};

export const matchesAnySelection = (selection, value) => {
  const selected = normalizeSelection(selection);
  if (!selected.length) return true;
  const candidates = new Set(normalizeSelection(value));
  return selected.some((item) => candidates.has(item));
};

export const selectionSummary = (
  selection,
  options = [],
  allLabel = "Todos",
) => {
  const selected = normalizeSelection(selection);
  if (!selected.length) return allLabel;

  const labels = new Map(
    options.map((option) => [
      normalizedValue(optionValue(option)),
      normalizedValue(optionLabel(option)),
    ]),
  );
  if (selected.length === 1) return labels.get(selected[0]) || selected[0];
  return `${selected.length} seleccionados`;
};
