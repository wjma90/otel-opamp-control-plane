import { useEffect, useId, useMemo, useRef, useState } from "react";
import {
  normalizeSelection,
  selectionSummary,
  toggleSelection,
} from "../multi-select-filter.js";
import { useI18n } from "../i18n.js";

const normalizedOptions = (options) => (options || [])
  .map((option) => typeof option === "string"
    ? { value: option, label: option }
    : {
      value: String(option?.value || ""),
      label: String(option?.label || option?.value || ""),
    })
  .filter((option) => option.value);

export function MultiSelectFilter({
  label,
  options = [],
  values = [],
  onChange,
  allLabel = "Todos",
  disabled = false,
}) {
  const { t } = useI18n();
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);
  const triggerRef = useRef(null);
  const firstOptionRef = useRef(null);
  const labelID = useId();
  const panelID = useId();
  const summaryID = useId();
  const items = useMemo(() => normalizedOptions(options), [options]);
  const selected = normalizeSelection(values);
  const localizedAllLabel = t(allLabel);
  const summary = selectionSummary(selected, items, localizedAllLabel);

  const close = (restoreFocus = false) => {
    setOpen(false);
    if (restoreFocus) {
      window.requestAnimationFrame(() => triggerRef.current?.focus());
    }
  };

  useEffect(() => {
    if (!open) return undefined;

    const focusFrame = window.requestAnimationFrame(() => {
      firstOptionRef.current?.focus();
    });
    const handlePointerDown = (event) => {
      if (!rootRef.current?.contains(event.target)) close(false);
    };
    const handleKeyDown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        close(true);
      }
    };

    document.addEventListener("pointerdown", handlePointerDown);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      window.cancelAnimationFrame(focusFrame);
      document.removeEventListener("pointerdown", handlePointerDown);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [open]);

  useEffect(() => {
    if (disabled && open) setOpen(false);
  }, [disabled, open]);

  return (
    <div className="multi-select-filter" ref={rootRef}>
      <span className="multi-select-filter-label" id={labelID}>{label}</span>
      <button
        ref={triggerRef}
        type="button"
        className={`multi-select-filter-trigger ${open ? "open" : ""}`}
        aria-labelledby={`${labelID} ${summaryID}`}
        aria-haspopup="true"
        aria-expanded={open}
        aria-controls={panelID}
        disabled={disabled}
        onClick={() => setOpen((current) => !current)}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown" && !open) {
            event.preventDefault();
            setOpen(true);
          }
        }}
      >
        <span className="multi-select-filter-summary" id={summaryID}>{summary}</span>
        {selected.length > 1 && (
          <span className="multi-select-filter-count" aria-hidden="true">
            {selected.length}
          </span>
        )}
        <span className="multi-select-filter-chevron" aria-hidden="true">⌄</span>
      </button>

      {open && (
        <div
          className="multi-select-filter-panel"
          id={panelID}
          role="group"
          aria-labelledby={labelID}
        >
          <div className="multi-select-filter-options">
            <label className="multi-select-filter-option all">
              <input
                ref={firstOptionRef}
                type="checkbox"
                checked={selected.length === 0}
                onChange={() => onChange([])}
              />
              <span>{localizedAllLabel}</span>
            </label>
            {items.map((option) => (
              <label className="multi-select-filter-option" key={option.value}>
                <input
                  type="checkbox"
                  checked={selected.includes(option.value)}
                  onChange={(event) => onChange(
                    toggleSelection(selected, option.value, event.target.checked),
                  )}
                />
                <span>{option.label}</span>
              </label>
            ))}
            {!items.length && (
              <small className="multi-select-filter-empty">{t("Sin criterios disponibles")}</small>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default MultiSelectFilter;
