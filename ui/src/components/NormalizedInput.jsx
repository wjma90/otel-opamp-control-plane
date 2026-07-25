import React, { useEffect, useRef, useState } from "react";

export function NormalizedInput({
  value = "",
  onChange,
  onFocus,
  onBlur,
  ...inputProps
}) {
  const normalizedValue = String(value ?? "");
  const [draft, setDraft] = useState(normalizedValue);
  const editing = useRef(false);

  useEffect(() => {
    if (!editing.current) {
      setDraft(normalizedValue);
    }
  }, [normalizedValue]);

  return (
    <input
      {...inputProps}
      value={draft}
      onFocus={(event) => {
        editing.current = true;
        onFocus?.(event);
      }}
      onChange={(event) => {
        setDraft(event.target.value);
        onChange?.(event);
      }}
      onBlur={(event) => {
        editing.current = false;
        setDraft(normalizedValue);
        onBlur?.(event);
      }}
    />
  );
}
