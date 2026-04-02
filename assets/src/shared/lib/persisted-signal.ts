import { createSignal, type Accessor } from "solid-js";

function loadPersistedValue(storageKey: string): string | null {
  try {
    if (typeof localStorage === "undefined") {
      return null;
    }
    return localStorage.getItem(storageKey);
  } catch {
    return null;
  }
}

function persistValue(storageKey: string, value: string | null): void {
  try {
    if (typeof localStorage === "undefined") {
      return;
    }
    if (value) {
      localStorage.setItem(storageKey, value);
    } else {
      localStorage.removeItem(storageKey);
    }
  } catch {
    // Ignore storage errors
  }
}

export function createPersistedSignal(
  storageKey: string,
): [Accessor<string | null>, (value: string | null) => void] {
  const [value, setValue] = createSignal<string | null>(loadPersistedValue(storageKey));

  return [
    value,
    (nextValue) => {
      setValue(nextValue);
      persistValue(storageKey, nextValue);
    },
  ];
}
