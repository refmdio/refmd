import { describe, expect, it, vi } from "vitest";
import type { DocumentState } from "../../model/document-state/types";
import { armSaveAckWatchdog, clearSaveAckWatchdog } from "./outbound-save-watchdog";

function stateWithSending(sending: boolean): DocumentState {
  return {
    sending,
    pendingSaveTimeout: null,
  } as DocumentState;
}

describe("outbound save watchdog", () => {
  it("does not arm after the send has already resolved", () => {
    vi.useFakeTimers();
    try {
      const state = stateWithSending(false);
      const onTimeout = vi.fn();

      armSaveAckWatchdog(state, onTimeout, "update");

      expect(state.pendingSaveTimeout).toBeNull();
      vi.advanceTimersByTime(15_000);
      expect(onTimeout).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("clears an armed watchdog", () => {
    vi.useFakeTimers();
    try {
      const state = stateWithSending(true);
      const onTimeout = vi.fn();

      armSaveAckWatchdog(state, onTimeout, "snapshot");
      expect(state.pendingSaveTimeout).not.toBeNull();
      clearSaveAckWatchdog(state);

      expect(state.pendingSaveTimeout).toBeNull();
      vi.advanceTimersByTime(15_000);
      expect(onTimeout).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });
});
