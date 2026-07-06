import { describe, expect, test } from "vitest";
import {
  shouldReplayCachedPendingChanges,
  shouldTreatCachedStateAsConfirmedBase,
} from "./pending-replay";

describe("offline pending replay", () => {
  test("does not replay pending changes when there is no confirmed cache entry", () => {
    expect(shouldReplayCachedPendingChanges(null, false)).toBe(false);
  });

  test("does not replay pending changes over a live no-baseline cache state", () => {
    expect(
      shouldReplayCachedPendingChanges(
        {
          encryptedStateKind: "live",
          encryptedConfirmedState: null,
          confirmedStateNonce: null,
        },
        false,
      ),
    ).toBe(false);
  });

  test("replays pending changes over confirmed cache baselines", () => {
    expect(
      shouldReplayCachedPendingChanges(
        {
          encryptedStateKind: "confirmed",
          encryptedConfirmedState: null,
          confirmedStateNonce: null,
        },
        false,
      ),
    ).toBe(true);
    expect(
      shouldReplayCachedPendingChanges(
        {
          encryptedConfirmedState: new Uint8Array([1]),
          confirmedStateNonce: new Uint8Array([2]),
        },
        true,
      ),
    ).toBe(true);
  });

  test("keeps legacy cache entries with pending changes out of confirmed baseline state", () => {
    expect(
      shouldTreatCachedStateAsConfirmedBase(
        {
          encryptedConfirmedState: null,
          confirmedStateNonce: null,
        },
        false,
        true,
      ),
    ).toBe(false);
    expect(
      shouldTreatCachedStateAsConfirmedBase(
        {
          encryptedConfirmedState: null,
          confirmedStateNonce: null,
        },
        false,
        false,
      ),
    ).toBe(true);
  });
});
