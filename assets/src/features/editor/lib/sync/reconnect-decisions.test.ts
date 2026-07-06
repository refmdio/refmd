import { describe, expect, test } from "vitest";
import {
  shouldRecomputeUnsavedLocalUpdate,
  shouldFailNoBaselineLocalTextReconnect,
  shouldUseDeltaReconnect,
} from "./reconnect-decisions";

describe("reconnect decisions", () => {
  test("requires a saved baseline before delta reconnect", () => {
    expect(
      shouldUseDeltaReconnect({
        stateKnownSnapshotId: "snap-1",
        pinSnapshotId: null,
        hasLastSavedState: false,
        forceCompleteReconnect: false,
      }),
    ).toBe(false);
    expect(
      shouldUseDeltaReconnect({
        stateKnownSnapshotId: "snap-1",
        pinSnapshotId: null,
        hasLastSavedState: true,
        forceCompleteReconnect: false,
      }),
    ).toBe(true);
  });

  test("rejects delta reconnect for mismatched pins or forced complete reconnect", () => {
    expect(
      shouldUseDeltaReconnect({
        stateKnownSnapshotId: "snap-1",
        pinSnapshotId: "snap-2",
        hasLastSavedState: true,
        forceCompleteReconnect: false,
      }),
    ).toBe(false);
    expect(
      shouldUseDeltaReconnect({
        stateKnownSnapshotId: "snap-1",
        pinSnapshotId: "snap-1",
        hasLastSavedState: true,
        forceCompleteReconnect: true,
      }),
    ).toBe(false);
  });

  test("fails no-baseline local text reconnect unless server-applied text matches exactly", () => {
    expect(shouldFailNoBaselineLocalTextReconnect("local\n", "local\n")).toBe(false);
    expect(shouldFailNoBaselineLocalTextReconnect("server\nlocal\n", "local\n")).toBe(true);
    expect(shouldFailNoBaselineLocalTextReconnect("prefix local suffix", "local")).toBe(true);
    expect(shouldFailNoBaselineLocalTextReconnect("server\n", "local\n")).toBe(true);
    expect(shouldFailNoBaselineLocalTextReconnect("same\nsame\n", "same\n")).toBe(true);
  });

  test("does not recompute local updates while exact pending update bytes exist", () => {
    expect(shouldRecomputeUnsavedLocalUpdate(true)).toBe(false);
    expect(shouldRecomputeUnsavedLocalUpdate(false)).toBe(true);
  });
});
