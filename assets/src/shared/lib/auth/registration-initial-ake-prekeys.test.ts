import { describe, expect, it, vi } from "vite-plus/test";
import {
  generateRegistrationInitialAkeResponderPrekeys,
  resolveRegistrationInitialAkeIssuedAtEventSequence,
} from "./registration-initial-ake-prekeys";
import type { InitialAkeResponderPrekeyRecord } from "@/shared/lib/crypto/initial-ake";

function prekey(label: string): InitialAkeResponderPrekeyRecord {
  return { label } as unknown as InitialAkeResponderPrekeyRecord;
}

describe("registration initial AKE prekeys", () => {
  it("prefers the server candidate event head over a local pin", () => {
    expect(
      resolveRegistrationInitialAkeIssuedAtEventSequence({
        candidateUserEventHeadSequence: 7,
        pinnedEventHeadSequence: 3,
      }),
    ).toBe(7);
  });

  it("falls back to the local pin, then genesis", () => {
    expect(
      resolveRegistrationInitialAkeIssuedAtEventSequence({
        pinnedEventHeadSequence: 4,
      }),
    ).toBe(4);
    expect(resolveRegistrationInitialAkeIssuedAtEventSequence({})).toBe(1);
  });

  it("generates the full purpose-scoped prekey set for pending registration", async () => {
    const operationIds = ["umk-operation", "trust-operation"];
    const generateInitialAkeResponderPrekey = vi
      .fn()
      .mockResolvedValueOnce(prekey("umk"))
      .mockResolvedValueOnce(prekey("trust"))
      .mockResolvedValueOnce(prekey("workspace-1"))
      .mockResolvedValueOnce(prekey("workspace-2"));

    await expect(
      generateRegistrationInitialAkeResponderPrekeys({
        userId: "user-1",
        deviceId: "device-1",
        workspaceIds: ["workspace-1", "workspace-2"],
        serverChallenge: "server-challenge",
        issuedAtEventSequence: 9,
        worker: { generateInitialAkeResponderPrekey },
        operationIdFactory: () => operationIds.shift()!,
      }),
    ).resolves.toEqual({
      umk_distribution: prekey("umk"),
      trust_transfer: prekey("trust"),
      device_approval_kek_initial: [
        { workspace_id: "workspace-1", prekey: prekey("workspace-1") },
        { workspace_id: "workspace-2", prekey: prekey("workspace-2") },
      ],
    });

    expect(generateInitialAkeResponderPrekey).toHaveBeenNthCalledWith(1, {
      operationId: "umk-operation",
      userId: "user-1",
      deviceId: "device-1",
      purpose: "umk_distribution",
      serverChallenge: "server-challenge",
      issuedAtEventSequence: 9,
      expiresEventSequence: 10,
    });
    expect(generateInitialAkeResponderPrekey).toHaveBeenNthCalledWith(2, {
      operationId: "trust-operation",
      userId: "user-1",
      deviceId: "device-1",
      purpose: "trust_transfer",
      serverChallenge: "server-challenge",
      issuedAtEventSequence: 9,
      expiresEventSequence: 10,
    });
    expect(generateInitialAkeResponderPrekey).toHaveBeenNthCalledWith(3, {
      operationId: "device-1",
      userId: "user-1",
      deviceId: "device-1",
      purpose: "device_approval_kek_initial",
      serverChallenge: "server-challenge",
      issuedAtEventSequence: 9,
      expiresEventSequence: 10,
    });
  });

  it("uses crypto.randomUUID without losing its browser method receiver", async () => {
    const originalRandomUUIDDescriptor = Object.getOwnPropertyDescriptor(crypto, "randomUUID");
    const randomUUID = vi
      .fn()
      .mockReturnValueOnce("umk-operation")
      .mockReturnValueOnce("trust-operation");
    Object.defineProperty(crypto, "randomUUID", {
      configurable: true,
      value: randomUUID,
    });

    try {
      const generateInitialAkeResponderPrekey = vi.fn().mockResolvedValue(prekey("prekey"));

      await generateRegistrationInitialAkeResponderPrekeys({
        userId: "user-1",
        deviceId: "device-1",
        workspaceIds: [],
        serverChallenge: "server-challenge",
        issuedAtEventSequence: 1,
        worker: { generateInitialAkeResponderPrekey },
      });

      expect(randomUUID).toHaveBeenCalledTimes(2);
      expect(generateInitialAkeResponderPrekey).toHaveBeenNthCalledWith(
        2,
        expect.objectContaining({ operationId: "trust-operation" }),
      );
    } finally {
      if (originalRandomUUIDDescriptor) {
        Object.defineProperty(crypto, "randomUUID", originalRandomUUIDDescriptor);
      } else {
        Reflect.deleteProperty(crypto, "randomUUID");
      }
    }
  });
});
