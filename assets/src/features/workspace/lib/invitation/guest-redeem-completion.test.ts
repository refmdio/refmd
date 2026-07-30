import { describe, expect, it, vi } from "vite-plus/test";
import { completeKnownGuestRedemption } from "./guest-redeem";

const completionStages = [
  "restoreWorker",
  "restoreShareKey",
  "persistAuthBootstrap",
  "pinUserKeyDirectory",
  "establishSession",
  "rememberRedeemMaterial",
] as const;

describe("known guest redemption completion", () => {
  it.each(completionStages)("retains pending keys when %s fails", async (failedStage) => {
    const order: string[] = [];
    const fail = (stage: (typeof completionStages)[number]) => {
      order.push(stage);
      if (stage === failedStage) throw new Error(`${stage}_failed`);
    };
    const deletePendingKeys = vi.fn(async () => {
      order.push("deletePendingKeys");
    });

    await expect(
      completeKnownGuestRedemption({
        restoreWorker: async () => {
          fail("restoreWorker");
          return { email: "guest@example.com", name: "Guest" } as never;
        },
        restoreShareKey: async () => fail("restoreShareKey"),
        persistAuthBootstrap: async () => fail("persistAuthBootstrap"),
        pinUserKeyDirectory: async () => fail("pinUserKeyDirectory"),
        establishSession: () => fail("establishSession"),
        rememberRedeemMaterial: async () => fail("rememberRedeemMaterial"),
        deletePendingKeys,
      }),
    ).rejects.toThrow(`${failedStage}_failed`);

    expect(deletePendingKeys).not.toHaveBeenCalled();
    expect(order).not.toContain("deletePendingKeys");
  });

  it("deletes pending keys only after every durable completion stage succeeds", async () => {
    const order: string[] = [];
    const stage = (name: string) => {
      order.push(name);
    };

    await completeKnownGuestRedemption({
      restoreWorker: async () => {
        stage("restoreWorker");
        return { email: "guest@example.com", name: "Guest" } as never;
      },
      restoreShareKey: async () => stage("restoreShareKey"),
      persistAuthBootstrap: async () => stage("persistAuthBootstrap"),
      pinUserKeyDirectory: async () => stage("pinUserKeyDirectory"),
      establishSession: () => stage("establishSession"),
      rememberRedeemMaterial: async () => stage("rememberRedeemMaterial"),
      deletePendingKeys: async () => stage("deletePendingKeys"),
    });

    expect(order).toEqual([
      "restoreWorker",
      "restoreShareKey",
      "persistAuthBootstrap",
      "pinUserKeyDirectory",
      "establishSession",
      "rememberRedeemMaterial",
      "deletePendingKeys",
    ]);
  });
});
