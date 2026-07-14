import { describe, expect, it, vi } from "vite-plus/test";
import { persistRedeemedGuestWorkspaceKek } from "./guest-workspace-kek";

describe("redeemed guest workspace KEK persistence", () => {
  it("stores the KEK through the offline owner before persisting worker keys", async () => {
    const storeKekForOffline = vi.fn().mockResolvedValue(undefined);
    const persistCurrentKeysWithDsk = vi.fn().mockResolvedValue(undefined);

    await persistRedeemedGuestWorkspaceKek(
      { storeKekForOffline, persistCurrentKeysWithDsk },
      { userId: "guest-user", workspaceId: "workspace", keyVersion: 3 },
    );

    expect(storeKekForOffline).toHaveBeenCalledWith({
      workspaceId: "workspace",
      keyVersion: 3,
    });
    expect(persistCurrentKeysWithDsk).toHaveBeenCalledWith("guest-user");
    expect(storeKekForOffline.mock.invocationCallOrder[0]).toBeLessThan(
      persistCurrentKeysWithDsk.mock.invocationCallOrder[0] ?? 0,
    );
  });

  it("does not claim durable persistence when offline KEK storage fails", async () => {
    const storeKekForOffline = vi.fn().mockRejectedValue(new Error("offline store failed"));
    const persistCurrentKeysWithDsk = vi.fn().mockResolvedValue(undefined);

    await expect(
      persistRedeemedGuestWorkspaceKek(
        { storeKekForOffline, persistCurrentKeysWithDsk },
        { userId: "guest-user", workspaceId: "workspace", keyVersion: 3 },
      ),
    ).rejects.toThrow("offline store failed");

    expect(persistCurrentKeysWithDsk).not.toHaveBeenCalled();
  });
});
