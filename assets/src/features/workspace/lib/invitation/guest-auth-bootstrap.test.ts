import { describe, expect, it, vi } from "vite-plus/test";
import { persistGuestAuthBootstrap } from "./guest-auth-bootstrap";

describe("guest auth bootstrap persistence", () => {
  it("stores the admitted guest device identity required for reload", async () => {
    const storeAuthBootstrap = vi.fn().mockResolvedValue(true);

    await persistGuestAuthBootstrap(
      { storeAuthBootstrap },
      {
        userId: "guest-user",
        email: "guest@example.com",
        name: "Guest",
        deviceId: "guest-device",
        deviceSigningKeyId: "guest-signing-key",
      },
      () => 1234,
    );

    expect(storeAuthBootstrap).toHaveBeenCalledWith({
      userId: "guest-user",
      email: "guest@example.com",
      name: "Guest",
      deviceId: "guest-device",
      deviceSigningKeyId: "guest-signing-key",
      cachedAt: 1234,
    });
  });

  it("fails redemption when reload identity persistence fails", async () => {
    await expect(
      persistGuestAuthBootstrap(
        { storeAuthBootstrap: vi.fn().mockResolvedValue(false) },
        {
          userId: "guest-user",
          email: "guest@example.com",
          name: "Guest",
          deviceId: "guest-device",
          deviceSigningKeyId: "guest-signing-key",
        },
      ),
    ).rejects.toThrow("Guest session keys could not be prepared for reload.");
  });
});
