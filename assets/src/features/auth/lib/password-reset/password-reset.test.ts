import { beforeEach, describe, expect, it, vi } from "vite-plus/test";

const mocks = vi.hoisted(() => ({
  passwordResetRequest: vi.fn(),
  passwordResetVerify: vi.fn(),
  getCryptoWorker: vi.fn(),
  lock: vi.fn(),
  terminateCryptoWorker: vi.fn(),
}));

vi.mock("@/shared/api", () => ({
  authApi: {
    passwordResetRequest: mocks.passwordResetRequest,
    passwordResetVerify: mocks.passwordResetVerify,
  },
}));

vi.mock("@/shared/lib/crypto/worker/client", () => ({
  getCryptoWorker: mocks.getCryptoWorker,
  terminateCryptoWorker: mocks.terminateCryptoWorker,
}));

import { requestPasswordReset, verifyPasswordResetToken } from "./password-reset";

describe("password-reset", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.getCryptoWorker.mockReturnValue({ lock: mocks.lock });
    mocks.lock.mockResolvedValue(undefined);
  });

  it("normalizes the email before requesting a password reset", async () => {
    mocks.passwordResetRequest.mockResolvedValue(undefined);

    await requestPasswordReset("  USER@Example.COM ");

    expect(mocks.passwordResetRequest).toHaveBeenCalledWith("user@example.com");
  });

  it("locks and terminates the worker before returning reset session data", async () => {
    mocks.passwordResetVerify.mockResolvedValue({
      user: { id: "user_1", email: "user@example.com", name: "User" },
      session_id: "session_1",
    });

    await expect(verifyPasswordResetToken("token-123")).resolves.toEqual({
      user: { id: "user_1", email: "user@example.com", name: "User" },
      sessionId: "session_1",
    });

    expect(mocks.passwordResetVerify).toHaveBeenCalledWith("token-123");
    expect(mocks.lock).toHaveBeenCalledTimes(1);
    expect(mocks.terminateCryptoWorker).toHaveBeenCalledTimes(1);
  });

  it("still terminates the worker when locking fails", async () => {
    mocks.passwordResetVerify.mockResolvedValue({
      user: { id: "user_2", email: "user@example.com", name: "User" },
      session_id: "session_2",
    });
    mocks.lock.mockRejectedValueOnce(new Error("not initialized"));

    await verifyPasswordResetToken("token-456");

    expect(mocks.terminateCryptoWorker).toHaveBeenCalledTimes(1);
  });
});
