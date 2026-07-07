import { render } from "solid-js/web";
import { afterEach, beforeEach, describe, expect, it, vi } from "vite-plus/test";

const securityNotificationsApiMock = vi.hoisted(() => ({
  list: vi.fn(),
  markRead: vi.fn(),
  dismiss: vi.fn(),
}));

vi.mock("@/shared/api/security-notifications", () => ({
  securityNotificationsApi: securityNotificationsApiMock,
}));

vi.mock("@/features/devices", () => ({
  RevokeDeviceDialog: () => null,
  useDeviceManagement: () => ({
    kekRotationsNeeded: () => [],
    pendingDevices: () => [],
    tofuWarnings: () => [],
    tofuHardFail: () => false,
    devices: { isLoading: false, data: { devices: [] } },
    currentDeviceId: () => "device-current",
    revokeTarget: () => null,
    editingId: () => null,
    editName: () => "",
    error: () => null,
    setEditName: vi.fn(),
    setError: vi.fn(),
    startEditing: vi.fn(),
    cancelEditing: vi.fn(),
    submitRename: vi.fn(),
    openRevokeDialog: vi.fn(),
    closeRevokeDialog: vi.fn(),
    handleRevoked: vi.fn(),
    showApprovalDialog: vi.fn(),
    refetchPending: vi.fn(async () => undefined),
  }),
}));

import { SettingsDialog } from "./SettingsDialog";

describe("SettingsDialog", () => {
  beforeEach(() => {
    securityNotificationsApiMock.list.mockResolvedValue([]);
    securityNotificationsApiMock.markRead.mockReset();
    securityNotificationsApiMock.dismiss.mockReset();
  });

  afterEach(() => {
    document.body.replaceChildren();
  });

  it("exposes Community Plugins in settings management navigation", async () => {
    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(() => <SettingsDialog open={true} onOpenChange={() => {}} />, root);
    await Promise.resolve();

    expect(document.body.textContent).toContain("Community Plugins");

    dispose();
  });

  it("opens directly to security notifications when requested", async () => {
    securityNotificationsApiMock.list.mockResolvedValue([
      {
        id: "notification-one",
        type: "plugin.consent_required",
        severity: "action_required",
        action_ref: { plugin_id: "plugin.example" },
      },
    ]);
    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(
      () => <SettingsDialog open={true} onOpenChange={() => {}} initialTab="security" />,
      root,
    );
    await Promise.resolve();
    await Promise.resolve();

    expect(document.body.textContent).toContain("Security Notifications");
    expect(document.body.textContent).toContain("Plugin Consent Required");
    expect(document.body.textContent).toContain("plugin.example");

    dispose();
  });
});
