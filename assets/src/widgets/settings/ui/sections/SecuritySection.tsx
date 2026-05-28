import { Show, For, createEffect, createSignal } from "solid-js";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Spinner } from "@/shared/ui/spinner";
import {
  securityNotificationsApi,
  type SecurityNotificationInfo,
} from "@/shared/api/security-notifications";
import {
  MonitorIcon,
  SmartphoneIcon,
  GlobeIcon,
  TrashIcon,
  ShieldAlertIcon,
  PencilIcon,
  CheckIcon,
  XIcon,
  ShieldCheckIcon,
} from "lucide-solid";
import { RevokeDeviceDialog, useDeviceManagement } from "@/features/devices";

function DeviceIcon(props: { type: string }) {
  switch (props.type) {
    case "desktop":
      return <MonitorIcon class="size-5" />;
    case "mobile":
      return <SmartphoneIcon class="size-5" />;
    default:
      return <GlobeIcon class="size-5" />;
  }
}

export function SecuritySection() {
  const deviceManagement = useDeviceManagement();
  const [notifications, setNotifications] = createSignal<readonly SecurityNotificationInfo[]>([]);
  const [notificationsLoading, setNotificationsLoading] = createSignal(false);
  const [notificationError, setNotificationError] = createSignal<string | null>(null);

  const refreshNotifications = async () => {
    setNotificationsLoading(true);
    setNotificationError(null);
    try {
      setNotifications(await securityNotificationsApi.list());
    } catch {
      setNotificationError("Security notifications could not be loaded.");
    } finally {
      setNotificationsLoading(false);
    }
  };

  const updateNotification = async (
    notification: SecurityNotificationInfo,
    action: "read" | "dismiss",
  ) => {
    setNotificationError(null);
    try {
      if (action === "read") {
        await securityNotificationsApi.markRead(notification.id);
      } else {
        await securityNotificationsApi.dismiss(notification.id);
      }
      await Promise.all([refreshNotifications(), deviceManagement.refetchPending()]);
    } catch {
      setNotificationError("Security notification state could not be updated.");
    }
  };

  createEffect(() => {
    void refreshNotifications();
  });

  const actionRequiredNotifications = () =>
    notifications().filter((notification) => {
      if (notification.severity !== "action_required") return false;
      if (notification.read_at || notification.dismissed_at || notification.acted_at) return false;
      if (!notification.expires_at) return true;
      return new Date(notification.expires_at).getTime() > Date.now();
    });

  return (
    <div class="p-6 space-y-6">
      <div>
        <h3 class="text-lg font-semibold mb-1">Security</h3>
        <p class="text-sm text-muted-foreground">
          Manage your trusted devices and security settings.
        </p>
      </div>

      <Show when={deviceManagement.kekRotationsNeeded().length > 0}>
        <Alert variant="destructive">
          <ShieldAlertIcon />
          <AlertDescription>
            {deviceManagement.kekRotationsNeeded().length} workspace(s) require encryption key
            rotation. Please revoke or re-approve the affected device to complete the rotation.
          </AlertDescription>
        </Alert>
      </Show>

      <section>
        <h4 class="text-sm font-medium mb-3 flex items-center gap-2">
          <ShieldAlertIcon class="size-4" />
          Security Notifications
        </h4>

        <Show when={notificationError()}>
          {(err) => (
            <Alert variant="destructive" class="mb-4">
              <AlertDescription>{err()}</AlertDescription>
            </Alert>
          )}
        </Show>

        <Show
          when={!notificationsLoading()}
          fallback={
            <div class="flex justify-center py-6">
              <Spinner class="size-5" />
            </div>
          }
        >
          <Show
            when={actionRequiredNotifications().length > 0}
            fallback={
              <p class="text-sm text-muted-foreground py-3">
                No action-required security notifications
              </p>
            }
          >
            <div class="space-y-3">
              <For each={actionRequiredNotifications()}>
                {(notification) => (
                  <div class="border border-border/60 bg-card p-3 space-y-3">
                    <div>
                      <div class="font-medium">{securityNotificationTitle(notification)}</div>
                      <div class="text-sm text-muted-foreground">
                        {securityNotificationSummary(notification)}
                      </div>
                    </div>
                    <SecurityNotificationActionRef notification={notification} />
                    <div class="flex flex-wrap gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void updateNotification(notification, "read")}
                      >
                        Mark read
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void updateNotification(notification, "dismiss")}
                      >
                        Dismiss
                      </Button>
                      <Show when={pendingDeviceForNotification(notification, deviceManagement)}>
                        {(device) => (
                          <Button
                            size="sm"
                            onClick={() => deviceManagement.showApprovalDialog(device())}
                            disabled={deviceManagement.tofuHardFail()}
                          >
                            Open
                          </Button>
                        )}
                      </Show>
                    </div>
                  </div>
                )}
              </For>
            </div>
          </Show>
        </Show>
      </section>

      <Show when={deviceManagement.pendingDevices().length > 0}>
        <section>
          <h4 class="text-sm font-medium mb-3 flex items-center gap-2">
            <ShieldCheckIcon class="size-4" />
            Pending Approval
          </h4>
          <div class="space-y-3">
            <For each={deviceManagement.pendingDevices()}>
              {(pd) => (
                <div class="flex items-center justify-between p-3 border border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/30">
                  <div class="flex items-center gap-3">
                    <DeviceIcon type={pd.device_type} />
                    <div>
                      <div class="font-medium">{pd.name}</div>
                      <div class="text-sm text-muted-foreground">
                        {pd.device_type} &middot; Requested{" "}
                        {new Date(pd.created_at).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>
                  <Button
                    size="sm"
                    onClick={() => deviceManagement.showApprovalDialog(pd)}
                    disabled={deviceManagement.tofuHardFail()}
                  >
                    Review
                  </Button>
                </div>
              )}
            </For>
          </div>
        </section>
      </Show>

      <section>
        <h4 class="text-sm font-medium mb-3 flex items-center gap-2">
          <ShieldAlertIcon class="size-4" />
          Devices
        </h4>

        <Show when={deviceManagement.tofuWarnings().length > 0}>
          <Alert variant="default" class="mb-4">
            <ShieldAlertIcon class="size-4" />
            <AlertDescription>
              Key verification warnings:
              <ul class="mt-1 list-disc list-inside">
                <For each={deviceManagement.tofuWarnings()}>{(e) => <li>{e}</li>}</For>
              </ul>
            </AlertDescription>
          </Alert>
        </Show>

        <Show when={deviceManagement.error()}>
          {(err) => (
            <Alert variant="destructive" class="mb-4">
              <AlertDescription>{err()}</AlertDescription>
            </Alert>
          )}
        </Show>

        <Show
          when={!deviceManagement.devices.isLoading}
          fallback={
            <div class="flex justify-center py-8">
              <Spinner class="size-6" />
            </div>
          }
        >
          <Show
            when={deviceManagement.devices.data?.devices.length}
            fallback={<p class="text-muted-foreground text-center py-8">No devices found</p>}
          >
            <div class="space-y-3">
              <For each={deviceManagement.devices.data?.devices}>
                {(device) => {
                  const isCurrent = () => device.id === deviceManagement.currentDeviceId();
                  const isEditing = () => deviceManagement.editingId() === device.id;
                  return (
                    <div class="flex items-center justify-between p-3 border border-border/60 bg-card">
                      <div class="flex items-center gap-3 flex-1 min-w-0">
                        <DeviceIcon type={device.device_type} />
                        <div class="flex-1 min-w-0">
                          <Show
                            when={!isEditing()}
                            fallback={
                              <div class="flex items-center gap-2">
                                <Input
                                  value={deviceManagement.editName()}
                                  onInput={(e) =>
                                    deviceManagement.setEditName(e.currentTarget.value)
                                  }
                                  class="h-7 text-sm"
                                  onKeyDown={(e) => {
                                    if (e.key === "Enter")
                                      void deviceManagement.submitRename(device.id);
                                    if (e.key === "Escape") deviceManagement.cancelEditing();
                                  }}
                                />
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  class="size-7"
                                  onClick={() => void deviceManagement.submitRename(device.id)}
                                >
                                  <CheckIcon class="size-3" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  class="size-7"
                                  onClick={deviceManagement.cancelEditing}
                                >
                                  <XIcon class="size-3" />
                                </Button>
                              </div>
                            }
                          >
                            <div class="font-medium">
                              {device.name}
                              <Show when={isCurrent()}>
                                <span class="ml-2 text-xs text-muted-foreground">
                                  (this device)
                                </span>
                              </Show>
                            </div>
                          </Show>
                          <div class="text-sm text-muted-foreground">
                            {device.device_type} &middot; Last seen{" "}
                            {device.last_seen_at
                              ? new Date(device.last_seen_at).toLocaleDateString()
                              : "Unknown"}
                          </div>
                        </div>
                      </div>
                      <div class="flex items-center gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          title="Rename device"
                          disabled={deviceManagement.tofuHardFail()}
                          onClick={() => deviceManagement.startEditing(device)}
                        >
                          <PencilIcon class="size-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          disabled={isCurrent() || deviceManagement.tofuHardFail()}
                          title={isCurrent() ? "Cannot remove current device" : "Remove device"}
                          onClick={() => deviceManagement.openRevokeDialog(device)}
                        >
                          <TrashIcon class="size-4" />
                        </Button>
                      </div>
                    </div>
                  );
                }}
              </For>
            </div>
          </Show>
        </Show>
      </section>

      <Show when={deviceManagement.revokeTarget()}>
        {(target) => (
          <RevokeDeviceDialog
            device={target()}
            onClose={deviceManagement.closeRevokeDialog}
            onRevoked={deviceManagement.handleRevoked}
            onError={(msg) => deviceManagement.setError(msg)}
          />
        )}
      </Show>
    </div>
  );
}

function SecurityNotificationActionRef(props: { notification: SecurityNotificationInfo }) {
  const entries = () =>
    Object.entries(props.notification.action_ref ?? {}).filter(
      ([, value]) => typeof value === "string" || typeof value === "number",
    );

  return (
    <Show when={entries().length > 0}>
      <dl class="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs text-muted-foreground">
        <For each={entries()}>
          {([key, value]) => (
            <>
              <dt>{securityNotificationFieldLabel(key)}</dt>
              <dd class="truncate">{String(value)}</dd>
            </>
          )}
        </For>
      </dl>
    </Show>
  );
}

function securityNotificationTitle(notification: SecurityNotificationInfo): string {
  switch (notification.type) {
    case "device.pending_approval":
      return "Pending Device Approval";
    case "plugin.consent_required":
      return "Plugin Consent Required";
    case "workspace.kek_rotation_needed":
      return "Workspace Key Rotation";
    default:
      return notification.type
        .split(/[._]/)
        .filter(Boolean)
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
  }
}

function securityNotificationSummary(notification: SecurityNotificationInfo): string {
  const ref = notification.action_ref ?? {};
  if (notification.type === "device.pending_approval") {
    return typeof ref.name === "string" ? ref.name : "New device";
  }
  if (notification.type === "plugin.consent_required") {
    return typeof ref.plugin_id === "string" ? ref.plugin_id : "Plugin application";
  }
  if (notification.type === "workspace.kek_rotation_needed") {
    return typeof ref.workspace_id === "string" ? ref.workspace_id : "Workspace";
  }
  return notification.severity;
}

function securityNotificationFieldLabel(key: string): string {
  return key
    .split("_")
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function pendingDeviceForNotification(
  notification: SecurityNotificationInfo,
  deviceManagement: ReturnType<typeof useDeviceManagement>,
) {
  if (notification.type !== "device.pending_approval") return null;
  const deviceId = notification.action_ref?.device_id;
  if (typeof deviceId !== "string") return null;
  return deviceManagement.pendingDevices().find((device) => device.id === deviceId) ?? null;
}
