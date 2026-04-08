import { Show, For } from "solid-js";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Spinner } from "@/shared/ui/spinner";
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
