import { createSignal, createEffect, on, Show, For } from "solid-js";
import { createQuery, useQueryClient } from "@tanstack/solid-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/shared/ui/card";
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
import { devicesApi } from "@/shared/api";
import type { DeviceInfo } from "@/shared/api/devices";
import { authState, deviceState, setTofuErrors as setGlobalTofuErrors } from "@/shared/lib/auth-state";
import { base64UrlDecode, verifyTofu, handleTofuResult, verifyDeviceIdentitySignature } from "@/shared/lib/crypto";
import { RevokeDeviceDialog } from "@/features/devices/revoke-dialog";
import { usePendingDevices } from "@/features/devices/pending-device-monitor";

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

export default function DevicesPage() {
  const queryClient = useQueryClient();
  const devices = createQuery(() => ({
    queryKey: ["devices"],
    queryFn: () => devicesApi.list(),
  }));
  const refetch = () => queryClient.invalidateQueries({ queryKey: ["devices"] });
  const { pendingDevices, showApprovalDialog, kekRotationsNeeded } = usePendingDevices();
  const [revokeTarget, setRevokeTarget] = createSignal<DeviceInfo | null>(null);
  const [error, setError] = createSignal<string | null>(null);
  const [editingId, setEditingId] = createSignal<string | null>(null);
  const [editName, setEditName] = createSignal("");

  const currentDeviceId = () => deviceState()?.deviceId;

  // TOFU verification for all devices on load
  // Hard-fail errors block the entire app; warnings are displayed locally only
  const [tofuHardFail, setTofuHardFail] = createSignal(false);
  const [tofuWarnings, setTofuWarnings] = createSignal<string[]>([]);
  createEffect(() => {
    const deviceList = devices.data?.devices;
    const auth = authState();
    if (!deviceList || !auth) return;

    (async () => {
      const warnings: string[] = [];
      const identitySigningPublic = auth.identityKeys?.signingPublic;

      for (const d of deviceList) {
        if (!d.signing_public_key || !d.ecdh_public_key) continue;
        try {
          const signingPk = base64UrlDecode(d.signing_public_key);
          const ecdhPk = base64UrlDecode(d.ecdh_public_key);
          const result = await verifyTofu(auth.user.id, d.id, signingPk, ecdhPk);

          if (result.status === "identity_key_changed" || result.status === "ecdh_key_mismatch") {
            const msg = result.status === "identity_key_changed"
              ? `${d.name}: Identity key changed — possible key compromise`
              : `${d.name}: ECDH key mismatch — possible key compromise`;
            setTofuHardFail(true);
            setGlobalTofuErrors([msg]);
            return;
          } else {
            if (!d.identity_signature || !d.client_nonce) {
              warnings.push(`${d.name}: Missing identity signature — device approval cannot be verified`);
              continue;
            }
            if (!identitySigningPublic) {
              continue;
            }
            const sig = base64UrlDecode(d.identity_signature);
            const nonce = base64UrlDecode(d.client_nonce);
            const sigValid = verifyDeviceIdentitySignature(
              signingPk, ecdhPk, nonce, sig, identitySigningPublic,
            );
            if (!sigValid) {
              warnings.push(`${d.name}: Invalid identity signature — device approval not verified`);
              continue;
            }
            await handleTofuResult(result);
          }
        } catch {
          warnings.push(`${d.name}: Key verification unavailable`);
        }
      }
      setTofuWarnings(warnings);
    })();
  });

  // Refetch active devices when pending list changes (e.g., device approved)
  createEffect(on(
    () => pendingDevices().length,
    () => refetch(),
    { defer: true },
  ));

  const handleRevoked = () => {
    setRevokeTarget(null);
    refetch();
  };

  const handleRename = async (deviceId: string) => {
    const name = editName().trim();
    if (!name) return;
    try {
      await devicesApi.rename(deviceId, name);
      setEditingId(null);
      refetch();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Rename failed");
    }
  };

  const startEditing = (device: DeviceInfo) => {
    setEditingId(device.id);
    setEditName(device.name);
  };

  return (
    <main class="max-w-2xl mx-auto p-6 space-y-4">
      {/* KEK rotation reminder notification */}
      <Show when={kekRotationsNeeded().length > 0}>
        <Alert variant="destructive">
          <ShieldAlertIcon />
          <AlertDescription>
            {kekRotationsNeeded().length} workspace(s) require encryption key rotation.
            Please revoke or re-approve the affected device to complete the rotation.
          </AlertDescription>
        </Alert>
      </Show>

      {/* Pending device approval requests */}
      <Show when={pendingDevices().length > 0}>
        <Card>
          <CardHeader>
            <CardTitle class="flex items-center gap-2">
              <ShieldCheckIcon class="size-5" />
              Pending Approval
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div class="space-y-3">
              <For each={pendingDevices()}>
                {(pd) => (
                  <div class="flex items-center justify-between p-3 rounded-lg border border-amber-200 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/30">
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
                    <Button size="sm" onClick={() => showApprovalDialog(pd)} disabled={tofuHardFail()}>
                      Review
                    </Button>
                  </div>
                )}
              </For>
            </div>
          </CardContent>
        </Card>
      </Show>

      {/* Active devices */}
      <Card>
        <CardHeader>
          <CardTitle class="flex items-center gap-2">
            <ShieldAlertIcon class="size-5" />
            Devices
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Show when={tofuWarnings().length > 0}>
            <Alert variant="default" class="mb-4">
              <ShieldAlertIcon class="size-4" />
              <AlertDescription>
                Key verification warnings:
                <ul class="mt-1 list-disc list-inside">
                  <For each={tofuWarnings()}>
                    {(e) => <li>{e}</li>}
                  </For>
                </ul>
              </AlertDescription>
            </Alert>
          </Show>

          <Show when={error()}>
            {(err) => (
              <Alert variant="destructive" class="mb-4">
                <AlertDescription>{err()}</AlertDescription>
              </Alert>
            )}
          </Show>

          <Show
            when={!devices.isLoading}
            fallback={
              <div class="flex justify-center py-8">
                <Spinner class="size-6" />
              </div>
            }
          >
            <Show
              when={devices.data?.devices.length}
              fallback={
                <p class="text-muted-foreground text-center py-8">
                  No devices found
                </p>
              }
            >
              <div class="space-y-3">
                <For each={devices.data?.devices}>
                  {(device) => {
                    const isCurrent = () => device.id === currentDeviceId();
                    const isEditing = () => editingId() === device.id;
                    return (
                      <div class="flex items-center justify-between p-3 rounded-lg border">
                        <div class="flex items-center gap-3 flex-1 min-w-0">
                          <DeviceIcon type={device.device_type} />
                          <div class="flex-1 min-w-0">
                            <Show
                              when={!isEditing()}
                              fallback={
                                <div class="flex items-center gap-2">
                                  <Input
                                    value={editName()}
                                    onInput={(e) => setEditName(e.currentTarget.value)}
                                    class="h-7 text-sm"
                                    onKeyDown={(e) => {
                                      if (e.key === "Enter") handleRename(device.id);
                                      if (e.key === "Escape") setEditingId(null);
                                    }}
                                  />
                                  <Button
                                    variant="ghost"
                                    size="icon"
                                    class="size-7"
                                    onClick={() => handleRename(device.id)}
                                  >
                                    <CheckIcon class="size-3" />
                                  </Button>
                                  <Button
                                    variant="ghost"
                                    size="icon"
                                    class="size-7"
                                    onClick={() => setEditingId(null)}
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
                              {device.last_seen_at ? new Date(device.last_seen_at).toLocaleDateString() : "Unknown"}
                            </div>
                          </div>
                        </div>
                        <div class="flex items-center gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            title="Rename device"
                            disabled={tofuHardFail()}
                            onClick={() => startEditing(device)}
                          >
                            <PencilIcon class="size-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            disabled={isCurrent() || tofuHardFail()}
                            title={
                              isCurrent()
                                ? "Cannot remove current device"
                                : "Remove device"
                            }
                            onClick={() => setRevokeTarget(device)}
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
        </CardContent>
      </Card>

      <Show when={revokeTarget()}>
        {(target) => (
          <RevokeDeviceDialog
            device={target()}
            onClose={() => setRevokeTarget(null)}
            onRevoked={handleRevoked}
            onError={(msg) => setError(msg)}
          />
        )}
      </Show>
    </main>
  );
}
