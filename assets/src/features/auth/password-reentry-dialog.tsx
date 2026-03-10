import { createSignal, Show } from "solid-js";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Spinner } from "@/shared/ui/spinner";
import { AlertTriangleIcon } from "lucide-solid";
import { deriveAuthKeys, base64UrlDecode, decryptIdentityPrivateKeys, verifyAllDeviceTofu, TofuHardFailError } from "@/shared/lib/crypto";
import { authApi, devicesApi, withPopDevice } from "@/shared/api";
import {
  restoreKeysFromPdk,
  persistSessionPdk,
  persistUmkForLogin,
} from "./lib/key-persistence";
import { authState, setFullSession, deviceState, setTofuErrors } from "@/shared/lib/auth-state";

export default function PasswordReentryDialog(props: {
  open: boolean;
  onComplete: () => void;
}) {
  const [password, setPassword] = createSignal("");
  const [error, setError] = createSignal<string | null>(null);
  const [loading, setLoading] = createSignal(false);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      const auth = authState();
      if (!auth) throw new Error("No session");

      const saltRes = await authApi.getSalt(auth.user.email);
      const derived = await deriveAuthKeys(password(), saltRes.salt, saltRes.kdf_params);

      const restored = restoreKeysFromPdk(derived.pdk, auth.user.id);
      if (!restored) {
        setError("Could not decrypt keys. Check your password.");
        return;
      }

      persistSessionPdk(derived.pdk);

      // Persist UMK based on current KMSI state
      const meRes = await authApi.me();
      await persistUmkForLogin({
        umk: restored.umk,
        pdk: derived.pdk,
        kmsi: !!meRes.remember_me,
        userId: auth.user.id,
      });

      // Decrypt identity keys if available
      let identityKeys = null;
      if (meRes.keys?.encrypted_ecdh_private) {
        identityKeys = decryptIdentityPrivateKeys(
          {
            encryptedEcdhPrivate: base64UrlDecode(meRes.keys.encrypted_ecdh_private),
            ecdhPrivateNonce: base64UrlDecode(meRes.keys.encrypted_ecdh_private_nonce),
            encryptedSigningPrivate: base64UrlDecode(meRes.keys.encrypted_signing_private),
            signingPrivateNonce: base64UrlDecode(meRes.keys.encrypted_signing_private_nonce),
          },
          restored.umk,
          auth.user.id,
        );
      }

      const device = deviceState();
      const resolvedDeviceId = device?.deviceId ?? meRes.device_id ?? "";

      setFullSession(
        {
          user: auth.user,
          sessionId: auth.sessionId,
          umk: restored.umk,
          identityKeys,
          expiresAt: auth.expiresAt,
        },
        {
          deviceId: resolvedDeviceId,
          deviceEcdhPrivate: restored.deviceEcdhPrivate,
          deviceSigningPrivate: restored.deviceSigningPrivate,
        },
      );

      // TOFU verification after key restoration
      if (resolvedDeviceId && restored.deviceSigningPrivate) {
        try {
          const { devices } = await withPopDevice(
            { deviceId: resolvedDeviceId, deviceSigningPrivate: restored.deviceSigningPrivate },
            () => devicesApi.list(),
          );
          const warnings = await verifyAllDeviceTofu(
            auth.user.id,
            devices,
            identityKeys?.signingPublic ?? null,
          );
          if (warnings.length > 0) {
            setTofuErrors(warnings);
          }
        } catch (e) {
          if (e instanceof TofuHardFailError) {
            setError(e.message);
            return;
          }
        }
      }

      props.onComplete();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Key restoration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={props.open}>
      <DialogContent showCloseButton={false}>
        <DialogHeader>
          <DialogTitle>Password Required</DialogTitle>
          <DialogDescription>
            Your encryption keys need to be restored. Please enter your password to continue.
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} class="space-y-4">
          <Show when={error()}>
            {(err) => (
              <Alert variant="destructive">
                <AlertTriangleIcon />
                <AlertDescription>{err()}</AlertDescription>
              </Alert>
            )}
          </Show>

          <Field>
            <FieldLabel for="reentry-password">Password</FieldLabel>
            <Input
              id="reentry-password"
              type="password"
              placeholder="--------"
              value={password()}
              onInput={(e) => setPassword(e.currentTarget.value)}
              required
              disabled={loading()}
              autocomplete="current-password"
            />
          </Field>

          <DialogFooter>
            <Button type="submit" disabled={loading()}>
              {loading() ? (
                <span class="flex items-center gap-2">
                  <Spinner class="size-3" /> Restoring keys...
                </span>
              ) : (
                "Unlock"
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
