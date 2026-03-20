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
import { base64UrlDecode } from "@/shared/lib/crypto/encoding";
import { CryptoWorkerError } from "@/shared/lib/crypto/worker/client";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { loadDskInitData } from "@/shared/lib/crypto/dsk";
import { authApi, devicesApi } from "@/shared/api";
import {
  authState,
  setFullSession,
  deviceState,
  setTofuErrors,
  setCryptoWorkerReady,
} from "@/shared/lib/auth-state";
import { storeWrappedUmkRaw } from "@/shared/lib/crypto/dsk";

export default function PasswordReentryDialog(props: { open: boolean; onComplete: () => void }) {
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

      const worker = getCryptoWorker();

      const saltRes = await authApi.getSalt(auth.user.email);
      const meRes = await authApi.me();

      const device = deviceState();
      const resolvedDeviceId = device?.deviceId ?? meRes.device_id ?? "";

      // Load DSK data and PDK blobs for Worker initialization
      const dskData = await loadDskInitData();
      const hadDsk = dskData?.dsk != null;
      const needPdkPersistence = !hadDsk;

      const pdkUmkRaw = localStorage.getItem("refmd-pdk-umk");
      const pdkEcdhRaw = localStorage.getItem("refmd-pdk-device-ecdh");
      const pdkSigningRaw = localStorage.getItem("refmd-pdk-device-signing");
      const pdkBlobs =
        pdkUmkRaw && pdkEcdhRaw && pdkSigningRaw
          ? {
              pdkWrappedUmk: JSON.parse(pdkUmkRaw),
              pdkWrappedDeviceEcdh: JSON.parse(pdkEcdhRaw),
              pdkWrappedDeviceSigning: JSON.parse(pdkSigningRaw),
            }
          : {};

      // initFromPassword: derives PDK/PUK, restores keys, optionally re-wraps with PDK
      // PDK is consumed and zeroed within the Worker before returning
      const initResult = await worker.initFromPassword({
        password: password(),
        salt: base64UrlDecode(saltRes.salt),
        kdfParams: saltRes.kdf_params,
        dsk: dskData?.dsk ?? null,
        wrappedDeviceEcdh: dskData?.wrappedDeviceEcdh ?? undefined,
        wrappedDeviceSigning: dskData?.wrappedDeviceSigning ?? undefined,
        serverEncryptedUmk: meRes.keys?.encrypted_umk
          ? base64UrlDecode(meRes.keys.encrypted_umk)
          : undefined,
        serverUmkNonce: meRes.keys?.umk_nonce ? base64UrlDecode(meRes.keys.umk_nonce) : undefined,
        userId: auth.user.id,
        deviceId: resolvedDeviceId,
        encryptedIdentityEcdh: meRes.keys?.encrypted_ecdh_private
          ? base64UrlDecode(meRes.keys.encrypted_ecdh_private)
          : undefined,
        identityEcdhNonce: meRes.keys?.encrypted_ecdh_private_nonce
          ? base64UrlDecode(meRes.keys.encrypted_ecdh_private_nonce)
          : undefined,
        encryptedIdentitySigning: meRes.keys?.encrypted_signing_private
          ? base64UrlDecode(meRes.keys.encrypted_signing_private)
          : undefined,
        identitySigningNonce: meRes.keys?.encrypted_signing_private_nonce
          ? base64UrlDecode(meRes.keys.encrypted_signing_private_nonce)
          : undefined,
        ...pdkBlobs,
        returnPdkWrapped: needPdkPersistence,
      });

      const publicKeys = await worker.getPublicKeys();

      // Persist UMK + device keys
      if (hadDsk) {
        try {
          const wrappedUmk = await worker.wrapUmkWithDsk(auth.user.id);
          if (meRes.remember_me) {
            await storeWrappedUmkRaw(wrappedUmk);
          } else {
            sessionStorage.setItem(
              "refmd-session-umk-wrapped",
              JSON.stringify({
                ciphertext: Array.from(new Uint8Array(wrappedUmk.ciphertext)),
                iv: Array.from(new Uint8Array(wrappedUmk.iv)),
              }),
            );
            const { clearWrappedUmk } = await import("@/shared/lib/crypto/dsk");
            await clearWrappedUmk();
          }
          // Re-persist device keys with DSK (may have been restored from PDK fallback)
          const wrappedDeviceKeys = await worker.wrapDeviceKeysWithDsk(auth.user.id);
          const { storeWrappedDeviceKeysRaw } = await import("@/shared/lib/crypto/dsk");
          await storeWrappedDeviceKeysRaw(
            wrappedDeviceKeys.wrappedEcdh,
            wrappedDeviceKeys.wrappedSigning,
          );
        } catch {
          // Best effort
        }
      } else if (initResult.pdkWrapped) {
        if (initResult.pdkWrapped.wrappedUmk) {
          localStorage.setItem("refmd-pdk-umk", JSON.stringify(initResult.pdkWrapped.wrappedUmk));
        }
        if (initResult.pdkWrapped.wrappedDeviceKeys) {
          localStorage.setItem(
            "refmd-pdk-device-ecdh",
            JSON.stringify(initResult.pdkWrapped.wrappedDeviceKeys.ecdh),
          );
          localStorage.setItem(
            "refmd-pdk-device-signing",
            JSON.stringify(initResult.pdkWrapped.wrappedDeviceKeys.signing),
          );
        }
      }

      const finalReady = await worker.isReady();
      if (!finalReady) {
        setError("Key restoration failed. Please try again.");
        return;
      }

      setFullSession(
        {
          user: auth.user,
          sessionId: auth.sessionId,
          identitySigningPublic: publicKeys.identitySigningPublic,
          identityEcdhPublic: publicKeys.identityEcdhPublic,
          expiresAt: auth.expiresAt,
        },
        {
          deviceId: resolvedDeviceId,
          deviceSigningPublic: publicKeys.deviceSigningPublic ?? null,
          deviceEcdhPublic: publicKeys.deviceEcdhPublic ?? null,
        },
      );

      // TOFU verification via Worker (before marking crypto ready)
      if (resolvedDeviceId && publicKeys.deviceSigningPublic) {
        try {
          const { devices } = await devicesApi.list({ popDeviceId: resolvedDeviceId });
          const { errors: warnings } = await worker.tofuVerifyAllDevices({
            devices: devices.map((d: any) => ({
              name: d.name,
              userId: d.user_id,
              deviceId: d.id,
              signingPublicKey: base64UrlDecode(d.signing_public_key),
              ecdhPublicKey: base64UrlDecode(d.ecdh_public_key),
              identitySignature: d.identity_signature ?? null,
              clientNonce: d.client_nonce ?? null,
            })),
          });
          if (warnings.length > 0) {
            setTofuErrors(warnings);
          }
        } catch (e) {
          if (e instanceof CryptoWorkerError && e.code === "tofu_hard_fail") {
            setError(e.message);
            return;
          }
        }
      }

      await worker.clearTransientKeys();
      setCryptoWorkerReady(true);
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
