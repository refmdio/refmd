import { authState, setCryptoWorkerReady, setFullSession } from "@/entities/session";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { authApi, workspacesApi, type components } from "@/shared/api";
import { persistDeviceId, persistWrappedUmk } from "@/shared/lib/auth/key-persistence";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { loadDsk, loadDskInitData, storeWrappedDeviceKeysRaw } from "@/shared/lib/crypto/dsk";
import { persistWorkspaceKekLocally } from "@/shared/lib/crypto/workspace-kek-persistence";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getDeviceName, getDeviceType } from "@/shared/lib/device/metadata";
import {
  deserializeWrappedBlob,
  hasGuestRedeemMaterial,
  readGuestRedeemMaterial,
  rememberGuestRedeemMaterial,
  serializeWrappedBlob,
  type GuestRedeemMaterial,
} from "./guest-material";

type RedeemResponse = components["schemas"]["RedeemGuestInvitationResponse"];
type MeResponse = Awaited<ReturnType<typeof authApi.me>>;

async function ensureDskInWorker(): Promise<void> {
  const worker = getCryptoWorker();
  const dsk = await loadDsk();
  if (dsk) {
    await worker.setDsk(dsk);
    return;
  }

  await worker.generateDsk();
}

async function createGuestRedeemMaterial(guestUserId: string): Promise<GuestRedeemMaterial> {
  const worker = getCryptoWorker();
  await worker.setUserContext(guestUserId);
  await worker.generateUmk();
  const recovery = await worker.generateRecoveryKey();
  const identityPublic = await worker.generateIdentityKeys();
  const encryptedIdentity = await worker.wrapIdentityKeysForServer(guestUserId);
  const devicePublic = await worker.generateDeviceKeys();
  const clientNonce = await worker.generateClientNonce();
  const { signature } = await worker.signDeviceRegistration({
    deviceSigningPublic: devicePublic.signingPublic,
    deviceEcdhPublic: devicePublic.ecdhPublic,
    clientNonce,
  });

  const identitySigningPublic = base64UrlEncode(identityPublic.signingPublic);
  const identityEcdhPublic = base64UrlEncode(identityPublic.ecdhPublic);
  const deviceSigningPublic = base64UrlEncode(devicePublic.signingPublic);
  const deviceEcdhPublic = base64UrlEncode(devicePublic.ecdhPublic);

  return {
    body: {
      guest_user_id: guestUserId,
      device_signing_pub_key: deviceSigningPublic,
      device_encryption_pub_key: deviceEcdhPublic,
      identity_signing_pub_key: identitySigningPublic,
      identity_encryption_pub_key: identityEcdhPublic,
      identity_signature: base64UrlEncode(signature),
      client_nonce: base64UrlEncode(clientNonce),
      recovery_encrypted_umk: base64UrlEncode(recovery.encryptedUmk),
      recovery_nonce: base64UrlEncode(recovery.nonce),
      encrypted_identity_encryption_private: base64UrlEncode(
        encryptedIdentity.encryptedEcdhPrivate,
      ),
      encrypted_identity_encryption_private_nonce: base64UrlEncode(
        encryptedIdentity.ecdhPrivateNonce,
      ),
      encrypted_identity_signing_private: base64UrlEncode(
        encryptedIdentity.encryptedSigningPrivate,
      ),
      encrypted_identity_signing_private_nonce: base64UrlEncode(
        encryptedIdentity.signingPrivateNonce,
      ),
      device_name: getDeviceName(),
      device_type: getDeviceType(),
    },
    publicKeys: {
      identitySigningPublic,
      identityEcdhPublic,
      deviceSigningPublic,
      deviceEcdhPublic,
    },
  };
}

async function restoreWorkerForGuestSession(
  response: RedeemResponse,
  material: GuestRedeemMaterial,
): Promise<MeResponse> {
  const [dskData, me] = await Promise.all([loadDskInitData(), authApi.me()]);
  const wrappedKeys = material.wrappedKeys;
  if (!dskData?.dsk || !wrappedKeys) {
    throw new Error("Guest keys are not available on this device.");
  }

  await getCryptoWorker().init({
    dsk: dskData.dsk,
    wrappedUmk: deserializeWrappedBlob(wrappedKeys.umk),
    wrappedDeviceEcdh: deserializeWrappedBlob(wrappedKeys.deviceEcdh),
    wrappedDeviceSigning: deserializeWrappedBlob(wrappedKeys.deviceSigning),
    userId: response.guest_user_id,
    deviceId: response.guest_device_id,
    ...(me.keys?.encrypted_ecdh_private
      ? {
          encryptedIdentityEcdh: base64UrlDecode(me.keys.encrypted_ecdh_private),
          identityEcdhNonce: base64UrlDecode(me.keys.encrypted_ecdh_private_nonce),
          encryptedIdentitySigning: base64UrlDecode(me.keys.encrypted_signing_private),
          identitySigningNonce: base64UrlDecode(me.keys.encrypted_signing_private_nonce),
        }
      : {}),
  });

  const ready = await getCryptoWorker().isReady();
  if (!ready || material.body.guest_user_id !== response.guest_user_id) {
    throw new Error("Guest keys are not available on this device.");
  }
  return me;
}

function setGuestSession(
  response: RedeemResponse,
  material: GuestRedeemMaterial,
  me: MeResponse,
): void {
  setCryptoWorkerReady(true);
  persistDeviceId(response.guest_device_id, response.guest_user_id);
  setFullSession(
    {
      user: { id: me.user_id, email: me.email, name: me.name, accountType: me.account_type },
      sessionId: me.session_id,
      identitySigningPublic: me.identity_signing_public_key
        ? base64UrlDecode(me.identity_signing_public_key)
        : base64UrlDecode(material.publicKeys.identitySigningPublic),
      identityEcdhPublic: base64UrlDecode(material.publicKeys.identityEcdhPublic),
      expiresAt: me.expires_at,
    },
    {
      deviceId: response.guest_device_id,
      deviceSigningPublic: base64UrlDecode(material.publicKeys.deviceSigningPublic),
      deviceEcdhPublic: base64UrlDecode(material.publicKeys.deviceEcdhPublic),
    },
  );
  setCurrentWorkspaceId(response.workspace_id);
}

export async function redeemGuestInvitation(token: string) {
  const worker = getCryptoWorker();
  const auth = authState();

  if (auth && auth.user.accountType !== "guest") {
    throw new Error("Sign out before joining as a guest.");
  }
  if (auth && !(await hasGuestRedeemMaterial(token))) {
    throw new Error("Guest access is not available on this device.");
  }

  await worker.lock();
  await ensureDskInWorker();

  const storedMaterial = await readGuestRedeemMaterial(token);
  if (storedMaterial) {
    const response = await workspacesApi.redeemGuestInvitation({
      token,
      ...storedMaterial.body,
    });
    const me = await restoreWorkerForGuestSession(response, storedMaterial);
    setGuestSession(response, storedMaterial, me);
    return response;
  }
  if (auth?.user.accountType === "guest") {
    throw new Error("Guest access is not available on this device.");
  }

  const material = await createGuestRedeemMaterial(crypto.randomUUID());
  const response = await workspacesApi.redeemGuestInvitation({
    token,
    ...material.body,
  });

  await worker.setUserContext(response.guest_user_id, response.guest_device_id);
  await worker.decryptKekFromInvitation({
    encryptedKek: base64UrlDecode(response.encrypted_kek),
    nonce: base64UrlDecode(response.kek_nonce),
    token: base64UrlDecode(token),
    workspaceId: response.workspace_id,
    invitationId: response.invitation_id,
    keyVersion: response.kek_version,
  });

  await persistWorkspaceKekLocally({
    workspaceId: response.workspace_id,
    userId: response.guest_user_id,
    deviceId: response.guest_device_id,
    deviceEcdhPublic: base64UrlDecode(material.publicKeys.deviceEcdhPublic),
    keyVersion: response.kek_version,
    isActive: true,
  });

  const wrappedUmk = await worker.wrapUmkWithDsk(response.guest_user_id);
  await persistWrappedUmk({ wrappedUmk, kmsi: true, userId: response.guest_user_id });
  const wrappedDeviceKeys = await worker.wrapDeviceKeysWithDsk(response.guest_user_id);
  await storeWrappedDeviceKeysRaw(wrappedDeviceKeys.wrappedEcdh, wrappedDeviceKeys.wrappedSigning);

  await worker.setInitialized();
  const persistentMaterial: GuestRedeemMaterial = {
    ...material,
    wrappedKeys: {
      umk: serializeWrappedBlob(wrappedUmk),
      deviceEcdh: serializeWrappedBlob(wrappedDeviceKeys.wrappedEcdh),
      deviceSigning: serializeWrappedBlob(wrappedDeviceKeys.wrappedSigning),
    },
  };
  await rememberGuestRedeemMaterial(token, persistentMaterial);
  const me = await authApi.me();
  setGuestSession(response, persistentMaterial, me);

  return response;
}
