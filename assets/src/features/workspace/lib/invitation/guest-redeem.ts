import { authState, deviceState, setCryptoWorkerReady, setFullSession } from "@/entities/session";
import { setCurrentWorkspaceId } from "@/entities/workspace";
import { ApiError, authApi, workspacesApi, type components } from "@/shared/api";
import { persistCurrentKeysWithDsk, persistDeviceId } from "@/shared/lib/auth/key-persistence";
import { base64UrlDecode, base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "@/shared/lib/crypto/jcs";
import { computeSigningKeyId } from "@/shared/lib/crypto/signature";
import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  rememberVerifiedKeyDirectoryLineage,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import type { SignedKeyDirectoryEnvelope } from "@/shared/lib/anti-rollback/key-directory-pin/types";
import { buildGuestInvitationRedeemedKeyDirectoryAppend } from "@/shared/lib/crypto/key-directory/invitation-events";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getDeviceName, getDeviceType } from "@/shared/lib/device/metadata";
import {
  readActiveGuestRedeemMaterial,
  readGuestRedeemMaterial,
  rememberGuestRedeemMaterial,
  type GuestRedeemMaterial,
} from "./guest-material";
import {
  invitationBootstrapSecret,
  invitationLookupToken,
  invitationSecretCommitment,
} from "./token";
import {
  assertGuestInvitationBootstrapPlaintext,
  pinWorkspaceCheckpointFromBootstrap,
  type GuestInvitationBootstrapPlaintext,
} from "./bootstrap";
import { fetchVerifiedKeyDirectory } from "@/shared/lib/key-directory/fetch";
import {
  assertKeyDirectoryEnvelope,
  type KeyDirectoryEnvelope,
} from "@/shared/lib/crypto/key-directory/types";

type RedeemResponse = components["schemas"]["RedeemGuestInvitationResponse"];
export type GuestRedeemResult = RedeemResponse;
type MeResponse = Awaited<ReturnType<typeof authApi.me>>;
type GuestRedeemBody = Omit<
  components["schemas"]["RedeemGuestInvitationRequest"],
  "token" | "workspace_key_directory_checkpoint" | "workspace_key_directory_events"
>;
interface GuestInvitationLookupResult {
  kind: "guest";
  invitation_id: string;
  workspace_id: string;
  scope_kind: "workspace" | "document" | "folder" | "share";
  scope_id: string;
  permission: "view" | "edit";
  kek_version: number;
  encrypted_bootstrap_package?: Record<string, unknown> | null;
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
  workspace_key_directory_checkpoint_ancestry?: KeyDirectoryEnvelope[];
  workspace_key_directory_event_ancestry?: KeyDirectoryEnvelope[];
}

function signingPublicMaterialJson(
  material: components["schemas"]["HybridSigningPublicKeyMaterial"],
): StrictJsonValue {
  return {
    protocol: material.protocol,
    version: material.version,
    suite_id: material.suite_id,
    suite_rank: material.suite_rank,
    owner_kind: material.owner_kind,
    owner_id: material.owner_id,
    ed25519_public: material.ed25519_public,
    mldsa65_public: material.mldsa65_public,
  };
}

function findGuestInvitationCreatedEvent(
  events: Record<string, unknown>[],
  invitationId: string,
): Record<string, unknown> {
  const event = events.find((envelope) => {
    const payload = envelope.payload as Record<string, unknown> | undefined;
    const body = payload?.body as Record<string, unknown> | undefined;
    return (
      payload?.event_type === "guest_invitation_created" &&
      body?.guest_invitation_id === invitationId
    );
  });
  if (!event) throw new Error("guest_invitation_created_event_missing");
  return event;
}

async function assertGuestInvitationBootstrapMatchesCreatedEvent(params: {
  lookupToken: string;
  bootstrapSecret: string;
  bootstrapPackage: Record<string, unknown>;
  plaintext: GuestInvitationBootstrapPlaintext;
  createdEvents: Record<string, unknown>[];
}): Promise<void> {
  const event = findGuestInvitationCreatedEvent(
    params.createdEvents,
    params.plaintext.guest_invitation_id,
  );
  const payload = event.payload as Record<string, unknown> | undefined;
  const body = payload?.body as Record<string, unknown> | undefined;
  const redeemAuthority = body?.redeem_authority as Record<string, unknown> | undefined;
  const expectedCapabilityContextHash = blake3Base64Url(
    canonicalizeStrictBytes({
      guest_invitation_id: params.plaintext.guest_invitation_id,
      permission: params.plaintext.permission,
      scope_id: params.plaintext.scope_id,
      scope_kind: params.plaintext.scope_kind,
      workspace_id: params.plaintext.workspace_id,
    } as StrictJsonValue),
  );
  if (
    body?.workspace_id !== params.plaintext.workspace_id ||
    body.guest_invitation_id !== params.plaintext.guest_invitation_id ||
    body.scope_kind !== params.plaintext.scope_kind ||
    body.scope_id !== params.plaintext.scope_id ||
    body.permission !== params.plaintext.permission ||
    body.bootstrap_key_commitment !==
      (await invitationSecretCommitment(params.lookupToken, params.bootstrapSecret, "guest")) ||
    body.bootstrap_package_hash !==
      blake3Base64Url(canonicalizeStrictBytes(params.bootstrapPackage as StrictJsonValue)) ||
    body.bootstrap_suite_id !== "refmd-v2-invitation-bootstrap-xchacha20poly1305" ||
    body.capability_context_hash !== expectedCapabilityContextHash ||
    redeemAuthority?.signing_key_id !== params.plaintext.redeem_authority_signing_key_id
  ) {
    throw new Error("guest_invitation_bootstrap_created_event_mismatch");
  }
}

async function ensureDskInWorker(): Promise<void> {
  const worker = getCryptoWorker();
  if (await worker.loadStoredDsk()) {
    return;
  }

  await worker.generateDsk();
}

async function createGuestRedeemMaterial(guestUserId: string): Promise<GuestRedeemMaterial> {
  const worker = getCryptoWorker();
  const deviceId = crypto.randomUUID();
  await worker.setUserContext(guestUserId, deviceId);
  await worker.generateUmk();
  const identityPublic = await worker.generateIdentityKeys();
  const devicePublic = await worker.generateDeviceKeys({ deviceId });
  const clientNonce = await worker.generateClientNonce();
  const pendingRegistrationChallengeHash = blake3Base64Url(
    canonicalizeStrictBytes({
      device_id: deviceId,
      guest_user_id: guestUserId,
      kind: "guest_invitation_genesis_device_bootstrap",
    } as StrictJsonValue),
  );
  const userIdentityPublicKeyHash = blake3Base64Url(
    canonicalizeStrictBytes(
      signingPublicMaterialJson(identityPublic.hybridSigningPublicKeyMaterial),
    ),
  );
  const { signature } = await worker.createGenesisDeviceBootstrapSignature({
    deviceEcdhPublic: devicePublic.ecdhPublic,
    clientNonce,
    registrationChallengeHash: pendingRegistrationChallengeHash,
    identitySigningKeyId: computeSigningKeyId(identityPublic.hybridSigningPublicKeyMaterial),
    userIdentityPublicKeyHash,
  });
  const identityHybridSigningPublicKeyMaterial = identityPublic.hybridSigningPublicKeyMaterial;
  const deviceHybridSigningPublicKeyMaterial = devicePublic.hybridSigningPublicKeyMaterial;

  const body: GuestRedeemBody = {
    guest_user_id: guestUserId,
    device_id: deviceId,
    device_hybrid_encryption_public_key_material: devicePublic.hybridEncryptionPublicKeyMaterial,
    device_hybrid_signing_public_key_material: devicePublic.hybridSigningPublicKeyMaterial,
    identity_hybrid_encryption_public_key_material:
      identityPublic.hybridEncryptionPublicKeyMaterial,
    identity_hybrid_signing_public_key_material: identityPublic.hybridSigningPublicKeyMaterial,
    approval_signature: signature,
    client_nonce: base64UrlEncode(clientNonce),
    pending_registration_challenge_hash: pendingRegistrationChallengeHash,
    device_name: getDeviceName(),
    device_type: getDeviceType(),
  };

  return {
    body,
    publicKeys: {
      identityHybridSigningPublicKeyMaterial,
      identityEcdhPublic: base64UrlEncode(identityPublic.ecdhPublic),
      deviceSigningKeyId: devicePublic.signingKeyId,
      deviceEncryptionKeyId: devicePublic.encryptionKeyId,
      deviceHybridSigningPublicKeyMaterial,
      deviceEcdhPublic: base64UrlEncode(devicePublic.ecdhPublic),
    },
  };
}

async function buildGuestRedeemAdmission(
  token: string,
  material: GuestRedeemMaterial,
): Promise<{
  workspace_key_directory_events: KeyDirectoryEnvelope[];
  workspace_key_directory_checkpoint: KeyDirectoryEnvelope;
  bootstrapPlaintext: GuestInvitationBootstrapPlaintext;
  baseCheckpoint: KeyDirectoryEnvelope;
  workspaceKeyDirectoryEventAncestry: KeyDirectoryEnvelope[];
}> {
  const lookupToken = invitationLookupToken(token);
  const bootstrapSecret = invitationBootstrapSecret(token);
  if (!bootstrapSecret) throw new Error("This invitation link is missing guest key material.");
  const lookup = (await workspacesApi.lookupInvitation(lookupToken)) as GuestInvitationLookupResult;
  if (lookup.kind !== "guest" || !lookup.encrypted_bootstrap_package) {
    throw new Error("This guest invitation is missing workspace trust state.");
  }
  const bootstrapPlaintext = assertGuestInvitationBootstrapPlaintext(
    await getCryptoWorker().unwrapKekFromInvitationBootstrap({
      bootstrap: lookup.encrypted_bootstrap_package,
      bootstrapSecret,
    }),
  );
  if (
    bootstrapPlaintext.workspace_id !== lookup.workspace_id ||
    bootstrapPlaintext.guest_invitation_id !== lookup.invitation_id ||
    bootstrapPlaintext.scope_kind !== lookup.scope_kind ||
    bootstrapPlaintext.scope_id !== lookup.scope_id ||
    bootstrapPlaintext.permission !== lookup.permission ||
    lookup.encrypted_bootstrap_package.workspace_id !== lookup.workspace_id ||
    lookup.encrypted_bootstrap_package.key_version !== lookup.kek_version ||
    !lookup.workspace_key_directory_checkpoint
  ) {
    throw new Error("Guest invitation key material is malformed.");
  }
  const workspaceKeyDirectoryCheckpoint = assertKeyDirectoryEnvelope(
    lookup.workspace_key_directory_checkpoint,
    "guest_invitation_workspace_key_directory_checkpoint_invalid",
  );
  const workspaceKeyDirectoryCheckpointAncestry = (
    lookup.workspace_key_directory_checkpoint_ancestry ?? []
  ).map((entry) =>
    assertKeyDirectoryEnvelope(entry, "guest_invitation_workspace_checkpoint_ancestry_invalid"),
  );
  const workspaceKeyDirectoryEventAncestry = (
    lookup.workspace_key_directory_event_ancestry ?? []
  ).map((entry) =>
    assertKeyDirectoryEnvelope(entry, "guest_invitation_workspace_event_ancestry_invalid"),
  );
  await assertGuestInvitationBootstrapMatchesCreatedEvent({
    lookupToken,
    bootstrapSecret,
    bootstrapPackage: lookup.encrypted_bootstrap_package,
    plaintext: bootstrapPlaintext,
    createdEvents: workspaceKeyDirectoryEventAncestry,
  });
  await pinWorkspaceCheckpointFromBootstrap({
    workspaceId: bootstrapPlaintext.workspace_id,
    checkpointEnvelope: bootstrapPlaintext.workspace_key_directory_checkpoint,
    workspaceKeyDirectoryEventAncestry,
    workspacePinBootstrapHash: bootstrapPlaintext.workspace_pin_bootstrap_hash,
    workspacePinBootstrap: bootstrapPlaintext.workspace_pin_bootstrap,
  });
  const baseCheckpoint = await ensureWorkspaceCheckpointPinned({
    workspaceId: lookup.workspace_id,
    checkpointEnvelope: workspaceKeyDirectoryCheckpoint,
    checkpointAncestry: workspaceKeyDirectoryCheckpointAncestry,
    eventAncestry: workspaceKeyDirectoryEventAncestry,
  });
  const append = await buildGuestInvitationRedeemedKeyDirectoryAppend({
    workspaceId: lookup.workspace_id,
    checkpointEnvelope: baseCheckpoint,
    invitationId: lookup.invitation_id,
    guestGrantId: crypto.randomUUID(),
    redeemAuthoritySigningKeyId: bootstrapPlaintext.redeem_authority_signing_key_id,
    guestUserId: material.body.guest_user_id,
    guestDeviceId: material.body.device_id,
    guestIdentityHybridEncryptionPublicKeyMaterial: material.body
      .identity_hybrid_encryption_public_key_material as never,
    guestDeviceHybridSigningPublicKeyMaterial: material.body
      .device_hybrid_signing_public_key_material as never,
    guestDeviceHybridEncryptionPublicKeyMaterial: material.body
      .device_hybrid_encryption_public_key_material as never,
    guestEncryptionKeyId: material.publicKeys.deviceEncryptionKeyId,
    guestSigningKeyId: material.publicKeys.deviceSigningKeyId,
    scopeKind: lookup.scope_kind,
    scopeId: lookup.scope_id,
    permission: lookup.permission,
  });
  return {
    workspace_key_directory_events: append.events,
    workspace_key_directory_checkpoint: append.checkpoint,
    bootstrapPlaintext,
    baseCheckpoint,
    workspaceKeyDirectoryEventAncestry: workspaceKeyDirectoryEventAncestry,
  };
}

async function ensureWorkspaceCheckpointPinned(params: {
  workspaceId: string;
  checkpointEnvelope: KeyDirectoryEnvelope;
  checkpointAncestry: KeyDirectoryEnvelope[];
  eventAncestry: KeyDirectoryEnvelope[];
}): Promise<KeyDirectoryEnvelope> {
  const pin = await getKeyDirectoryPin("workspace", params.workspaceId);
  const checkpointHash = hashKeyDirectoryCheckpointEnvelope(params.checkpointEnvelope);
  const operationCheckpoint = operationCheckpointFromEnvelope(params.checkpointEnvelope);
  if (
    pin &&
    pin.checkpointSequence === operationCheckpoint.sequence &&
    pin.checkpointHash === checkpointHash &&
    pin.eventHeadSequence === operationCheckpoint.coveredHeadSequence &&
    pin.eventHeadHash === operationCheckpoint.coveredHeadHash
  ) {
    rememberVerifiedKeyDirectoryLineage({
      scopeKind: "workspace",
      scopeId: params.workspaceId,
      checkpointEnvelope: params.checkpointEnvelope as unknown as SignedKeyDirectoryEnvelope,
      checkpointAncestry: params.checkpointAncestry as unknown as SignedKeyDirectoryEnvelope[],
      eventAncestry: params.eventAncestry as unknown as SignedKeyDirectoryEnvelope[],
    });
    return params.checkpointEnvelope;
  }

  await advanceKeyDirectoryPinWithProof({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    checkpointEnvelope: params.checkpointEnvelope,
    checkpointAncestry: params.checkpointAncestry,
    eventAncestry: params.eventAncestry,
  });
  return params.checkpointEnvelope;
}

async function advanceWorkspacePinWithAcceptedAppend(params: {
  workspaceId: string;
  baseCheckpointEnvelope: KeyDirectoryEnvelope;
  acceptedCheckpointEnvelope: KeyDirectoryEnvelope;
  acceptedEventEnvelopes: KeyDirectoryEnvelope[];
  authorityEventAncestry: KeyDirectoryEnvelope[];
}): Promise<void> {
  await advanceKeyDirectoryPinWithProof({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    checkpointEnvelope: params.acceptedCheckpointEnvelope,
    checkpointAncestry: [params.baseCheckpointEnvelope],
    eventAncestry: params.acceptedEventEnvelopes,
    authorityEventAncestry: params.authorityEventAncestry,
  });
}

function operationCheckpointFromEnvelope(checkpointEnvelope: KeyDirectoryEnvelope) {
  const payload = checkpointEnvelope.payload as Record<string, unknown> | undefined;
  const covered = payload?.covered_event_head as Record<string, unknown> | undefined;
  if (!payload || !covered) throw new Error("key_directory_checkpoint_invalid");
  return {
    sequence: numberField(payload.sequence),
    coveredHeadSequence: numberField(covered.head_sequence),
    coveredHeadHash: stringField(covered.head_hash),
  };
}

function numberField(value: unknown): number {
  if (typeof value !== "number" || !Number.isInteger(value) || value < 1) {
    throw new Error("key_directory_number_invalid");
  }
  return value;
}

function stringField(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error("key_directory_string_invalid");
  }
  return value;
}

async function restoreWorkerForGuestSession(
  response: RedeemResponse,
  material: GuestRedeemMaterial,
): Promise<MeResponse> {
  const [hasStoredDsk, me] = await Promise.all([getCryptoWorker().hasStoredDsk(), authApi.me()]);
  if (!hasStoredDsk) {
    throw new Error("Guest keys are not available on this device.");
  }

  await getCryptoWorker().init({
    dsk: null,
    useStoredDsk: true,
    userId: response.guest_user_id,
    deviceId: response.guest_device_id,
    deviceSigningKeyId: material.publicKeys.deviceSigningKeyId,
    keyRestoreEndpointRef: me.key_restore_endpoint_ref ?? null,
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
      user: { id: me.user_id, email: me.email, name: me.name, accountType: "guest" },
      sessionId: me.session_id,
      identityHybridSigningPublicKeyMaterial:
        material.publicKeys.identityHybridSigningPublicKeyMaterial,
      identityEcdhPublic: base64UrlDecode(material.publicKeys.identityEcdhPublic),
      expiresAt: me.expires_at,
    },
    {
      deviceId: response.guest_device_id,
      deviceSigningKeyId: material.publicKeys.deviceSigningKeyId,
      deviceKeyCheckpointSequence: me.device_key_checkpoint_sequence ?? null,
      deviceKeyCheckpointHash: me.device_key_checkpoint_hash ?? null,
      deviceHybridSigningPublicKeyMaterial:
        material.publicKeys.deviceHybridSigningPublicKeyMaterial,
      deviceEcdhPublic: base64UrlDecode(material.publicKeys.deviceEcdhPublic),
    },
  );
  setCurrentWorkspaceId(response.workspace_id);
}

async function redeemGuestInvitationWithRebasedAdmission(
  token: string,
  lookupToken: string,
  material: GuestRedeemMaterial,
): Promise<{
  admission: Awaited<ReturnType<typeof buildGuestRedeemAdmission>>;
  response: RedeemResponse;
}> {
  let admission = await buildGuestRedeemAdmission(token, material);
  const submit = () => {
    const {
      bootstrapPlaintext: _bootstrapPlaintext,
      baseCheckpoint: _baseCheckpoint,
      workspaceKeyDirectoryEventAncestry: _workspaceKeyDirectoryEventAncestry,
      ...redeemAdmission
    } = admission;
    return workspacesApi.redeemGuestInvitation({
      token: lookupToken,
      ...material.body,
      ...redeemAdmission,
    });
  };

  try {
    return { admission, response: await submit() };
  } catch (err) {
    if (!(err instanceof ApiError && err.status === 422 && err.code === "invalid_key_directory")) {
      throw err;
    }
    admission = await buildGuestRedeemAdmission(token, material);
    return { admission, response: await submit() };
  }
}

export async function redeemGuestInvitation(token: string) {
  const worker = getCryptoWorker();

  await worker.lock();
  await ensureDskInWorker();
  const bootstrapSecret = invitationBootstrapSecret(token);
  if (!bootstrapSecret) throw new Error("This invitation link is missing guest key material.");
  const lookupToken = invitationLookupToken(token);

  const storedMaterial =
    (await readGuestRedeemMaterial(token)) ?? (await readCurrentGuestRedeemMaterial());
  if (storedMaterial) {
    const { admission, response } = await redeemGuestInvitationWithRebasedAdmission(
      token,
      lookupToken,
      storedMaterial,
    );
    const me = await restoreWorkerForGuestSession(response, storedMaterial);
    await acceptGuestRedeemCheckpoint({
      response,
      admission,
      existingGuestDeviceId: response.guest_device_id,
      allowReentryCheckpoint: true,
    });
    setGuestSession(response, storedMaterial, me);
    await rememberGuestRedeemMaterial(token, storedMaterial);
    return response satisfies GuestRedeemResult;
  }
  const auth = authState();
  if (auth?.user.accountType === "guest") {
    throw new Error("Guest access is not available on this device.");
  }

  const material = await createGuestRedeemMaterial(crypto.randomUUID());
  const { admission, response } = await redeemGuestInvitationWithRebasedAdmission(
    token,
    lookupToken,
    material,
  );

  await worker.setUserContext(response.guest_user_id, response.guest_device_id);
  await persistCurrentKeysWithDsk(response.guest_user_id);

  await worker.setInitialized();
  await acceptGuestRedeemCheckpoint({
    response,
    admission,
    existingGuestDeviceId: response.guest_device_id,
    allowReentryCheckpoint: false,
  });
  const persistentMaterial: GuestRedeemMaterial = material;
  await rememberGuestRedeemMaterial(token, persistentMaterial);
  const me = await authApi.me();
  setGuestSession(response, persistentMaterial, me);

  return response satisfies GuestRedeemResult;
}

async function acceptGuestRedeemCheckpoint(params: {
  response: RedeemResponse;
  admission: Awaited<ReturnType<typeof buildGuestRedeemAdmission>>;
  existingGuestDeviceId: string;
  allowReentryCheckpoint: boolean;
}): Promise<void> {
  const responseCheckpoint = params.response.workspace_key_directory_checkpoint;
  if (!responseCheckpoint) {
    throw new Error("Guest invitation acceptance is missing workspace trust state.");
  }
  const responseKeyDirectoryCheckpoint = assertKeyDirectoryEnvelope(
    responseCheckpoint,
    "guest_response_key_directory_checkpoint_invalid",
  );
  const submittedHash = hashKeyDirectoryCheckpointEnvelope(
    params.admission.workspace_key_directory_checkpoint,
  );
  const responseHash = hashKeyDirectoryCheckpointEnvelope(responseKeyDirectoryCheckpoint);
  if (responseHash === submittedHash) {
    await advanceWorkspacePinWithAcceptedAppend({
      workspaceId: params.response.workspace_id,
      baseCheckpointEnvelope: params.admission.baseCheckpoint,
      acceptedCheckpointEnvelope: params.admission.workspace_key_directory_checkpoint,
      acceptedEventEnvelopes: params.admission.workspace_key_directory_events,
      authorityEventAncestry: params.admission.workspaceKeyDirectoryEventAncestry,
    });
    return;
  }

  if (!params.allowReentryCheckpoint) {
    throw new Error("Guest invitation trust state does not match the submitted append.");
  }

  await acceptGuestReentryCheckpoint({
    workspaceId: params.response.workspace_id,
    guestDeviceId: params.existingGuestDeviceId,
    responseCheckpoint: responseKeyDirectoryCheckpoint,
  });
}

async function acceptGuestReentryCheckpoint(params: {
  workspaceId: string;
  guestDeviceId: string;
  responseCheckpoint: KeyDirectoryEnvelope;
}): Promise<void> {
  const responseHash = hashKeyDirectoryCheckpointEnvelope(params.responseCheckpoint);
  const pin = await getKeyDirectoryPin("workspace", params.workspaceId);
  if (pin?.checkpointHash === responseHash) return;

  await fetchVerifiedKeyDirectory({
    scopeKind: "workspace",
    scopeId: params.workspaceId,
    popDeviceId: params.guestDeviceId,
    popWorker: getCryptoWorker(),
  });
  const updated = await getKeyDirectoryPin("workspace", params.workspaceId);
  const responseState = operationCheckpointFromEnvelope(params.responseCheckpoint);
  if (!updated || updated.checkpointSequence < responseState.sequence) {
    throw new Error("Guest invitation trust state does not match the accepted reentry checkpoint.");
  }
}

async function readCurrentGuestRedeemMaterial(): Promise<GuestRedeemMaterial | null> {
  const auth = authState();
  const device = deviceState();
  if (auth?.user.accountType !== "guest" || !device?.deviceId) return null;
  return readActiveGuestRedeemMaterial(auth.user.id, device.deviceId);
}
