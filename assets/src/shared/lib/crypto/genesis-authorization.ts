import { blake3Base64Url } from "./hash";
import { auditCheckpointHash } from "./signature-audit-transcript";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import {
  buildGenesisPqWrapSigningInput,
  deriveGenesisWorkspaceMemberEnvelopeValues,
  type GenesisWorkspaceMemberEnvelopePrecommit,
} from "./signed-pq-wrap";
import type { HybridSignature } from "./signature";
import type { getCryptoWorker } from "./worker/client";

type GenesisSigningWorker = Pick<
  ReturnType<typeof getCryptoWorker>,
  | "createGenesisDeviceBootstrapSignature"
  | "signAuditCheckpoint"
  | "signDeviceKeyDirectoryCheckpoint"
  | "signDeviceKeyDirectoryEvent"
  | "signGenesisPqWrap"
  | "signIdentityKeyDirectoryCheckpoint"
  | "signIdentityKeyDirectoryEvent"
>;

interface SignedArtifact {
  signature: HybridSignature;
}

export interface GenesisCompoundAuthorization {
  protocol: "refmd.audit.compound-append-authorization";
  version: 1;
  compound_intent_id: string;
  mutation_id: string;
  intent_hash: string;
  scope_signatures: Array<{
    chain_scope_kind: string;
    chain_scope_id: string;
    checkpoint_hash: string;
    checkpoint_variant: string;
    signature: HybridSignature;
  }>;
  effect_authorizations: Array<{
    requirement_order: number;
    authorization_kind: string;
    signing_purpose: string;
    surface_variant: string;
    subject_hash: string;
    signer_key_id: string;
    signature: HybridSignature;
    approval_proof: "NONE";
  }>;
}

export interface GenesisKeyDirectoryBootstrap {
  userEvents: Array<{
    payload: Record<string, unknown>;
    signatures: Array<Record<string, unknown>>;
  }>;
  userCheckpoint: {
    payload: Record<string, unknown>;
    signatures: Array<Record<string, unknown>>;
  };
  workspaceEvents: Array<{
    payload: Record<string, unknown>;
    signatures: Array<Record<string, unknown>>;
  }>;
  workspaceCheckpoint: {
    payload: Record<string, unknown>;
    signatures: Array<Record<string, unknown>>;
  };
}

export async function createWorkspaceGenesisAuthorization(params: {
  worker: GenesisSigningWorker;
  intent: StrictJsonValue;
  precommit: GenesisWorkspaceMemberEnvelopePrecommit;
}): Promise<GenesisCompoundAuthorization> {
  const intent = exactRecord(params.intent, [
    "challenge_id",
    "compound_intent_id",
    "expires_at",
    "key_directory_effects_hash",
    "mutation_id",
    "protocol",
    "scopes",
    "version",
  ]);
  literal(intent.protocol, "refmd.audit.compound-append-intent");
  literal(intent.version, 1);
  const scopes = recordArray(intent.scopes);
  if (scopes.length !== 1 || scopes[0]?.chain_scope_kind !== "workspace") {
    throw new Error("workspace_genesis_intent_scope_invalid");
  }
  const scope = scopes[0];
  const effects = recordArray(scope.candidate_key_directory_effects);
  const firstEffect = effects[0];
  if (!firstEffect) throw new Error("workspace_genesis_effect_missing");
  const actor = record(record(firstEffect.event_payload).actor);
  const deviceId = requiredString(actor.device_id);
  const userId = requiredString(actor.user_id);
  const signingKeyId = requiredString(actor.signing_key_id);
  const event = recordArray(scope.candidate_events).at(-1);
  if (!event) throw new Error("workspace_genesis_audit_event_missing");
  const auditPayload: StrictJsonValue = {
    protocol: "refmd.signed-audit-checkpoint",
    version: 1,
    chain_scope_kind: "workspace",
    chain_scope_id: requiredString(scope.chain_scope_id),
    sequence: positiveInteger(event.sequence),
    event_hash: requiredString(event.event_hash),
    signer_user_id: userId,
    signer_device_id: deviceId,
    signing_key_id: signingKeyId,
    authorization_checkpoint_scope_kind: "workspace",
    authorization_checkpoint_scope_id: requiredString(scope.chain_scope_id),
    authorization_checkpoint_sequence: 0,
    authorization_checkpoint_hash: "GENESIS",
    covered_event_class: "authority",
    covered_event_type: requiredString(event.event_type),
  };
  const checkpointHash = auditCheckpointHash(auditPayload);
  literal(checkpointHash, scope.checkpoint_payload_hash);
  const auditSignature = await params.worker.signAuditCheckpoint({
    variant: "workspace_device",
    payload: auditPayload,
  });

  const effectAuthorizations = [];
  for (const requirement of recordArray(scope.effect_signature_requirements)) {
    const kind = requiredString(requirement.authorization_kind);
    let artifact: SignedArtifact;
    if (kind === "key_directory_event") {
      const effect = effects[positiveInteger(requirement.requirement_order) - 1];
      if (!effect) throw new Error("workspace_genesis_effect_missing");
      const payload = record(effect.event_payload);
      literal(hash(payload as StrictJsonValue), effect.event_hash);
      artifact = await params.worker.signDeviceKeyDirectoryEvent({
        eventType: requiredString(payload.event_type),
        eventPayload: payload,
      });
    } else if (kind === "key_directory_checkpoint") {
      const payload = record(scope.candidate_key_directory_checkpoint_payload);
      literal(hash(payload as StrictJsonValue), scope.candidate_key_directory_checkpoint_hash);
      artifact = await params.worker.signDeviceKeyDirectoryCheckpoint({
        variant: "workspace_initial",
        checkpointPayload: payload,
      });
    } else if (kind === "pq_wrap") {
      const envelopeEvent = record(
        findEffect(scope, "workspace_member_envelope_issued").event_payload,
      ) as StrictJsonValue;
      artifact = await params.worker.signGenesisPqWrap(
        buildGenesisPqWrapSigningInput({
          precommit: params.precommit,
          envelopeEventPayload: envelopeEvent,
          workspaceCheckpointHash: requiredString(scope.candidate_key_directory_checkpoint_hash),
        }),
      );
    } else {
      throw new Error("workspace_genesis_authorization_kind_invalid");
    }
    const subjectHash = requiredString(requirement.subject_hash);
    literal(artifact.signature.transcript_hash, subjectHash);
    effectAuthorizations.push({
      requirement_order: positiveInteger(requirement.requirement_order),
      authorization_kind: kind,
      signing_purpose: requiredString(requirement.signing_purpose),
      surface_variant: requiredString(requirement.surface_variant),
      subject_hash: subjectHash,
      signer_key_id: requiredString(requirement.signer_key_id),
      signature: artifact.signature,
      approval_proof: "NONE" as const,
    });
  }

  return {
    protocol: "refmd.audit.compound-append-authorization",
    version: 1,
    compound_intent_id: requiredString(intent.compound_intent_id),
    mutation_id: requiredString(intent.mutation_id),
    intent_hash: hash(params.intent),
    scope_signatures: [
      {
        chain_scope_kind: "workspace",
        chain_scope_id: requiredString(scope.chain_scope_id),
        checkpoint_hash: checkpointHash,
        checkpoint_variant: "workspace_device",
        signature: auditSignature.signature,
      },
    ],
    effect_authorizations: effectAuthorizations,
  };
}

export function materializeWorkspaceGenesisKeyDirectory(
  intentValue: StrictJsonValue,
  authorization: GenesisCompoundAuthorization,
): Pick<GenesisKeyDirectoryBootstrap, "workspaceEvents" | "workspaceCheckpoint"> {
  const scopes = recordArray(record(intentValue).scopes);
  if (scopes.length !== 1) throw new Error("workspace_genesis_intent_scope_invalid");
  const scope = scopes[0]!;
  const events: GenesisKeyDirectoryBootstrap["workspaceEvents"] = [];
  let checkpoint: GenesisKeyDirectoryBootstrap["workspaceCheckpoint"] | undefined;

  for (const [index, requirement] of recordArray(scope.effect_signature_requirements).entries()) {
    const entry = authorization.effect_authorizations[index];
    if (!entry) throw new Error("workspace_genesis_authorization_missing");
    literal(entry.authorization_kind, requirement.authorization_kind);
    if (entry.authorization_kind === "key_directory_event") {
      const effect = recordArray(scope.candidate_key_directory_effects)[
        entry.requirement_order - 1
      ];
      if (!effect) throw new Error("workspace_genesis_effect_missing");
      const payload = record(effect.event_payload);
      events.push({
        payload,
        signatures: [{ signer: record(payload.actor), signature: entry.signature }],
      });
    } else if (entry.authorization_kind === "key_directory_checkpoint") {
      const payload = record(scope.candidate_key_directory_checkpoint_payload);
      checkpoint = {
        payload,
        signatures: [
          { signer: genesisCheckpointSigner(scope, payload), signature: entry.signature },
        ],
      };
    }
  }
  if (!checkpoint) throw new Error("workspace_genesis_checkpoint_missing");
  return { workspaceEvents: events, workspaceCheckpoint: checkpoint };
}

export async function createGenesisCompoundAuthorization(params: {
  worker: GenesisSigningWorker;
  intent: StrictJsonValue;
  prepare: StrictJsonValue;
  registrationChallengeHash: string;
  deviceEcdhPublic: Uint8Array;
  clientNonce: Uint8Array;
}): Promise<GenesisCompoundAuthorization> {
  const intent = exactRecord(params.intent, [
    "challenge_id",
    "compound_intent_id",
    "expires_at",
    "key_directory_effects_hash",
    "mutation_id",
    "protocol",
    "scopes",
    "version",
  ]);
  literal(intent.protocol, "refmd.audit.compound-append-intent");
  literal(intent.version, 1);
  const prepare = record(params.prepare);
  const scopes = recordArray(intent.scopes);
  if (
    scopes.length !== 2 ||
    scopes[0]?.chain_scope_kind !== "user" ||
    scopes[1]?.chain_scope_kind !== "workspace"
  ) {
    throw new Error("genesis_intent_scope_order_invalid");
  }

  const scopeSignatures = [];
  for (const scope of scopes) {
    const variant = requiredString(scope.required_checkpoint_variant);
    const payload = auditCheckpointPayload(scope, prepare, variant);
    const checkpointHash = auditCheckpointHash(payload);
    literal(checkpointHash, scope.checkpoint_payload_hash);
    const artifact = await params.worker.signAuditCheckpoint({
      variant: auditVariant(variant),
      payload,
    });
    scopeSignatures.push({
      chain_scope_kind: requiredString(scope.chain_scope_kind),
      chain_scope_id: requiredString(scope.chain_scope_id),
      checkpoint_hash: checkpointHash,
      checkpoint_variant: variant,
      signature: artifact.signature,
    });
  }

  const precommit = prepare.workspace_member_envelope_precommit as unknown as
    | GenesisWorkspaceMemberEnvelopePrecommit
    | undefined;
  if (!precommit) throw new Error("genesis_workspace_member_envelope_precommit_missing");
  const envelopeValues = deriveGenesisWorkspaceMemberEnvelopeValues(precommit);
  const userDevice = findEffect(scopes[0], "device_key_added");
  const workspaceDevice = findEffect(scopes[1], "device_key_added");
  const ownerMember = findEffect(scopes[1], "member_added");
  const contextHash = compoundContextHash({
    intent,
    prepare,
    prepareRequestHash: hash(params.prepare),
    userDeviceEventHash: requiredString(userDevice.event_hash),
    workspaceDeviceEventHash: requiredString(workspaceDevice.event_hash),
    ownerMemberEventHash: requiredString(ownerMember.event_hash),
    envelopeCommitmentHash: envelopeValues.commitmentHash,
  });

  const effectAuthorizations = [];
  for (const scope of scopes) {
    const requirements = recordArray(scope.effect_signature_requirements);
    for (const requirement of requirements) {
      const artifact = await signEffect({
        worker: params.worker,
        intent,
        scope,
        requirement,
        prepare,
        precommit,
        contextHash,
        registrationChallengeHash: params.registrationChallengeHash,
        deviceEcdhPublic: params.deviceEcdhPublic,
        clientNonce: params.clientNonce,
        userDeviceEventHash: requiredString(userDevice.event_hash),
        workspaceDeviceEventHash: requiredString(workspaceDevice.event_hash),
        ownerMemberEventHash: requiredString(ownerMember.event_hash),
        envelopeCommitmentHash: envelopeValues.commitmentHash,
        scopes,
      });
      const subjectHash = requiredString(requirement.subject_hash);
      literal(artifact.signature.transcript_hash, subjectHash);
      effectAuthorizations.push({
        requirement_order: positiveInteger(requirement.requirement_order),
        authorization_kind: requiredString(requirement.authorization_kind),
        signing_purpose: requiredString(requirement.signing_purpose),
        surface_variant: requiredString(requirement.surface_variant),
        subject_hash: subjectHash,
        signer_key_id: requiredString(requirement.signer_key_id),
        signature: artifact.signature,
        approval_proof: "NONE" as const,
      });
    }
  }

  return {
    protocol: "refmd.audit.compound-append-authorization",
    version: 1,
    compound_intent_id: requiredString(intent.compound_intent_id),
    mutation_id: requiredString(intent.mutation_id),
    intent_hash: hash(params.intent),
    scope_signatures: scopeSignatures,
    effect_authorizations: effectAuthorizations,
  };
}

export function materializeGenesisKeyDirectoryBootstrap(
  intentValue: StrictJsonValue,
  authorization: GenesisCompoundAuthorization,
): GenesisKeyDirectoryBootstrap {
  const intent = record(intentValue);
  const scopes = recordArray(intent.scopes);
  let authorizationIndex = 0;

  const materialized = scopes.map((scope) => {
    const events: GenesisKeyDirectoryBootstrap["userEvents"] = [];
    let checkpoint: GenesisKeyDirectoryBootstrap["userCheckpoint"] | undefined;

    for (const requirement of recordArray(scope.effect_signature_requirements)) {
      const entry = authorization.effect_authorizations[authorizationIndex++];
      if (!entry) throw new Error("genesis_effect_authorization_missing");
      literal(entry.authorization_kind, requirement.authorization_kind);
      literal(entry.requirement_order, requirement.requirement_order);

      if (entry.authorization_kind === "key_directory_event") {
        const effect = recordArray(scope.candidate_key_directory_effects)[
          entry.requirement_order - 1
        ];
        if (!effect) throw new Error("genesis_key_directory_effect_missing");
        const payload = record(effect.event_payload);
        events.push({
          payload,
          signatures: [{ signer: record(payload.actor), signature: entry.signature }],
        });
      } else if (entry.authorization_kind === "key_directory_checkpoint") {
        const payload = record(scope.candidate_key_directory_checkpoint_payload);
        checkpoint = {
          payload,
          signatures: [
            {
              signer: genesisCheckpointSigner(scope, payload),
              signature: entry.signature,
            },
          ],
        };
      }
    }

    if (!checkpoint) throw new Error("genesis_key_directory_checkpoint_missing");
    return { events, checkpoint };
  });

  if (
    authorizationIndex !== authorization.effect_authorizations.length ||
    materialized.length !== 2
  ) {
    throw new Error("genesis_effect_authorization_count_invalid");
  }

  return {
    userEvents: materialized[0]!.events,
    userCheckpoint: materialized[0]!.checkpoint,
    workspaceEvents: materialized[1]!.events,
    workspaceCheckpoint: materialized[1]!.checkpoint,
  };
}

export function genesisAuditCheckpointHashes(intentValue: StrictJsonValue): {
  user: string;
  workspace: string;
} {
  const scopes = recordArray(record(intentValue).scopes);
  const byKind = new Map(
    scopes.map((scope) => [requiredString(scope.chain_scope_kind), scope] as const),
  );
  if (scopes.length !== 2 || byKind.size !== 2) {
    throw new Error("genesis_scope_set_invalid");
  }
  const user = byKind.get("user");
  const workspace = byKind.get("workspace");
  if (!user || !workspace) throw new Error("genesis_scope_set_invalid");
  return {
    user: requiredString(user.checkpoint_payload_hash),
    workspace: requiredString(workspace.checkpoint_payload_hash),
  };
}

function genesisCheckpointSigner(
  scope: Record<string, unknown>,
  payload: Record<string, unknown>,
): Record<string, unknown> {
  const identityKeys = recordArray(payload.identity_keys);
  const deviceKeys = recordArray(payload.device_keys);
  if (scope.chain_scope_kind === "user") {
    const signing = identityKeys.find(
      (entry) =>
        record(entry.key_material).owner_kind === "identity" &&
        record(entry.key_material).protocol === "refmd.hybrid-signing-key-material",
    );
    if (!signing) throw new Error("genesis_identity_signing_key_missing");
    const material = record(signing.key_material);
    return {
      signer_kind: "identity",
      user_id: requiredString(material.owner_id),
      signing_key_id: requiredString(signing.key_id),
      authorizing_checkpoint_sequence: 0,
      authorizing_checkpoint_hash: "GENESIS",
    };
  }
  const signing = deviceKeys.find(
    (entry) =>
      record(entry.key_material).owner_kind === "device" &&
      record(entry.key_material).protocol === "refmd.hybrid-signing-key-material",
  );
  if (!signing) throw new Error("genesis_device_signing_key_missing");
  const material = record(signing.key_material);
  const firstEffect = recordArray(scope.candidate_key_directory_effects)[0];
  if (!firstEffect) throw new Error("genesis_workspace_effect_missing");
  const actor = record(record(firstEffect.event_payload).actor);
  return {
    signer_kind: "device",
    user_id: requiredString(actor.user_id),
    device_id: requiredString(material.owner_id),
    signing_key_id: requiredString(signing.key_id),
    authorizing_checkpoint_sequence: 0,
    authorizing_checkpoint_hash: "GENESIS",
  };
}

async function signEffect(params: {
  worker: GenesisSigningWorker;
  intent: Record<string, unknown>;
  scope: Record<string, unknown>;
  requirement: Record<string, unknown>;
  prepare: Record<string, unknown>;
  precommit: GenesisWorkspaceMemberEnvelopePrecommit;
  contextHash: string;
  registrationChallengeHash: string;
  deviceEcdhPublic: Uint8Array;
  clientNonce: Uint8Array;
  userDeviceEventHash: string;
  workspaceDeviceEventHash: string;
  ownerMemberEventHash: string;
  envelopeCommitmentHash: string;
  scopes: Record<string, unknown>[];
}): Promise<SignedArtifact> {
  const kind = requiredString(params.requirement.authorization_kind);
  const scopeKind = requiredString(params.scope.chain_scope_kind);
  if (kind === "key_directory_event") {
    const effects = recordArray(params.scope.candidate_key_directory_effects);
    const effect = effects[positiveInteger(params.requirement.requirement_order) - 1];
    if (!effect) throw new Error("genesis_key_directory_effect_missing");
    const event = record(effect.event_payload);
    literal(hash(event as StrictJsonValue), effect.event_hash);
    return scopeKind === "user"
      ? params.worker.signIdentityKeyDirectoryEvent({
          eventType: requiredString(event.event_type),
          eventPayload: event,
        })
      : params.worker.signDeviceKeyDirectoryEvent({
          eventType: requiredString(event.event_type),
          eventPayload: event,
        });
  }
  if (kind === "key_directory_checkpoint") {
    const checkpoint = record(params.scope.candidate_key_directory_checkpoint_payload);
    literal(
      hash(checkpoint as StrictJsonValue),
      params.scope.candidate_key_directory_checkpoint_hash,
    );
    const variant = requiredString(params.requirement.surface_variant);
    if (scopeKind === "user") {
      literal(variant, "identity_initial");
      return params.worker.signIdentityKeyDirectoryCheckpoint({
        variant: "identity_initial",
        checkpointPayload: checkpoint,
      });
    }
    literal(variant, "workspace_initial");
    return params.worker.signDeviceKeyDirectoryCheckpoint({
      variant: "workspace_initial",
      checkpointPayload: checkpoint,
    });
  }
  if (kind === "pq_wrap") {
    const event = record(
      findEffect(params.scope, "workspace_member_envelope_issued").event_payload,
    ) as StrictJsonValue;
    return params.worker.signGenesisPqWrap(
      buildGenesisPqWrapSigningInput({
        precommit: params.precommit,
        envelopeEventPayload: event,
        workspaceCheckpointHash: requiredString(
          params.scope.candidate_key_directory_checkpoint_hash,
        ),
      }),
    );
  }
  if (kind === "genesis_device_bootstrap") {
    const [userScope, workspaceScope] = params.scopes;
    return params.worker.createGenesisDeviceBootstrapSignature({
      registrationId: requiredString(params.prepare.registration_id),
      compoundIntentId: requiredString(params.intent.compound_intent_id),
      mutationId: requiredString(params.intent.mutation_id),
      genesisCompoundContextHash: params.contextHash,
      workspaceId: requiredString(params.prepare.workspace_id),
      ownerRoleId: requiredString(params.prepare.owner_role_id),
      deviceEcdhPublic: params.deviceEcdhPublic,
      clientNonce: params.clientNonce,
      registrationChallengeHash: params.registrationChallengeHash,
      identitySigningKeyId: requiredString(params.prepare.identity_signing_key_id),
      userIdentityPublicKeyHash: hash(
        params.prepare.identity_hybrid_signing_public_key_material as StrictJsonValue,
      ),
      userDeviceKeyAddedEventHash: params.userDeviceEventHash,
      workspaceDeviceKeyAddedEventHash: params.workspaceDeviceEventHash,
      ownerMemberAddedEventHash: params.ownerMemberEventHash,
      workspaceMemberEnvelopeCommitmentHash: params.envelopeCommitmentHash,
      userAuditCheckpoint: {
        sequence: 2,
        checkpoint_hash: requiredString(userScope?.checkpoint_payload_hash),
      },
      workspaceAuditCheckpoint: {
        sequence: 1,
        checkpoint_hash: requiredString(workspaceScope?.checkpoint_payload_hash),
      },
    });
  }
  throw new Error("genesis_effect_authorization_kind_invalid");
}

function auditCheckpointPayload(
  scope: Record<string, unknown>,
  prepare: Record<string, unknown>,
  variant: string,
): StrictJsonValue {
  const events = recordArray(scope.candidate_events);
  const event = events.at(-1);
  if (!event) throw new Error("genesis_audit_event_missing");
  return {
    protocol: "refmd.signed-audit-checkpoint",
    version: 1,
    chain_scope_kind: requiredString(scope.chain_scope_kind),
    chain_scope_id: requiredString(scope.chain_scope_id),
    sequence: positiveInteger(event.sequence),
    event_hash: requiredString(event.event_hash),
    signer_user_id: requiredString(prepare.user_id),
    ...(variant === "user_identity"
      ? { signing_key_id: requiredString(prepare.identity_signing_key_id) }
      : {
          signer_device_id: requiredString(prepare.device_id),
          signing_key_id: requiredString(prepare.device_signing_key_id),
        }),
    authorization_checkpoint_scope_kind: requiredString(scope.chain_scope_kind),
    authorization_checkpoint_scope_id: requiredString(scope.chain_scope_id),
    authorization_checkpoint_sequence: 0,
    authorization_checkpoint_hash: "GENESIS",
    covered_event_class: "authority",
    covered_event_type: requiredString(event.event_type),
  };
}

function compoundContextHash(params: {
  intent: Record<string, unknown>;
  prepare: Record<string, unknown>;
  prepareRequestHash: string;
  userDeviceEventHash: string;
  workspaceDeviceEventHash: string;
  ownerMemberEventHash: string;
  envelopeCommitmentHash: string;
}): string {
  const scopes = recordArray(params.intent.scopes);
  return hash({
    protocol: "refmd.genesis-compound-authorization-context",
    version: 1,
    registration_id: requiredString(params.prepare.registration_id),
    compound_intent_id: requiredString(params.intent.compound_intent_id),
    mutation_id: requiredString(params.intent.mutation_id),
    challenge_id: requiredString(params.intent.challenge_id),
    expires_at: requiredString(params.intent.expires_at),
    prepare_request_hash: params.prepareRequestHash,
    key_directory_effects_hash: requiredString(params.intent.key_directory_effects_hash),
    scopes: scopes.map((scope) => ({
      chain_scope_kind: requiredString(scope.chain_scope_kind),
      chain_scope_id: requiredString(scope.chain_scope_id),
      candidate_event_head_sequence: positiveInteger(record(scope.candidate_event_head).sequence),
      candidate_event_head_hash: requiredString(record(scope.candidate_event_head).event_hash),
      candidate_key_directory_checkpoint_hash: requiredString(
        scope.candidate_key_directory_checkpoint_hash,
      ),
      checkpoint_payload_hash: requiredString(scope.checkpoint_payload_hash),
    })),
    user_device_key_added_event_hash: params.userDeviceEventHash,
    workspace_device_key_added_event_hash: params.workspaceDeviceEventHash,
    owner_membership: {
      user_id: requiredString(params.prepare.user_id),
      role_id: requiredString(params.prepare.owner_role_id),
      role: "Owner",
      member_added_event_hash: params.ownerMemberEventHash,
    },
    workspace_member_envelope_commitment_hash: params.envelopeCommitmentHash,
  });
}

function findEffect(scope: Record<string, unknown>, eventType: string): Record<string, unknown> {
  const effect = recordArray(scope.candidate_key_directory_effects).find(
    (entry) => record(entry.event_payload).event_type === eventType,
  );
  if (!effect) throw new Error("genesis_effect_missing");
  return effect;
}

function auditVariant(value: string): "user_identity" | "workspace_device" {
  if (value === "user_identity" || value === "workspace_device") return value;
  throw new Error("genesis_audit_checkpoint_variant_invalid");
}

function hash(value: StrictJsonValue): string {
  return blake3Base64Url(canonicalizeStrictBytes(value));
}

function exactRecord(value: unknown, keys: string[]): Record<string, unknown> {
  const result = record(value);
  if (Object.keys(result).sort().join("\0") !== [...keys].sort().join("\0")) {
    throw new Error("genesis_object_keys_invalid");
  }
  return result;
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("genesis_object_invalid");
  }
  return value as Record<string, unknown>;
}

function recordArray(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) throw new Error("genesis_array_invalid");
  return value.map(record);
}

function requiredString(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new Error("genesis_string_invalid");
  return value;
}

function positiveInteger(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    throw new Error("genesis_integer_invalid");
  }
  return value;
}

function literal(actual: unknown, expected: unknown): void {
  if (actual !== expected) throw new Error("genesis_binding_mismatch");
}
