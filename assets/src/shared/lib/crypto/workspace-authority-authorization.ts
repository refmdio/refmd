import { auditCheckpointHash } from "./signature-audit-transcript";
import { blake3Base64Url } from "./hash";
import { canonicalizeStrictBytes, type StrictJsonValue } from "./jcs";
import type { GenesisCompoundAuthorization } from "./genesis-authorization";
import type { HybridSignature } from "./signature";
import type { getCryptoWorker } from "./worker/client";

type Worker = Pick<
  ReturnType<typeof getCryptoWorker>,
  | "signAuditCheckpoint"
  | "signDeviceKeyDirectoryCheckpoint"
  | "signDeviceKeyDirectoryEvent"
  | "signPqWrap"
>;

interface SignedArtifact {
  signature: HybridSignature;
}

export async function createWorkspaceAuthorityAuthorization(params: {
  worker: Worker;
  intent: StrictJsonValue;
}): Promise<GenesisCompoundAuthorization> {
  const intent = record(params.intent);
  const scopes = records(intent.scopes);
  if (scopes.length !== 1 || scopes[0]?.chain_scope_kind !== "workspace") {
    throw new Error("workspace_authority_intent_scope_invalid");
  }

  const scope = scopes[0]!;
  const event = records(scope.candidate_events).at(-1);
  const effects = records(scope.candidate_key_directory_effects);
  const firstEffect = effects[0];
  if (!event || !firstEffect) throw new Error("workspace_authority_intent_incomplete");

  const kdActor = record(record(firstEffect.event_payload).actor);
  const candidateCheckpoint = record(scope.candidate_key_directory_checkpoint_payload);
  const authorizationCheckpointSequence = integer(candidateCheckpoint.sequence) - 1;
  const authorizationCheckpointHash = string(candidateCheckpoint.previous_checkpoint_hash);
  const auditActor = record(record(event.event_body).actor);
  const previous = record(scope.previous_signed_checkpoint);
  const checkpointPayload: StrictJsonValue = {
    protocol: "refmd.signed-audit-checkpoint",
    version: 1,
    chain_scope_kind: "workspace",
    chain_scope_id: string(scope.chain_scope_id),
    sequence: integer(event.sequence),
    event_hash: string(event.event_hash),
    previous_signed_checkpoint_sequence: integer(previous.sequence),
    previous_signed_checkpoint_hash: string(previous.checkpoint_hash),
    signer_user_id: string(auditActor.user_id),
    signer_device_id: string(auditActor.device_id),
    signing_key_id: string(kdActor.signing_key_id),
    authorization_checkpoint_scope_kind: "workspace",
    authorization_checkpoint_scope_id: string(scope.chain_scope_id),
    authorization_checkpoint_sequence: authorizationCheckpointSequence,
    authorization_checkpoint_hash: authorizationCheckpointHash,
    covered_event_class: "authority",
    covered_event_type: string(event.event_type),
  };
  const checkpointHash = auditCheckpointHash(checkpointPayload);
  literal(checkpointHash, scope.checkpoint_payload_hash);
  const audit = await params.worker.signAuditCheckpoint({
    variant: "workspace_device",
    payload: checkpointPayload,
  });

  const effectAuthorizations = [];
  for (const requirement of records(scope.effect_signature_requirements)) {
    const kind = string(requirement.authorization_kind);
    let artifact: SignedArtifact;

    if (kind === "key_directory_event") {
      const effect = effects[integer(requirement.requirement_order) - 1];
      if (!effect) throw new Error("workspace_authority_effect_missing");
      const payload = record(effect.event_payload);
      artifact = await params.worker.signDeviceKeyDirectoryEvent({
        eventType: string(payload.event_type),
        eventPayload: payload,
      });
    } else if (kind === "key_directory_checkpoint") {
      artifact = await params.worker.signDeviceKeyDirectoryCheckpoint({
        variant: "workspace_authorized",
        checkpointPayload: record(scope.candidate_key_directory_checkpoint_payload),
      });
    } else if (kind === "pq_wrap") {
      const input = record(requirement.pq_wrap_signing_input);
      artifact = await params.worker.signPqWrap({
        actor: record(input.actor) as StrictJsonValue,
        authorityBoundary: record(input.authority_boundary) as StrictJsonValue,
        subjectHashes: record(input.subject_hashes) as StrictJsonValue,
      });
    } else {
      throw new Error("workspace_authority_authorization_kind_invalid");
    }

    literal(artifact.signature.transcript_hash, requirement.subject_hash);
    effectAuthorizations.push({
      requirement_order: integer(requirement.requirement_order),
      authorization_kind: kind,
      signing_purpose: string(requirement.signing_purpose),
      surface_variant: string(requirement.surface_variant),
      subject_hash: string(requirement.subject_hash),
      signer_key_id: string(requirement.signer_key_id),
      signature: artifact.signature,
      approval_proof: "NONE" as const,
    });
  }

  return {
    protocol: "refmd.audit.compound-append-authorization",
    version: 1,
    compound_intent_id: string(intent.compound_intent_id),
    mutation_id: string(intent.mutation_id),
    intent_hash: hash(params.intent),
    scope_signatures: [
      {
        chain_scope_kind: "workspace",
        chain_scope_id: string(scope.chain_scope_id),
        checkpoint_hash: checkpointHash,
        checkpoint_variant: "workspace_device",
        signature: audit.signature,
      },
    ],
    effect_authorizations: effectAuthorizations,
  };
}

export function materializeWorkspaceAuthorityKeyDirectory(
  intentValue: StrictJsonValue,
  authorization: GenesisCompoundAuthorization,
) {
  const scope = records(record(intentValue).scopes)[0]!;
  const requirements = records(scope.effect_signature_requirements);
  const effects = records(scope.candidate_key_directory_effects);
  const events = [];
  let checkpoint: Record<string, unknown> | undefined;

  for (const [index, requirement] of requirements.entries()) {
    const entry = authorization.effect_authorizations[index]!;
    if (requirement.authorization_kind === "key_directory_event") {
      const effect = effects[integer(requirement.requirement_order) - 1]!;
      const payload = record(effect.event_payload);
      events.push({
        payload,
        signatures: [{ signer: record(payload.actor), signature: entry.signature }],
      });
    } else if (requirement.authorization_kind === "key_directory_checkpoint") {
      const payload = record(scope.candidate_key_directory_checkpoint_payload);
      const actor = record(record(effects[0]!.event_payload).actor);
      checkpoint = {
        payload,
        signatures: [
          {
            signer: {
              signer_kind: "device",
              user_id: string(actor.user_id),
              device_id: string(actor.device_id),
              signing_key_id: string(requirement.signer_key_id),
              authorizing_checkpoint_sequence: integer(actor.key_checkpoint_sequence),
              authorizing_checkpoint_hash: string(actor.key_checkpoint_hash),
            },
            signature: entry.signature,
          },
        ],
      };
    }
  }

  if (!checkpoint) throw new Error("workspace_authority_checkpoint_missing");
  return { events, checkpoint };
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("record_expected");
  }
  return value as Record<string, unknown>;
}

function records(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) throw new Error("array_expected");
  return value.map(record);
}

function string(value: unknown): string {
  if (typeof value !== "string" || value.length === 0) throw new Error("string_expected");
  return value;
}

function integer(value: unknown): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1) throw new Error("integer_expected");
  return value as number;
}

function literal(actual: unknown, expected: unknown): void {
  if (actual !== expected) throw new Error("workspace_authority_binding_invalid");
}

function hash(value: StrictJsonValue): string {
  return blake3Base64Url(canonicalizeStrictBytes(value));
}
