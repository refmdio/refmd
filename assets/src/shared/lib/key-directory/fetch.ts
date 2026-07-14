import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  hydrateVerifiedKeyDirectoryLineage,
  lookupVerifiedKeyDirectoryEventBodies,
  verifyAndRememberKeyDirectoryLineageFromTrustedAnchor,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { getRrpHeaders } from "@/shared/lib/auth/rrp";
import {
  getPreferredSessionScope,
  SHARE_SESSION_SCOPE_HEADER,
} from "@/shared/lib/auth/session-scope";
import { canonicalQueryString } from "@/shared/lib/crypto/canonical-query";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import type { CryptoWorkerClient } from "@/shared/lib/crypto/worker/client";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";

interface KeyDirectoryAnchor {
  checkpointSequence: number;
  checkpointHash: string;
  eventHeadSequence: number;
  eventHeadHash: string;
}

interface KeyDirectoryLatestBody {
  checkpoint: KeyDirectoryEnvelope;
  checkpoint_ancestry?: Record<string, unknown>[];
  event_ancestry?: Record<string, unknown>[];
  authority_event_ancestry: Record<string, unknown>[];
  rotation_deletion_evidences?: Record<string, unknown>[];
  pin?: {
    checkpoint_sequence?: number;
    checkpoint_hash?: string;
    event_head_sequence?: number;
    event_head_hash?: string;
  };
}

const KEY_DIRECTORY_FETCH_RETRY_LIMIT = 3;

function envelopeRecords(values: unknown[] | undefined): Record<string, unknown>[] {
  return (values ?? []).map((value) => value as Record<string, unknown>);
}

function isRetryablePinRace(error: unknown): boolean {
  return error instanceof Error && error.message === "key_directory_pin_conflict";
}

interface FetchVerifiedKeyDirectoryParams {
  scopeKind: "user" | "workspace";
  scopeId: string;
  rrpDeviceId: string;
  popScope?: "user" | "share";
  popWorker?: CryptoWorkerClient;
  signal?: AbortSignal;
}

async function fetchLatestBody(
  params: FetchVerifiedKeyDirectoryParams,
  anchor: KeyDirectoryAnchor,
): Promise<KeyDirectoryLatestBody> {
  const query = new URLSearchParams({
    checkpoint_sequence: String(anchor.checkpointSequence),
    checkpoint_hash: anchor.checkpointHash,
    event_head_sequence: String(anchor.eventHeadSequence),
    event_head_hash: anchor.eventHeadHash,
  });
  const encodedScopeId = encodeURIComponent(params.scopeId);
  const path =
    params.scopeKind === "user"
      ? `/api/users/${encodedScopeId}/key-directory/latest`
      : `/api/workspaces/${encodedScopeId}/key-directory/latest`;
  const canonicalQuery = canonicalQueryString(query.toString());
  const popScope = params.popScope ?? (getPreferredSessionScope() === "share" ? "share" : "user");
  const resource = {
    body_hash: blake3Base64Url(new Uint8Array()),
    canonical_query: canonicalQuery,
    method: "GET",
    path,
    query_hash: blake3Base64Url(new TextEncoder().encode(canonicalQuery)),
  };

  const fetchLatest = async () => {
    const headers = await getRrpHeaders(
      params.rrpDeviceId,
      params.signal,
      popScope,
      params.popWorker,
      resource,
    );
    return fetch(`${path}?${query.toString()}`, {
      credentials: "same-origin",
      headers: {
        ...(headers as unknown as Record<string, string>),
        ...(popScope === "share" ? { [SHARE_SESSION_SCOPE_HEADER]: "share" } : {}),
      },
      signal: params.signal,
    });
  };

  let response = await fetchLatest();
  if (response.status === 403) {
    response = await fetchLatest();
  }
  if (!response.ok) throw new Error("key_directory_fetch_failed");

  return (await response.json()) as KeyDirectoryLatestBody;
}

export async function fetchVerifiedKeyDirectory(
  params: FetchVerifiedKeyDirectoryParams,
  retryCount = 0,
): Promise<{ checkpoint: KeyDirectoryEnvelope }> {
  const pin = await getKeyDirectoryPin(params.scopeKind, params.scopeId);
  if (!pin) throw new Error("key_directory_pin_required");
  await hydrateVerifiedKeyDirectoryLineage(params.scopeKind, params.scopeId, pin);

  const body = await fetchLatestBody(params, pin);

  const serverPin = body.pin;
  const rememberResponseLineage = () =>
    advanceKeyDirectoryPinWithProof({
      scopeKind: params.scopeKind,
      scopeId: params.scopeId,
      checkpointEnvelope: body.checkpoint,
      checkpointAncestry: body.checkpoint_ancestry ?? [],
      eventAncestry: body.event_ancestry ?? [],
      authorityEventAncestry: [
        ...envelopeRecords(lookupVerifiedKeyDirectoryEventBodies(params.scopeKind, params.scopeId)),
        ...body.authority_event_ancestry,
        ...(body.event_ancestry ?? []),
      ],
      rotationDeletionEvidences: body.rotation_deletion_evidences ?? [],
    });

  if (
    serverPin &&
    ((serverPin.checkpoint_sequence ?? pin.checkpointSequence) > pin.checkpointSequence ||
      (serverPin.event_head_sequence ?? pin.eventHeadSequence) > pin.eventHeadSequence)
  ) {
    try {
      await rememberResponseLineage();
    } catch (error) {
      if (isRetryablePinRace(error) && retryCount < KEY_DIRECTORY_FETCH_RETRY_LIMIT) {
        return fetchVerifiedKeyDirectory(params, retryCount + 1);
      }
      throw error;
    }
    const advanced = await getKeyDirectoryPin(params.scopeKind, params.scopeId);
    if (
      !advanced ||
      advanced.checkpointHash !== hashKeyDirectoryCheckpointEnvelope(body.checkpoint)
    ) {
      throw new Error("key_directory_pin_advance_failed");
    }
  } else if (
    !serverPin ||
    serverPin.checkpoint_sequence !== pin.checkpointSequence ||
    serverPin.checkpoint_hash !== pin.checkpointHash ||
    serverPin.event_head_sequence !== pin.eventHeadSequence ||
    serverPin.event_head_hash !== pin.eventHeadHash ||
    hashKeyDirectoryCheckpointEnvelope(body.checkpoint) !== pin.checkpointHash
  ) {
    throw new Error("key_directory_pin_mismatch");
  } else {
    try {
      await rememberResponseLineage();
    } catch (error) {
      if (isRetryablePinRace(error) && retryCount < KEY_DIRECTORY_FETCH_RETRY_LIMIT) {
        return fetchVerifiedKeyDirectory(params, retryCount + 1);
      }
      throw error;
    }
  }

  return { checkpoint: body.checkpoint };
}

export async function fetchVerifiedKeyDirectoryFromTrustedCheckpoint(
  params: FetchVerifiedKeyDirectoryParams & {
    trustedCheckpointEnvelope: KeyDirectoryEnvelope;
  },
  retryCount = 0,
): Promise<{ checkpoint: KeyDirectoryEnvelope }> {
  const current = await getKeyDirectoryPin(params.scopeKind, params.scopeId);
  if (!current) throw new Error("key_directory_pin_required");
  await hydrateVerifiedKeyDirectoryLineage(params.scopeKind, params.scopeId, current);

  const trustedAnchor = pinFromCheckpointEnvelope(params.trustedCheckpointEnvelope);
  if (anchorIsOlderThan(current, trustedAnchor)) {
    return fetchVerifiedKeyDirectory(params, retryCount);
  }

  const body = await fetchLatestBody(params, trustedAnchor);
  if (!responsePinMatchesCheckpoint(body)) {
    throw new Error("key_directory_pin_mismatch");
  }

  if (responsePinIsOlderThanCurrent(body, current)) {
    throw new Error("key_directory_pin_mismatch");
  }

  const rememberTrustedLineage = () =>
    verifyAndRememberKeyDirectoryLineageFromTrustedAnchor({
      scopeKind: params.scopeKind,
      scopeId: params.scopeId,
      trustedCheckpointEnvelope: params.trustedCheckpointEnvelope,
      checkpointEnvelope: body.checkpoint,
      checkpointAncestry: body.checkpoint_ancestry ?? [],
      eventAncestry: body.event_ancestry ?? [],
      authorityEventAncestry: [...body.authority_event_ancestry, ...(body.event_ancestry ?? [])],
      rotationDeletionEvidences: body.rotation_deletion_evidences ?? [],
    });

  try {
    await rememberTrustedLineage();
  } catch (error) {
    if (isRetryablePinRace(error) && retryCount < KEY_DIRECTORY_FETCH_RETRY_LIMIT) {
      return fetchVerifiedKeyDirectoryFromTrustedCheckpoint(params, retryCount + 1);
    }
    throw error;
  }

  if (responsePinIsNewerThanCurrent(body, current)) {
    try {
      await advanceKeyDirectoryPinWithProof({
        scopeKind: params.scopeKind,
        scopeId: params.scopeId,
        checkpointEnvelope: body.checkpoint,
        checkpointAncestry: responseCheckpointsFromCurrent(body, current),
        eventAncestry: responseEventsAfterCurrent(body, current),
        authorityEventAncestry: [...body.authority_event_ancestry, ...(body.event_ancestry ?? [])],
        rotationDeletionEvidences: body.rotation_deletion_evidences ?? [],
      });
    } catch (error) {
      if (isRetryablePinRace(error) && retryCount < KEY_DIRECTORY_FETCH_RETRY_LIMIT) {
        return fetchVerifiedKeyDirectoryFromTrustedCheckpoint(params, retryCount + 1);
      }
      throw error;
    }

    const advanced = await getKeyDirectoryPin(params.scopeKind, params.scopeId);
    if (!advanced || !responsePinEqualsCurrent(body, advanced)) {
      throw new Error("key_directory_pin_advance_failed");
    }
  } else if (!responsePinEqualsCurrent(body, current)) {
    throw new Error("key_directory_pin_mismatch");
  }

  return { checkpoint: body.checkpoint };
}

function responsePinMatchesCheckpoint(body: KeyDirectoryLatestBody): boolean {
  return (
    !!body.pin &&
    typeof body.pin.checkpoint_sequence === "number" &&
    typeof body.pin.checkpoint_hash === "string" &&
    typeof body.pin.event_head_sequence === "number" &&
    typeof body.pin.event_head_hash === "string" &&
    hashKeyDirectoryCheckpointEnvelope(body.checkpoint) === body.pin.checkpoint_hash
  );
}

function responsePinIsNewerThanCurrent(
  body: KeyDirectoryLatestBody,
  current: KeyDirectoryAnchor,
): boolean {
  const pin = body.pin;
  return (
    !!pin &&
    ((pin.checkpoint_sequence ?? current.checkpointSequence) > current.checkpointSequence ||
      (pin.event_head_sequence ?? current.eventHeadSequence) > current.eventHeadSequence)
  );
}

function anchorIsOlderThan(left: KeyDirectoryAnchor, right: KeyDirectoryAnchor): boolean {
  return (
    left.checkpointSequence < right.checkpointSequence ||
    left.eventHeadSequence < right.eventHeadSequence
  );
}

function responsePinIsOlderThanCurrent(
  body: KeyDirectoryLatestBody,
  current: KeyDirectoryAnchor,
): boolean {
  const pin = body.pin;
  return (
    !!pin &&
    ((pin.checkpoint_sequence ?? current.checkpointSequence) < current.checkpointSequence ||
      (pin.event_head_sequence ?? current.eventHeadSequence) < current.eventHeadSequence)
  );
}

function responsePinEqualsCurrent(
  body: KeyDirectoryLatestBody,
  current: KeyDirectoryAnchor,
): boolean {
  const pin = body.pin;
  return (
    !!pin &&
    pin.checkpoint_sequence === current.checkpointSequence &&
    pin.checkpoint_hash === current.checkpointHash &&
    pin.event_head_sequence === current.eventHeadSequence &&
    pin.event_head_hash === current.eventHeadHash
  );
}

function responseCheckpointsFromCurrent(
  body: KeyDirectoryLatestBody,
  current: KeyDirectoryAnchor,
): Record<string, unknown>[] {
  const checkpoints = body.checkpoint_ancestry ?? [];
  const fromCurrent = checkpoints.filter(
    (checkpoint) => checkpointSequence(checkpoint) >= current.checkpointSequence,
  );
  const first = fromCurrent[0];
  if (
    !first ||
    checkpointSequence(first) !== current.checkpointSequence ||
    hashKeyDirectoryCheckpointEnvelope(first as KeyDirectoryEnvelope) !== current.checkpointHash
  ) {
    throw new Error("key_directory_current_checkpoint_missing");
  }
  return fromCurrent;
}

function responseEventsAfterCurrent(
  body: KeyDirectoryLatestBody,
  current: KeyDirectoryAnchor,
): Record<string, unknown>[] {
  return (body.event_ancestry ?? []).filter(
    (event) => eventSequence(event) > current.eventHeadSequence,
  );
}

function checkpointSequence(checkpoint: Record<string, unknown>): number {
  const payload = checkpoint.payload as Record<string, unknown> | undefined;
  const sequence = payload?.sequence;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1) {
    throw new Error("key_directory_checkpoint_sequence_invalid");
  }
  return sequence;
}

function eventSequence(event: Record<string, unknown>): number {
  const payload = event.payload as Record<string, unknown> | undefined;
  const sequence = payload?.sequence;
  if (typeof sequence !== "number" || !Number.isSafeInteger(sequence) || sequence < 1) {
    throw new Error("key_directory_event_sequence_invalid");
  }
  return sequence;
}

function pinFromCheckpointEnvelope(checkpoint: KeyDirectoryEnvelope): KeyDirectoryAnchor {
  const payload = checkpoint.payload as Record<string, unknown> | undefined;
  const head = payload?.covered_event_head as Record<string, unknown> | undefined;
  const checkpointSequence = payload?.sequence;
  const eventHeadSequence = head?.head_sequence;
  const eventHeadHash = head?.head_hash;
  if (
    typeof checkpointSequence !== "number" ||
    !Number.isSafeInteger(checkpointSequence) ||
    checkpointSequence < 1 ||
    typeof eventHeadSequence !== "number" ||
    !Number.isSafeInteger(eventHeadSequence) ||
    eventHeadSequence < 1 ||
    typeof eventHeadHash !== "string" ||
    eventHeadHash.length === 0
  ) {
    throw new Error("key_directory_checkpoint_pin_invalid");
  }
  return {
    checkpointSequence,
    checkpointHash: hashKeyDirectoryCheckpointEnvelope(checkpoint),
    eventHeadSequence,
    eventHeadHash,
  };
}
