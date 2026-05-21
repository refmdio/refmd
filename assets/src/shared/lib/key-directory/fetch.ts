import {
  advanceKeyDirectoryPinWithProof,
  getKeyDirectoryPin,
  hashKeyDirectoryCheckpointEnvelope,
  lookupVerifiedKeyDirectoryLineage,
} from "@/shared/lib/anti-rollback/key-directory-pin/pins";
import { getPopHeaders } from "@/shared/lib/auth/pop";
import {
  getPreferredSessionScope,
  SHARE_SESSION_SCOPE_HEADER,
} from "@/shared/lib/auth/session-scope";
import { canonicalQueryString } from "@/shared/lib/crypto/canonical-query";
import { blake3Base64Url } from "@/shared/lib/crypto/hash";
import type { CryptoWorkerClient } from "@/shared/lib/crypto/worker/client";
import type { KeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";

function envelopeRecords(values: unknown[] | undefined): Record<string, unknown>[] {
  return (values ?? []).map((value) => value as Record<string, unknown>);
}

export async function fetchVerifiedKeyDirectory(params: {
  scopeKind: "user" | "workspace";
  scopeId: string;
  popDeviceId: string;
  popScope?: "user" | "share";
  popWorker?: CryptoWorkerClient;
  signal?: AbortSignal;
}): Promise<{ checkpoint: KeyDirectoryEnvelope }> {
  const pin = await getKeyDirectoryPin(params.scopeKind, params.scopeId);
  if (!pin) throw new Error("key_directory_pin_required");

  const query = new URLSearchParams({
    checkpoint_sequence: String(pin.checkpointSequence),
    checkpoint_hash: pin.checkpointHash,
    event_head_sequence: String(pin.eventHeadSequence),
    event_head_hash: pin.eventHeadHash,
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
    const headers = await getPopHeaders(
      params.popDeviceId,
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

  const body = (await response.json()) as {
    checkpoint: KeyDirectoryEnvelope;
    checkpoint_ancestry?: Record<string, unknown>[];
    event_ancestry?: Record<string, unknown>[];
    rotation_deletion_evidences?: Record<string, unknown>[];
    pin?: {
      checkpoint_sequence?: number;
      checkpoint_hash?: string;
      event_head_sequence?: number;
      event_head_hash?: string;
    };
  };

  const serverPin = body.pin;
  if (
    serverPin &&
    ((serverPin.checkpoint_sequence ?? pin.checkpointSequence) > pin.checkpointSequence ||
      (serverPin.event_head_sequence ?? pin.eventHeadSequence) > pin.eventHeadSequence)
  ) {
    const cachedLineage = lookupVerifiedKeyDirectoryLineage(params.scopeKind, params.scopeId, pin);
    try {
      await advanceKeyDirectoryPinWithProof({
        scopeKind: params.scopeKind,
        scopeId: params.scopeId,
        checkpointEnvelope: body.checkpoint,
        checkpointAncestry: body.checkpoint_ancestry ?? [],
        eventAncestry: body.event_ancestry ?? [],
        authorityEventAncestry: [
          ...envelopeRecords(cachedLineage?.events),
          ...(body.event_ancestry ?? []),
        ],
        rotationDeletionEvidences: body.rotation_deletion_evidences ?? [],
      });
    } catch (error) {
      if (error instanceof Error && error.message === "key_directory_pin_conflict") {
        return fetchVerifiedKeyDirectory(params);
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
  }

  return { checkpoint: body.checkpoint };
}
