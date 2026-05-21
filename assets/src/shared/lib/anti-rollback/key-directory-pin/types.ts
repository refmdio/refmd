import type { HybridSignature } from "@/shared/lib/crypto/signature-types";

export interface SignedKeyDirectoryEnvelope {
  payload: Record<string, unknown>;
  signatures: KeyDirectorySignatureEnvelope[];
}

export interface KeyDirectorySignatureEnvelope {
  signer: Record<string, unknown>;
  signature: HybridSignature;
}

export interface KeyDirectoryPin {
  pinKey: string;
  scopeKind: "user" | "workspace";
  scopeId: string;
  checkpointSequence: number;
  checkpointHash: string;
  eventHeadSequence: number;
  eventHeadHash: string;
  suitePolicyVersion: number;
  minSuiteRank: number;
  allowedSuiteIdsHash: string;
  observedAt: number;
}
