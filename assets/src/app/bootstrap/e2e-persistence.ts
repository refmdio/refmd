import {
  getDocumentStatePin,
  putDocumentStatePin,
} from "@/shared/lib/anti-rollback/document-state-pins";
import { getPluginConsentPin, savePluginConsentPin } from "@/shared/lib/crypto/trust-store";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getPendingChanges, putPendingChanges } from "@/shared/lib/offline/storage/pending";
import { PERSISTED_DATABASE_NAMES } from "@/shared/lib/storage/persistence-registry";
import { login } from "@/features/auth";
import { registerBeforeSessionCleanup } from "@/shared/lib/auth/session-cleanup";
import { setPreferredSessionScope } from "@/shared/lib/auth/session-scope";

const SECURE_CLEANUP_RETRY_PENDING_KEY = "e2e-secure-cleanup-retry-pending";
const SECURE_CLEANUP_RETRY_ATTEMPTS_KEY = "e2e-secure-cleanup-retry-attempts";

declare global {
  interface Window {
    __refmdSeedSecureLogoutPersistence?: () => Promise<{
      databaseNames: readonly string[];
      verified: Record<string, boolean>;
    }>;
    __refmdE2ELoginForIdentityRecovery?: (email: string, password: string) => Promise<string>;
    __refmdE2ESetPreferredSessionScope?: (scope: "share" | null) => void;
    __refmdE2ESeedRetryingSecureCleanup?: () => void;
    __refmdE2ESecureCleanupAttempts?: number;
    __refmdE2ESecureCleanupRegistered?: boolean;
  }
}

export function installSecureLogoutPersistenceE2EHook(): void {
  if (typeof window === "undefined" || !window.__REFMD_E2E__) return;

  window.__refmdE2ELoginForIdentityRecovery = async (email, password) =>
    (await login(email, password, false)).type;
  window.__refmdE2ESetPreferredSessionScope = setPreferredSessionScope;
  window.__refmdE2ESeedRetryingSecureCleanup = () => {
    localStorage.setItem(SECURE_CLEANUP_RETRY_PENDING_KEY, "true");
    localStorage.setItem(SECURE_CLEANUP_RETRY_ATTEMPTS_KEY, "0");
    registerRetryingSecureCleanupE2EHook();
  };
  registerRetryingSecureCleanupE2EHook();

  window.__refmdSeedSecureLogoutPersistence = async () => {
    const worker = getCryptoWorker();
    if (!(await worker.loadStoredDsk())) throw new Error("secure_logout_e2e_dsk_unavailable");

    await worker.storeShareSessionTrustAnchorWithDsk({
      shareSlug: "secure-logout-e2e-share",
      plaintext: new TextEncoder().encode("secure-logout-share-secret"),
      aadRecord: {
        protocol: "refmd.share-session-trust-anchor",
        version: 1,
        share_id: "secure-logout-e2e-share-id",
        token_hash: "secure-logout-e2e-token-hash",
        share_participant_principal_id: "secure-logout-e2e-principal",
        share_participant_device_id: "secure-logout-e2e-device",
        scope_kind: "document",
        scope_id: "secure-logout-e2e-document",
        permission: "edit",
        created_event_hash: "secure-logout-e2e-event-hash",
        capability_context_hash: "secure-logout-e2e-context-hash",
        share_capability_secret_commitment: "secure-logout-e2e-share-commitment",
        password_capability_secret_commitment: "secure-logout-e2e-password-commitment",
        workspace_pin_bootstrap_hash: "secure-logout-e2e-pin-hash",
      },
    });

    await putDocumentStatePin({
      documentId: "secure-logout-e2e-document",
      targetDocumentId: "secure-logout-e2e-document",
      latestSnapshotId: "secure-logout-e2e-snapshot",
      latestSnapshotProofHash: "secure-logout-e2e-proof-hash",
      latestSnapshotCiphertextHash: "secure-logout-e2e-ciphertext-hash",
      perDeviceMaxClocks: { "secure-logout-e2e-device": 1 },
      latestGlobalVersion: 1,
      observedAt: Date.now(),
    });

    const pendingStored = await putPendingChanges({
      documentId: "secure-logout-e2e-document",
      encryptedDiff: new Uint8Array([1, 2, 3]),
      diffNonce: new Uint8Array([4, 5, 6]),
      keyVersion: 1,
      writeId: "secure-logout-e2e-write",
      createdAt: Date.now(),
      updatedAt: Date.now(),
    });
    if (!pendingStored) throw new Error("secure_logout_e2e_pending_write_rejected");

    await savePluginConsentPin({
      workspaceId: "secure-logout-e2e-workspace",
      packageId: "secure-logout-e2e-package",
      applicationId: "secure-logout-e2e-application",
      activationId: "secure-logout-e2e-activation",
      userId: "secure-logout-e2e-user",
      consentEpoch: 1,
      latestEventHash: "secure-logout-e2e-consent-hash",
      updatedAtMs: Date.now(),
    });

    localStorage.setItem("refmd-e2e-secret", "local-secret");
    localStorage.setItem("recent-docs:e2e", "document-secret");
    localStorage.setItem("editor-mode:e2e", "markdown");
    sessionStorage.setItem("refmd-e2e-session", "session-secret");
    const cache = await caches.open("refmd-e2e-cache");
    await cache.put("/e2e-secret", new Response("cache-secret"));

    const [shareAnchor, documentPin, pendingChange, consentPin] = await Promise.all([
      worker.loadShareSessionTrustAnchorWithDsk("secure-logout-e2e-share"),
      getDocumentStatePin("secure-logout-e2e-document"),
      getPendingChanges("secure-logout-e2e-document"),
      getPluginConsentPin(
        "secure-logout-e2e-workspace",
        "secure-logout-e2e-package",
        "secure-logout-e2e-application",
        "secure-logout-e2e-activation",
        "secure-logout-e2e-user",
      ),
    ]);

    return {
      databaseNames: PERSISTED_DATABASE_NAMES,
      verified: {
        workerShare:
          new TextDecoder().decode(shareAnchor ?? new Uint8Array()) ===
          "secure-logout-share-secret",
        trustPin: consentPin?.latestEventHash === "secure-logout-e2e-consent-hash",
        documentPin: documentPin?.latestSnapshotId === "secure-logout-e2e-snapshot",
        pendingChange: pendingChange?.writeId === "secure-logout-e2e-write",
        localStorage: localStorage.getItem("refmd-e2e-secret") === "local-secret",
        sessionStorage: sessionStorage.getItem("refmd-e2e-session") === "session-secret",
        cacheStorage: (await caches.keys()).includes("refmd-e2e-cache"),
      },
    };
  };
}

function registerRetryingSecureCleanupE2EHook(): void {
  if (
    localStorage.getItem(SECURE_CLEANUP_RETRY_PENDING_KEY) !== "true" ||
    window.__refmdE2ESecureCleanupRegistered
  ) {
    return;
  }

  window.__refmdE2ESecureCleanupRegistered = true;
  registerBeforeSessionCleanup(
    () => {
      const attempts = Number(localStorage.getItem(SECURE_CLEANUP_RETRY_ATTEMPTS_KEY) ?? "0") + 1;
      window.__refmdE2ESecureCleanupAttempts = attempts;
      localStorage.setItem(SECURE_CLEANUP_RETRY_ATTEMPTS_KEY, String(attempts));
      if (attempts === 1) throw new Error("e2e_secure_cleanup_retry_required");

      localStorage.removeItem(SECURE_CLEANUP_RETRY_PENDING_KEY);
      localStorage.removeItem(SECURE_CLEANUP_RETRY_ATTEMPTS_KEY);
    },
    { scope: "secure" },
  );
}
