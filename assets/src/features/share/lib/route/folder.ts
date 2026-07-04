import { sharesApi } from "@/shared/api";
import type { components } from "@/shared/api/schema";
import { getShareParticipantCryptoWorker } from "@/shared/lib/crypto/worker/scoped";
import { resolveShareTitle } from "./title";
import {
  ensureShareParticipantDeviceReady,
  readShareSessionTrustAnchor,
  refreshShareSessionTrustAnchorFromBootstrap,
  resolveShareSlugForTokenHash,
} from "../session/session";
import { assertKeyDirectoryEnvelope } from "@/shared/lib/crypto/key-directory/types";
import { ensureShareWorkspaceKeyDirectoryPin } from "./workspace-pin";
import {
  assertWorkspacePinBootstrapEnvelope,
  type WorkspacePinBootstrapEnvelope,
} from "@/shared/lib/key-directory/workspace-pin-bootstrap";

type ShareTreeEntry = Omit<components["schemas"]["ShareTreeEntry"], "encrypted_dek" | "nonce"> & {
  encrypted_key_refs: string[];
};
type ShareFolderBootstrap = Omit<
  components["schemas"]["ShareFolderBootstrapResponse"],
  "folder" | "entries"
> & {
  share_slug: string;
  folder: ShareTreeEntry;
  entries: ShareTreeEntry[];
};
type BootstrapRequired = components["schemas"]["ShareDocumentBootstrapRequiredResponse"];

export type ResolvedShareFolderEntry = ShareTreeEntry & {
  label: string;
};

export type ResolvedShareFolderRoute =
  | {
      kind: "bootstrap-required";
      shareSlug: string;
    }
  | {
      kind: "ready";
      shareId: string;
      shareSlug: string;
      folderToken: string;
      folder: ResolvedShareFolderEntry;
      entries: ResolvedShareFolderEntry[];
    };

function isBootstrapRequired(
  response: Record<string, unknown> | BootstrapRequired,
): response is BootstrapRequired {
  return "bootstrap_required" in response && response.bootstrap_required === true;
}

function keyDirectoryEnvelopeArray(value: unknown, code: string) {
  if (!Array.isArray(value)) throw new Error(code);
  return value.map((entry) => assertKeyDirectoryEnvelope(entry, code));
}

export async function resolveShareFolderRoute(
  folderToken: string,
): Promise<ResolvedShareFolderRoute> {
  const requirement = await sharesApi.getFolderBootstrapRequirement(folderToken);
  const requirementShareSlug = await resolveShareSlugForTokenHash(requirement.share_token_hash);
  if (isBootstrapRequired(requirement)) {
    if (!requirementShareSlug) throw new Error("share_session_required");
    const session = await ensureShareParticipantDeviceReady({
      requiredShareSlug: requirementShareSlug,
    });
    if (
      !session ||
      !(await getShareParticipantCryptoWorker(requirementShareSlug).hasShareDekEncryptionKey(
        requirementShareSlug,
      ))
    ) {
      return {
        kind: "bootstrap-required",
        shareSlug: requirementShareSlug,
      };
    }
  }

  if (!requirementShareSlug) throw new Error("share_session_required");

  const anchor = await readShareSessionTrustAnchor(requirementShareSlug);
  if (!anchor.workspacePinBootstrapHash) {
    return {
      kind: "bootstrap-required",
      shareSlug: requirementShareSlug,
    };
  }

  const session = await ensureShareParticipantDeviceReady({
    requiredShareSlug: requirementShareSlug,
  });
  if (!session) {
    return {
      kind: "bootstrap-required",
      shareSlug: requirementShareSlug,
    };
  }

  const response = await getShareParticipantCryptoWorker(
    requirementShareSlug,
  ).fetchShareFolderBootstrap({
    folderToken,
    authenticatedWorkspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
  });
  if (isBootstrapRequired(response)) {
    return {
      kind: "bootstrap-required",
      shareSlug: requirementShareSlug,
    };
  }
  const canonicalResponse = {
    ...response,
    share_slug: requirementShareSlug,
  } as ShareFolderBootstrap;
  await refreshShareSessionTrustAnchorFromBootstrap(
    requirementShareSlug,
    anchor.anchor,
    canonicalResponse,
  );

  if (
    !(await getShareParticipantCryptoWorker(requirementShareSlug).hasShareDekEncryptionKey(
      requirementShareSlug,
    ))
  ) {
    return {
      kind: "bootstrap-required",
      shareSlug: requirementShareSlug,
    };
  }
  await getShareParticipantCryptoWorker(requirementShareSlug).cloneShareDekEncryptionKey(
    requirementShareSlug,
    canonicalResponse.share_id,
  );
  const workspacePinBootstrap =
    canonicalResponse.workspace_pin_bootstrap === null
      ? null
      : assertWorkspacePinBootstrapEnvelope(
          canonicalResponse.workspace_pin_bootstrap,
          "folder_workspace_pin_bootstrap_invalid",
        );
  const workspaceKeyDirectoryCheckpoint = assertKeyDirectoryEnvelope(
    canonicalResponse.workspace_key_directory_checkpoint,
    "folder_workspace_key_directory_checkpoint_invalid",
  );
  const workspaceKeyDirectoryLatestCheckpoint =
    canonicalResponse.workspace_key_directory_latest_checkpoint === null
      ? null
      : assertKeyDirectoryEnvelope(
          canonicalResponse.workspace_key_directory_latest_checkpoint,
          "folder_workspace_key_directory_latest_checkpoint_invalid",
        );
  const workspaceKeyDirectoryCheckpointAncestry = keyDirectoryEnvelopeArray(
    canonicalResponse.workspace_key_directory_checkpoint_ancestry,
    "folder_workspace_key_directory_checkpoint_ancestry_invalid",
  );
  const workspaceKeyDirectoryEventAncestry = keyDirectoryEnvelopeArray(
    canonicalResponse.workspace_key_directory_event_ancestry,
    "folder_workspace_key_directory_event_ancestry_invalid",
  );
  await ensureShareWorkspaceKeyDirectoryPin({
    workspaceId: canonicalResponse.workspace_id,
    workspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
    workspacePinBootstrap,
    workspaceKeyDirectoryCheckpoint,
    workspaceKeyDirectoryLatestCheckpoint,
    workspaceKeyDirectoryCheckpointAncestry,
    workspaceKeyDirectoryEventAncestry,
    mismatchCode: "folder_workspace_pin_bootstrap_hash_mismatch",
  });

  const [folder, entries] = await Promise.all([
    resolveShareFolderEntry(
      canonicalResponse.folder,
      canonicalResponse.password_protected,
      requirementShareSlug,
      {
        workspaceId: canonicalResponse.workspace_id,
        workspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
        workspacePinBootstrap,
      },
    ),
    Promise.all(
      canonicalResponse.entries.map((entry) =>
        resolveShareFolderEntry(entry, canonicalResponse.password_protected, requirementShareSlug, {
          workspaceId: canonicalResponse.workspace_id,
          workspacePinBootstrapHash: anchor.workspacePinBootstrapHash,
          workspacePinBootstrap,
        }),
      ),
    ),
  ]);

  return {
    kind: "ready",
    shareId: canonicalResponse.share_id,
    shareSlug: requirementShareSlug,
    folderToken,
    folder,
    entries,
  };
}

async function resolveShareFolderEntry(
  entry: ShareTreeEntry,
  passwordProtected: boolean,
  shareSlug: string,
  bootstrap: {
    workspaceId?: string | null;
    workspacePinBootstrapHash?: string | null;
    workspacePinBootstrap?: WorkspacePinBootstrapEnvelope | null;
  },
): Promise<ResolvedShareFolderEntry> {
  return {
    ...entry,
    label: await resolveShareTitle(entry, {
      passwordProtected,
      passwordKey: shareSlug,
      workspaceId: bootstrap.workspaceId,
      workspacePinBootstrapHash: bootstrap.workspacePinBootstrapHash,
      workspacePinBootstrap: bootstrap.workspacePinBootstrap,
    }),
  };
}
