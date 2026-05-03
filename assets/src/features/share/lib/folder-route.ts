import { sharesApi } from "@/shared/api";
import type { components } from "@/shared/api/schema";
import { getShareDekEncryptionKey } from "@/shared/lib/crypto/share-dek";
import { resolveShareTitle } from "./title";

type ShareTreeEntry = components["schemas"]["ShareTreeEntry"];
type ShareFolderBootstrap = components["schemas"]["ShareFolderBootstrapResponse"];
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
  response: ShareFolderBootstrap | BootstrapRequired,
): response is BootstrapRequired {
  return "bootstrap_required" in response && response.bootstrap_required === true;
}

export async function resolveShareFolderRoute(
  folderToken: string,
): Promise<ResolvedShareFolderRoute> {
  const response = await sharesApi.getFolderBootstrap(folderToken);
  if (isBootstrapRequired(response)) {
    return {
      kind: "bootstrap-required",
      shareSlug: response.share_slug,
    };
  }

  if (response.password_protected && !getShareDekEncryptionKey(response.share_slug)) {
    return {
      kind: "bootstrap-required",
      shareSlug: response.share_slug,
    };
  }

  const [folder, entries] = await Promise.all([
    resolveShareFolderEntry(response.folder, response.password_protected, response.share_slug),
    Promise.all(
      response.entries.map((entry) =>
        resolveShareFolderEntry(entry, response.password_protected, response.share_slug),
      ),
    ),
  ]);

  return {
    kind: "ready",
    shareId: response.share_id,
    shareSlug: response.share_slug,
    folderToken,
    folder,
    entries,
  };
}

async function resolveShareFolderEntry(
  entry: ShareTreeEntry,
  passwordProtected: boolean,
  shareSlug: string,
): Promise<ResolvedShareFolderEntry> {
  return {
    ...entry,
    label: await resolveShareTitle(entry, {
      passwordProtected,
      passwordKey: shareSlug,
    }),
  };
}
