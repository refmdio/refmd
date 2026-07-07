import { createEffect, createMemo, createSignal, For, Show } from "solid-js";
import { createQuery, useQueryClient } from "@tanstack/solid-query";
import { CopyIcon, ExternalLinkIcon, Globe2Icon, LinkIcon, SettingsIcon } from "lucide-solid";
import { useDocuments, useDocumentTitles, type DocumentResponse } from "@/entities/document";
import { currentWorkspaceId, useWorkspaces } from "@/entities/workspace";
import { getPublication, PublishDialog, type Publication } from "@/features/publication";
import {
  listDocumentShares,
  readShareUrl,
  ShareManagementDialog,
  type ShareListItem,
} from "@/features/share";
import { useDocumentSharePermissions } from "@/features/workspace";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { workspacesApi } from "@/shared/api";
import { Button } from "@/shared/ui/button";
import { Spinner } from "@/shared/ui/spinner";

const UNBOUNDED_SHARE_VIEWS = Number.MAX_SAFE_INTEGER;

function shareMaxViews(share: ShareListItem): number {
  return share.max_views ?? UNBOUNDED_SHARE_VIEWS;
}

function shareExpiresEventSequence(share: ShareListItem): number {
  return share.expires_event_sequence ?? UNBOUNDED_SHARE_VIEWS;
}

interface SharedPage {
  document: DocumentResponse;
  shares: ShareListItem[];
}

interface SharedLink {
  document: DocumentResponse;
  share: ShareListItem;
}

interface PublishedPage {
  document: DocumentResponse;
  publication: Publication | null;
}

function absoluteUrl(url: string): string {
  if (/^https?:\/\//.test(url)) return url;
  return `${window.location.origin}${url.startsWith("/") ? url : `/${url}`}`;
}

function shareUrl(documentId: string, share: ShareListItem): string {
  return readShareUrl(documentId, share.id) ?? "";
}

function pageLabel(document: DocumentResponse): string {
  return document.doc_type === "folder" ? "Folder" : "Document";
}

async function copyText(value: string): Promise<void> {
  await navigator.clipboard.writeText(value);
}

function EmptyState(props: { children: string }) {
  return <p class="py-6 text-center text-sm text-muted-foreground">{props.children}</p>;
}

function ExternalAccessRow(props: {
  kind: string;
  title: string;
  url: string | null;
  meta: string;
  copied: boolean;
  onCopy?: () => void;
  onOpen?: () => void;
  onManage?: () => void;
}) {
  return (
    <div class="flex items-start justify-between gap-3 p-4">
      <div class="min-w-0 flex-1">
        <p class="text-xs text-muted-foreground">{props.kind}</p>
        <h5 class="mt-1 truncate text-sm font-medium">{props.title}</h5>
        <Show
          when={props.url}
          fallback={<p class="mt-2 text-xs text-muted-foreground">URL is unavailable.</p>}
        >
          {(url) => <p class="mt-2 truncate font-mono text-xs">{url()}</p>}
        </Show>
        <p class="mt-1 text-xs text-muted-foreground">{props.meta}</p>
        <Show when={props.copied}>
          <p class="mt-2 text-[10px] uppercase tracking-[0.16em] text-muted-foreground">Copied</p>
        </Show>
      </div>
      <div class="flex shrink-0 items-center gap-1">
        <Show when={props.url && props.onCopy}>
          <Button size="icon-sm" variant="ghost" title="Copy URL" onClick={props.onCopy}>
            <CopyIcon class="size-3.5" />
          </Button>
        </Show>
        <Show when={props.url && props.onOpen}>
          <Button size="icon-sm" variant="ghost" title="Open URL" onClick={props.onOpen}>
            <ExternalLinkIcon class="size-3.5" />
          </Button>
        </Show>
        <Show when={props.onManage}>
          <Button size="sm" variant="outline" onClick={props.onManage}>
            <SettingsIcon class="size-3.5" />
            Manage
          </Button>
        </Show>
      </div>
    </div>
  );
}

export function ExternalAccessSection() {
  const workspaceId = () => currentWorkspaceId();
  const { allWorkspaces } = useWorkspaces();
  const { flatDocuments, query: documentsQuery } = useDocuments(workspaceId);
  const { getTitle } = useDocumentTitles(flatDocuments, workspaceId);
  const permissions = useDocumentSharePermissions(workspaceId);
  const queryClient = useQueryClient();
  const [error, setError] = createSignal<string | null>(null);
  const [copiedShareId, setCopiedShareId] = createSignal<string | null>(null);
  const [copiedDocumentId, setCopiedDocumentId] = createSignal<string | null>(null);
  const [shareDialogOpen, setShareDialogOpen] = createSignal(false);
  const [publishDialogOpen, setPublishDialogOpen] = createSignal(false);
  const [proxySaving, setProxySaving] = createSignal(false);
  const [proxyEnabled, setProxyEnabled] = createSignal(true);
  const [proxyId, setProxyId] = createSignal("");
  const [proxyLabel, setProxyLabel] = createSignal("");
  const [proxyBaseUrl, setProxyBaseUrl] = createSignal("");
  const [proxyOperatorLabel, setProxyOperatorLabel] = createSignal("");
  const [proxyAllowedWorkspaceIds, setProxyAllowedWorkspaceIds] = createSignal("");
  const [proxyAllowedUserIds, setProxyAllowedUserIds] = createSignal("");
  const [proxyVerificationMaterial, setProxyVerificationMaterial] = createSignal("{}");
  const [proxyPolicy, setProxyPolicy] = createSignal("{}");
  const [proxyRevoked, setProxyRevoked] = createSignal(false);
  const [selectedShareDocument, setSelectedShareDocument] = createSignal<DocumentResponse | null>(
    null,
  );
  const [selectedPublishedDocument, setSelectedPublishedDocument] =
    createSignal<DocumentResponse | null>(null);

  const activeDocuments = createMemo(() =>
    flatDocuments()
      .filter((document) => !document.archived_at)
      .slice()
      .sort((a, b) => a.position - b.position),
  );

  const publishedDocuments = createMemo(() =>
    activeDocuments()
      .filter((document) => document.doc_type === "document" && document.is_published)
      .slice()
      .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime()),
  );

  const sharedPages = createQuery(() => ({
    queryKey: [
      "settings-external-shared-pages",
      workspaceId(),
      activeDocuments()
        .map((document) => document.id)
        .join(","),
    ],
    queryFn: async (): Promise<SharedPage[]> => {
      const results = await Promise.all(
        activeDocuments().map(async (document) => {
          const shares = await listDocumentShares(document.id);
          return { document, shares };
        }),
      );
      return results.filter((entry) => entry.shares.length > 0);
    },
    enabled:
      Boolean(workspaceId()) && permissions.canManageShares() && activeDocuments().length > 0,
  }));

  const publishedPages = createQuery(() => ({
    queryKey: [
      "settings-external-public-pages",
      workspaceId(),
      publishedDocuments()
        .map((document) => document.id)
        .join(","),
    ],
    queryFn: async (): Promise<PublishedPage[]> => {
      return Promise.all(
        publishedDocuments().map(async (document) => {
          try {
            const publication = await getPublication(document.id);
            return { document, publication };
          } catch {
            return { document, publication: null };
          }
        }),
      );
    },
    enabled: Boolean(workspaceId()) && publishedDocuments().length > 0,
  }));

  const sharedLinks = createMemo<SharedLink[]>(() =>
    (sharedPages.data ?? []).flatMap((entry) =>
      entry.shares.map((share) => ({ document: entry.document, share })),
    ),
  );

  const workspaceProxy = createMemo(() => {
    const id = workspaceId();
    return workspacePluginNetworkProxy(allWorkspaces().find((workspace) => workspace.id === id));
  });

  createEffect(() => {
    const proxy = workspaceProxy();
    if (!proxy) {
      setProxyEnabled(true);
      setProxyId("");
      setProxyLabel("");
      setProxyBaseUrl("");
      setProxyOperatorLabel("");
      setProxyAllowedWorkspaceIds("");
      setProxyAllowedUserIds("");
      setProxyVerificationMaterial("{}");
      setProxyPolicy("{}");
      setProxyRevoked(false);
      return;
    }

    setProxyEnabled(proxy.enabled !== false);
    setProxyId(typeof proxy.id === "string" ? proxy.id : "");
    setProxyLabel(typeof proxy.label === "string" ? proxy.label : "");
    setProxyBaseUrl(typeof proxy.base_url === "string" ? proxy.base_url : "");
    setProxyOperatorLabel(typeof proxy.operator_label === "string" ? proxy.operator_label : "");
    setProxyAllowedWorkspaceIds(stringListInput(proxy.allowed_workspace_ids));
    setProxyAllowedUserIds(stringListInput(proxy.allowed_user_ids));
    setProxyVerificationMaterial(jsonInput(proxy.verification_material));
    setProxyPolicy(jsonInput(proxy.policy));
    setProxyRevoked(proxy.revoked === true);
  });

  const refetchExternalAccess = () => {
    const id = workspaceId();
    void sharedPages.refetch();
    void publishedPages.refetch();
    if (id) {
      void queryClient.invalidateQueries({ queryKey: ["documents", id] });
    }
  };

  const openShareDialog = (document: DocumentResponse) => {
    setSelectedShareDocument(document);
    setShareDialogOpen(true);
  };

  const openPublishDialog = (document: DocumentResponse) => {
    setSelectedPublishedDocument(document);
    setPublishDialogOpen(true);
  };

  const saveNetworkProxy = async () => {
    const id = workspaceId();
    if (!id) return;

    setProxySaving(true);
    setError(null);
    try {
      const registration =
        proxyId().trim() && proxyLabel().trim() && proxyBaseUrl().trim()
          ? {
              id: proxyId().trim(),
              label: proxyLabel().trim(),
              base_url: proxyBaseUrl().trim(),
              scope: "workspace" as const,
              enabled: proxyEnabled(),
              operator_label: proxyOperatorLabel().trim() || proxyLabel().trim(),
              allowed_workspace_ids: parseStringList(proxyAllowedWorkspaceIds()),
              allowed_user_ids: parseStringList(proxyAllowedUserIds()),
              verification_material: parseObject(proxyVerificationMaterial()),
              revoked: proxyRevoked(),
              policy: parseObject(proxyPolicy()),
            }
          : null;

      await workspacesApi.updateFeatures(id, { plugin_network_proxy: registration });
      await queryClient.invalidateQueries({ queryKey: ["workspaces"] });
    } catch {
      setError("Failed to save network proxy settings.");
    } finally {
      setProxySaving(false);
    }
  };

  return (
    <div class="p-6 space-y-6">
      <div>
        <h3 class="text-lg font-semibold mb-1">External Access</h3>
        <p class="text-sm text-muted-foreground">
          Review pages that are accessible outside the workspace.
        </p>
      </div>

      <Show when={error()}>
        {(message) => (
          <Alert variant="destructive">
            <AlertDescription>{message()}</AlertDescription>
          </Alert>
        )}
      </Show>

      <section>
        <h4 class="mb-3 flex items-center gap-2 text-sm font-medium">
          <ExternalLinkIcon class="size-4" />
          Network Proxy
        </h4>
        <div class="border border-border/60 bg-card p-4">
          <div class="grid gap-3 md:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <label class="space-y-1 text-sm">
              <span class="text-xs text-muted-foreground">Proxy ID</span>
              <input
                class="h-9 w-full border border-input bg-background px-3 text-sm"
                value={proxyId()}
                onInput={(event) => setProxyId(event.currentTarget.value)}
              />
            </label>
            <label class="space-y-1 text-sm">
              <span class="text-xs text-muted-foreground">Label</span>
              <input
                class="h-9 w-full border border-input bg-background px-3 text-sm"
                value={proxyLabel()}
                onInput={(event) => setProxyLabel(event.currentTarget.value)}
              />
            </label>
            <label class="space-y-1 text-sm md:col-span-2">
              <span class="text-xs text-muted-foreground">Base URL</span>
              <input
                class="h-9 w-full border border-input bg-background px-3 font-mono text-sm"
                value={proxyBaseUrl()}
                onInput={(event) => setProxyBaseUrl(event.currentTarget.value)}
              />
            </label>
            <label class="space-y-1 text-sm md:col-span-2">
              <span class="text-xs text-muted-foreground">Operator</span>
              <input
                class="h-9 w-full border border-input bg-background px-3 text-sm"
                value={proxyOperatorLabel()}
                onInput={(event) => setProxyOperatorLabel(event.currentTarget.value)}
              />
            </label>
            <label class="space-y-1 text-sm">
              <span class="text-xs text-muted-foreground">Allowed Workspaces</span>
              <textarea
                class="min-h-16 w-full border border-input bg-background px-3 py-2 font-mono text-xs"
                value={proxyAllowedWorkspaceIds()}
                onInput={(event) => setProxyAllowedWorkspaceIds(event.currentTarget.value)}
              />
            </label>
            <label class="space-y-1 text-sm">
              <span class="text-xs text-muted-foreground">Allowed Users</span>
              <textarea
                class="min-h-16 w-full border border-input bg-background px-3 py-2 font-mono text-xs"
                value={proxyAllowedUserIds()}
                onInput={(event) => setProxyAllowedUserIds(event.currentTarget.value)}
              />
            </label>
            <label class="space-y-1 text-sm">
              <span class="text-xs text-muted-foreground">Verification Material</span>
              <textarea
                class="min-h-20 w-full border border-input bg-background px-3 py-2 font-mono text-xs"
                value={proxyVerificationMaterial()}
                onInput={(event) => setProxyVerificationMaterial(event.currentTarget.value)}
              />
            </label>
            <label class="space-y-1 text-sm">
              <span class="text-xs text-muted-foreground">Policy</span>
              <textarea
                class="min-h-20 w-full border border-input bg-background px-3 py-2 font-mono text-xs"
                value={proxyPolicy()}
                onInput={(event) => setProxyPolicy(event.currentTarget.value)}
              />
            </label>
          </div>
          <div class="mt-4 flex items-center justify-between gap-3">
            <label class="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={proxyEnabled()}
                onChange={(event) => setProxyEnabled(event.currentTarget.checked)}
              />
              Enabled
            </label>
            <label class="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={proxyRevoked()}
                onChange={(event) => setProxyRevoked(event.currentTarget.checked)}
              />
              Revoked
            </label>
            <Button size="sm" onClick={saveNetworkProxy} disabled={proxySaving()}>
              {proxySaving() ? "Saving..." : "Save"}
            </Button>
          </div>
        </div>
      </section>

      <Show
        when={!documentsQuery.isLoading}
        fallback={
          <div class="flex justify-center py-8">
            <Spinner class="size-6" />
          </div>
        }
      >
        <section>
          <h4 class="mb-3 flex items-center gap-2 text-sm font-medium">
            <LinkIcon class="size-4" />
            Share Links
          </h4>
          <div class="border border-border/60 bg-card">
            <Show
              when={permissions.canManageShares()}
              fallback={
                <div class="p-4">
                  <Alert>
                    <AlertDescription>
                      You need document write permission to list share links.
                    </AlertDescription>
                  </Alert>
                </div>
              }
            >
              <Show
                when={!sharedPages.isLoading}
                fallback={
                  <div class="flex justify-center py-8">
                    <Spinner class="size-5" />
                  </div>
                }
              >
                <Show
                  when={!sharedPages.isError}
                  fallback={
                    <div class="p-4">
                      <Alert variant="destructive">
                        <AlertDescription>Failed to load share links.</AlertDescription>
                      </Alert>
                    </div>
                  }
                >
                  <Show
                    when={sharedLinks().length > 0}
                    fallback={<EmptyState>No pages have share links.</EmptyState>}
                  >
                    <div class="divide-y divide-border/60">
                      <For each={sharedLinks()}>
                        {(entry) => (
                          <ExternalAccessRow
                            kind={pageLabel(entry.document)}
                            title={getTitle(entry.document)}
                            url={shareUrl(entry.document.id, entry.share)}
                            meta={`${entry.share.permission} / ${entry.share.scope} · ${
                              entry.share.view_count
                            }${
                              shareMaxViews(entry.share) === UNBOUNDED_SHARE_VIEWS
                                ? ""
                                : `/${shareMaxViews(entry.share)}`
                            } uses${
                              shareExpiresEventSequence(entry.share) !== UNBOUNDED_SHARE_VIEWS
                                ? ` · Expires at event ${shareExpiresEventSequence(entry.share)}`
                                : ""
                            }`}
                            copied={copiedShareId() === entry.share.id}
                            onCopy={() => {
                              copyText(shareUrl(entry.document.id, entry.share))
                                .then(() => setCopiedShareId(entry.share.id))
                                .catch(() => setError("Failed to copy share link."));
                            }}
                            onOpen={() =>
                              window.open(
                                shareUrl(entry.document.id, entry.share),
                                "_blank",
                                "noopener",
                              )
                            }
                            onManage={() => openShareDialog(entry.document)}
                          />
                        )}
                      </For>
                    </div>
                  </Show>
                </Show>
              </Show>
            </Show>
          </div>
        </section>

        <div class="border-t border-border/40" />

        <section>
          <h4 class="mb-3 flex items-center gap-2 text-sm font-medium">
            <Globe2Icon class="size-4" />
            Public Pages
          </h4>
          <div class="border border-border/60 bg-card">
            <Show
              when={!publishedPages.isLoading}
              fallback={
                <div class="flex justify-center py-8">
                  <Spinner class="size-5" />
                </div>
              }
            >
              <Show
                when={(publishedPages.data?.length ?? 0) > 0}
                fallback={<EmptyState>No documents are published.</EmptyState>}
              >
                <div class="divide-y divide-border/60">
                  <For each={publishedPages.data}>
                    {(entry) => (
                      <ExternalAccessRow
                        kind="Document"
                        title={getTitle(entry.document)}
                        url={entry.publication ? absoluteUrl(entry.publication.url) : null}
                        meta={
                          entry.publication
                            ? `${entry.publication.noindex ? "Noindex" : "Indexable"} · Updated ${new Date(entry.publication.updated_at).toLocaleDateString()}`
                            : "Publication settings could not be loaded."
                        }
                        copied={copiedDocumentId() === entry.document.id}
                        onCopy={
                          entry.publication
                            ? () => {
                                copyText(absoluteUrl(entry.publication!.url))
                                  .then(() => setCopiedDocumentId(entry.document.id))
                                  .catch(() => setError("Failed to copy public URL."));
                              }
                            : undefined
                        }
                        onOpen={
                          entry.publication
                            ? () =>
                                window.open(
                                  absoluteUrl(entry.publication!.url),
                                  "_blank",
                                  "noopener",
                                )
                            : undefined
                        }
                        onManage={
                          permissions.canPublishPublic()
                            ? () => openPublishDialog(entry.document)
                            : undefined
                        }
                      />
                    )}
                  </For>
                </div>
              </Show>
            </Show>
          </div>
        </section>
      </Show>

      <ShareManagementDialog
        open={shareDialogOpen()}
        onOpenChange={(open) => {
          setShareDialogOpen(open);
          if (!open) refetchExternalAccess();
        }}
        document={selectedShareDocument()}
        documents={flatDocuments()}
        canDeleteShares={permissions.canDeleteShares()}
        getTitle={getTitle}
        title={selectedShareDocument() ? getTitle(selectedShareDocument()!) : ""}
        setError={setError}
      />

      <PublishDialog
        open={publishDialogOpen()}
        onOpenChange={(open) => {
          setPublishDialogOpen(open);
          if (!open) refetchExternalAccess();
        }}
        document={selectedPublishedDocument()}
        title={selectedPublishedDocument() ? getTitle(selectedPublishedDocument()!) : ""}
        canPublishPublic={permissions.canPublishPublic()}
        setError={setError}
      />
    </div>
  );
}

function workspacePluginNetworkProxy(workspace: unknown): Record<string, unknown> | null {
  if (!workspace || typeof workspace !== "object") return null;
  const proxy = (workspace as { plugin_network_proxy?: unknown }).plugin_network_proxy;
  return proxy && typeof proxy === "object" ? (proxy as Record<string, unknown>) : null;
}

function stringListInput(value: unknown): string {
  return Array.isArray(value) ? value.filter((entry) => typeof entry === "string").join("\n") : "";
}

function jsonInput(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "{}";
  return JSON.stringify(value, null, 2);
}

function parseStringList(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parseObject(value: string): Record<string, unknown> {
  const trimmed = value.trim();
  if (!trimmed) return {};
  const parsed: unknown = JSON.parse(trimmed);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("proxy_json_object_required");
  }
  return parsed as Record<string, unknown>;
}
