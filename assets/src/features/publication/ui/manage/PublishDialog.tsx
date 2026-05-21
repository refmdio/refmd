import { createEffect, createSignal, onCleanup, Show } from "solid-js";
import { useQuery } from "@tanstack/solid-query";
import { CheckIcon, CopyIcon } from "lucide-solid";
import type { DocumentResponse } from "@/entities/document";
import { currentWorkspaceId } from "@/entities/workspace";
import { ApiError, publicApi, type components, workspacesApi } from "@/shared/api";
import { base64UrlEncode } from "@/shared/lib/crypto/encoding";
import { getCryptoWorker } from "@/shared/lib/crypto/worker/client";
import { getDocumentRuntime, type AppDocuments } from "@/shared/lib/document/manager";
import { setDocumentPublicationState } from "@/shared/lib/document/publication-state";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Field, FieldDescription, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Switch } from "@/shared/ui/switch";

type Publication = components["schemas"]["PublicationResponse"];

interface PublishDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentResponse | null;
  title: string;
  canPublishPublic: boolean;
  setError: (value: string | null) => void;
}

function slugify(value: string): string {
  const slug = value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return slug || `document-${Date.now()}`;
}

async function contentHash(title: string, content: string): Promise<string> {
  return base64UrlEncode(
    await getCryptoWorker().blake3Hash(new TextEncoder().encode(`${title}\n${content}`)),
  );
}

function absolutePublicUrl(url: string): string {
  if (/^https?:\/\//.test(url)) return url;
  return `${window.location.origin}${url.startsWith("/") ? url : `/${url}`}`;
}

async function getDocumentContent(documentId: string) {
  const runtime = getDocumentRuntime() as unknown as Pick<AppDocuments, "getDocumentById">;
  return runtime.getDocumentById(documentId);
}

export function PublishDialog(props: PublishDialogProps) {
  const workspace = useQuery(() => ({
    queryKey: ["workspace", currentWorkspaceId()],
    queryFn: () => workspacesApi.get(currentWorkspaceId() ?? ""),
    enabled: Boolean(currentWorkspaceId()),
  }));
  const [publication, setPublication] = createSignal<Publication | null>(null);
  const [slug, setSlug] = createSignal("");
  const [noindex, setNoindex] = createSignal(false);
  const [loading, setLoading] = createSignal(false);
  const [submitting, setSubmitting] = createSignal(false);
  const [copied, setCopied] = createSignal(false);
  const publicPublishingEnabled = () => workspace.data?.public_publishing_enabled === true;
  const publicAuthorConfigured = () => Boolean(workspace.data?.public_author_profile);
  let copiedTimer: ReturnType<typeof setTimeout> | undefined;

  onCleanup(() => {
    if (copiedTimer) clearTimeout(copiedTimer);
  });

  createEffect(() => {
    if (!props.open || !props.document) return;

    const documentId = props.document.id;
    setLoading(true);
    setPublication(null);
    setSlug(slugify(props.title));
    setNoindex(false);

    void (async () => {
      try {
        const current = await publicApi.getPublication(documentId);
        setPublication(current);
        setSlug(current.slug);
        setNoindex(current.noindex);
      } catch (error) {
        if (!(error instanceof ApiError && error.status === 404)) {
          props.setError("Failed to load publication settings.");
        }
      } finally {
        setLoading(false);
      }
    })();
  });

  const publishOrSync = async () => {
    const document = props.document;
    if (!document || document.doc_type !== "document") return;
    if (!props.canPublishPublic) {
      props.setError("Only workspace admins can publish documents.");
      return;
    }

    setSubmitting(true);
    try {
      const content = await getDocumentContent(document.id);
      if (!content) {
        props.setError("Open the document once before publishing.");
        return;
      }

      const title = props.title;
      const body = {
        title,
        content: content.text,
        content_hash: await contentHash(title, content.text),
      };

      try {
        if (publication()) {
          const updated = await publicApi.updatePublication(document.id, {
            slug: slug(),
            noindex: noindex(),
          });
          await publicApi.syncPublicationContent(document.id, body);
          updateOpenDocumentPublicationState(document.id, updated, body.content_hash);
          setPublication(updated);
        } else {
          const created = await publicApi.publishDocument(document.id, {
            ...body,
            slug: slug(),
            noindex: noindex(),
          });
          updateOpenDocumentPublicationState(document.id, created, body.content_hash);
          setPublication(created);
        }
      } finally {
        content.release();
      }
    } catch {
      props.setError("Failed to update publication.");
    } finally {
      setSubmitting(false);
    }
  };

  const unpublish = async () => {
    const document = props.document;
    if (!document || !publication()) return;
    if (!props.canPublishPublic) {
      props.setError("Only workspace admins can unpublish documents.");
      return;
    }

    setSubmitting(true);
    try {
      await publicApi.unpublishDocument(document.id);
      updateOpenDocumentPublicationState(document.id, null);
      setPublication(null);
      setSlug(slugify(props.title));
    } catch {
      props.setError("Failed to unpublish document.");
    } finally {
      setSubmitting(false);
    }
  };

  const copyPublicUrl = async () => {
    const url = publication()?.url ? absolutePublicUrl(publication()!.url) : null;
    if (!url) return;

    try {
      await navigator.clipboard.writeText(url);
      setCopied(true);
      if (copiedTimer) clearTimeout(copiedTimer);
      copiedTimer = setTimeout(() => {
        setCopied(false);
        copiedTimer = undefined;
      }, 2000);
    } catch {
      props.setError("Failed to copy public URL.");
    }
  };

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Publish</DialogTitle>
          <DialogDescription>
            Publish this document as a public article. Published article content is no longer
            end-to-end encrypted.
          </DialogDescription>
        </DialogHeader>

        <div class="space-y-4">
          <Show when={!publicPublishingEnabled()}>
            <Alert>
              <AlertDescription>
                Public publishing is disabled for this workspace. Enable it in Workspace settings
                before publishing.
              </AlertDescription>
            </Alert>
          </Show>
          <Show when={publicPublishingEnabled() && !props.canPublishPublic}>
            <Alert>
              <AlertDescription>Only workspace admins can publish documents.</AlertDescription>
            </Alert>
          </Show>
          <Show when={publicPublishingEnabled() && !publicAuthorConfigured()}>
            <Alert>
              <AlertDescription>
                Configure a Public Author in Workspace settings before publishing.
              </AlertDescription>
            </Alert>
          </Show>
          <Field>
            <FieldLabel for="publication-slug">Slug</FieldLabel>
            <Input
              id="publication-slug"
              value={slug()}
              onInput={(event) => setSlug(event.currentTarget.value)}
              disabled={loading() || submitting()}
            />
            <FieldDescription>Used in the public URL.</FieldDescription>
          </Field>

          <Field>
            <div class="flex items-center justify-between gap-4">
              <div>
                <FieldLabel>Noindex</FieldLabel>
                <FieldDescription>Ask search engines not to index this page.</FieldDescription>
              </div>
              <Switch
                checked={noindex()}
                onChange={setNoindex}
                disabled={loading() || submitting()}
              />
            </div>
          </Field>

          <Show when={publication()}>
            {(pub) => (
              <div class="space-y-2">
                <p class="text-sm text-muted-foreground">Public URL</p>
                <div class="flex items-center gap-2">
                  <Input value={absolutePublicUrl(pub().url)} readOnly class="font-mono text-xs" />
                  <Button variant="outline" size="icon" onClick={copyPublicUrl}>
                    <Show when={copied()} fallback={<CopyIcon class="size-4" />}>
                      <CheckIcon class="size-4" />
                    </Show>
                  </Button>
                </div>
              </div>
            )}
          </Show>
        </div>

        <DialogFooter>
          <Show when={publication()}>
            <Button
              variant="destructive"
              onClick={unpublish}
              disabled={submitting() || !props.canPublishPublic}
            >
              Unpublish
            </Button>
          </Show>
          <Button
            onClick={publishOrSync}
            disabled={
              loading() ||
              submitting() ||
              !slug() ||
              !props.canPublishPublic ||
              !publicPublishingEnabled() ||
              !publicAuthorConfigured()
            }
          >
            {publication() ? "Update Publication" : "Publish"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function updateOpenDocumentPublicationState(
  documentId: string,
  publication: Publication | null,
  hash?: string,
) {
  setDocumentPublicationState(documentId, {
    isPublished: Boolean(publication),
    updatedAt: publication?.updated_at ?? null,
    contentHash: hash ?? null,
  });
}
