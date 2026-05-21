import { createEffect, createSignal, onCleanup } from "solid-js";
import { publicApi } from "@/shared/api";

export type PublicDocument = Awaited<ReturnType<typeof publicApi.getDocument>>;
export type PublicAuthor = Awaited<ReturnType<typeof publicApi.getAuthor>>;

export function usePublicDocument(
  authorSlug: () => string | undefined,
  documentSlug: () => string | undefined,
) {
  const [document, setDocument] = createSignal<PublicDocument | null>(null);
  const [error, setError] = createSignal<string | null>(null);

  createEffect(() => {
    const author = authorSlug();
    const document = documentSlug();
    setDocument(null);
    setError(null);

    if (!author || !document) {
      setError("Public document not found.");
      return;
    }

    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });

    void (async () => {
      try {
        const response = await publicApi.getDocument(author, document);
        if (!cancelled) setDocument(response);
      } catch {
        if (!cancelled) setError("Public document not found.");
      }
    })();
  });

  return { document, error };
}

export function usePublicAuthor(slug: () => string | undefined) {
  const [author, setAuthor] = createSignal<PublicAuthor | null>(null);
  const [error, setError] = createSignal<string | null>(null);

  createEffect(() => {
    const authorSlug = slug();
    setAuthor(null);
    setError(null);

    if (!authorSlug) {
      setError("Public author not found.");
      return;
    }

    let cancelled = false;
    onCleanup(() => {
      cancelled = true;
    });

    void (async () => {
      try {
        const response = await publicApi.getAuthor(authorSlug);
        if (!cancelled) setAuthor(response);
      } catch {
        if (!cancelled) setError("Public author not found.");
      }
    })();
  });

  return { author, error };
}
