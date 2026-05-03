import { For, Show } from "solid-js";
import { A, useParams } from "@solidjs/router";
import { Spinner } from "@/shared/ui/spinner";
import { usePublicAuthor } from "../model/usePublicDocument";
import { PublicPageChrome } from "./PublicPageChrome";

export default function PublicAuthorPage() {
  const params = useParams<{ authorHandle?: string; authorSlug?: string }>();
  const authorSlug = () => (params.authorHandle ?? params.authorSlug ?? "").replace(/^@/, "");
  const { author, error } = usePublicAuthor(authorSlug);

  return (
    <PublicPageChrome label="Public Author">
      <Show
        when={author()}
        fallback={
          <div class="flex min-h-[70vh] items-center justify-center p-6">
            {error() ? (
              <p class="text-sm text-muted-foreground">{error()}</p>
            ) : (
              <Spinner class="size-6" />
            )}
          </div>
        }
      >
        {(page) => (
          <section class="mx-auto w-full max-w-5xl px-4 py-8 sm:px-6">
            <header class="border-b border-border px-2 py-8 sm:px-6">
              <p class="mb-3 text-sm font-medium text-muted-foreground">@{page().author_slug}</p>
              <h1 class="text-4xl font-bold leading-tight tracking-tight sm:text-5xl">
                {page().author_name}
              </h1>
              <Show when={page().author_description}>
                {(description) => (
                  <p class="mt-5 text-base leading-7 text-muted-foreground">{description()}</p>
                )}
              </Show>
            </header>

            <div class="mt-6 grid gap-4">
              <For each={page().documents}>
                {(doc) => (
                  <A
                    href={`/@${page().author_slug}/${doc.slug}`}
                    class="group block border-b border-border px-2 py-5 transition hover:border-primary/40 sm:px-6"
                  >
                    <h2 class="text-2xl font-bold leading-tight tracking-tight transition group-hover:text-primary">
                      {doc.title}
                    </h2>
                    <Show when={doc.excerpt}>
                      {(excerpt) => (
                        <p class="mt-3 line-clamp-2 text-sm leading-6 text-muted-foreground">
                          {excerpt()}
                        </p>
                      )}
                    </Show>
                    <p class="mt-3 text-sm text-muted-foreground">
                      Updated {new Date(doc.updated_at).toLocaleDateString()}
                    </p>
                  </A>
                )}
              </For>
            </div>
          </section>
        )}
      </Show>
    </PublicPageChrome>
  );
}
