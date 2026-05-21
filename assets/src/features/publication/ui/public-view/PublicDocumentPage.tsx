import { createMemo, For, Show } from "solid-js";
import { useParams } from "@solidjs/router";
import { Spinner } from "@/shared/ui/spinner";
import { usePublicDocument } from "../../model/public-view/use-public-document";
import { PublicPageChrome } from "./PublicPageChrome";
import {
  parsePublicMarkdown,
  publicMarkdownHeadings,
  PublicMarkdownView,
} from "./PublicMarkdownView";

export default function PublicDocumentPage() {
  const params = useParams<{ authorHandle?: string; authorSlug?: string; documentSlug?: string }>();
  const authorSlug = () => (params.authorHandle ?? params.authorSlug ?? "").replace(/^@/, "");
  const { document, error } = usePublicDocument(authorSlug, () => params.documentSlug);
  const markdownRoot = createMemo(() => parsePublicMarkdown(document()?.content ?? ""));
  const headings = () => publicMarkdownHeadings(markdownRoot());

  return (
    <PublicPageChrome label="Public Article">
      <Show
        when={document()}
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
        {(doc) => (
          <div class="min-h-[calc(100vh-3.5rem)] bg-muted/40">
            <section>
              <div class="mx-auto flex w-full max-w-5xl flex-col items-center px-4 py-8 text-center sm:px-6 sm:py-10">
                <h1 class="max-w-4xl text-4xl font-bold leading-tight tracking-tight sm:text-5xl">
                  {doc().title}
                </h1>
                <p class="mt-4 text-sm text-muted-foreground">
                  Updated {new Date(doc().updated_at).toLocaleDateString()}
                </p>
              </div>
            </section>

            <div class="mx-auto grid w-full max-w-7xl gap-6 px-4 py-6 sm:px-6 lg:grid-cols-[minmax(0,820px)_280px] lg:items-start lg:justify-center lg:py-8">
              <article class="min-w-0 border border-border bg-background px-5 py-8 sm:px-8 lg:px-10">
                <PublicMarkdownView root={markdownRoot()} />
              </article>

              <aside class="space-y-4 lg:sticky lg:top-20">
                <section class="border border-border bg-background p-5 text-foreground">
                  <a href={`/@${doc().author_slug}`} class="block transition hover:text-primary">
                    <p class="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                      Author
                    </p>
                    <p class="mt-1 text-sm font-semibold">{doc().author_name}</p>
                    <Show when={doc().author_description}>
                      {(description) => (
                        <p class="mt-2 text-sm leading-6 text-muted-foreground">{description()}</p>
                      )}
                    </Show>
                  </a>
                </section>

                <nav class="border border-border bg-background p-5">
                  <p class="mb-4 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                    Contents
                  </p>
                  <Show
                    when={headings().length > 0}
                    fallback={<p class="text-sm text-muted-foreground">No headings</p>}
                  >
                    <div class="space-y-2">
                      <For each={headings()}>
                        {(heading) => (
                          <a
                            href={`#${heading.id}`}
                            class="block text-sm leading-6 text-muted-foreground transition hover:text-foreground"
                            classList={{
                              "pl-3": heading.level === 2,
                              "pl-6": heading.level >= 3,
                            }}
                          >
                            {heading.title}
                          </a>
                        )}
                      </For>
                    </div>
                  </Show>
                </nav>
              </aside>
            </div>
          </div>
        )}
      </Show>
    </PublicPageChrome>
  );
}
