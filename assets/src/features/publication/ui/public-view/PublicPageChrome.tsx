import { createSignal, type JSX } from "solid-js";
import { MoonIcon, SunIcon } from "lucide-solid";
import { cn } from "@/shared/lib/utils";

type PublicPageTheme = "light" | "dark";

interface PublicPageChromeProps {
  label: string;
  children: JSX.Element;
}

export function PublicPageChrome(props: PublicPageChromeProps) {
  const [theme, setTheme] = createSignal<PublicPageTheme>("light");

  return (
    <main class={cn(theme(), "min-h-screen bg-background text-foreground")}>
      <div class="min-h-screen">
        <header class="sticky top-0 z-20 border-b border-border bg-background/90 backdrop-blur">
          <div class="mx-auto flex h-14 w-full max-w-7xl items-center justify-between gap-4 px-4 sm:px-6">
            <div class="flex items-center gap-4">
              <a href="/" class="text-base font-bold tracking-tight text-foreground">
                RefMD
              </a>
              <span class="hidden h-4 border-l border-border sm:block" />
              <p class="hidden text-sm text-muted-foreground sm:block">{props.label}</p>
            </div>
            <div class="flex border border-border bg-background text-foreground">
              <button
                type="button"
                class={cn(
                  "inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition",
                  theme() === "light"
                    ? "bg-foreground text-background"
                    : "text-muted-foreground hover:text-foreground",
                )}
                onClick={() => setTheme("light")}
              >
                <SunIcon class="size-3.5" />
                Light
              </button>
              <button
                type="button"
                class={cn(
                  "inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition",
                  theme() === "dark"
                    ? "bg-foreground text-background"
                    : "text-muted-foreground hover:text-foreground",
                )}
                onClick={() => setTheme("dark")}
              >
                <MoonIcon class="size-3.5" />
                Dark
              </button>
            </div>
          </div>
        </header>
        {props.children}
      </div>
    </main>
  );
}
