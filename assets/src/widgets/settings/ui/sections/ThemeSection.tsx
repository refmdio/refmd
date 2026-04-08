import { For } from "solid-js";
import { useTheme, type ThemeSetting } from "@/shared/ui/theme-provider";
import { cn } from "@/shared/lib/utils";
import { SunIcon, MoonIcon, MonitorIcon } from "lucide-solid";

const THEME_OPTIONS: { value: ThemeSetting; label: string; icon: typeof SunIcon }[] = [
  { value: "light", label: "Light", icon: SunIcon },
  { value: "dark", label: "Dark", icon: MoonIcon },
  { value: "system", label: "System", icon: MonitorIcon },
];

export function ThemeSection() {
  const { theme, setTheme } = useTheme();

  return (
    <div class="p-6 space-y-6">
      <div>
        <h3 class="text-lg font-semibold mb-1">Appearance</h3>
        <p class="text-sm text-muted-foreground">Choose how RefMD looks to you.</p>
      </div>

      <section>
        <h4 class="text-sm font-medium mb-3">Theme</h4>
        <div class="grid grid-cols-3 gap-3">
          <For each={THEME_OPTIONS}>
            {(option) => {
              const Icon = option.icon;
              const isActive = () => theme() === option.value;
              return (
                <button
                  onClick={() => setTheme(option.value)}
                  class={cn(
                    "flex flex-col items-center gap-2 p-4 border transition-colors",
                    isActive()
                      ? "border-foreground bg-foreground/5"
                      : "border-border/60 hover:border-foreground/40",
                  )}
                >
                  <Icon class="size-5" />
                  <span class="text-sm">{option.label}</span>
                </button>
              );
            }}
          </For>
        </div>
      </section>
    </div>
  );
}
