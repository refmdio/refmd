import { Show, type JSX } from "solid-js";
import { useSettings, useUpdateSettings } from "@/entities/settings";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/shared/ui/select";

const MODE_OPTIONS = [
  { value: "split", label: "Split" },
  { value: "markdown", label: "Markdown" },
  { value: "wysiwyg", label: "WYSIWYG" },
];

const LAYOUT_OPTIONS = [
  { value: "tiling", label: "Tiling" },
  { value: "horizontal", label: "Horizontal" },
  { value: "vertical", label: "Vertical" },
];

type EditorMode = "split" | "markdown" | "wysiwyg";
type EditorLayoutMode = "tiling" | "horizontal" | "vertical";
type SelectOption = { value: string; label: string };
type SelectItemProps = { item: { rawValue: string } };

function findLabel(options: SelectOption[], value: string): string {
  return options.find((o) => o.value === value)?.label ?? value;
}

function isEditorMode(value: string): value is EditorMode {
  return value === "split" || value === "markdown" || value === "wysiwyg";
}

function isEditorLayoutMode(value: string): value is EditorLayoutMode {
  return value === "tiling" || value === "horizontal" || value === "vertical";
}

export function EditorSection() {
  const settings = useSettings();
  const updateSettings = useUpdateSettings();

  const currentMode = () => settings.data?.editor_default_mode ?? "split";
  const currentLayout = () => settings.data?.editor_layout_mode ?? "tiling";

  return (
    <div class="p-6 space-y-6">
      <div>
        <h3 class="text-lg font-semibold">Editor</h3>
        <p class="text-sm text-muted-foreground">Configure the default editor behavior.</p>
      </div>

      <Show when={settings.data} fallback={<p class="text-sm text-muted-foreground">Loading...</p>}>
        <div class="space-y-4">
          <SettingRow
            label="Default Editor Mode"
            description="Choose how documents open by default."
          >
            <SettingSelect
              value={currentMode()}
              options={MODE_OPTIONS}
              onChange={(value) => {
                if (isEditorMode(value)) {
                  updateSettings.mutate({ editor_default_mode: value });
                }
              }}
              disabled={updateSettings.isPending}
            />
          </SettingRow>

          <SettingRow
            label="Layout Mode"
            description="How multiple documents are arranged. Tiling allows splitting in both directions."
          >
            <SettingSelect
              value={currentLayout()}
              options={LAYOUT_OPTIONS}
              onChange={(value) => {
                if (isEditorLayoutMode(value)) {
                  updateSettings.mutate({ editor_layout_mode: value });
                }
              }}
              disabled={updateSettings.isPending}
            />
          </SettingRow>
        </div>
      </Show>
    </div>
  );
}

function SettingRow(props: { label: string; description: string; children: JSX.Element }) {
  return (
    <div class="flex items-center justify-between gap-4">
      <div class="space-y-0.5">
        <label class="text-sm font-medium">{props.label}</label>
        <p class="text-xs text-muted-foreground">{props.description}</p>
      </div>
      <div class="shrink-0">{props.children}</div>
    </div>
  );
}

function SettingSelect(props: {
  value: string;
  options: { value: string; label: string }[];
  onChange: (value: string) => void;
  disabled: boolean;
}) {
  return (
    <Select
      value={props.value}
      onChange={(value: string | null) => {
        if (value) props.onChange(value);
      }}
      options={props.options.map((o) => o.value)}
      itemComponent={(itemProps: SelectItemProps) => (
        <SelectItem item={itemProps.item}>
          {findLabel(props.options, itemProps.item.rawValue)}
        </SelectItem>
      )}
      disabled={props.disabled}
    >
      <SelectTrigger class="w-40">
        <SelectValue>{() => findLabel(props.options, props.value)}</SelectValue>
      </SelectTrigger>
      <SelectContent />
    </Select>
  );
}
