import type { DocumentResponse } from "@/entities/document";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/shared/ui/select";

export type SelectOption = { value: string; label: string };
export type DescendantRow = { document: DocumentResponse; depth: number };

export const SHARE_EXPIRY_UPDATE_OPTIONS: SelectOption[] = [
  { value: "", label: "Keep expiry" },
  { value: "0", label: "No expiry" },
  { value: "1", label: "Expire at event 1" },
  { value: "7", label: "Expire at event 7" },
  { value: "14", label: "Expire at event 14" },
  { value: "30", label: "Expire at event 30" },
];

export const SHARE_PERMISSION_OPTIONS: SelectOption[] = [
  { value: "view", label: "View" },
  { value: "edit", label: "Edit" },
];

export const SHARE_EXPIRY_CREATE_OPTIONS: SelectOption[] = [
  { value: "", label: "No expiry" },
  { value: "1", label: "Event 1" },
  { value: "7", label: "Event 7" },
  { value: "14", label: "Event 14" },
  { value: "30", label: "Event 30" },
];

function optionLabel(options: SelectOption[], value: string): string {
  return options.find((option) => option.value === value)?.label ?? "";
}

export function buildDescendantRows(
  root: DocumentResponse | null,
  descendants: DocumentResponse[],
): DescendantRow[] {
  const byId = new Map(descendants.map((document) => [document.id, document]));

  const depthFor = (document: DocumentResponse): number => {
    let depth = 0;
    let parentId = document.parent_id;

    while (parentId && parentId !== root?.id) {
      const parent = byId.get(parentId);
      if (!parent) break;
      depth++;
      parentId = parent.parent_id;
    }

    return depth;
  };

  return descendants.map((document) => ({ document, depth: depthFor(document) }));
}

export function OptionSelect(props: {
  id?: string;
  size?: "sm" | "default";
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  class?: string;
}) {
  return (
    <Select
      options={props.options.map((option) => option.value)}
      value={props.value}
      onChange={(value: string | null) => props.onChange(value ?? "")}
      itemComponent={(itemProps) => (
        <SelectItem item={itemProps.item}>
          {optionLabel(props.options, itemProps.item.rawValue as string)}
        </SelectItem>
      )}
    >
      <SelectTrigger id={props.id} size={props.size} class={props.class ?? "w-full"}>
        <SelectValue>{() => optionLabel(props.options, props.value)}</SelectValue>
      </SelectTrigger>
      <SelectContent />
    </Select>
  );
}

export function passwordStrengthLabel(password: string): string {
  const value = password.trim();
  if (!value) return "";

  const score = [
    value.length >= 12,
    /[a-z]/.test(value) && /[A-Z]/.test(value),
    /\d/.test(value),
    /[^A-Za-z0-9]/.test(value),
  ].filter(Boolean).length;

  if (score >= 3) return "Strong password";
  if (score === 2) return "Fair password";
  return "Weak password";
}

export function targetLabel(document: DocumentResponse | null, title: string): string {
  if (!document) return title;
  return `${document.doc_type === "folder" ? "Folder" : "Document"} · ${title}`;
}
