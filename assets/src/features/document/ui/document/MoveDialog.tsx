import { createSignal, For } from "solid-js";
import { Button } from "@/shared/ui/button";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/shared/ui/dialog";
import { FolderIcon } from "lucide-solid";
import type { DocumentResponse } from "@/entities/document";

interface MoveDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentResponse;
  folders: DocumentResponse[];
  getTitle: (doc: DocumentResponse) => string;
  onSubmit: (parentId: string | null) => Promise<void>;
}

export function MoveDialog(props: MoveDialogProps) {
  const [selectedParent, setSelectedParent] = createSignal<string | null>(null);
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const isDescendantOf = (candidateId: string, ancestorId: string): boolean => {
    let current = props.folders.find((f) => f.id === candidateId);
    while (current) {
      if (current.parent_id === ancestorId) return true;
      if (!current.parent_id) return false;
      current = props.folders.find((f) => f.id === current!.parent_id);
    }
    return false;
  };

  const availableFolders = () =>
    props.folders.filter(
      (f) =>
        f.id !== props.document.id &&
        f.doc_type === "folder" &&
        !f.archived_at &&
        !isDescendantOf(f.id, props.document.id),
    );

  const handleSubmit = async () => {
    const newParent = selectedParent();
    if (newParent === (props.document.parent_id ?? null)) return;
    setSubmitting(true);
    setError(null);
    try {
      await props.onSubmit(newParent);
      props.onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to move");
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenChange = (open: boolean) => {
    if (open) {
      setSelectedParent(props.document.parent_id ?? null);
      setError(null);
    }
    props.onOpenChange(open);
  };

  return (
    <Dialog open={props.open} onOpenChange={handleOpenChange}>
      <DialogContent class="max-w-sm">
        <DialogHeader>
          <DialogTitle>Move</DialogTitle>
        </DialogHeader>
        <div class="flex flex-col gap-1 max-h-60 overflow-y-auto">
          <button
            class={`flex items-center gap-2 px-3 py-2 text-sm text-left transition-colors ${
              selectedParent() === null ? "bg-accent text-accent-foreground" : "hover:bg-accent/50"
            }`}
            onClick={() => setSelectedParent(null)}
          >
            <FolderIcon class="size-4 text-muted-foreground" />
            Root
          </button>
          <For each={availableFolders()}>
            {(folder) => (
              <button
                class={`flex items-center gap-2 px-3 py-2 text-sm text-left transition-colors ${
                  selectedParent() === folder.id
                    ? "bg-accent text-accent-foreground"
                    : "hover:bg-accent/50"
                }`}
                onClick={() => setSelectedParent(folder.id)}
              >
                <FolderIcon class="size-4 text-muted-foreground" />
                {props.getTitle(folder)}
              </button>
            )}
          </For>
        </div>
        {error() && <p class="text-xs text-destructive">{error()}</p>}
        <DialogFooter>
          <Button variant="outline" onClick={() => props.onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleSubmit}
            disabled={submitting() || selectedParent() === (props.document.parent_id ?? null)}
          >
            {submitting() ? "Moving..." : "Move"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
