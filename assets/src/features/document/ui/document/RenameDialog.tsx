import { createSignal, createEffect } from "solid-js";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/shared/ui/dialog";

interface RenameDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  currentTitle: string;
  onSubmit: (newTitle: string) => Promise<void>;
}

export function RenameDialog(props: RenameDialogProps) {
  const [title, setTitle] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  createEffect(() => {
    if (props.open) {
      setTitle(props.currentTitle);
      setError(null);
    }
  });

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    const t = title().trim();
    if (!t || t === props.currentTitle) return;
    setSubmitting(true);
    setError(null);
    try {
      await props.onSubmit(t);
      props.onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to rename");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={props.open} onOpenChange={props.onOpenChange}>
      <DialogContent class="max-w-sm">
        <DialogHeader>
          <DialogTitle>Rename</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} class="flex flex-col gap-4">
          <Input value={title()} onInput={(e) => setTitle(e.currentTarget.value)} autofocus />
          {error() && <p class="text-xs text-destructive">{error()}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => props.onOpenChange(false)}>
              Cancel
            </Button>
            <Button
              type="submit"
              disabled={!title().trim() || title().trim() === props.currentTitle || submitting()}
            >
              {submitting() ? "Renaming..." : "Rename"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
