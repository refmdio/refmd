import { createSignal } from "solid-js";
import { Button } from "@/shared/ui/button";
import { Input } from "@/shared/ui/input";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/shared/ui/dialog";

interface CreateDocumentDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (title: string) => Promise<void>;
}

export function CreateDocumentDialog(props: CreateDocumentDialogProps) {
  const [title, setTitle] = createSignal("");
  const [submitting, setSubmitting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const handleSubmit = async (e: Event) => {
    e.preventDefault();
    const t = title().trim();
    if (!t) return;
    setSubmitting(true);
    setError(null);
    try {
      await props.onSubmit(t);
      setTitle("");
      props.onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create document");
    } finally {
      setSubmitting(false);
    }
  };

  const handleOpenChange = (open: boolean) => {
    if (!open) {
      setTitle("");
      setError(null);
    }
    props.onOpenChange(open);
  };

  return (
    <Dialog open={props.open} onOpenChange={handleOpenChange}>
      <DialogContent class="max-w-sm">
        <DialogHeader>
          <DialogTitle>New Document</DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} class="flex flex-col gap-4">
          <Input
            placeholder="Document title"
            value={title()}
            onInput={(e) => setTitle(e.currentTarget.value)}
            autofocus
          />
          {error() && <p class="text-xs text-destructive">{error()}</p>}
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => handleOpenChange(false)}>
              Cancel
            </Button>
            <Button type="submit" disabled={!title().trim() || submitting()}>
              {submitting() ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
