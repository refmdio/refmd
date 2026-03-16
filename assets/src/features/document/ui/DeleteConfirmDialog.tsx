import { createSignal } from "solid-js";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";

interface DeleteConfirmDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  isFolder: boolean;
  onConfirm: () => Promise<void>;
}

export function DeleteConfirmDialog(props: DeleteConfirmDialogProps) {
  const [deleting, setDeleting] = createSignal(false);
  const [error, setError] = createSignal<string | null>(null);

  const handleConfirm = async () => {
    setDeleting(true);
    setError(null);
    try {
      await props.onConfirm();
      props.onOpenChange(false);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to delete";
      setError(msg);
    } finally {
      setDeleting(false);
    }
  };

  const handleOpenChange = (open: boolean) => {
    if (!open) setError(null);
    props.onOpenChange(open);
  };

  return (
    <Dialog open={props.open} onOpenChange={handleOpenChange}>
      <DialogContent class="max-w-sm">
        <DialogHeader>
          <DialogTitle>Delete {props.isFolder ? "Folder" : "Document"}</DialogTitle>
          <DialogDescription>
            Are you sure you want to permanently delete "{props.title}"?
            {props.isFolder && " The folder must be empty to delete."}
          </DialogDescription>
        </DialogHeader>
        {error() && <p class="text-xs text-destructive">{error()}</p>}
        <DialogFooter>
          <Button variant="outline" onClick={() => handleOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="destructive" onClick={handleConfirm} disabled={deleting()}>
            {deleting() ? "Deleting..." : "Delete"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
