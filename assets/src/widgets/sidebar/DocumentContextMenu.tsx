import { createSignal, Show } from "solid-js";
import {
  PencilIcon,
  MoveIcon,
  PanelRightIcon,
  ArchiveIcon,
  ArchiveRestoreIcon,
  TrashIcon,
} from "lucide-solid";
import type { DocumentResponse } from "@/entities/document";
import { RenameDialog, DeleteConfirmDialog, MoveDialog } from "@/features/document";

interface DocumentContextMenuProps {
  targetDoc: DocumentResponse | null;
  position: { x: number; y: number } | null;
  onClose: () => void;
  getTitle: (doc: DocumentResponse) => string;
  folders: DocumentResponse[];
  onRename: (doc: DocumentResponse, newTitle: string) => Promise<void>;
  onMove: (doc: DocumentResponse, parentId: string | null) => Promise<void>;
  isTitleReady: (doc: DocumentResponse) => boolean;
  onAddToTile: (doc: DocumentResponse) => void;
  onArchive: (doc: DocumentResponse) => Promise<void>;
  onUnarchive: (doc: DocumentResponse) => Promise<void>;
  onDelete: (doc: DocumentResponse) => Promise<void>;
}

export function DocumentContextMenu(props: DocumentContextMenuProps) {
  const [renameOpen, setRenameOpen] = createSignal(false);
  const [moveOpen, setMoveOpen] = createSignal(false);
  const [deleteOpen, setDeleteOpen] = createSignal(false);
  const [dialogDoc, setDialogDoc] = createSignal<DocumentResponse | null>(null);

  const doc = () => props.targetDoc;
  const isArchived = () => doc()?.archived_at != null;

  const openRename = () => {
    setDialogDoc(doc());
    setRenameOpen(true);
    props.onClose();
  };

  const openMove = () => {
    setDialogDoc(doc());
    setMoveOpen(true);
    props.onClose();
  };

  const openDelete = () => {
    setDialogDoc(doc());
    setDeleteOpen(true);
    props.onClose();
  };

  return (
    <>
      <Show when={doc() && props.position}>
        <div
          class="fixed inset-0 z-40"
          onClick={props.onClose}
          onContextMenu={(e) => {
            e.preventDefault();
            props.onClose();
          }}
        >
          <div
            class="absolute z-50 min-w-[10rem] border border-border/60 bg-muted/60 p-1 text-foreground shadow-[var(--glass-shadow-outline)] backdrop-blur-[6px]"
            style={{
              left: `${props.position!.x}px`,
              top: `${props.position!.y}px`,
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <Show when={doc()?.doc_type === "document" && props.isTitleReady(doc()!)}>
              <button
                class="relative flex w-full cursor-default items-center gap-3 px-3 py-2 text-[11px] font-mono uppercase tracking-[0.28em] text-muted-foreground/80 outline-hidden transition-[background,color] hover:bg-foreground hover:text-background"
                onClick={() => {
                  props.onAddToTile(doc()!);
                  props.onClose();
                }}
              >
                <PanelRightIcon class="size-3.5" />
                Add to Tile
              </button>
            </Show>
            <Show when={!isArchived()}>
              <button
                class="relative flex w-full cursor-default items-center gap-3 px-3 py-2 text-[11px] font-mono uppercase tracking-[0.28em] text-muted-foreground/80 outline-hidden transition-[background,color] hover:bg-foreground hover:text-background"
                onClick={openRename}
              >
                <PencilIcon class="size-3.5" />
                Rename
              </button>
              <button
                class="relative flex w-full cursor-default items-center gap-3 px-3 py-2 text-[11px] font-mono uppercase tracking-[0.28em] text-muted-foreground/80 outline-hidden transition-[background,color] hover:bg-foreground hover:text-background"
                onClick={openMove}
              >
                <MoveIcon class="size-3.5" />
                Move
              </button>
            </Show>
            <Show when={!isArchived()}>
              <button
                class="relative flex w-full cursor-default items-center gap-3 px-3 py-2 text-[11px] font-mono uppercase tracking-[0.28em] text-muted-foreground/80 outline-hidden transition-[background,color] hover:bg-foreground hover:text-background"
                onClick={() => {
                  props.onArchive(doc()!);
                  props.onClose();
                }}
              >
                <ArchiveIcon class="size-3.5" />
                Archive
              </button>
            </Show>
            <Show when={isArchived()}>
              <button
                class="relative flex w-full cursor-default items-center gap-3 px-3 py-2 text-[11px] font-mono uppercase tracking-[0.28em] text-muted-foreground/80 outline-hidden transition-[background,color] hover:bg-foreground hover:text-background"
                onClick={() => {
                  props.onUnarchive(doc()!);
                  props.onClose();
                }}
              >
                <ArchiveRestoreIcon class="size-3.5" />
                Unarchive
              </button>
            </Show>
            <div class="pointer-events-none -mx-1 my-1 h-px bg-gradient-to-r from-transparent via-border/60 to-transparent" />
            <button
              class="relative flex w-full cursor-default items-center gap-3 px-3 py-2 text-[11px] font-mono uppercase tracking-[0.28em] text-destructive outline-hidden transition-[background,color] hover:bg-destructive hover:text-background"
              onClick={openDelete}
            >
              <TrashIcon class="size-3.5" />
              Delete
            </button>
          </div>
        </div>
      </Show>
      <Show when={dialogDoc()}>
        <RenameDialog
          open={renameOpen()}
          onOpenChange={setRenameOpen}
          currentTitle={props.getTitle(dialogDoc()!)}
          onSubmit={(newTitle) => props.onRename(dialogDoc()!, newTitle)}
        />
        <MoveDialog
          open={moveOpen()}
          onOpenChange={setMoveOpen}
          document={dialogDoc()!}
          folders={props.folders}
          onSubmit={(parentId) => props.onMove(dialogDoc()!, parentId)}
        />
        <DeleteConfirmDialog
          open={deleteOpen()}
          onOpenChange={setDeleteOpen}
          title={props.getTitle(dialogDoc()!)}
          isFolder={dialogDoc()!.doc_type === "folder"}
          onConfirm={() => props.onDelete(dialogDoc()!)}
        />
      </Show>
    </>
  );
}
