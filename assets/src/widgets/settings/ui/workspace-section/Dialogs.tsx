import {
  WorkspaceInvitationDialog,
  WorkspaceMemberManagementDialogs,
  WorkspaceRoleManagementDialogs,
} from "@/features/workspace";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import type { WorkspaceSectionModel } from "../../model/workspace-section/useSection";

interface WorkspaceSectionDialogsProps {
  state: WorkspaceSectionModel;
}

export function WorkspaceSectionDialogs(props: WorkspaceSectionDialogsProps) {
  const state = () => props.state;

  return (
    <>
      <WorkspaceInvitationDialog state={state().invitationManagement} />
      <WorkspaceMemberManagementDialogs
        state={state().memberManagement}
        assignableRoles={state().assignableRoles()}
      />
      <WorkspaceRoleManagementDialogs state={state().roleManagement} />

      <Dialog open={state().showDelete()} onOpenChange={state().setShowDelete}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Delete Workspace</DialogTitle>
            <DialogDescription>
              This action cannot be undone. All documents and data in this workspace will be
              permanently deleted.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => state().setShowDelete(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={state().handleDelete}
              disabled={state().deleting()}
            >
              {state().deleting() ? "Deleting..." : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={state().showLeave()} onOpenChange={state().setShowLeave}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Leave Workspace</DialogTitle>
            <DialogDescription>
              You will lose access to all documents in this workspace.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => state().setShowLeave(false)}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={state().handleLeave}
              disabled={state().leaving()}
            >
              {state().leaving() ? "Leaving..." : "Leave"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
