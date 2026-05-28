import { Show } from "solid-js";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { useWorkspaceSection } from "../../model/workspace-section/use-section";
import { WorkspaceSectionContent } from "../workspace-section/Content";
import { WorkspaceSectionDialogs } from "../workspace-section/Dialogs";

interface WorkspaceSectionProps {
  closePluginRuntimeByWorkspace?: (workspaceId: string, reason?: string) => void | Promise<void>;
  releasePluginRuntimeWorkspaceRevocation?: (workspaceId: string) => void;
}

export function WorkspaceSection(props: WorkspaceSectionProps = {}) {
  const state = useWorkspaceSection({
    closePluginRuntimeByWorkspace: props.closePluginRuntimeByWorkspace,
    releasePluginRuntimeWorkspaceRevocation: props.releasePluginRuntimeWorkspaceRevocation,
  });

  return (
    <div class="p-6 space-y-6">
      <div>
        <h3 class="text-lg font-semibold mb-1">Workspace</h3>
        <p class="text-sm text-muted-foreground">
          Manage workspace settings, members, roles, and invitations.
        </p>
      </div>

      <Show
        when={state.wsId()}
        fallback={<p class="text-sm text-muted-foreground">No workspace selected.</p>}
      >
        <Show when={state.error()}>
          {(err) => (
            <Alert variant="destructive">
              <AlertDescription>{err()}</AlertDescription>
            </Alert>
          )}
        </Show>

        <Show when={state.info()}>
          {(msg) => (
            <Alert>
              <AlertDescription>{msg()}</AlertDescription>
            </Alert>
          )}
        </Show>

        <WorkspaceSectionContent state={state} />
      </Show>

      <WorkspaceSectionDialogs state={state} />
    </div>
  );
}
