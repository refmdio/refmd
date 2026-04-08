import { Show, type ParentComponent } from "solid-js";
import { Alert, AlertDescription } from "@/shared/ui/alert";
import { ApproveDeviceDialog } from "../../approve";
import { PendingDeviceContext, usePendingDeviceMonitorState } from "../model/pending-monitor";

export const PendingDeviceMonitor: ParentComponent = (props) => {
  const model = usePendingDeviceMonitorState();

  return (
    <PendingDeviceContext.Provider value={model.contextValue}>
      {props.children}
      <Show when={model.currentDialog()}>
        {(target) => (
          <ApproveDeviceDialog
            device={target()}
            transferNonce={model.contextValue.transferNonces()[target().id] ?? null}
            onClose={model.handleDialogClose}
            onApproved={model.handleApproved}
            onError={model.handleApprovalError}
          />
        )}
      </Show>
      <Show when={model.approvalError()}>
        <div class="fixed bottom-4 right-4 z-50 max-w-md">
          <Alert variant="destructive">
            <AlertDescription>{model.approvalError()}</AlertDescription>
          </Alert>
        </div>
      </Show>
    </PendingDeviceContext.Provider>
  );
};
