import { Show, type ParentProps } from "solid-js";
import { Spinner } from "@/shared/ui/spinner";
import { AlertCircleIcon } from "lucide-solid";

interface DocumentPanelShellProps {
  documentId: string;
  isLoading?: boolean;
  error?: string | null;
}

export function DocumentPanelShell(props: ParentProps<DocumentPanelShellProps>) {
  return (
    <Show
      when={!props.error}
      fallback={
        <div class="flex flex-col items-center justify-center h-full bg-background">
          <AlertCircleIcon class="size-6 text-destructive" />
          <p class="mt-2 text-sm text-destructive">{props.error}</p>
        </div>
      }
    >
      <Show
        when={!props.isLoading}
        fallback={
          <div class="flex items-center justify-center h-full bg-background">
            <Spinner class="size-6" />
          </div>
        }
      >
        {props.children}
      </Show>
    </Show>
  );
}
