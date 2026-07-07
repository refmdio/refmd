import { createEffect, createSignal, For, onCleanup, Show } from "solid-js";
import { workspaceManager } from "@/features/panel";
import {
  closePluginUiModal,
  getActivePluginUiModalId,
  getDefaultPluginUiContributionRegistry,
  getPluginUiModalIframeSurface,
  pluginUiCommandId,
  pluginUiOwnerSurfaceId,
  subscribePluginUiModal,
  type PluginUiFormField,
  type PluginUiModalSubmitPayload,
  type PluginUiRegistryEntry,
} from "@/features/plugin-runtime";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Button } from "@/shared/ui/button";

const uiRegistry = getDefaultPluginUiContributionRegistry();

export function PluginUiModalHost() {
  const [version, setVersion] = createSignal(0);
  const unsubscribeRegistry = uiRegistry.subscribe(() => setVersion((value) => value + 1));
  const unsubscribeModal = subscribePluginUiModal(() => setVersion((value) => value + 1));
  onCleanup(() => {
    unsubscribeModal();
    unsubscribeRegistry();
  });

  const activeEntry = () => {
    version();
    const activeId = getActivePluginUiModalId();
    if (!activeId) return null;
    return (
      uiRegistry
        .list("declarative_modal")
        .find(
          (entry) => entry.id === activeId && entry.contribution.surface === "declarative_modal",
        ) ?? null
    );
  };

  return (
    <Show when={activeEntry()} keyed>
      {(entry) => <PluginUiModal entry={entry} />}
    </Show>
  );
}

function PluginUiModal(props: { entry: PluginUiRegistryEntry }) {
  const contribution = () => props.entry.contribution;
  let formEl: HTMLFormElement | undefined;
  const submit = () => {
    const current = contribution();
    if (current.surface !== "declarative_modal" || !current.submit_command_ref) {
      closePluginUiModal();
      return;
    }
    const commandId = pluginUiCommandId(props.entry, current.submit_command_ref);
    const command = workspaceManager.listCommands().find((item) => item.id === commandId);
    const payload =
      current.body.kind === "schema_form" && formEl
        ? modalSubmitPayload(current.modal_id, current.body.fields, formEl)
        : undefined;
    command?.callback?.(payload);
    closePluginUiModal();
  };
  const current = contribution();
  if (current.surface !== "declarative_modal") return null;

  return (
    <Dialog open={true} onOpenChange={(open: boolean) => !open && closePluginUiModal()}>
      <DialogContent class="max-w-lg" showCloseButton={true}>
        <DialogHeader>
          <DialogTitle>{current.title}</DialogTitle>
          <DialogDescription>Plugin action</DialogDescription>
        </DialogHeader>
        <Show
          when={current.body.kind === "schema_form"}
          fallback={
            <PluginUiModalIframe
              entry={props.entry}
              iframePanelId={
                current.body.kind === "iframe" ? current.body.iframe_panel_id : undefined
              }
              title={current.title}
            />
          }
        >
          <form
            ref={(el) => {
              formEl = el;
            }}
            class="space-y-3"
            onSubmit={(event) => {
              event.preventDefault();
              submit();
            }}
          >
            <For each={current.body.kind === "schema_form" ? current.body.fields : []}>
              {(field) => <PluginUiModalField field={field} />}
            </For>
          </form>
        </Show>
        <DialogFooter>
          <Button variant="secondary" onClick={closePluginUiModal}>
            Cancel
          </Button>
          <Button onClick={submit}>Submit</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function modalSubmitPayload(
  modalId: string,
  fields: readonly PluginUiFormField[],
  form: HTMLFormElement,
): PluginUiModalSubmitPayload {
  const data = new FormData(form);
  const values: PluginUiModalSubmitPayload["values"] = {};

  for (const field of fields) {
    if (field.kind === "checkbox") {
      values[field.name] = data.has(field.name);
    } else {
      const value = data.get(field.name);
      values[field.name] = typeof value === "string" ? value : "";
    }
  }

  return { modal_id: modalId, values };
}

function PluginUiModalIframe(props: {
  entry: PluginUiRegistryEntry;
  iframePanelId: string | undefined;
  title: string;
}) {
  const [container, setContainer] = createSignal<HTMLDivElement | null>(null);

  createEffect(() => {
    const id = props.iframePanelId
      ? pluginUiOwnerSurfaceId(props.entry.owner, props.iframePanelId)
      : null;
    const iframeSurface = getPluginUiModalIframeSurface(props.entry.owner);
    const containerEl = container();
    if (!id || !iframeSurface || !containerEl) return;
    iframeSurface.mount({
      id,
      surface: "declarative_modal",
      title: props.title,
      container: containerEl,
    });
    onCleanup(() => iframeSurface.unmount(id));
  });

  return (
    <div ref={setContainer} class="min-h-80 w-full overflow-hidden rounded border border-border" />
  );
}

function PluginUiModalField(props: { field: PluginUiFormField }) {
  return (
    <label class="grid gap-1.5 text-sm">
      <span class="font-medium">{props.field.label}</span>
      <Show
        when={props.field.kind === "select"}
        fallback={
          <Show
            when={props.field.kind === "checkbox"}
            fallback={
              <Show
                when={props.field.kind === "textarea"}
                fallback={
                  <input
                    name={props.field.name}
                    maxLength={props.field.kind === "text" ? props.field.max_length : undefined}
                    class="min-h-9 rounded-md border border-input bg-background px-3 py-2 text-sm"
                  />
                }
              >
                <textarea
                  name={props.field.name}
                  maxLength={props.field.kind === "textarea" ? props.field.max_length : undefined}
                  class="min-h-24 rounded-md border border-input bg-background px-3 py-2 text-sm"
                />
              </Show>
            }
          >
            <input type="checkbox" name={props.field.name} />
          </Show>
        }
      >
        <select
          name={props.field.name}
          class="h-9 rounded-md border border-input bg-background px-3 text-sm"
        >
          <For each={props.field.kind === "select" ? props.field.options : []}>
            {(option) => <option value={option.value}>{option.label}</option>}
          </For>
        </select>
      </Show>
    </label>
  );
}
