import { createEffect, createSignal, For, Show } from "solid-js";
import { CheckIcon, CopyIcon, LinkIcon } from "lucide-solid";
import type { DocumentResponse } from "@/entities/document";
import { Button } from "@/shared/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/shared/ui/dialog";
import { Field, FieldLabel } from "@/shared/ui/field";
import { Input } from "@/shared/ui/input";
import { Checkbox } from "@/shared/ui/checkbox";
import { Spinner } from "@/shared/ui/spinner";
import { Switch } from "@/shared/ui/switch";
import { Tabs, TabsList, TabsTrigger } from "@/shared/ui/tabs";
import { useShareManagement } from "../../model/manage/use-share-management";
import { ExistingShareItem } from "./ExistingShareItem";
import {
  buildDescendantRows,
  OptionSelect,
  passwordStrengthLabel,
  SHARE_EXPIRY_CREATE_OPTIONS,
  SHARE_PERMISSION_OPTIONS,
  targetLabel,
} from "./share-dialog-helpers";

type ShareDialogTab = "links" | "create";

interface ShareManagementDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  document: DocumentResponse | null;
  documents: DocumentResponse[];
  canDeleteShares: boolean;
  getTitle: (document: DocumentResponse) => string;
  title: string;
  setError: (value: string | null) => void;
}

export function ShareManagementDialog(props: ShareManagementDialogProps) {
  const [activeTab, setActiveTab] = createSignal<ShareDialogTab>("links");
  const state = useShareManagement({
    document: () => props.document,
    documents: () => props.documents,
    canDeleteShares: () => props.canDeleteShares,
    getTitle: props.getTitle,
    setError: props.setError,
  });

  createEffect(() => {
    state.setOpen(props.open);
  });

  const createExpandedExclusionIds = () => state.expandedExclusionIds(state.excludedDocumentIds());
  const createDescendantRows = () =>
    buildDescendantRows(props.document, state.activeDescendantOptions());

  return (
    <Dialog
      open={props.open}
      onOpenChange={(open: boolean) => {
        state.setOpen(open);
        props.onOpenChange(open);
        if (!open) {
          state.resetCreateState();
          setActiveTab("links");
        }
      }}
    >
      <DialogContent class="max-w-2xl">
        <DialogHeader>
          <DialogTitle>Share Access</DialogTitle>
          <DialogDescription>Create and revoke links for {props.title}.</DialogDescription>
        </DialogHeader>

        <div class="space-y-5">
          <Tabs
            value={activeTab()}
            onChange={(value: string) => setActiveTab(value as ShareDialogTab)}
          >
            <TabsList
              aria-label="Share access sections"
              class="h-auto w-full justify-start border-x-0 border-t-0 bg-transparent"
            >
              <TabsTrigger value="links" class="h-9 flex-none px-4">
                Links
              </TabsTrigger>
              <TabsTrigger value="create" class="h-9 flex-none px-4">
                Create
              </TabsTrigger>
            </TabsList>
          </Tabs>

          <Show
            when={activeTab() === "links"}
            fallback={
              <Show
                when={!state.createdLink()}
                fallback={
                  <section class="space-y-3">
                    <p class="text-sm text-muted-foreground">Share link created.</p>
                    <div class="flex items-center gap-2">
                      <Input value={state.createdLink() ?? ""} readOnly class="font-mono text-xs" />
                      <Button variant="outline" size="icon" onClick={state.copyCreatedLink}>
                        <Show when={state.copied()} fallback={<CopyIcon class="size-4" />}>
                          <CheckIcon class="size-4" />
                        </Show>
                      </Button>
                    </div>
                  </section>
                }
              >
                <section class="space-y-4">
                  <div class="text-sm font-medium">{targetLabel(props.document, props.title)}</div>
                  <Show when={props.document?.doc_type === "folder"}>
                    <Field>
                      <FieldLabel>Included contents</FieldLabel>
                      <p class="text-xs text-muted-foreground">
                        Checked items are included in the shared folder.
                      </p>
                      <div class="max-h-36 overflow-y-auto border border-border/50 p-2 space-y-1">
                        <For each={createDescendantRows()}>
                          {(row) => (
                            <label
                              class="flex items-center gap-2 text-xs"
                              style={{ "padding-left": `${row.depth * 1}rem` }}
                            >
                              <span
                                class="h-5 border-l border-border/60"
                                classList={{ invisible: row.depth === 0 }}
                              />
                              <Checkbox
                                class="size-3.5"
                                checked={!createExpandedExclusionIds().has(row.document.id)}
                                disabled={
                                  createExpandedExclusionIds().has(row.document.id) &&
                                  !state.excludedDocumentIds().includes(row.document.id)
                                }
                                onChange={(checked: boolean) =>
                                  state.toggleCreateExclusion(row.document.id, !checked)
                                }
                              />
                              <span>
                                {row.document.doc_type === "folder" ? "Folder" : "Document"} ·{" "}
                                {state.getTitle(row.document)}
                              </span>
                            </label>
                          )}
                        </For>
                      </div>
                    </Field>
                  </Show>

                  <div class="grid gap-3 md:grid-cols-3">
                    <Field class="border border-border/60 bg-muted/20 p-3">
                      <FieldLabel for="share-permission">Permission</FieldLabel>
                      <OptionSelect
                        id="share-permission"
                        value={state.permission()}
                        options={SHARE_PERMISSION_OPTIONS}
                        onChange={(value) => state.setPermission(value as "view" | "edit")}
                      />
                    </Field>
                    <Field class="border border-border/60 bg-muted/20 p-3">
                      <FieldLabel for="share-expiry">Expires</FieldLabel>
                      <OptionSelect
                        id="share-expiry"
                        value={state.expiryDays()?.toString() ?? ""}
                        options={SHARE_EXPIRY_CREATE_OPTIONS}
                        onChange={(value) => state.setExpiryDays(value ? Number(value) : null)}
                      />
                    </Field>
                    <Field class="border border-border/60 bg-muted/20 p-3">
                      <FieldLabel for="share-access-limit">Limit</FieldLabel>
                      <Input
                        id="share-access-limit"
                        type="number"
                        min="0"
                        placeholder="No limit"
                        value={state.accessLimit()}
                        onInput={(event) => state.setAccessLimit(event.currentTarget.value)}
                      />
                    </Field>
                  </div>

                  <Field class="border border-border/60 bg-muted/20 p-3">
                    <div class="flex items-center justify-between gap-4">
                      <div>
                        <FieldLabel>Password protection</FieldLabel>
                        <p class="text-xs text-muted-foreground">
                          Require a password before this link can be opened.
                        </p>
                      </div>
                      <Switch
                        checked={state.passwordEnabled()}
                        onChange={(checked: boolean) => {
                          state.setPasswordEnabled(checked);
                          if (!checked) state.setPassword("");
                        }}
                      />
                    </div>

                    <Show when={state.passwordEnabled()}>
                      <div class="mt-3 space-y-2 border-t border-border/50 pt-3">
                        <FieldLabel for="share-password">Password</FieldLabel>
                        <Input
                          id="share-password"
                          type="password"
                          placeholder="Enter password"
                          value={state.password()}
                          onInput={(event) => state.setPassword(event.currentTarget.value)}
                        />
                        <Show when={passwordStrengthLabel(state.password())}>
                          <p class="text-xs text-muted-foreground">
                            {passwordStrengthLabel(state.password())}
                          </p>
                        </Show>
                      </div>
                    </Show>
                  </Field>
                </section>
              </Show>
            }
          >
            <section class="space-y-3">
              <h4 class="text-sm font-medium flex items-center gap-2">
                <LinkIcon class="size-4" />
                Links
              </h4>
              <Show
                when={!state.shares.isLoading}
                fallback={
                  <div class="flex justify-center py-3">
                    <Spinner class="size-5" />
                  </div>
                }
              >
                <Show
                  when={(state.shares.data?.shares?.length ?? 0) > 0}
                  fallback={<p class="text-sm text-muted-foreground">No share links yet.</p>}
                >
                  <div class="space-y-2">
                    <For each={state.shares.data?.shares}>
                      {(share) => <ExistingShareItem share={share} state={state} />}
                    </For>
                  </div>
                </Show>
              </Show>
              <div class="flex justify-end">
                <Button variant="outline" onClick={() => setActiveTab("create")}>
                  Create new link
                </Button>
              </div>
            </section>
          </Show>
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            onClick={() => {
              if (activeTab() === "create" && state.createdLink()) {
                state.resetCreateState();
                setActiveTab("links");
                return;
              }
              state.resetCreateState();
              props.onOpenChange(false);
            }}
          >
            {activeTab() === "create" && state.createdLink() ? "Back to Links" : "Close"}
          </Button>
          <Show when={activeTab() === "create" && !state.createdLink()}>
            <Button onClick={state.createShare} disabled={state.creating()}>
              {state.creating() ? "Creating..." : "Create Link"}
            </Button>
          </Show>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
