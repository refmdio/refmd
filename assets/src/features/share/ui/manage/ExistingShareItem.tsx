import { createSignal, For, Show } from "solid-js";
import {
  CheckIcon,
  CopyIcon,
  PencilIcon,
  RefreshCwIcon,
  SaveIcon,
  TrashIcon,
  XIcon,
} from "lucide-solid";
import { Button } from "@/shared/ui/button";
import { Checkbox } from "@/shared/ui/checkbox";
import { Input } from "@/shared/ui/input";
import type { ShareListItem } from "../../model/manage/types";
import type { ShareManagementModel } from "../../model/manage/use-share-management";
import {
  buildDescendantRows,
  OptionSelect,
  SHARE_EXPIRY_UPDATE_OPTIONS,
} from "./share-dialog-helpers";

const UNBOUNDED_SHARE_VIEWS = Number.MAX_SAFE_INTEGER;

function shareAccessLimitInput(share: ShareListItem): string {
  return shareMaxViews(share) === UNBOUNDED_SHARE_VIEWS ? "" : shareMaxViews(share).toString();
}

function shareMaxViews(share: ShareListItem): number {
  return share.max_views ?? UNBOUNDED_SHARE_VIEWS;
}

function shareExpiresEventSequence(share: ShareListItem): number {
  return share.expires_event_sequence ?? UNBOUNDED_SHARE_VIEWS;
}

export function ExistingShareItem(props: { share: ShareListItem; state: ShareManagementModel }) {
  const [expiryDays, setExpiryDays] = createSignal("");
  const [accessLimit, setAccessLimit] = createSignal(shareAccessLimitInput(props.share));
  const [refreshPassword, setRefreshPassword] = createSignal("");
  const [editing, setEditing] = createSignal(false);
  const shareId = () => props.share.id;
  const canManage = () => props.state.canManageShare(shareId());
  const canRevoke = () => props.state.canRevokeShare(shareId());
  const hasUrl = () => !!props.state.shareUrl(shareId());
  const directExclusionIds = () => new Set(props.share.exclusions ?? []);
  const exclusionIds = () => props.state.expandedExclusionIds(props.share.exclusions ?? []);
  const hasSettingsChanges = () =>
    expiryDays() !== "" || accessLimit() !== shareAccessLimitInput(props.share);
  const descendantRows = () => buildDescendantRows(null, props.state.activeDescendantOptions());

  const updateSettings = () => {
    if (!hasSettingsChanges()) return;

    return props.state.updateShareSettings(shareId(), {
      currentExpiresEventSequence: shareExpiresEventSequence(props.share),
      currentMaxViews: shareMaxViews(props.share),
      ...(expiryDays() !== "" ? { expiryDays: expiryDays() ? Number(expiryDays()) : null } : {}),
      accessLimitInput: accessLimit(),
    });
  };

  return (
    <div class="space-y-2 border border-border/50 p-2">
      <div class="flex items-center justify-between gap-2">
        <div>
          <div class="flex items-center gap-2 text-sm font-medium">
            <span>{props.share.permission}</span>
            <span class="text-muted-foreground">/</span>
            <span>{props.share.scope}</span>
            <span class="font-mono text-xs text-muted-foreground">{props.share.token_prefix}</span>
          </div>
          <div class="text-xs text-muted-foreground">
            {props.share.password_protected ? "Password" : "Open link"} &middot;{" "}
            {props.share.view_count}
            {shareMaxViews(props.share) === UNBOUNDED_SHARE_VIEWS
              ? ""
              : `/${shareMaxViews(props.share)}`}{" "}
            uses
            {shareExpiresEventSequence(props.share) === UNBOUNDED_SHARE_VIEWS
              ? ""
              : ` · Expires at event ${shareExpiresEventSequence(props.share)}`}
          </div>
        </div>
      </div>

      <Show when={hasUrl()}>
        <div class="flex items-center gap-2">
          <Input
            value={props.state.shareUrl(shareId()) ?? ""}
            readOnly
            class="h-8 font-mono text-xs"
          />
          <Show when={canManage()}>
            <Button
              variant="outline"
              size="icon"
              class="size-8"
              title={editing() ? "Close share settings" : "Edit share settings"}
              onClick={() => setEditing((value) => !value)}
            >
              <Show when={editing()} fallback={<PencilIcon class="size-3.5" />}>
                <XIcon class="size-3.5" />
              </Show>
            </Button>
          </Show>
          <Button
            variant="outline"
            size="icon"
            class="size-8"
            title="Copy share link"
            onClick={() => props.state.copyShareLink(shareId())}
          >
            <Show
              when={props.state.copiedShareId() === shareId()}
              fallback={<CopyIcon class="size-3.5" />}
            >
              <CheckIcon class="size-3.5" />
            </Show>
          </Button>
          <Show when={canRevoke()}>
            <Button
              variant="ghost"
              size="icon"
              class="size-8"
              title="Revoke share"
              onClick={() => props.state.revokeShare(shareId())}
            >
              <TrashIcon class="size-3.5" />
            </Button>
          </Show>
        </div>
      </Show>

      <Show when={canManage() && editing()}>
        <div class="grid gap-2 sm:grid-cols-[1fr_1fr_auto]">
          <OptionSelect
            size="sm"
            value={expiryDays()}
            options={SHARE_EXPIRY_UPDATE_OPTIONS}
            onChange={setExpiryDays}
            class="w-full text-xs"
          />
          <Input
            type="number"
            min="0"
            placeholder="No limit"
            value={accessLimit()}
            onInput={(event) => setAccessLimit(event.currentTarget.value)}
            class="h-8 text-xs"
          />
          <Button
            size="sm"
            variant="outline"
            onClick={updateSettings}
            disabled={props.state.updatingShareId() === shareId() || !hasSettingsChanges()}
            title="Save share settings"
          >
            <SaveIcon class="size-3.5" />
          </Button>
        </div>
        <Show when={props.share.scope === "folder"}>
          <div class="space-y-2">
            <div class="flex items-center justify-between gap-3 text-xs">
              <span class="font-medium">Included contents</span>
              <span class="text-muted-foreground">Uncheck items to exclude them.</span>
            </div>
            <div class="max-h-40 space-y-1 overflow-y-auto border border-border/50 p-2">
              <For each={descendantRows()}>
                {(row) => {
                  const directExcluded = () => directExclusionIds().has(row.document.id);
                  const excluded = () => exclusionIds().has(row.document.id);
                  const implicitExcluded = () => excluded() && !directExcluded();
                  const busy = () =>
                    props.state.updatingShareId() === shareId() ||
                    props.state.refreshingShareId() === shareId();

                  return (
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
                        checked={!excluded()}
                        disabled={busy() || implicitExcluded()}
                        onChange={(checked: boolean) => {
                          if (checked) {
                            void props.state.includeFolderDescendant(
                              props.share,
                              row.document.id,
                              refreshPassword(),
                            );
                            return;
                          }

                          void props.state.updateFolderShareExclusions(shareId(), {
                            add: [row.document.id],
                          });
                        }}
                      />
                      <span classList={{ "text-muted-foreground": implicitExcluded() }}>
                        {row.document.doc_type === "folder" ? "Folder" : "Document"} ·{" "}
                        {props.state.getTitle(row.document)}
                      </span>
                      <Show when={directExcluded()}>
                        <span class="ml-auto text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
                          excluded
                        </span>
                      </Show>
                      <Show when={implicitExcluded()}>
                        <span class="ml-auto text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
                          parent
                        </span>
                      </Show>
                    </label>
                  );
                }}
              </For>
            </div>
            <p class="text-xs text-muted-foreground">
              Items disabled by a parent exclusion must be restored from the parent folder first.
            </p>
          </div>
          <div class="grid gap-2 sm:grid-cols-[1fr_auto]">
            <Show when={props.share.password_protected}>
              <Input
                type="password"
                placeholder="Share password for key refresh"
                value={refreshPassword()}
                onInput={(event) => setRefreshPassword(event.currentTarget.value)}
                class="h-8 text-xs"
              />
            </Show>
            <Button
              size="sm"
              variant="outline"
              disabled={props.state.refreshingShareId() === shareId()}
              onClick={() => props.state.refreshFolderShareKeys(props.share, refreshPassword())}
              title="Refresh folder share keys"
            >
              <RefreshCwIcon class="size-3.5" />
              Refresh Keys
            </Button>
          </div>
        </Show>
      </Show>
    </div>
  );
}
