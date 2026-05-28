import {
  PluginHostRpcError,
  type PluginHostRpcHandlerOwnerDescriptor,
  type PluginHostRpcSession,
} from "../../lib/host-rpc/host-rpc";
import type {
  PluginAuditSink,
  PluginDocumentScope,
} from "../../lib/capability/capability-enforcement";
import {
  assertLocalId,
  validateCommandRef,
  validateCommandRefs,
  validateDocumentQueryRegistrationAuthority,
  validatePluginUiContribution,
} from "./host-ui-validation";
import { contributionKey, ownerKey, pluginContributionId, sameOwner } from "./host-ui-identity";
export { pluginContributionId } from "./host-ui-identity";
export { validatePluginUiContribution } from "./host-ui-validation";

export type PluginUiSurface =
  | "command"
  | "status"
  | "sidebar_panel"
  | "workspace_tile"
  | "workspace_tile_action"
  | "auxiliary_pane"
  | "document_tree_action"
  | "document_tree_badge"
  | "document_tree_decoration"
  | "document_tree_virtual_section"
  | "settings_iframe"
  | "settings_declarative"
  | "menu_item"
  | "declarative_modal";

export type PluginUiResourcePredicate =
  | { kind: "always" }
  | { kind: "resource_kind"; is: "document" | "folder" | "workspace" }
  | { kind: "document_open" }
  | { kind: "selection_present" }
  | { kind: "capability"; has: string }
  | { kind: "all"; of: PluginUiResourcePredicate[] }
  | { kind: "any"; of: PluginUiResourcePredicate[] }
  | { kind: "not"; of: PluginUiResourcePredicate };

export interface PluginUiCommandRef {
  kind: "local_command";
  local_id: string;
}

interface PluginUiContributionBase {
  local_id: string;
  surface: PluginUiSurface;
  label?: string;
  icon?: string;
  order?: number;
  when?: PluginUiResourcePredicate;
}

export interface PluginUiCommandContribution extends PluginUiContributionBase {
  surface: "command";
  title: string;
  category?: string;
  enablement?: PluginUiResourcePredicate;
  plaintext_request?: "none" | "active_document" | "selection" | "editor_context";
  document_query?: PluginUiWorkspaceDocumentQueryInvocation;
}

export interface PluginUiWorkspaceDocumentQueryInvocation {
  scope: "workspace";
  max_documents: number;
  max_bytes: number;
  reason?: string;
}

export interface PluginUiStatusContribution extends PluginUiContributionBase {
  surface: "status";
  zone: "normal";
  value: { kind: "text"; text?: string } | { kind: "iframe"; panel_id: string };
  plaintext_request?: "none" | "active_document";
  max_width?: number;
}

export interface PluginUiSidebarPanelContribution extends PluginUiContributionBase {
  surface: "sidebar_panel";
  panel_id: string;
  title: string;
  default_width?: number;
  allowed_locations: ("left" | "right")[];
}

export interface PluginUiWorkspaceTileContribution extends PluginUiContributionBase {
  surface: "workspace_tile";
  tile_id: string;
  title: string;
  scope: "workspace" | "document";
  preferred_open?: "manual" | "document_menu" | "command";
}

export interface PluginUiWorkspaceTileRef {
  kind: "local_tile";
  local_id: string;
}

export interface PluginUiWorkspaceTileActionContribution extends PluginUiContributionBase {
  surface: "workspace_tile_action";
  tile_ref: PluginUiWorkspaceTileRef;
  action_id: string;
  title: string;
  placement: "tile_toolbar" | "tile_menu" | "refresh";
  document_query?: PluginUiWorkspaceDocumentQueryInvocation;
}

export interface PluginUiAuxiliaryPaneContribution extends PluginUiContributionBase {
  surface: "auxiliary_pane";
  pane_id: string;
  title: string;
  default_width?: number;
  allowed_locations: ("left" | "right" | "document_left" | "document_right")[];
  actions?: PluginUiAuxiliaryPaneAction[];
}

export interface PluginUiAuxiliaryPaneAction {
  action_id: string;
  title: string;
  icon?: string;
  order?: number;
  command_ref: PluginUiCommandRef;
}

export interface PluginUiDocumentTreeActionContribution extends PluginUiContributionBase {
  surface: "document_tree_action";
  placement: "row_context_menu" | "row_inline_action";
  title: string;
  command_ref: PluginUiCommandRef;
}

export interface PluginUiDocumentTreeBadgeContribution extends PluginUiContributionBase {
  surface: "document_tree_badge";
  placement: "row_trailing_badge";
  text?: string;
  plaintext_request?: "none" | "active_document";
  tone?: PluginUiTone;
}

export interface PluginUiDocumentTreeDecorationContribution extends PluginUiContributionBase {
  surface: "document_tree_decoration";
  placement: "row_prefix" | "row_suffix";
  tone?: PluginUiTone;
}

export interface PluginUiDocumentTreeVirtualSectionContribution extends PluginUiContributionBase {
  surface: "document_tree_virtual_section";
  placement: "before_tree" | "after_tree";
  title: string;
  source_command_ref: PluginUiCommandRef;
}

export interface PluginUiSettingsIframeContribution extends PluginUiContributionBase {
  surface: "settings_iframe";
  settings_id: string;
  title: string;
  placement: "plugin_settings";
  iframe_panel_id: string;
}

export interface PluginUiSettingsDeclarativeContribution extends PluginUiContributionBase {
  surface: "settings_declarative";
  settings_id: string;
  title: string;
  placement: "plugin_settings";
  sections: PluginUiFormSection[];
  submit_command_ref?: PluginUiCommandRef;
}

export interface PluginUiMenuItemContribution extends PluginUiContributionBase {
  surface: "menu_item";
  placement:
    | "command_palette"
    | "editor_context_menu"
    | "document_tree_context_menu"
    | "document_tab_menu";
  title: string;
  command_ref: PluginUiCommandRef;
  enablement?: PluginUiResourcePredicate;
}

export interface PluginUiDeclarativeModalContribution extends PluginUiContributionBase {
  surface: "declarative_modal";
  modal_id: string;
  title: string;
  trigger_command_ref: PluginUiCommandRef;
  body:
    | { kind: "schema_form"; fields: PluginUiFormField[] }
    | { kind: "iframe"; iframe_panel_id: string };
  submit_command_ref?: PluginUiCommandRef;
}

export interface PluginUiModalSubmitPayload {
  modal_id: string;
  values: Record<string, boolean | string>;
}

export type PluginUiContribution =
  | PluginUiCommandContribution
  | PluginUiStatusContribution
  | PluginUiSidebarPanelContribution
  | PluginUiWorkspaceTileContribution
  | PluginUiWorkspaceTileActionContribution
  | PluginUiAuxiliaryPaneContribution
  | PluginUiDocumentTreeActionContribution
  | PluginUiDocumentTreeBadgeContribution
  | PluginUiDocumentTreeDecorationContribution
  | PluginUiDocumentTreeVirtualSectionContribution
  | PluginUiSettingsIframeContribution
  | PluginUiSettingsDeclarativeContribution
  | PluginUiMenuItemContribution
  | PluginUiDeclarativeModalContribution;

export type PluginUiTone = "neutral" | "info" | "warning";

export interface PluginUiFormSection {
  title?: string;
  fields: PluginUiFormField[];
}

export type PluginUiFormField =
  | { kind: "text"; name: string; label: string; max_length: number }
  | { kind: "textarea"; name: string; label: string; max_length: number }
  | { kind: "checkbox"; name: string; label: string }
  | { kind: "select"; name: string; label: string; options: PluginUiSelectOption[] };

export interface PluginUiSelectOption {
  value: string;
  label: string;
}

export interface PluginUiRegistryEntry {
  id: string;
  owner: PluginHostRpcHandlerOwnerDescriptor;
  contribution: PluginUiContribution;
  capabilities: readonly string[];
  display?: PluginUiDisplayState;
}

type PluginUiStoredRegistryEntry = PluginUiRegistryEntry & { active: boolean };

export interface PluginUiDisplayState {
  text?: string;
  tone?: PluginUiTone;
}

export interface PluginUiResourceContext {
  resourceKind: "document" | "folder" | "workspace";
  workspaceId?: string;
  documentId?: string;
  folderId?: string;
  documentOpen?: boolean;
  selectionPresent?: boolean;
  capabilities?: readonly string[];
}

export interface PluginHostUiServices {
  registry: PluginUiContributionRegistry;
  auditSink?: PluginAuditSink;
  commandSurface?: PluginUiCommandSurface;
  plaintextContext?: PluginUiPlaintextCommandContext;
  resourceContext?: PluginUiResourceContextProvider;
  statusSurface?: PluginUiStatusSurface;
  sidebarSurface?: PluginUiSidebarSurface;
  workspaceTileSurface?: PluginUiWorkspaceTileSurface;
  auxiliaryPaneSurface?: PluginUiAuxiliaryPaneSurface;
  settingsSurface?: PluginUiSettingsSurface;
  iframeSurface?: PluginUiIframeSurface;
  settingsRenderer?: PluginUiSettingsRenderer;
}

export interface PluginUiPlaintextCommandContext {
  activeDocument(): { documentId: string; maxBytes?: number } | null;
  selection?(session: PluginHostRpcSession): PluginUiPlaintextCommandHandle | null;
  editorContext?(session: PluginHostRpcSession): PluginUiPlaintextCommandHandle | null;
}

export interface PluginUiPlaintextCommandHandle {
  executionContextId: string;
  dispose?(): void;
}

export interface PluginUiResourceContextProvider {
  workspace(): PluginUiResourceContext;
  activeDocument(): PluginUiResourceContext | null;
  editor?(editor: unknown, view: unknown): PluginUiResourceContext | null;
}

export interface PluginUiCommandSurface {
  add(command: {
    id: string;
    owner: PluginHostRpcHandlerOwnerDescriptor;
    name: string;
    icon?: string;
    callback: (payload?: unknown) => void;
    checkCallback?: (checking: boolean) => boolean | void;
    editorCheckCallback?: (checking: boolean, editor: unknown, view: unknown) => boolean | void;
  }): void;
  remove(id: string): void;
}

export interface PluginUiStatusSurface {
  add(item: {
    id: string;
    owner: PluginHostRpcHandlerOwnerDescriptor;
    label?: string;
    maxWidth?: number;
    content:
      | { kind: "text"; text: string }
      | { kind: "host_render"; render: (container: HTMLElement) => void };
  }): void;
  remove(id: string): void;
}

export interface PluginUiSidebarSurface {
  add(panel: {
    id: string;
    owner: PluginHostRpcHandlerOwnerDescriptor;
    title: string;
    icon?: string;
    render: (container: HTMLElement) => void;
    hide?: () => void;
  }): void;
  remove(id: string): void;
}

export interface PluginUiWorkspaceTileSurface {
  add(panel: {
    id: string;
    tileId: string;
    owner: PluginHostRpcHandlerOwnerDescriptor;
    title: string;
    icon?: string;
    scope: "workspace" | "document";
    preferredOpen: "manual" | "document_menu" | "command";
    actions?: () => PluginUiWorkspaceTileActionControl[] | undefined;
    isAvailable?: (context: PluginUiWorkspaceTileAvailabilityContext) => boolean;
    open?: (context: PluginUiWorkspaceTileAvailabilityContext) => boolean | Promise<boolean>;
    render: (container: HTMLElement, context?: PluginUiWorkspaceTileRenderContext) => void;
    hide?: (context?: PluginUiWorkspaceTileRenderContext) => void;
  }): void;
  open?: (id: string, documentId?: string) => void;
  remove(id: string): void;
}

export interface PluginUiWorkspaceTileActionControl {
  id: string;
  actionId: string;
  title: string;
  icon?: string;
  order?: number;
  placement: "tile_toolbar" | "tile_menu" | "refresh";
  documentQuery?: PluginUiWorkspaceDocumentQueryInvocation;
}

export interface PluginUiAuxiliaryPaneSurface {
  add(pane: {
    id: string;
    owner: PluginHostRpcHandlerOwnerDescriptor;
    title: string;
    icon?: string;
    allowedLocations: ("left" | "right" | "document_left" | "document_right")[];
    defaultWidth?: number;
    actions?: PluginUiAuxiliaryPaneActionControl[];
    render: (container: HTMLElement) => void;
    hide?: () => void;
    close?: () => void;
  }): void;
  remove(id: string): void;
}

export interface PluginUiAuxiliaryPaneActionControl {
  id: string;
  title: string;
  icon?: string;
  order?: number;
  invoke: () => void;
  isAvailable?: () => boolean;
}

export interface PluginUiWorkspaceTileAvailabilityContext {
  resourceKind: "document" | "folder" | "workspace";
  workspaceId?: string;
  documentId?: string;
  folderId?: string;
  documentOpen?: boolean;
  selectionPresent?: boolean;
}

export interface PluginUiWorkspaceTileRenderContext {
  tileInstanceId: string;
  documentId?: string;
  action?: PluginUiWorkspaceTileActionContext;
}

export interface PluginUiWorkspaceTileActionContext {
  actionId: string;
  tileId: string;
  tileInstanceId: string;
  documentId?: string;
  kind?: "tile_action";
  tileActionId?: string;
  documentQuery?: PluginUiWorkspaceDocumentQueryInvocation;
  issuedAtMs: number;
}

export interface PluginUiSettingsSurface {
  add(tab: {
    id: string;
    owner: PluginHostRpcHandlerOwnerDescriptor;
    title: string;
    render: (container: HTMLElement) => void;
    hide?: () => void;
  }): void;
  remove(id: string): void;
}

export interface PluginUiIframeSurface {
  mount(options: {
    id: string;
    mountKey?: string;
    surface: Extract<
      PluginUiSurface,
      | "status"
      | "sidebar_panel"
      | "workspace_tile"
      | "auxiliary_pane"
      | "settings_iframe"
      | "declarative_modal"
    >;
    title: string;
    container: HTMLElement;
    resource?: {
      tileId?: string;
      documentId?: string;
      tileInstanceId?: string;
      action?: PluginUiWorkspaceTileActionContext;
    };
  }): void;
  unmount(id: string): void;
}

export type PluginUiSettingsRenderer = (
  container: HTMLElement,
  contribution: PluginUiSettingsIframeContribution | PluginUiSettingsDeclarativeContribution,
  id: string,
  iframeSurface: PluginUiIframeSurface | undefined,
  options?: PluginUiSettingsRendererOptions,
) => void;

export interface PluginUiSettingsRendererOptions {
  submit?(payload: PluginUiSettingsSubmitPayload): void;
}

export interface PluginUiSettingsSubmitPayload {
  settings_id: string;
  values: Record<string, boolean | string>;
}

export class PluginUiContributionRegistry {
  private readonly entries = new Map<string, PluginUiStoredRegistryEntry>();
  private readonly listeners = new Set<() => void>();

  prepareRegistration(
    owner: PluginHostRpcHandlerOwnerDescriptor,
    contribution: PluginUiContribution,
    capabilities: Iterable<string> = [],
    documentScope: PluginDocumentScope = {},
  ): { id: string; contribution: PluginUiContribution } {
    const prepared = this.prepareEntry(owner, contribution, capabilities, documentScope);
    this.entries.set(prepared.key, { ...prepared.entry, active: false });
    return {
      id: prepared.entry.id,
      contribution: structuredCloneContribution(prepared.entry.contribution),
    };
  }

  activateRegistration(owner: PluginHostRpcHandlerOwnerDescriptor, localId: string): string {
    assertLocalId(localId);
    const key = contributionKey(owner, localId);
    const entry = this.entries.get(key);
    if (!entry || !sameOwner(entry.owner, owner)) {
      throw new PluginHostRpcError(
        "ui_contribution_unknown",
        "UI contribution is not registered for this owner",
      );
    }
    if (!entry.active) {
      this.entries.set(key, { ...entry, active: true });
      this.notify();
    }
    return entry.id;
  }

  register(
    owner: PluginHostRpcHandlerOwnerDescriptor,
    contribution: PluginUiContribution,
    capabilities: Iterable<string> = [],
    documentScope: PluginDocumentScope = {},
  ): string {
    const prepared = this.prepareEntry(owner, contribution, capabilities, documentScope);
    this.entries.set(prepared.key, { ...prepared.entry, active: true });
    this.notify();
    return prepared.entry.id;
  }

  private prepareEntry(
    owner: PluginHostRpcHandlerOwnerDescriptor,
    contribution: PluginUiContribution,
    capabilities: Iterable<string>,
    documentScope: PluginDocumentScope,
  ): { key: string; entry: PluginUiRegistryEntry } {
    const validated = validatePluginUiContribution(contribution);
    const capabilityList = [...capabilities];
    validateDocumentQueryRegistrationAuthority(validated, capabilityList, documentScope);
    validateCommandRefs(validated, (localId) => this.hasCommand(owner, localId));
    const id = pluginContributionId(owner, validated.local_id);
    const key = contributionKey(owner, validated.local_id);
    if (this.entries.has(key)) {
      throw new PluginHostRpcError(
        "ui_contribution_duplicate",
        "UI contribution is already registered for this owner",
      );
    }
    return { key, entry: { id, owner, contribution: validated, capabilities: capabilityList } };
  }

  updateDisplay(
    owner: PluginHostRpcHandlerOwnerDescriptor,
    localId: string,
    display: PluginUiDisplayState,
  ): void {
    assertLocalId(localId);
    const key = contributionKey(owner, localId);
    const entry = this.entries.get(key);
    if (!entry || !entry.active || !sameOwner(entry.owner, owner)) {
      throw new PluginHostRpcError(
        "ui_contribution_unknown",
        "UI contribution is not registered for this owner",
      );
    }
    this.entries.set(key, { ...entry, display: { ...display } });
    this.notify();
  }

  unregister(owner: PluginHostRpcHandlerOwnerDescriptor, localId: string): void {
    assertLocalId(localId);
    const key = contributionKey(owner, localId);
    if (!this.entries.delete(key)) {
      throw new PluginHostRpcError(
        "ui_contribution_unknown",
        "UI contribution is not registered for this owner",
      );
    }
    this.notify();
  }

  clearOwner(owner: PluginHostRpcHandlerOwnerDescriptor): void {
    let changed = false;
    for (const [key, entry] of this.entries) {
      if (sameOwner(entry.owner, owner)) {
        this.entries.delete(key);
        changed = true;
      }
    }
    if (changed) this.notify();
  }

  list(surface?: PluginUiSurface): PluginUiRegistryEntry[] {
    return [...this.entries.values()]
      .filter((entry) => entry.active && (!surface || entry.contribution.surface === surface))
      .map((entry) => ({
        id: entry.id,
        owner: entry.owner,
        contribution: structuredCloneContribution(entry.contribution),
        capabilities: [...entry.capabilities],
        ...(entry.display ? { display: { ...entry.display } } : {}),
      }))
      .sort(compareEntries);
  }

  resolveCommandRef(
    owner: PluginHostRpcHandlerOwnerDescriptor,
    ref: PluginUiCommandRef,
  ): PluginUiRegistryEntry {
    validateCommandRef(ref);
    const entry = this.entries.get(contributionKey(owner, ref.local_id));
    if (
      !entry ||
      !entry.active ||
      entry.contribution.surface !== "command" ||
      !sameOwner(entry.owner, owner)
    ) {
      throw new PluginHostRpcError(
        "ui_command_ref_denied",
        "command reference is not registered for this owner",
      );
    }
    return {
      id: entry.id,
      owner: entry.owner,
      contribution: structuredCloneContribution(entry.contribution),
      capabilities: [...entry.capabilities],
      ...(entry.display ? { display: { ...entry.display } } : {}),
    };
  }

  resolveWorkspaceTileRef(
    owner: PluginHostRpcHandlerOwnerDescriptor,
    localId: string,
  ): PluginUiRegistryEntry {
    assertLocalId(localId);
    const entry = this.entries.get(contributionKey(owner, localId));
    if (
      !entry ||
      !entry.active ||
      entry.contribution.surface !== "workspace_tile" ||
      !sameOwner(entry.owner, owner)
    ) {
      throw new PluginHostRpcError(
        "ui_workspace_tile_ref_denied",
        "workspace tile reference is not registered for this owner",
      );
    }
    return {
      id: entry.id,
      owner: entry.owner,
      contribution: structuredCloneContribution(entry.contribution),
      capabilities: [...entry.capabilities],
      ...(entry.display ? { display: { ...entry.display } } : {}),
    };
  }

  hasCommand(owner: PluginHostRpcHandlerOwnerDescriptor, localId: string): boolean {
    const entry = this.entries.get(contributionKey(owner, localId));
    return (
      entry?.active === true &&
      entry.contribution.surface === "command" &&
      sameOwner(entry.owner, owner)
    );
  }

  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private notify(): void {
    for (const listener of this.listeners) listener();
  }
}

export function createPluginUiContributionRegistry(): PluginUiContributionRegistry {
  return new PluginUiContributionRegistry();
}

const defaultPluginUiContributionRegistry = createPluginUiContributionRegistry();
let activeModalId: string | null = null;
const modalListeners = new Set<() => void>();
const modalIframeSurfaces = new Map<string, PluginUiIframeSurface>();

export function getDefaultPluginUiContributionRegistry(): PluginUiContributionRegistry {
  return defaultPluginUiContributionRegistry;
}

export function pluginUiEntryMatchesResource(
  entry: PluginUiRegistryEntry,
  context: PluginUiResourceContext,
): boolean {
  if (!context.workspaceId || entry.owner.workspaceId !== context.workspaceId) return false;
  return evaluatePluginUiPredicate(entry.contribution.when, context);
}

export function pluginUiEntryCommandEnabled(
  entry: PluginUiRegistryEntry,
  context: PluginUiResourceContext,
  registry?: PluginUiContributionRegistry,
): boolean {
  if (!pluginUiEntryMatchesResource(entry, context)) return false;
  const contribution = entry.contribution;
  if (
    (contribution.surface === "command" || contribution.surface === "menu_item") &&
    contribution.enablement !== undefined
  ) {
    if (!evaluatePluginUiPredicate(contribution.enablement, context)) return false;
  }
  const commandRef = pluginUiPrimaryCommandRef(contribution);
  if (contribution.surface !== "command" && commandRef && registry) {
    const command = registry.resolveCommandRef(entry.owner, commandRef);
    return pluginUiEntryCommandEnabled(command, context, registry);
  }
  return true;
}

function pluginUiPrimaryCommandRef(contribution: PluginUiContribution): PluginUiCommandRef | null {
  if ("command_ref" in contribution) return contribution.command_ref;
  if ("source_command_ref" in contribution) return contribution.source_command_ref;
  if ("trigger_command_ref" in contribution) return contribution.trigger_command_ref;
  return null;
}

export interface PluginUiCommandResourcePayload {
  resource: {
    kind: PluginUiResourceContext["resourceKind"];
    workspace_id?: string;
    document_id?: string;
    folder_id?: string;
  };
}

export function pluginUiCommandResourcePayload(
  entry: PluginUiRegistryEntry,
  context: PluginUiResourceContext,
  registry: PluginUiContributionRegistry,
): PluginUiCommandResourcePayload | null {
  if (!pluginUiEntryCommandEnabled(entry, context, registry)) return null;

  const resource = pluginUiInvocationResource(context);
  if (!resource) return null;

  return { resource };
}

export function pluginUiCommandId(entry: PluginUiRegistryEntry, ref: PluginUiCommandRef): string {
  return pluginContributionId(entry.owner, ref.local_id);
}

export function pluginUiOwnerSurfaceId(
  owner: PluginHostRpcHandlerOwnerDescriptor,
  localId: string,
): string {
  return pluginContributionId(owner, localId);
}

export function evaluatePluginUiPredicate(
  predicate: PluginUiResourcePredicate | undefined,
  context: PluginUiResourceContext,
): boolean {
  if (!predicate || predicate.kind === "always") return true;

  switch (predicate.kind) {
    case "resource_kind":
      return context.resourceKind === predicate.is;
    case "document_open":
      return context.documentOpen === true;
    case "selection_present":
      return context.selectionPresent === true;
    case "capability":
      return context.capabilities?.includes(predicate.has) === true;
    case "all":
      return predicate.of.every((item) => evaluatePluginUiPredicate(item, context));
    case "any":
      return predicate.of.some((item) => evaluatePluginUiPredicate(item, context));
    case "not":
      return !evaluatePluginUiPredicate(predicate.of, context);
  }
}

function pluginUiInvocationResource(
  context: PluginUiResourceContext,
): PluginUiCommandResourcePayload["resource"] | null {
  if (context.resourceKind === "document") {
    if (!context.documentId) return null;
    return {
      kind: "document",
      ...(context.workspaceId ? { workspace_id: context.workspaceId } : {}),
      document_id: context.documentId,
    };
  }

  if (context.resourceKind === "folder") {
    if (!context.folderId) return null;
    return {
      kind: "folder",
      ...(context.workspaceId ? { workspace_id: context.workspaceId } : {}),
      folder_id: context.folderId,
    };
  }

  if (!context.workspaceId) return null;
  return { kind: "workspace", workspace_id: context.workspaceId };
}

export function openPluginUiModal(id: string): void {
  activeModalId = id;
  notifyModalListeners();
}

export function closePluginUiModal(): void {
  activeModalId = null;
  notifyModalListeners();
}

export function getActivePluginUiModalId(): string | null {
  return activeModalId;
}

export function subscribePluginUiModal(listener: () => void): () => void {
  modalListeners.add(listener);
  return () => {
    modalListeners.delete(listener);
  };
}

export function setPluginUiModalIframeSurface(
  owner: PluginHostRpcHandlerOwnerDescriptor,
  surface: PluginUiIframeSurface,
): () => void {
  const key = ownerKey(owner);
  modalIframeSurfaces.set(key, surface);
  return () => {
    if (modalIframeSurfaces.get(key) === surface) modalIframeSurfaces.delete(key);
  };
}

export function getPluginUiModalIframeSurface(
  owner: PluginHostRpcHandlerOwnerDescriptor,
): PluginUiIframeSurface | null {
  return modalIframeSurfaces.get(ownerKey(owner)) ?? null;
}

export { registerPluginHostUiHandlers, invokePluginUiCommand } from "./host-ui-handlers";

function notifyModalListeners(): void {
  for (const listener of modalListeners) listener();
}

function compareEntries(first: PluginUiRegistryEntry, second: PluginUiRegistryEntry): number {
  return (
    orderFor(first.contribution) - orderFor(second.contribution) ||
    first.contribution.surface.localeCompare(second.contribution.surface) ||
    first.id.localeCompare(second.id)
  );
}

function orderFor(contribution: PluginUiContribution): number {
  return contribution.order ?? 0;
}

function structuredCloneContribution<T extends PluginUiContribution>(contribution: T): T {
  return JSON.parse(JSON.stringify(contribution)) as T;
}
