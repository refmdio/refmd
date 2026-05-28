import { PluginHostRpcError } from "../../lib/host-rpc/host-rpc";
import {
  pluginPayloadByteLength,
  type PluginDocumentScope,
} from "../../lib/capability/capability-enforcement";
import type {
  PluginUiCommandContribution,
  PluginUiCommandRef,
  PluginUiAuxiliaryPaneAction,
  PluginUiAuxiliaryPaneContribution,
  PluginUiContribution,
  PluginUiDeclarativeModalContribution,
  PluginUiDocumentTreeActionContribution,
  PluginUiDocumentTreeBadgeContribution,
  PluginUiDocumentTreeDecorationContribution,
  PluginUiDocumentTreeVirtualSectionContribution,
  PluginUiFormField,
  PluginUiFormSection,
  PluginUiMenuItemContribution,
  PluginUiResourcePredicate,
  PluginUiSettingsDeclarativeContribution,
  PluginUiSettingsIframeContribution,
  PluginUiSidebarPanelContribution,
  PluginUiStatusContribution,
  PluginUiSurface,
  PluginUiWorkspaceTileActionContribution,
  PluginUiWorkspaceTileContribution,
  PluginUiWorkspaceTileRef,
  PluginUiWorkspaceDocumentQueryInvocation,
} from "./host-ui";

const LOCAL_ID_PATTERN = /^[a-z][a-z0-9._:-]{0,95}$/;
const ICON_PATTERN = /^[a-z][a-z0-9-]{0,63}$/;
const TEXT_FIELD_PATTERN = /^[a-zA-Z0-9 _.,:;!?@/#()[\]-]{1,160}$/;
const FIELD_NAME_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const MAX_TEXT_BYTES = 512;
const MAX_STATUS_TEXT_BYTES = 160;
const MAX_FORM_FIELDS = 50;
const MAX_FORM_OPTIONS = 50;
const MAX_AUXILIARY_PANE_ACTIONS = 8;
const MAX_PREDICATE_DEPTH = 5;
const MAX_PREDICATE_NODES = 50;
const MAX_WORKSPACE_DOCUMENT_QUERY_REASON_BYTES = 160;
const DOCUMENT_QUERY_REASON_MARKUP_PATTERN = /[<>[\]()#*_`]/;
const PROTECTED_LABEL_WORDS = [
  "security",
  "encryption",
  "permission",
  "credential",
  "approval",
  "verified",
  "sync secure",
  "network trusted",
];
const DOCUMENT_QUERY_REASON_PROTECTED_WORDS = [
  "security",
  "sync",
  "encryption",
  "credential",
  "approval",
];

export const UI_OPERATION_SURFACES: Record<string, PluginUiSurface> = {
  "ui.command.register": "command",
  "ui.status.register_item": "status",
  "ui.sidebar.register_panel": "sidebar_panel",
  "ui.workspace.register_tile": "workspace_tile",
  "ui.workspace.register_tile_action": "workspace_tile_action",
  "ui.auxiliary.register_pane": "auxiliary_pane",
  "ui.document_tree.register_action": "document_tree_action",
  "ui.document_tree.register_badge": "document_tree_badge",
  "ui.document_tree.register_decoration": "document_tree_decoration",
  "ui.document_tree.register_virtual_section": "document_tree_virtual_section",
  "ui.settings.register_iframe": "settings_iframe",
  "ui.settings.register_declarative": "settings_declarative",
  "ui.menu.register_item": "menu_item",
  "ui.modal.register_declarative": "declarative_modal",
};

const COMMAND_REF_SURFACES = new Set<PluginUiSurface>([
  "auxiliary_pane",
  "document_tree_action",
  "document_tree_virtual_section",
  "settings_declarative",
  "menu_item",
  "declarative_modal",
]);

export const MAX_WORKSPACE_DOCUMENT_QUERY_DOCUMENTS = 500;
export const MAX_WORKSPACE_DOCUMENT_QUERY_BYTES = 1024 * 1024;

export function validatePluginUiContribution(
  contribution: PluginUiContribution,
): PluginUiContribution {
  assertSafePlainObject(contribution);
  assertForbiddenHostObjects(contribution);
  assertLocalId(contribution.local_id);
  assertSurface(contribution.surface);
  assertOptionalLabel(contribution.label);
  assertOptionalIcon(contribution.icon);
  assertOptionalOrder(contribution.order);
  if (contribution.when !== undefined) validatePredicate(contribution.when);

  switch (contribution.surface) {
    case "command":
      return validateCommand(contribution);
    case "status":
      return validateStatus(contribution);
    case "sidebar_panel":
      return validateSidebarPanel(contribution);
    case "workspace_tile":
      return validateWorkspaceTile(contribution);
    case "workspace_tile_action":
      return validateWorkspaceTileAction(contribution);
    case "auxiliary_pane":
      return validateAuxiliaryPane(contribution);
    case "document_tree_action":
      return validateDocumentTreeAction(contribution);
    case "document_tree_badge":
      return validateDocumentTreeBadge(contribution);
    case "document_tree_decoration":
      return validateDocumentTreeDecoration(contribution);
    case "document_tree_virtual_section":
      return validateDocumentTreeVirtualSection(contribution);
    case "settings_iframe":
      return validateSettingsIframe(contribution);
    case "settings_declarative":
      return validateSettingsDeclarative(contribution);
    case "menu_item":
      return validateMenuItem(contribution);
    case "declarative_modal":
      return validateModal(contribution);
  }
}

function validateCommand(contribution: PluginUiCommandContribution): PluginUiCommandContribution {
  assertDisplayText(contribution.title, "title");
  if (contribution.category !== undefined) assertDisplayText(contribution.category, "category");
  if (contribution.enablement !== undefined) validatePredicate(contribution.enablement);
  if (contribution.plaintext_request !== undefined && contribution.document_query !== undefined) {
    throw new PluginHostRpcError(
      "ui_schema_invalid",
      "command plaintext request and document query cannot be combined",
    );
  }
  if (
    contribution.plaintext_request !== undefined &&
    contribution.plaintext_request !== "none" &&
    contribution.plaintext_request !== "active_document" &&
    contribution.plaintext_request !== "selection" &&
    contribution.plaintext_request !== "editor_context"
  ) {
    throw new PluginHostRpcError("ui_schema_invalid", "command plaintext request is invalid");
  }
  if (contribution.document_query !== undefined)
    validateWorkspaceDocumentQuery(contribution.document_query);
  return structuredCloneContribution(contribution);
}

function validateWorkspaceDocumentQuery(query: PluginUiWorkspaceDocumentQueryInvocation): void {
  if (!isRecord(query) || query.scope !== "workspace") {
    throw new PluginHostRpcError("ui_schema_invalid", "document query scope is invalid");
  }
  if (
    !Number.isSafeInteger(query.max_documents) ||
    query.max_documents <= 0 ||
    query.max_documents > MAX_WORKSPACE_DOCUMENT_QUERY_DOCUMENTS
  ) {
    throw new PluginHostRpcError("ui_schema_invalid", "document query limit is invalid");
  }
  if (
    !Number.isSafeInteger(query.max_bytes) ||
    query.max_bytes <= 0 ||
    query.max_bytes > MAX_WORKSPACE_DOCUMENT_QUERY_BYTES
  ) {
    throw new PluginHostRpcError("ui_schema_invalid", "document query byte limit is invalid");
  }
  if (query.reason !== undefined) validateDocumentQueryReason(query.reason);
}

export function validateDocumentQueryRegistrationAuthority(
  contribution: PluginUiContribution,
  capabilities: readonly string[],
  documentScope: PluginDocumentScope,
): void {
  const documentQuery =
    contribution.surface === "command" || contribution.surface === "workspace_tile_action"
      ? contribution.document_query
      : undefined;
  if (documentQuery === undefined) return;
  if (!capabilities.includes("document:read:workspace")) {
    throw new PluginHostRpcError(
      "permission_denied",
      "workspace document query requires document:read:workspace",
    );
  }
  if (documentScope.workspaceReadAllowed !== true) {
    throw new PluginHostRpcError(
      "document_scope_denied",
      "workspace document query requires workspace document scope",
    );
  }
}

function validateDocumentQueryReason(reason: unknown): void {
  const text = requiredString(
    reason,
    "document query reason",
    MAX_WORKSPACE_DOCUMENT_QUERY_REASON_BYTES,
  );
  if (hasControlCharacter(text)) {
    throw new PluginHostRpcError(
      "ui_schema_invalid",
      "document query reason contains unsupported characters",
    );
  }
  if (DOCUMENT_QUERY_REASON_MARKUP_PATTERN.test(text)) {
    throw new PluginHostRpcError(
      "ui_schema_invalid",
      "document query reason cannot contain markup",
    );
  }
  const normalized = text.toLowerCase();
  if (DOCUMENT_QUERY_REASON_PROTECTED_WORDS.some((word) => normalized.includes(word))) {
    throw new PluginHostRpcError(
      "ui_protected_label_denied",
      "document query reason uses protected wording",
    );
  }
}

function validateStatus(contribution: PluginUiStatusContribution): PluginUiStatusContribution {
  if (contribution.zone !== "normal") {
    throw new PluginHostRpcError("ui_schema_invalid", "status zone is not supported");
  }
  assertOptionalPlaintextRequest(contribution.plaintext_request);
  if (!isRecord(contribution.value)) {
    throw new PluginHostRpcError("ui_schema_invalid", "status value must be an object");
  }
  if (contribution.value.kind === "text") {
    if (contribution.plaintext_request === "active_document") {
      if (contribution.value.text !== undefined) {
        throw new PluginHostRpcError(
          "ui_plaintext_display_denied",
          "contextual status text must be produced by Host refresh",
        );
      }
    } else {
      validatePluginUiStatusText(contribution.value.text);
    }
  } else if (contribution.value.kind === "iframe") {
    if (contribution.plaintext_request === "active_document") {
      throw new PluginHostRpcError(
        "ui_schema_invalid",
        "status plaintext request requires a text value",
      );
    }
    assertLocalId(contribution.value.panel_id);
  } else {
    throw new PluginHostRpcError("ui_schema_invalid", "status value kind is not supported");
  }
  if (
    contribution.max_width !== undefined &&
    (!Number.isSafeInteger(contribution.max_width) ||
      contribution.max_width < 24 ||
      contribution.max_width > 640)
  ) {
    throw new PluginHostRpcError("ui_schema_invalid", "status width is outside supported bounds");
  }
  return structuredCloneContribution(contribution);
}

function validateSidebarPanel(
  contribution: PluginUiSidebarPanelContribution,
): PluginUiSidebarPanelContribution {
  assertLocalId(contribution.panel_id);
  assertDisplayText(contribution.title, "title");
  if (
    !Array.isArray(contribution.allowed_locations) ||
    contribution.allowed_locations.length < 1 ||
    contribution.allowed_locations.length > 2 ||
    contribution.allowed_locations.some((location) => location !== "left" && location !== "right")
  ) {
    throw new PluginHostRpcError("ui_schema_invalid", "sidebar locations are invalid");
  }
  if (
    contribution.default_width !== undefined &&
    (!Number.isSafeInteger(contribution.default_width) ||
      contribution.default_width < 180 ||
      contribution.default_width > 720)
  ) {
    throw new PluginHostRpcError("ui_schema_invalid", "sidebar width is outside supported bounds");
  }
  return structuredCloneContribution(contribution);
}

function validateWorkspaceTile(
  contribution: PluginUiWorkspaceTileContribution,
): PluginUiWorkspaceTileContribution {
  assertLocalId(contribution.tile_id);
  assertDisplayText(contribution.title, "title");
  if (contribution.scope !== "workspace" && contribution.scope !== "document") {
    throw new PluginHostRpcError("ui_schema_invalid", "workspace tile scope is invalid");
  }
  if (
    contribution.preferred_open !== undefined &&
    contribution.preferred_open !== "manual" &&
    contribution.preferred_open !== "document_menu" &&
    contribution.preferred_open !== "command"
  ) {
    throw new PluginHostRpcError("ui_schema_invalid", "workspace tile open mode is invalid");
  }
  if (
    (contribution as { document_query?: unknown }).document_query !== undefined ||
    (contribution as { documentQuery?: unknown }).documentQuery !== undefined
  ) {
    throw new PluginHostRpcError(
      "ui_schema_invalid",
      "workspace tile placement cannot declare document query",
    );
  }
  return structuredCloneContribution(contribution);
}

function validateWorkspaceTileAction(
  contribution: PluginUiWorkspaceTileActionContribution,
): PluginUiWorkspaceTileActionContribution {
  validateWorkspaceTileRef(contribution.tile_ref);
  assertLocalId(contribution.action_id);
  assertDisplayText(contribution.title, "title");
  if (
    contribution.placement !== "tile_toolbar" &&
    contribution.placement !== "tile_menu" &&
    contribution.placement !== "refresh"
  ) {
    throw new PluginHostRpcError("ui_schema_invalid", "workspace tile action placement is invalid");
  }
  if (contribution.document_query !== undefined)
    validateWorkspaceDocumentQuery(contribution.document_query);
  return structuredCloneContribution(contribution);
}

function validateWorkspaceTileRef(ref: PluginUiWorkspaceTileRef): void {
  if (!isRecord(ref) || ref.kind !== "local_tile") {
    throw new PluginHostRpcError("ui_schema_invalid", "workspace tile action ref is invalid");
  }
  assertLocalId(ref.local_id);
}

function validateAuxiliaryPane(
  contribution: PluginUiAuxiliaryPaneContribution,
): PluginUiAuxiliaryPaneContribution {
  assertLocalId(contribution.pane_id);
  assertDisplayText(contribution.title, "title");
  const validLocations = new Set(["left", "right", "document_left", "document_right"]);
  if (
    !Array.isArray(contribution.allowed_locations) ||
    contribution.allowed_locations.length < 1 ||
    contribution.allowed_locations.length > validLocations.size ||
    contribution.allowed_locations.some((location) => !validLocations.has(location))
  ) {
    throw new PluginHostRpcError("ui_schema_invalid", "auxiliary pane locations are invalid");
  }
  if (
    contribution.default_width !== undefined &&
    (!Number.isSafeInteger(contribution.default_width) ||
      contribution.default_width < 180 ||
      contribution.default_width > 720)
  ) {
    throw new PluginHostRpcError(
      "ui_schema_invalid",
      "auxiliary pane width is outside supported bounds",
    );
  }
  if (contribution.actions !== undefined) {
    if (
      !Array.isArray(contribution.actions) ||
      contribution.actions.length > MAX_AUXILIARY_PANE_ACTIONS
    ) {
      throw new PluginHostRpcError("ui_schema_invalid", "auxiliary pane actions are invalid");
    }
    const actionIds = new Set<string>();
    for (const action of contribution.actions) {
      validateAuxiliaryPaneAction(action);
      if (actionIds.has(action.action_id)) {
        throw new PluginHostRpcError(
          "ui_schema_invalid",
          "auxiliary pane action ids must be unique",
        );
      }
      actionIds.add(action.action_id);
    }
  }
  return structuredCloneContribution(contribution);
}

function validateAuxiliaryPaneAction(action: PluginUiAuxiliaryPaneAction): void {
  if (!isRecord(action)) {
    throw new PluginHostRpcError("ui_schema_invalid", "auxiliary pane action must be an object");
  }
  assertLocalId(action.action_id);
  assertDisplayText(action.title, "title");
  assertOptionalIcon(action.icon);
  if (action.order !== undefined && !Number.isSafeInteger(action.order)) {
    throw new PluginHostRpcError("ui_schema_invalid", "auxiliary pane action order is invalid");
  }
  validateCommandRef(action.command_ref);
}

function validateDocumentTreeAction(
  contribution: PluginUiDocumentTreeActionContribution,
): PluginUiDocumentTreeActionContribution {
  if (
    contribution.placement !== "row_context_menu" &&
    contribution.placement !== "row_inline_action"
  ) {
    throw new PluginHostRpcError("ui_schema_invalid", "document tree action placement is invalid");
  }
  assertDisplayText(contribution.title, "title");
  validateCommandRef(contribution.command_ref);
  return structuredCloneContribution(contribution);
}

function validateDocumentTreeBadge(
  contribution: PluginUiDocumentTreeBadgeContribution,
): PluginUiDocumentTreeBadgeContribution {
  if (contribution.placement !== "row_trailing_badge") {
    throw new PluginHostRpcError("ui_schema_invalid", "document tree badge placement is invalid");
  }
  assertOptionalPlaintextRequest(contribution.plaintext_request);
  if (contribution.text !== undefined) {
    if (contribution.plaintext_request === "active_document") {
      throw new PluginHostRpcError(
        "ui_plaintext_display_denied",
        "contextual document tree badge text must be produced by Host refresh",
      );
    }
    validatePluginUiStatusText(contribution.text);
  }
  assertOptionalTone(contribution.tone);
  return structuredCloneContribution(contribution);
}

function validateDocumentTreeDecoration(
  contribution: PluginUiDocumentTreeDecorationContribution,
): PluginUiDocumentTreeDecorationContribution {
  if (contribution.placement !== "row_prefix" && contribution.placement !== "row_suffix") {
    throw new PluginHostRpcError(
      "ui_schema_invalid",
      "document tree decoration placement is invalid",
    );
  }
  assertOptionalTone(contribution.tone);
  return structuredCloneContribution(contribution);
}

function validateDocumentTreeVirtualSection(
  contribution: PluginUiDocumentTreeVirtualSectionContribution,
): PluginUiDocumentTreeVirtualSectionContribution {
  if (contribution.placement !== "before_tree" && contribution.placement !== "after_tree") {
    throw new PluginHostRpcError(
      "ui_schema_invalid",
      "document tree virtual section placement is invalid",
    );
  }
  assertDisplayText(contribution.title, "title");
  validateCommandRef(contribution.source_command_ref);
  return structuredCloneContribution(contribution);
}

function validateSettingsIframe(
  contribution: PluginUiSettingsIframeContribution,
): PluginUiSettingsIframeContribution {
  assertLocalId(contribution.settings_id);
  assertDisplayText(contribution.title, "title");
  if (contribution.placement !== "plugin_settings") {
    throw new PluginHostRpcError("ui_schema_invalid", "settings placement is invalid");
  }
  assertLocalId(contribution.iframe_panel_id);
  return structuredCloneContribution(contribution);
}

function validateSettingsDeclarative(
  contribution: PluginUiSettingsDeclarativeContribution,
): PluginUiSettingsDeclarativeContribution {
  assertLocalId(contribution.settings_id);
  assertDisplayText(contribution.title, "title");
  if (contribution.placement !== "plugin_settings") {
    throw new PluginHostRpcError("ui_schema_invalid", "settings placement is invalid");
  }
  if (!Array.isArray(contribution.sections) || contribution.sections.length < 1) {
    throw new PluginHostRpcError("ui_schema_invalid", "settings sections are required");
  }
  for (const section of contribution.sections) validateFormSection(section);
  if (contribution.submit_command_ref !== undefined)
    validateCommandRef(contribution.submit_command_ref);
  return structuredCloneContribution(contribution);
}

function validateMenuItem(
  contribution: PluginUiMenuItemContribution,
): PluginUiMenuItemContribution {
  if (
    contribution.placement !== "command_palette" &&
    contribution.placement !== "editor_context_menu" &&
    contribution.placement !== "document_tree_context_menu" &&
    contribution.placement !== "document_tab_menu"
  ) {
    throw new PluginHostRpcError("ui_schema_invalid", "menu placement is invalid");
  }
  assertDisplayText(contribution.title, "title");
  validateCommandRef(contribution.command_ref);
  if (contribution.enablement !== undefined) validatePredicate(contribution.enablement);
  return structuredCloneContribution(contribution);
}

function validateModal(
  contribution: PluginUiDeclarativeModalContribution,
): PluginUiDeclarativeModalContribution {
  assertLocalId(contribution.modal_id);
  assertDisplayText(contribution.title, "title");
  validateCommandRef(contribution.trigger_command_ref);
  if (!isRecord(contribution.body)) {
    throw new PluginHostRpcError("ui_schema_invalid", "modal body must be an object");
  }
  if (contribution.body.kind === "schema_form") {
    if (!Array.isArray(contribution.body.fields)) {
      throw new PluginHostRpcError("ui_schema_invalid", "modal form fields are required");
    }
    validateFormFields(contribution.body.fields);
  } else if (contribution.body.kind === "iframe") {
    assertLocalId(contribution.body.iframe_panel_id);
  } else {
    throw new PluginHostRpcError("ui_schema_invalid", "modal body kind is not supported");
  }
  if (contribution.submit_command_ref !== undefined)
    validateCommandRef(contribution.submit_command_ref);
  return structuredCloneContribution(contribution);
}

function validateFormSection(section: PluginUiFormSection): void {
  if (!isRecord(section)) {
    throw new PluginHostRpcError("ui_schema_invalid", "settings section must be an object");
  }
  if (section.title !== undefined) assertDisplayText(section.title, "title");
  if (!Array.isArray(section.fields)) {
    throw new PluginHostRpcError("ui_schema_invalid", "settings fields are required");
  }
  validateFormFields(section.fields);
}

function validateFormFields(fields: PluginUiFormField[]): void {
  if (fields.length < 1 || fields.length > MAX_FORM_FIELDS) {
    throw new PluginHostRpcError(
      "ui_schema_invalid",
      "form field count is outside supported bounds",
    );
  }
  const names = new Set<string>();
  for (const field of fields) {
    if (!isRecord(field)) {
      throw new PluginHostRpcError("ui_schema_invalid", "form field must be an object");
    }
    if (!FIELD_NAME_PATTERN.test(String(field.name))) {
      throw new PluginHostRpcError("ui_schema_invalid", "form field name is invalid");
    }
    if (names.has(field.name)) {
      throw new PluginHostRpcError("ui_schema_invalid", "form field names must be unique");
    }
    names.add(field.name);
    assertDisplayText(field.label, "label");
    if (field.kind === "text" || field.kind === "textarea") {
      if (
        !Number.isSafeInteger(field.max_length) ||
        field.max_length < 1 ||
        field.max_length > 10_000
      ) {
        throw new PluginHostRpcError("ui_schema_invalid", "form field length is invalid");
      }
    } else if (field.kind === "checkbox") {
      // No additional payload.
    } else if (field.kind === "select") {
      if (
        !Array.isArray(field.options) ||
        field.options.length < 1 ||
        field.options.length > MAX_FORM_OPTIONS
      ) {
        throw new PluginHostRpcError("ui_schema_invalid", "select options are invalid");
      }
      const optionValues = new Set<string>();
      for (const option of field.options) {
        if (!isRecord(option)) {
          throw new PluginHostRpcError("ui_schema_invalid", "select option must be an object");
        }
        const value = requiredString(option.value, "value", MAX_TEXT_BYTES);
        if (optionValues.has(value)) {
          throw new PluginHostRpcError("ui_schema_invalid", "select option values must be unique");
        }
        optionValues.add(value);
        assertDisplayText(option.label, "label");
      }
    } else {
      throw new PluginHostRpcError("ui_schema_invalid", "form field kind is not supported");
    }
  }
}

export function validateCommandRefs(
  contribution: PluginUiContribution,
  hasCommand: (localId: string) => boolean,
): void {
  if (!COMMAND_REF_SURFACES.has(contribution.surface)) return;
  const refs = commandRefsForContribution(contribution);
  for (const ref of refs) {
    validateCommandRef(ref);
    if (!hasCommand(ref.local_id)) {
      throw new PluginHostRpcError(
        "ui_command_ref_denied",
        "command reference must target a registered local command",
      );
    }
  }
}

function commandRefsForContribution(contribution: PluginUiContribution): PluginUiCommandRef[] {
  switch (contribution.surface) {
    case "auxiliary_pane":
      return contribution.actions?.map((action) => action.command_ref) ?? [];
    case "document_tree_action":
      return [contribution.command_ref];
    case "document_tree_virtual_section":
      return [contribution.source_command_ref];
    case "settings_declarative":
      return contribution.submit_command_ref ? [contribution.submit_command_ref] : [];
    case "menu_item":
      return [contribution.command_ref];
    case "declarative_modal":
      return [
        contribution.trigger_command_ref,
        ...(contribution.submit_command_ref ? [contribution.submit_command_ref] : []),
      ];
    default:
      return [];
  }
}

export function validateCommandRef(ref: PluginUiCommandRef): void {
  if (!isRecord(ref) || ref.kind !== "local_command") {
    throw new PluginHostRpcError("ui_command_ref_invalid", "command reference is invalid");
  }
  assertLocalId(ref.local_id);
}

function validatePredicate(predicate: PluginUiResourcePredicate): void {
  const result = inspectPredicate(predicate, 0);
  if (result.nodes > MAX_PREDICATE_NODES) {
    throw new PluginHostRpcError("ui_predicate_invalid", "resource predicate is too large");
  }
}

function inspectPredicate(predicate: unknown, depth: number): { nodes: number } {
  if (depth > MAX_PREDICATE_DEPTH || !isRecord(predicate)) {
    throw new PluginHostRpcError("ui_predicate_invalid", "resource predicate is invalid");
  }
  switch (predicate.kind) {
    case "always":
    case "document_open":
    case "selection_present":
      return { nodes: 1 };
    case "resource_kind":
      if (
        predicate.is !== "document" &&
        predicate.is !== "folder" &&
        predicate.is !== "workspace"
      ) {
        throw new PluginHostRpcError("ui_predicate_invalid", "resource kind predicate is invalid");
      }
      return { nodes: 1 };
    case "capability":
      requiredString(predicate.has, "has", MAX_TEXT_BYTES);
      return { nodes: 1 };
    case "all":
    case "any":
      if (!Array.isArray(predicate.of) || predicate.of.length < 1 || predicate.of.length > 10) {
        throw new PluginHostRpcError("ui_predicate_invalid", "resource predicate group is invalid");
      }
      return {
        nodes:
          1 + predicate.of.reduce((sum, item) => sum + inspectPredicate(item, depth + 1).nodes, 0),
      };
    case "not":
      return { nodes: 1 + inspectPredicate(predicate.of, depth + 1).nodes };
    default:
      throw new PluginHostRpcError("ui_predicate_invalid", "resource predicate kind is invalid");
  }
}

function assertSurface(surface: unknown): asserts surface is PluginUiSurface {
  if (!Object.values(UI_OPERATION_SURFACES).includes(surface as PluginUiSurface)) {
    throw new PluginHostRpcError("ui_schema_invalid", "UI contribution surface is invalid");
  }
}

export function assertLocalId(value: unknown): asserts value is string {
  if (
    typeof value !== "string" ||
    !LOCAL_ID_PATTERN.test(value) ||
    value.startsWith("builtin:") ||
    value.startsWith("plugin:")
  ) {
    throw new PluginHostRpcError("ui_local_id_invalid", "UI contribution id is invalid");
  }
}

function assertOptionalLabel(value: unknown): void {
  if (value === undefined) return;
  assertDisplayText(value, "label");
}

function assertOptionalIcon(value: unknown): void {
  if (value === undefined) return;
  if (typeof value !== "string" || !ICON_PATTERN.test(value)) {
    throw new PluginHostRpcError("ui_schema_invalid", "icon token is invalid");
  }
}

function assertOptionalOrder(value: unknown): void {
  if (value === undefined) return;
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < -10_000 ||
    value > 10_000
  ) {
    throw new PluginHostRpcError("ui_schema_invalid", "order is outside supported bounds");
  }
}

function assertOptionalTone(value: unknown): void {
  if (value === undefined) return;
  if (value !== "neutral" && value !== "info" && value !== "warning") {
    throw new PluginHostRpcError("ui_schema_invalid", "tone is not supported");
  }
}

function assertOptionalPlaintextRequest(value: unknown): void {
  if (value === undefined || value === "none" || value === "active_document") return;
  throw new PluginHostRpcError("ui_schema_invalid", "plaintext request is not supported");
}

export function validatePluginUiStatusText(value: unknown, field = "text"): string {
  const text = requiredString(value, field, MAX_STATUS_TEXT_BYTES);
  assertNotProtectedLabel(text);
  return text;
}

function assertDisplayText(value: unknown, field: string): void {
  const text = requiredString(value, field, MAX_TEXT_BYTES);
  if (hasControlCharacter(text)) {
    throw new PluginHostRpcError("ui_schema_invalid", `${field} contains unsupported characters`);
  }
  if (!TEXT_FIELD_PATTERN.test(text)) {
    throw new PluginHostRpcError("ui_schema_invalid", `${field} contains unsupported characters`);
  }
  assertNotProtectedLabel(text);
}

function assertNotProtectedLabel(value: string): void {
  const normalized = value.toLowerCase();
  if (PROTECTED_LABEL_WORDS.some((word) => normalized.includes(word))) {
    throw new PluginHostRpcError("ui_protected_label_denied", "UI label uses protected wording");
  }
}

function hasControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 32 || code === 127) return true;
  }
  return false;
}

function requiredString(value: unknown, field: string, maxBytes: number): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new PluginHostRpcError("ui_schema_invalid", `${field} must be a non-empty string`);
  }
  if (pluginPayloadByteLength(value) > maxBytes) {
    throw new PluginHostRpcError("ui_schema_invalid", `${field} exceeds supported length`);
  }
  return value;
}

function assertSafePlainObject(value: unknown): void {
  if (!isRecord(value)) {
    throw new PluginHostRpcError("ui_schema_invalid", "UI contribution must be an object");
  }
  const proto = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    throw new PluginHostRpcError("ui_schema_invalid", "UI contribution must be plain data");
  }
}

function assertForbiddenHostObjects(value: unknown, depth = 0): void {
  if (depth > 20 || value === null || typeof value !== "object") return;
  if (typeof HTMLElement !== "undefined" && value instanceof HTMLElement) {
    throw new PluginHostRpcError("ui_schema_forbidden", "UI contribution cannot carry DOM nodes");
  }
  if (typeof Node !== "undefined" && value instanceof Node) {
    throw new PluginHostRpcError("ui_schema_forbidden", "UI contribution cannot carry DOM nodes");
  }
  for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
    if (typeof child === "function") {
      throw new PluginHostRpcError("ui_schema_forbidden", "UI contribution cannot carry functions");
    }
    if (
      key === "html" ||
      key === "raw_html" ||
      key === "svg" ||
      key === "element" ||
      key === "containerEl" ||
      key === "component" ||
      key === "owner" ||
      key === "store" ||
      key === "signal" ||
      key === "view" ||
      key === "state" ||
      key === "extension" ||
      key === "plugin"
    ) {
      throw new PluginHostRpcError(
        "ui_schema_forbidden",
        "UI contribution cannot carry host objects or raw markup",
      );
    }
    assertForbiddenHostObjects(child, depth + 1);
  }
}

function structuredCloneContribution<T extends PluginUiContribution>(contribution: T): T {
  return JSON.parse(JSON.stringify(contribution)) as T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
