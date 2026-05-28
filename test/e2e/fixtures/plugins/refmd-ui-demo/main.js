const root = document.createElement("main");
root.setAttribute("aria-label", "RefMD UI demo plugin");
root.innerHTML = `
  <h1>RefMD UI Demo Plugin</h1>
  <p data-role="status">Waiting for UI runtime</p>
`;
document.body.append(root);

const statusEl = root.querySelector('[data-role="status"]');
let statusTextHandle = null;

function setStatus(value) {
  if (statusEl) statusEl.textContent = value;
}

async function setHostStatus(runtime, value) {
  setStatus(value);
  if (statusTextHandle) {
    await statusTextHandle.dispose().catch(() => undefined);
  }
  statusTextHandle = await runtime.ui.status.registerItem({
    localId: "status-text",
    label: "UI Demo Status",
    zone: "normal",
    value: { kind: "text", text: value },
    maxWidth: 360,
  });
}

function commandLocalId(event) {
  const payload = event.payload && typeof event.payload === "object" ? event.payload : {};
  return typeof payload.local_id === "string" ? payload.local_id : "unknown";
}

function commandResourceKind(event) {
  const payload = event.payload && typeof event.payload === "object" ? event.payload : {};
  const nested = payload.payload && typeof payload.payload === "object" ? payload.payload : {};
  const resource = nested.resource && typeof nested.resource === "object" ? nested.resource : {};
  return typeof resource.kind === "string" ? resource.kind : "workspace";
}

function settingsValues(event) {
  const payload = event.payload && typeof event.payload === "object" ? event.payload : {};
  const nested = payload.payload && typeof payload.payload === "object" ? payload.payload : {};
  return nested.values && typeof nested.values === "object" ? nested.values : {};
}

async function registerRuntime(runtime) {
  if (runtime.runtime?.context?.frame_scope === "secondary") {
    setStatus("UI Demo Surface Frame Ready");
    return;
  }

  const triggerCommand = { kind: "local_command", local_id: "trigger.modal" };
  const settingsCommand = { kind: "local_command", local_id: "settings.submit" };

  await runtime.commands.register({
    localId: "trigger.modal",
    title: "UI Demo Trigger",
    plaintextRequest: "none",
  });
  await runtime.commands.register({
    localId: "settings.submit",
    title: "UI Demo Settings Submit",
    plaintextRequest: "none",
  });

  runtime.commands.onInvoke((event) => {
    const localId = commandLocalId(event);
    if (localId === "settings.submit") {
      const values = settingsValues(event);
      void setHostStatus(
        runtime,
        `Settings saved: note=${values.note ?? ""} enabled=${values.enabled === true}`,
      );
      event.respond({ handled: true });
      return;
    }
    void setHostStatus(runtime, `Command invoked: ${localId} (${commandResourceKind(event)})`);
    event.respond({ handled: true });
  });

  await setHostStatus(runtime, "UI Demo Ready");
  await runtime.ui.status.registerItem({
    localId: "status-frame",
    label: "UI Demo Status Frame",
    zone: "normal",
    value: { kind: "iframe", panel_id: "status-frame" },
    maxWidth: 360,
  });
  await runtime.ui.sidebar.registerPanel({
    localId: "sidebar",
    panelId: "sidebar",
    title: "UI Demo Sidebar",
    allowedLocations: ["left"],
  });
  await runtime.ui.documentTree.registerVirtualSection({
    localId: "tree-section",
    placement: "before_tree",
    title: "UI Demo Tree Section",
    sourceCommandRef: triggerCommand,
  });
  await runtime.ui.documentTree.registerAction({
    localId: "tree-action",
    placement: "row_context_menu",
    title: "UI Demo Tree Action",
    commandRef: triggerCommand,
  });
  await runtime.ui.documentTree.registerBadge({
    localId: "tree-badge",
    placement: "row_trailing_badge",
    text: "dt",
  });
  await runtime.ui.documentTree.registerDecoration({
    localId: "tree-decoration",
    placement: "row_prefix",
    tone: "info",
  });
  await runtime.ui.settings.registerDeclarative({
    localId: "settings-form",
    settingsId: "settings-form",
    title: "UI Demo Settings",
    placement: "plugin_settings",
    sections: [
      {
        title: "UI Demo Controls",
        fields: [
          { kind: "text", name: "note", label: "UI Demo Note", max_length: 64 },
          { kind: "checkbox", name: "enabled", label: "UI Demo Enabled" },
        ],
      },
    ],
    submitCommandRef: settingsCommand,
  });
  await runtime.ui.settings.registerIframe({
    localId: "settings-frame",
    settingsId: "settings-frame",
    title: "UI Demo Iframe Settings",
    placement: "plugin_settings",
    iframePanelId: "settings-frame",
  });
  await runtime.ui.menu.registerItem({
    localId: "tab-action",
    placement: "document_tab_menu",
    title: "UI Demo Tab Action",
    commandRef: triggerCommand,
  });
  await runtime.ui.modal.registerDeclarative({
    localId: "modal",
    modalId: "modal",
    title: "UI Demo Modal",
    triggerCommandRef: triggerCommand,
    body: {
      kind: "schema_form",
      fields: [{ kind: "text", name: "message", label: "UI Demo Message", max_length: 64 }],
    },
  });
  await runtime.ui.workspace.registerTile({
    localId: "workspace-tile",
    tileId: "workspace-tile",
    title: "UI Demo Workspace Tile",
    scope: "document",
    preferredOpen: "document_menu",
  });
  await runtime.ui.auxiliary.registerPane({
    localId: "comments-pane",
    paneId: "comments-pane",
    title: "UI Demo Comments",
    allowedLocations: ["document_right"],
    defaultWidth: 260,
    actions: [{ actionId: "trigger", title: "Trigger", commandRef: triggerCommand }],
  });
}

function waitForRuntime() {
  const runtime = globalThis.refmd;
  if (!runtime || typeof runtime.onload !== "function") {
    window.setTimeout(waitForRuntime, 25);
    return;
  }
  runtime.onload(() => {
    void registerRuntime(runtime).catch((error) => setStatus(`UI demo failed: ${error.message}`));
  });
}

waitForRuntime();

export default {};
