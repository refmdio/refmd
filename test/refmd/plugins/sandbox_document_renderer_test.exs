defmodule RefMD.Plugins.SandboxDocumentRendererTest do
  use ExUnit.Case, async: true

  alias RefMD.Crypto.Hash
  alias RefMD.Plugins.SandboxDocumentRenderer

  test "keeps WASM resources disabled for the default sandbox document" do
    assert {:error, :plugin_wasm_runtime_disabled} =
             SandboxDocumentRenderer.render(payload([wasm_resource()]), session())
  end

  test "renders a WASM-capable sandbox document only through the explicit variant" do
    assert {:ok, document} =
             SandboxDocumentRenderer.render(payload([wasm_resource()]), session(),
               variant: :wasm_capable,
               browser_target: "test-browser"
             )

    assert document.csp =~ "'wasm-unsafe-eval'"
    refute document.csp =~ "'unsafe-eval'"
    assert document.html =~ "NativeWebAssembly.instantiate"
    assert document.html =~ "resourceEntry(path, 'wasm')"
    assert document.html =~ "browserTarget"
    assert document.html =~ "Object.defineProperty(globalThis, 'WebAssembly'"
    assert document.html =~ "plugin_resource_object_url_forbidden"
  end

  test "fails closed when the WASM-capable variant is not fully bound" do
    assert {:error, :plugin_wasm_variant_invalid} =
             SandboxDocumentRenderer.render(payload([wasm_resource()]), session(),
               variant: :wasm_capable
             )

    assert {:error, :plugin_wasm_variant_invalid} =
             SandboxDocumentRenderer.render(payload([]), session(),
               variant: :wasm_capable,
               browser_target: "test-browser"
             )

    assert {:error, :plugin_wasm_variant_invalid} =
             SandboxDocumentRenderer.render(
               payload([wasm_resource()], %{bundle_hash: hash("other-bundle")}),
               session(),
               variant: :wasm_capable,
               browser_target: "test-browser"
             )
  end

  test "delays Host RPC boot until plugin main can register listeners" do
    assert {:ok, document} = SandboxDocumentRenderer.render(payload([]), session())

    assert document.html =~ "pendingPortListeners"
    assert document.html =~ "function rejectPendingRequests(code, message)"
    assert document.html =~ "rejectPendingRequests('session_closed'"
    assert document.html =~ "event.stopImmediatePropagation();"
    assert document.html =~ "event.stopPropagation();"
    assert document.html =~ "addEventListener(type, listener)"
    assert document.html =~ "request(operation, payload, options)"
    assert document.html =~ "plugin_rpc_timeout"
    assert document.html =~ "}, 120000); pendingRequests.set(requestId"
    pending_request_index = :binary.match(document.html, "pendingRequests.set(requestId")
    post_request_index = :binary.match(document.html, "hostPort.postMessage(envelope);")
    assert pending_request_index != :nomatch
    assert post_request_index != :nomatch
    assert elem(pending_request_index, 0) < elem(post_request_index, 0)
    refute document.html =~ "registerWorkspacePanel"
    assert document.html =~ "const commands = Object.freeze"
    assert document.html =~ "ui.command.register"
    assert document.html =~ "onInvoke(listener)"
    assert document.html =~ "onload"
    assert document.html =~ "onunload"
    assert document.html =~ "registerContribution"
    assert document.html =~ "ui.contribution.unregister"
    assert document.html =~ "const ui = Object.freeze"
    assert document.html =~ "registerItem(descriptor)"
    assert document.html =~ "ui.status.register_item"
    assert document.html =~ "updateItem(descriptor)"
    assert document.html =~ "ui.status.update_item"

    assert document.html =~
             "assignOptionalString(payload, 'plaintext_request', camelOrSnake(input, 'plaintextRequest', 'plaintext_request')); if (Number.isSafeInteger(input.maxWidth))"

    assert document.html =~ "onRefresh(listener)"
    assert document.html =~ "ui.status.refresh"
    assert document.html =~ "registerPanel(descriptor)"
    assert document.html =~ "ui.sidebar.register_panel"
    assert document.html =~ "registerTile(descriptor)"
    assert document.html =~ "ui.workspace.register_tile"
    assert document.html =~ "plugin_workspace_tile_scope_required"
    assert document.html =~ "workspaceTileActionRegistrationPayload(descriptor)"
    assert document.html =~ "registerTileAction(descriptor)"
    assert document.html =~ "ui.workspace.register_tile_action"

    refute document.html =~ "ui.workspace.register_panel"
    refute document.html =~ "openTile(descriptor)"
    refute document.html =~ "ui.workspace.open_tile"
    assert document.html =~ "onTileRender(listener)"
    assert document.html =~ "ui.workspace_tile.render"
    assert document.html =~ "onTileAction(listener)"
    assert document.html =~ "ui.workspace_tile.action"
    assert document.html =~ "registerPane(descriptor)"
    assert document.html =~ "ui.auxiliary.register_pane"
    assert document.html =~ "auxiliaryPaneActionPayload(action)"
    assert document.html =~ "plugin_auxiliary_pane_action_command_ref_required"
    assert document.html =~ "registerAction(descriptor)"
    assert document.html =~ "ui.document_tree.register_action"
    assert document.html =~ "registerBadge(descriptor)"
    assert document.html =~ "ui.document_tree.register_badge"

    assert document.html =~
             "assignOptionalString(payload, 'text', input.text); assignOptionalString(payload, 'plaintext_request', camelOrSnake(input, 'plaintextRequest', 'plaintext_request')); assignOptionalString(payload, 'tone', input.tone);"

    assert document.html =~ "onBadgeRefresh(listener)"
    assert document.html =~ "ui.document_tree.badge.refresh"
    assert document.html =~ "registerDecoration(descriptor)"
    assert document.html =~ "ui.document_tree.register_decoration"
    assert document.html =~ "registerVirtualSection(descriptor)"
    assert document.html =~ "ui.document_tree.register_virtual_section"
    assert document.html =~ "registerIframe(descriptor)"
    assert document.html =~ "ui.settings.register_iframe"
    assert document.html =~ "registerDeclarative(descriptor)"
    assert document.html =~ "ui.settings.register_declarative"
    assert document.html =~ "ui.menu.register_item"
    assert document.html =~ "ui.modal.register_declarative"
    refute document.html =~ "ui.workspace.register_panel"
    refute document.html =~ "onPanelRender(listener)"
    refute document.html =~ "ui.workspace_panel.render"
    refute document.html =~ "onCommandInvoke"

    assert document.html =~
             "getSelectedDocuments: fixedRequest('documents.getSelectedDocuments')"

    assert document.html =~ "replaceSelection: fixedRequest('editor.replaceSelection')"

    assert document.html =~ "portData.kind === 'boot-context'"
    assert document.html =~ "runtime_context"
    refute document.html =~ "data.runtime_context"
    assert document.html =~ "get context() { return rpcContext; }"
    assert document.html =~ "plugin_rpc_context_unavailable"
    assert document.html =~ "const renderer = Object.freeze"
    assert document.html =~ "renderer.getSource"
    assert document.html =~ "renderer.setHeight"
    assert document.html =~ "register_block(type, listener)"
    assert document.html =~ "register_inline_code(listener)"
    refute document.html =~ "onRender(listener)"

    assert document.html =~
             "Object.freeze({ runtime: runtimeInfo, onload, onunload, resources, renderer, documents, editor, storage, network, credential, commands, ui })"

    refute document.html =~ "__refmdPluginHostRpc"
    assert document.html =~ "DOMContentLoaded"
    assert document.html =~ "sendBootReady"
    assert document.html =~ "kind: 'boot-ready'"
  end

  test "escapes plugin script parser-breakout tokens before computing runtime CSP" do
    main_js = ~S"""
    const arrow = /^(?:-->)/;
    const comment = "<!--";
    const closeScript = "</script>";
    const closeStyle = `</style>`;
    globalThis.__parserBreakoutTokens = [arrow, comment, closeScript, closeStyle];
    """

    assert {:ok, document} =
             SandboxDocumentRenderer.render(payload([], %{main_js: main_js}), session())

    assert document.html =~ "\\x2d->"
    assert document.html =~ "\\x3c!--"
    assert document.html =~ "\\x3c/script>"
    assert document.html =~ "\\x3c/style>"
    refute document.html =~ main_js
    assert document.csp =~ "script-src 'sha256-"
  end

  test "keeps session-specific boot data outside the cached bundle artifact" do
    main_js = "globalThis.__refmdPluginLoaded = true;"

    assert {:ok, first} =
             SandboxDocumentRenderer.render(
               payload([], %{main_js: main_js}),
               session(%{boot_nonce: "boot_nonce_1", frame_generation: 1})
             )

    assert {:ok, second} =
             SandboxDocumentRenderer.render(
               payload([], %{main_js: main_js}),
               session(%{boot_nonce: "boot_nonce_2", frame_generation: 2})
             )

    assert first.html =~ ~s(const bootNonce = "boot_nonce_1";)
    assert first.html =~ "const frameGeneration = 1;"
    refute first.html =~ "boot_nonce_2"

    assert second.html =~ ~s(const bootNonce = "boot_nonce_2";)
    assert second.html =~ "const frameGeneration = 2;"
    refute second.html =~ "boot_nonce_1"
  end

  test "rejects parser-breakout tokens in executable script context" do
    assert {:error, :plugin_script_inline_forbidden} =
             SandboxDocumentRenderer.render(
               payload([], %{main_js: "if (a <!-- b) {}"}),
               session()
             )
  end

  test "allows import-like words and markup tokens when they are not executable dependencies" do
    main_js = ~S"""
    const important = true;
    const importedValue = "from the plugin bundle";
    const template = "<script type=\"text/plain\"></script><link rel=\"preload\">";
    const matcher = /<script(?=\s|>)/i;
    globalThis.__refmdPluginLoaded = { important, importedValue, template, matcher };
    """

    assert {:ok, _document} =
             SandboxDocumentRenderer.render(payload([], %{main_js: main_js}), session())
  end

  test "rejects executable runtime dependency syntax" do
    for source <- [
          "import('https://example.com/plugin.js');",
          "import 'https://example.com/plugin.js';",
          "import { helper } from 'https://example.com/plugin.js';",
          "const worker = new Worker('worker.js');",
          "URL.createObjectURL(blob);"
        ] do
      assert {:error, :plugin_bundle_dependency_forbidden} =
               SandboxDocumentRenderer.render(payload([], %{main_js: source}), session())
    end
  end

  defp payload(resources, attrs \\ %{}) do
    Map.merge(
      %{
        resources: resources,
        main_js: "globalThis.__refmdPluginLoaded = true;",
        styles_css: "",
        application_id: "application-1",
        bundle_hash: hash("bundle"),
        manifest_hash: hash("manifest"),
        resource_manifest_hash: hash("resources"),
        capability_grant_id: "capability-grant-1",
        consent_epoch: 1
      },
      attrs
    )
  end

  defp session(attrs \\ %{}) do
    Map.merge(
      %{
        boot_nonce: "boot_nonce_1",
        frame_generation: 1,
        application_id: "application-1",
        bundle_hash: hash("bundle"),
        resource_manifest_hash: hash("resources"),
        consent_epoch: 1,
        capability_grant_id: "capability-grant-1"
      },
      attrs
    )
  end

  defp wasm_resource do
    bytes = <<0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00>>

    %{
      path: "resources/engine/search.wasm",
      kind: "wasm",
      media_type: "application/wasm",
      byte_length: byte_size(bytes),
      hash: Hash.blake3_base64url(bytes),
      bytes: bytes
    }
  end

  defp hash(value), do: Hash.blake3_base64url(value)
end
