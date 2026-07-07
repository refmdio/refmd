defmodule RefMD.Plugins.SandboxDocumentRenderer do
  @moduledoc false

  alias RefMD.Plugins.{JavaScriptSource, SandboxDocumentArtifacts}

  @rpc_protocol "refmd.plugin-host-rpc"
  @rpc_version 1
  @bundle_artifact_cache_version 1
  @plugin_host_rpc_request_timeout_ms 120_000
  @normalized_forbidden_fragments [
    "import(",
    "import \"",
    "import '",
    "import ;",
    "import {",
    "import *",
    "from \"",
    "from '",
    "importScripts(",
    "navigator.serviceWorker",
    "new Worker",
    "new SharedWorker",
    "new Blob",
    "URL.createObjectURL"
  ]
  @compact_forbidden_fragments [
    "import(",
    "import\"",
    "import'",
    "import;",
    "import{",
    "import*",
    "from\"",
    "from'",
    "importScripts(",
    "navigator.serviceWorker",
    "newWorker(",
    "newSharedWorker(",
    "newBlob(",
    "URL.createObjectURL",
    "navigator[\"serviceWorker\"]",
    "navigator['serviceWorker']",
    "navigator[`serviceWorker`]",
    "URL[\"createObjectURL\"]",
    "URL['createObjectURL']",
    "URL[`createObjectURL`]"
  ]
  @html_subresource_fragments ["<script", "<link"]

  def render(payload, session, opts \\ []) do
    with {:ok, variant_context} <- sandbox_document_variant(payload, session, opts),
         {:ok, main_script} <- plugin_source(payload.main_js, :plugin_source_encoding_invalid),
         {:ok, styles_css} <-
           plugin_source(payload.styles_css || "", :plugin_source_encoding_invalid),
         {:ok, bundle_artifact} <- cached_bundle_artifact(main_script, styles_css),
         {:ok, root_id} <- html_id("refmd-plugin-root"),
         {:ok, boot_script} <- boot_script(payload, session, variant_context),
         {:ok, escaped_boot_script} <- JavaScriptSource.escape_inline_script(boot_script) do
      boot_hash = script_sha256(escaped_boot_script)
      bundle_hash = bundle_artifact.script_sha256
      csp = runtime_csp([boot_hash, bundle_hash], variant_context.variant)

      html =
        sandbox_html(
          root_id,
          bundle_artifact.styles_css,
          escaped_boot_script,
          bundle_artifact.main_script
        )

      {:ok, %{html: html, csp: csp}}
    end
  end

  defp cached_bundle_artifact(main_script, styles_css) do
    key = bundle_artifact_cache_key(main_script, styles_css)

    case SandboxDocumentArtifacts.get(key) do
      :miss ->
        with {:ok, artifact} <- build_bundle_artifact(main_script, styles_css) do
          SandboxDocumentArtifacts.put(key, artifact, bundle_artifact_size(artifact))
          {:ok, artifact}
        end

      {:ok, artifact} ->
        {:ok, artifact}
    end
  end

  defp build_bundle_artifact(main_script, styles_css) do
    with :ok <- safe_script_source(main_script),
         :ok <- safe_style_source(styles_css),
         normalized_main_script = masked_source(main_script),
         :ok <- single_bundle(main_script, normalized_main_script),
         {:ok, escaped_main_script} <-
           JavaScriptSource.escape_inline_script(main_script, normalized_main_script) do
      {:ok,
       %{
         main_script: escaped_main_script,
         script_sha256: script_sha256(escaped_main_script),
         styles_css: styles_css
       }}
    end
  end

  defp bundle_artifact_cache_key(main_script, styles_css) do
    {
      __MODULE__,
      :bundle_artifact,
      @bundle_artifact_cache_version,
      :crypto.hash(:sha256, main_script),
      :crypto.hash(:sha256, styles_css)
    }
  end

  defp bundle_artifact_size(artifact) do
    byte_size(artifact.main_script) + byte_size(artifact.styles_css)
  end

  defp sandbox_document_variant(payload, session, opts) do
    case Keyword.get(opts, :variant, :default) do
      :default ->
        with :ok <- reject_wasm_resources(payload.resources) do
          {:ok, %{variant: :default, browser_target: nil}}
        end

      :wasm_capable ->
        wasm_capable_variant(payload, session, Keyword.get(opts, :browser_target))

      _variant ->
        {:error, :plugin_wasm_variant_invalid}
    end
  end

  defp reject_wasm_resources(resources) do
    if Enum.any?(resources, &(&1.kind == "wasm")) do
      {:error, :plugin_wasm_runtime_disabled}
    else
      :ok
    end
  end

  defp wasm_capable_variant(payload, session, browser_target) do
    with :ok <- validate_wasm_variant_resources(payload.resources),
         :ok <- validate_wasm_variant_binding(payload, session, browser_target) do
      {:ok, %{variant: :wasm_capable, browser_target: browser_target}}
    end
  end

  defp validate_wasm_variant_resources(resources) do
    if Enum.any?(resources, &(&1.kind == "wasm")) do
      :ok
    else
      {:error, :plugin_wasm_variant_invalid}
    end
  end

  defp validate_wasm_variant_binding(payload, session, browser_target) do
    required = [
      payload.application_id,
      session.application_id,
      payload.bundle_hash,
      session.bundle_hash,
      payload.resource_manifest_hash,
      session.resource_manifest_hash,
      payload.consent_epoch,
      session.consent_epoch,
      browser_target
    ]

    cond do
      Enum.any?(required, &blank?/1) ->
        {:error, :plugin_wasm_variant_invalid}

      payload.application_id != session.application_id ->
        {:error, :plugin_wasm_variant_invalid}

      payload.bundle_hash != session.bundle_hash ->
        {:error, :plugin_wasm_variant_invalid}

      payload.resource_manifest_hash != session.resource_manifest_hash ->
        {:error, :plugin_wasm_variant_invalid}

      payload.consent_epoch != session.consent_epoch ->
        {:error, :plugin_wasm_variant_invalid}

      true ->
        :ok
    end
  end

  defp blank?(value), do: value in [nil, ""]

  defp plugin_source(source, error) when is_binary(source) do
    if String.valid?(source), do: {:ok, source}, else: {:error, error}
  end

  defp plugin_source(_source, error), do: {:error, error}

  defp safe_script_source(source) do
    if JavaScriptSource.unsafe_control_character?(source) do
      {:error, :plugin_script_inline_forbidden}
    else
      :ok
    end
  end

  defp safe_style_source(source) do
    cond do
      String.match?(source, ~r/<\/style/iu) ->
        {:error, :plugin_style_inline_forbidden}

      JavaScriptSource.unsafe_control_character?(source) ->
        {:error, :plugin_style_inline_forbidden}

      true ->
        :ok
    end
  end

  defp single_bundle(source, normalized) do
    compact = normalized |> String.replace(~r/\s+/u, "") |> normalize_computed_concatenations()

    computed_compact =
      source |> String.replace(~r/\s+/u, "") |> normalize_computed_concatenations()

    if forbidden_bundle_source?(normalized, compact, computed_compact) do
      {:error, :plugin_bundle_dependency_forbidden}
    else
      :ok
    end
  end

  defp masked_source(source) do
    JavaScriptSource.mask_non_code(source)
  end

  defp forbidden_bundle_source?(normalized, compact, computed_compact) do
    String.contains?(normalized, @normalized_forbidden_fragments) or
      String.contains?(compact, @compact_forbidden_fragments) or
      computed_runtime_dependency?(computed_compact) or
      normalized
      |> String.downcase()
      |> String.contains?(@html_subresource_fragments)
  end

  defp computed_runtime_dependency?(compact) do
    Enum.any?(
      [
        ~r/(?:navigator|globalThis|window|self)\[[`"']serviceWorker[`"']\]/u,
        ~r/(?:globalThis|window|self)\[[`"']importScripts[`"']\]\(/u,
        ~r/new\(*?(?:globalThis|window|self)\[[`"'](?:Worker|SharedWorker|Blob)[`"']\]\)*\(/u,
        ~r/(?:URL|\(*?(?:globalThis|window|self)\[[`"']URL[`"']\]\)*?)\[[`"']createObjectURL[`"']\]\(/u
      ],
      &Regex.match?(&1, compact)
    )
  end

  defp normalize_computed_concatenations(source) do
    next = Regex.replace(~r/(["'])([A-Za-z]+)\1\+(["'])([A-Za-z]+)\3/u, source, ~s("\\2\\4"))
    if next == source, do: next, else: normalize_computed_concatenations(next)
  end

  defp html_id(value) do
    if Regex.match?(~r/^[A-Za-z][A-Za-z0-9_:-]{0,127}$/u, value) do
      {:ok, value}
    else
      {:error, :invalid_root_element_id}
    end
  end

  defp boot_script(payload, session, variant_context) do
    resource_context = resource_context(payload, session, variant_context)
    resource_records = Enum.map(payload.resources, &resource_record/1)
    wasm_capable? = variant_context.variant == :wasm_capable

    script =
      ([
         "(() => {",
         ~s("use strict";),
         "const protocol = #{Jason.encode!(@rpc_protocol)};",
         "const version = #{@rpc_version};",
         "const bootNonce = #{Jason.encode!(session.boot_nonce)};",
         "const frameGeneration = #{session.frame_generation};",
         "const resourceContext = #{Jason.encode!(resource_context)};",
         "const resourceRecords = #{Jason.encode!(resource_records)};",
         "const wasmCapable = #{Jason.encode!(wasm_capable?)};",
         "const NativeWebAssembly = globalThis.WebAssembly;",
         "const objectUrls = new Set();",
         "const resourceMap = new Map(resourceRecords.map((entry) => [entry.path, Object.freeze(entry)]));",
         "let resourceApiActive = false;",
         "function resourceBytes(entry) {",
         "const binary = atob(entry.bytes);",
         "const bytes = new Uint8Array(binary.length);",
         "for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);",
         "return bytes;",
         "}"
       ] ++
         resource_hash_script_lines() ++
         [
           "function assertResourceApiActive() {",
           "if (!resourceApiActive || !hostPort || connectedFrameGeneration !== frameGeneration) throw new Error('plugin_resource_context_stale');",
           "if (resourceMap.size > 0 && (!resourceContext.capabilityGrantId || !resourceContext.applicationId || !resourceContext.bundleHash || !resourceContext.manifestHash || !resourceContext.resourceManifestHash)) throw new Error('plugin_resource_context_stale');",
           "if (wasmCapable && !resourceContext.browserTarget) throw new Error('plugin_resource_context_stale');",
           "}",
           "function resourceEntry(path, requestedKind) {",
           "assertResourceApiActive();",
           "if (typeof path !== 'string' || !resourceMap.has(path)) throw new Error('plugin_resource_not_found');",
           "const entry = resourceMap.get(path);",
           "if (requestedKind && entry.kind !== requestedKind) throw new Error(requestedKind === 'wasm' ? 'plugin_wasm_resource_required' : 'plugin_resource_kind_mismatch');",
           "if (!entry.hash || !Number.isInteger(entry.byteLength) || entry.byteLength < 0) throw new Error('plugin_resource_manifest_invalid');",
           "const bytes = resourceBytes(entry);",
           "if (bytes.byteLength !== entry.byteLength) throw new Error('plugin_resource_integrity_invalid');",
           "if (blake3Base64Url(bytes) !== entry.hash) throw new Error('plugin_resource_integrity_invalid');",
           "return { entry, bytes };",
           "}",
           "function deactivateResources() {",
           "resourceApiActive = false;",
           "for (const url of objectUrls) URL.revokeObjectURL(url);",
           "objectUrls.clear();",
           "resourceMap.clear();",
           "}",
           "const resources = Object.freeze({",
           "async read(path, expectedKind) {",
           "const checked = resourceEntry(path, expectedKind);",
           "return checked.bytes.slice();",
           "},",
           "async objectUrl(path) {",
           "const { entry, bytes } = resourceEntry(path);",
           "if (entry.kind === 'wasm') throw new Error('plugin_resource_object_url_forbidden');",
           "const url = URL.createObjectURL(new Blob([bytes], { type: entry.mediaType }));",
           "objectUrls.add(url);",
           "return url;",
           "},",
           "async revokeObjectUrl(url) {",
           "if (objectUrls.has(url)) { URL.revokeObjectURL(url); objectUrls.delete(url); }",
           "},"
         ] ++
         wasm_resource_script_lines(variant_context.variant) ++
         [
           "});",
           "try { Object.defineProperty(globalThis, 'WebAssembly', { value: undefined, configurable: false, enumerable: false, writable: false }); } catch (_) { }",
           "let hostPort = null;",
           "let connectedFrameGeneration = null;",
           "let rpcContext = null;",
           "let bootReadyTimer = null;",
           "const pendingPortListeners = [];",
           "const loadListeners = new Set();",
           "const unloadListeners = new Set();",
           "let lifecycleLoaded = false;",
           "let lifecycleUnloaded = false;",
           "let nextRequestSequence = 0;",
           "const pendingRequests = new Map();",
           "function rejectPendingRequests(code, message) {",
           "for (const [requestId, pending] of pendingRequests) { pendingRequests.delete(requestId); clearTimeout(pending.timeoutId); const error = new Error(message || 'plugin_rpc_error'); error.code = code; pending.reject(error); }",
           "}",
           "function assertRpcActive() { if (!hostPort || connectedFrameGeneration !== frameGeneration) throw new Error('plugin_host_port_not_connected'); if (!rpcContext || !rpcContext.plugin_id || !rpcContext.package_id || !rpcContext.application_id || !rpcContext.activation_id || !rpcContext.owner_scope_kind || !rpcContext.workspace_id || !rpcContext.user_id || !rpcContext.device_id || !rpcContext.bundle_hash || !rpcContext.manifest_hash || !rpcContext.capability_id || !rpcContext.capability_grant_id || !Number.isInteger(rpcContext.consent_epoch)) throw new Error('plugin_rpc_context_unavailable'); }",
           "function request(operation, payload, options) {",
           "assertRpcActive();",
           "if (typeof operation !== 'string' || operation.trim() === '') throw new Error('plugin_rpc_operation_invalid');",
           "const requestId = 'plugin-request-' + Date.now().toString(36) + '-' + (++nextRequestSequence).toString(36);",
           "const envelope = Object.assign({}, rpcContext, { protocol, version, kind: 'request', request_id: requestId, request_nonce: requestId + '-nonce', frame_generation: frameGeneration, operation, payload });",
           "if (options && Object.prototype.hasOwnProperty.call(options, 'resource')) envelope.resource = options.resource;",
           "if (options && typeof options.executionContextId === 'string') envelope.execution_context_id = options.executionContextId;",
           "return new Promise((resolve, reject) => { const timeoutId = setTimeout(() => { pendingRequests.delete(requestId); reject(new Error('plugin_rpc_timeout')); }, #{@plugin_host_rpc_request_timeout_ms}); pendingRequests.set(requestId, { resolve, reject, timeoutId }); try { hostPort.postMessage(envelope); } catch (error) { pendingRequests.delete(requestId); clearTimeout(timeoutId); reject(error); } });",
           "}",
           "const runtime = Object.freeze({",
           "get connected() { return hostPort !== null; },",
           "get context() { return rpcContext; },",
           "postMessage(message) { if (!hostPort) throw new Error('plugin_host_port_not_connected'); hostPort.postMessage(message); },",
           "request,",
           "addEventListener(type, listener) { if (hostPort) { hostPort.addEventListener(type, listener); return; } pendingPortListeners.push({ type, listener }); },",
           "removeEventListener(type, listener) { for (let index = pendingPortListeners.length - 1; index >= 0; index -= 1) { const entry = pendingPortListeners[index]; if (entry.type === type && entry.listener === listener) pendingPortListeners.splice(index, 1); } if (hostPort) hostPort.removeEventListener(type, listener); },",
           "});",
           "function fixedRequest(operation) { return (payload, options) => request(operation, payload, options); }",
           "function respond(requestId, payload) { runtime.postMessage({ protocol, version, kind: 'response', request_id: requestId, payload }); }",
           "function onRequest(operation, listener) { if (typeof listener !== 'function') throw new Error('plugin_listener_invalid'); const handler = (event) => { const message = event.data; if (!message || message.protocol !== protocol || message.version !== version || message.kind !== 'request' || message.operation !== operation) return; listener(message); }; runtime.addEventListener('message', handler); return Object.freeze({ dispose() { runtime.removeEventListener('message', handler); } }); }",
           "function requestEvent(message) { const payload = message.payload && typeof message.payload === 'object' ? message.payload : {}; const executionContextId = typeof message.execution_context_id === 'string' ? message.execution_context_id : payload.execution_context_id; return Object.freeze({ operation: message.operation, requestId: message.request_id, executionContextId, resource: message.resource, payload, respond(value) { respond(message.request_id, value); } }); }",
           "function lifecycleHandle(set, listener, code) { if (typeof listener !== 'function') throw new Error(code); set.add(listener); return Object.freeze({ dispose() { set.delete(listener); } }); }",
           "function runLifecycleListener(listener) { Promise.resolve().then(() => listener()).catch(() => undefined); }",
           "function onload(listener) { const handle = lifecycleHandle(loadListeners, listener, 'plugin_onload_listener_invalid'); if (lifecycleLoaded && !lifecycleUnloaded) runLifecycleListener(listener); return handle; }",
           "function onunload(listener) { return lifecycleHandle(unloadListeners, listener, 'plugin_onunload_listener_invalid'); }",
           "function fireLoad() { if (lifecycleLoaded || lifecycleUnloaded) return; lifecycleLoaded = true; for (const listener of Array.from(loadListeners)) runLifecycleListener(listener); }",
           "function fireUnload() { if (lifecycleUnloaded) return; lifecycleUnloaded = true; for (const listener of Array.from(unloadListeners)) runLifecycleListener(listener); loadListeners.clear(); unloadListeners.clear(); }",
           "function registrationHandle(localId, response) { const id = response && typeof response === 'object' && typeof response.id === 'string' ? response.id : undefined; let disposed = false; return Object.freeze({ id, localId, dispose() { if (disposed) return Promise.resolve({ local_id: localId }); disposed = true; return request('ui.contribution.unregister', { local_id: localId }); } }); }",
           "function registerContribution(operation, payload) { return request(operation, payload).then((response) => registrationHandle(payload.local_id, response)); }",
           "const runtimeInfo = Object.freeze({ get connected() { return hostPort !== null; }, get context() { return rpcContext; } });",
           "const documents = Object.freeze({ getActiveDocument: fixedRequest('documents.getActiveDocument'), getSelectedDocuments: fixedRequest('documents.getSelectedDocuments'), queryWorkspaceDocuments: fixedRequest('documents.queryWorkspaceDocuments') });",
           "const editor = Object.freeze({ setValue: fixedRequest('editor.setValue'), replaceSelection: fixedRequest('editor.replaceSelection'), registerContribution: fixedRequest('editor.contribution.register'), getFormatterInput: fixedRequest('formatter.getInput'), getDiagnosticsContext: fixedRequest('diagnostics.getContext'), getDecorationContext: fixedRequest('decoration.getContext'), getSuggestionContext: fixedRequest('suggestion.getContext'), onRequest(listener) { if (typeof listener !== 'function') throw new Error('plugin_listener_invalid'); const handlers = ['editor.command.run', 'formatter.run', 'diagnostics.run', 'decoration.run', 'suggestion.run'].map((operation) => onRequest(operation, (message) => listener(requestEvent(message)))); return Object.freeze({ dispose() { for (const handler of handlers) handler.dispose(); } }); } });",
           "const storage = Object.freeze({ userLocal: Object.freeze({ get: fixedRequest('storage.userLocal.get'), set: fixedRequest('storage.userLocal.set'), delete: fixedRequest('storage.userLocal.delete') }), cache: Object.freeze({ get: fixedRequest('storage.cache.get'), set: fixedRequest('storage.cache.set'), delete: fixedRequest('storage.cache.delete') }), workspace: Object.freeze({ get: fixedRequest('storage.workspace.get'), set: fixedRequest('storage.workspace.set'), delete: fixedRequest('storage.workspace.delete'), recordCreate: fixedRequest('storage.workspace.record.create'), recordGet: fixedRequest('storage.workspace.record.get'), recordDelete: fixedRequest('storage.workspace.record.delete') }), document: Object.freeze({ get: fixedRequest('storage.document.get'), set: fixedRequest('storage.document.set'), delete: fixedRequest('storage.document.delete'), recordCreate: fixedRequest('storage.document.record.create'), recordGet: fixedRequest('storage.document.record.get'), recordDelete: fixedRequest('storage.document.record.delete') }) });",
           "const network = Object.freeze({ fetch: fixedRequest('app.network.fetch') });",
           "const credential = Object.freeze({ use: fixedRequest('credential.use') });",
           "function descriptorObject(descriptor) { return descriptor && typeof descriptor === 'object' ? descriptor : {}; }",
           "function camelOrSnake(input, camel, snake) { return input[camel] !== undefined ? input[camel] : input[snake]; }",
           "function requireStringField(input, camel, snake, code) { const value = camelOrSnake(input, camel, snake); if (typeof value !== 'string' || value.length === 0) throw new Error(code); return value; }",
           "function requireObjectField(input, camel, snake, code) { const value = camelOrSnake(input, camel, snake); if (!value || typeof value !== 'object') throw new Error(code); return value; }",
           "function requireArrayField(input, camel, snake, code) { const value = camelOrSnake(input, camel, snake); if (!Array.isArray(value)) throw new Error(code); return value; }",
           "function assignOptionalString(payload, key, value) { if (typeof value === 'string') payload[key] = value; }",
           "function assignOptionalObject(payload, key, value) { if (value && typeof value === 'object') payload[key] = value; }",
           "function copyBaseContribution(payload, input) { assignOptionalString(payload, 'label', input.label); assignOptionalString(payload, 'icon', input.icon); if (Number.isSafeInteger(input.order)) payload.order = input.order; assignOptionalObject(payload, 'when', input.when); return payload; }",
           "function localId(input, code) { return requireStringField(input, 'localId', 'local_id', code); }",
           "function commandRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'command', local_id: localId(input, 'plugin_command_local_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_command_title_required') }, input); assignOptionalString(payload, 'category', input.category); assignOptionalObject(payload, 'enablement', input.enablement); assignOptionalString(payload, 'plaintext_request', camelOrSnake(input, 'plaintextRequest', 'plaintext_request')); assignOptionalObject(payload, 'document_query', camelOrSnake(input, 'documentQuery', 'document_query')); return payload; }",
           "function statusItemRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const value = requireObjectField(input, 'value', 'value', 'plugin_status_value_required'); const payload = copyBaseContribution({ surface: 'status', local_id: localId(input, 'plugin_status_local_id_required'), zone: requireStringField(input, 'zone', 'zone', 'plugin_status_zone_required'), value }, input); assignOptionalString(payload, 'plaintext_request', camelOrSnake(input, 'plaintextRequest', 'plaintext_request')); if (Number.isSafeInteger(input.maxWidth)) payload.max_width = input.maxWidth; else if (Number.isSafeInteger(input.max_width)) payload.max_width = input.max_width; return payload; }",
           "function sidebarPanelRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const locations = requireArrayField(input, 'allowedLocations', 'allowed_locations', 'plugin_sidebar_panel_locations_required'); const payload = copyBaseContribution({ surface: 'sidebar_panel', local_id: localId(input, 'plugin_sidebar_panel_local_id_required'), panel_id: requireStringField(input, 'panelId', 'panel_id', 'plugin_sidebar_panel_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_sidebar_panel_title_required'), allowed_locations: locations }, input); if (Number.isSafeInteger(input.defaultWidth)) payload.default_width = input.defaultWidth; else if (Number.isSafeInteger(input.default_width)) payload.default_width = input.default_width; return payload; }",
           "function workspaceTileRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'workspace_tile', local_id: localId(input, 'plugin_workspace_tile_local_id_required'), tile_id: requireStringField(input, 'tileId', 'tile_id', 'plugin_workspace_tile_tile_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_workspace_tile_title_required'), scope: input.scope }, input); if (input.scope !== 'workspace' && input.scope !== 'document') throw new Error('plugin_workspace_tile_scope_required'); assignOptionalString(payload, 'preferred_open', camelOrSnake(input, 'preferredOpen', 'preferred_open')); return payload; }",
           "function workspaceTileActionRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'workspace_tile_action', local_id: localId(input, 'plugin_workspace_tile_action_local_id_required'), tile_ref: requireObjectField(input, 'tileRef', 'tile_ref', 'plugin_workspace_tile_action_tile_ref_required'), action_id: requireStringField(input, 'actionId', 'action_id', 'plugin_workspace_tile_action_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_workspace_tile_action_title_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_workspace_tile_action_placement_required') }, input); assignOptionalObject(payload, 'document_query', camelOrSnake(input, 'documentQuery', 'document_query')); return payload; }",
           "function auxiliaryPaneActionPayload(action) { const input = descriptorObject(action); const payload = { action_id: requireStringField(input, 'actionId', 'action_id', 'plugin_auxiliary_pane_action_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_auxiliary_pane_action_title_required'), command_ref: requireObjectField(input, 'commandRef', 'command_ref', 'plugin_auxiliary_pane_action_command_ref_required') }; assignOptionalString(payload, 'icon', input.icon); if (Number.isSafeInteger(input.order)) payload.order = input.order; return payload; }",
           "function auxiliaryPaneRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const locations = requireArrayField(input, 'allowedLocations', 'allowed_locations', 'plugin_auxiliary_pane_locations_required'); const payload = copyBaseContribution({ surface: 'auxiliary_pane', local_id: localId(input, 'plugin_auxiliary_pane_local_id_required'), pane_id: requireStringField(input, 'paneId', 'pane_id', 'plugin_auxiliary_pane_pane_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_auxiliary_pane_title_required'), allowed_locations: locations }, input); if (Number.isSafeInteger(input.defaultWidth)) payload.default_width = input.defaultWidth; else if (Number.isSafeInteger(input.default_width)) payload.default_width = input.default_width; if (Array.isArray(input.actions)) payload.actions = input.actions.map(auxiliaryPaneActionPayload); return payload; }",
           "function documentTreeActionRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); return copyBaseContribution({ surface: 'document_tree_action', local_id: localId(input, 'plugin_document_tree_action_local_id_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_document_tree_action_placement_required'), title: requireStringField(input, 'title', 'title', 'plugin_document_tree_action_title_required'), command_ref: requireObjectField(input, 'commandRef', 'command_ref', 'plugin_document_tree_action_command_ref_required') }, input); }",
           "function documentTreeBadgeRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'document_tree_badge', local_id: localId(input, 'plugin_document_tree_badge_local_id_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_document_tree_badge_placement_required') }, input); assignOptionalString(payload, 'text', input.text); assignOptionalString(payload, 'plaintext_request', camelOrSnake(input, 'plaintextRequest', 'plaintext_request')); assignOptionalString(payload, 'tone', input.tone); return payload; }",
           "function documentTreeDecorationRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'document_tree_decoration', local_id: localId(input, 'plugin_document_tree_decoration_local_id_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_document_tree_decoration_placement_required') }, input); assignOptionalString(payload, 'tone', input.tone); return payload; }",
           "function documentTreeVirtualSectionRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); return copyBaseContribution({ surface: 'document_tree_virtual_section', local_id: localId(input, 'plugin_document_tree_virtual_section_local_id_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_document_tree_virtual_section_placement_required'), title: requireStringField(input, 'title', 'title', 'plugin_document_tree_virtual_section_title_required'), source_command_ref: requireObjectField(input, 'sourceCommandRef', 'source_command_ref', 'plugin_document_tree_virtual_section_source_command_ref_required') }, input); }",
           "function settingsIframeRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); return copyBaseContribution({ surface: 'settings_iframe', local_id: localId(input, 'plugin_settings_iframe_local_id_required'), settings_id: requireStringField(input, 'settingsId', 'settings_id', 'plugin_settings_iframe_settings_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_settings_iframe_title_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_settings_iframe_placement_required'), iframe_panel_id: requireStringField(input, 'iframePanelId', 'iframe_panel_id', 'plugin_settings_iframe_panel_id_required') }, input); }",
           "function settingsDeclarativeRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const sections = input.sections; if (!Array.isArray(sections)) throw new Error('plugin_settings_sections_required'); const payload = copyBaseContribution({ surface: 'settings_declarative', local_id: localId(input, 'plugin_settings_declarative_local_id_required'), settings_id: requireStringField(input, 'settingsId', 'settings_id', 'plugin_settings_declarative_settings_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_settings_declarative_title_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_settings_declarative_placement_required'), sections }, input); assignOptionalObject(payload, 'submit_command_ref', camelOrSnake(input, 'submitCommandRef', 'submit_command_ref')); return payload; }",
           "function menuItemRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'menu_item', local_id: localId(input, 'plugin_menu_item_local_id_required'), placement: requireStringField(input, 'placement', 'placement', 'plugin_menu_item_placement_required'), title: requireStringField(input, 'title', 'title', 'plugin_menu_item_title_required'), command_ref: requireObjectField(input, 'commandRef', 'command_ref', 'plugin_menu_item_command_ref_required') }, input); assignOptionalObject(payload, 'enablement', input.enablement); return payload; }",
           "function modalDeclarativeRegistrationPayload(descriptor) { const input = descriptorObject(descriptor); const payload = copyBaseContribution({ surface: 'declarative_modal', local_id: localId(input, 'plugin_modal_local_id_required'), modal_id: requireStringField(input, 'modalId', 'modal_id', 'plugin_modal_id_required'), title: requireStringField(input, 'title', 'title', 'plugin_modal_title_required'), trigger_command_ref: requireObjectField(input, 'triggerCommandRef', 'trigger_command_ref', 'plugin_modal_trigger_command_ref_required'), body: requireObjectField(input, 'body', 'body', 'plugin_modal_body_required') }, input); assignOptionalObject(payload, 'submit_command_ref', camelOrSnake(input, 'submitCommandRef', 'submit_command_ref')); return payload; }",
           "const commands = Object.freeze({ register(descriptor) { return registerContribution('ui.command.register', commandRegistrationPayload(descriptor)); }, onInvoke(listener) { return onRequest('ui.command.invoke', (message) => listener(requestEvent(message))); } });",
           "const ui = Object.freeze({ status: Object.freeze({ registerItem(descriptor) { return registerContribution('ui.status.register_item', statusItemRegistrationPayload(descriptor)); }, updateItem(descriptor) { return request('ui.status.update_item', statusItemRegistrationPayload(descriptor)); }, onRefresh(listener) { return onRequest('ui.status.refresh', (message) => listener(requestEvent(message))); } }), sidebar: Object.freeze({ registerPanel(descriptor) { return registerContribution('ui.sidebar.register_panel', sidebarPanelRegistrationPayload(descriptor)); } }), workspace: Object.freeze({ registerTile(descriptor) { return registerContribution('ui.workspace.register_tile', workspaceTileRegistrationPayload(descriptor)); }, registerTileAction(descriptor) { return registerContribution('ui.workspace.register_tile_action', workspaceTileActionRegistrationPayload(descriptor)); }, onTileRender(listener) { return onRequest('ui.workspace_tile.render', (message) => listener(requestEvent(message))); }, onTileAction(listener) { return onRequest('ui.workspace_tile.action', (message) => listener(requestEvent(message))); } }), auxiliary: Object.freeze({ registerPane(descriptor) { return registerContribution('ui.auxiliary.register_pane', auxiliaryPaneRegistrationPayload(descriptor)); } }), documentTree: Object.freeze({ registerAction(descriptor) { return registerContribution('ui.document_tree.register_action', documentTreeActionRegistrationPayload(descriptor)); }, registerBadge(descriptor) { return registerContribution('ui.document_tree.register_badge', documentTreeBadgeRegistrationPayload(descriptor)); }, onBadgeRefresh(listener) { return onRequest('ui.document_tree.badge.refresh', (message) => listener(requestEvent(message))); }, registerDecoration(descriptor) { return registerContribution('ui.document_tree.register_decoration', documentTreeDecorationRegistrationPayload(descriptor)); }, registerVirtualSection(descriptor) { return registerContribution('ui.document_tree.register_virtual_section', documentTreeVirtualSectionRegistrationPayload(descriptor)); } }), settings: Object.freeze({ registerIframe(descriptor) { return registerContribution('ui.settings.register_iframe', settingsIframeRegistrationPayload(descriptor)); }, registerDeclarative(descriptor) { return registerContribution('ui.settings.register_declarative', settingsDeclarativeRegistrationPayload(descriptor)); } }), menu: Object.freeze({ registerItem(descriptor) { return registerContribution('ui.menu.register_item', menuItemRegistrationPayload(descriptor)); } }), modal: Object.freeze({ registerDeclarative(descriptor) { return registerContribution('ui.modal.register_declarative', modalDeclarativeRegistrationPayload(descriptor)); } }) });",
           "function rendererRequestOptions(context) { const options = {}; if (context && typeof context.executionContextId === 'string') options.executionContextId = context.executionContextId; if (context && Object.prototype.hasOwnProperty.call(context, 'resource')) options.resource = context.resource; return options; }",
           "function rendererResponsePayload(value) { if (value && typeof value === 'object') return value; return { rendered: true }; }",
           "function rendererErrorPayload(error) { return { rendered: false, error: error instanceof Error ? error.message : String(error) }; }",
           "const rendererListeners = new Map();",
           "let rendererDispatchRegistered = false;",
           "function rendererListenerKey(kind, type) { return String(kind) + ':' + String(type); }",
           "function rendererContext(message) { const payload = message.payload && typeof message.payload === 'object' ? message.payload : {}; const executionContextId = typeof payload.execution_context_id === 'string' ? payload.execution_context_id : undefined; return Object.freeze({ executionContextId, kind: payload.kind, type: payload.type, resource: message.resource, requestId: message.request_id, getSource() { return renderer.getSource(this); }, setHeight(height) { return renderer.setHeight(this, height); } }); }",
           "function rendererDispatch(event) { const message = event.data; if (!message || message.protocol !== protocol || message.version !== version || message.kind !== 'request' || message.operation !== 'renderer.render') return; const context = rendererContext(message); const listener = rendererListeners.get(rendererListenerKey(context.kind, context.type)); if (typeof listener !== 'function') { runtime.postMessage({ protocol, version, kind: 'response', request_id: message.request_id, payload: { rendered: false, error: 'renderer_listener_not_registered' } }); return; } Promise.resolve().then(() => listener(context)).then((result) => runtime.postMessage({ protocol, version, kind: 'response', request_id: message.request_id, payload: rendererResponsePayload(result) }), (error) => runtime.postMessage({ protocol, version, kind: 'response', request_id: message.request_id, payload: rendererErrorPayload(error) })); }",
           "function ensureRendererDispatch() { if (rendererDispatchRegistered) return; rendererDispatchRegistered = true; runtime.addEventListener('message', rendererDispatch); }",
           "function registerRendererListener(kind, type, listener) { if (typeof listener !== 'function') throw new Error('renderer_listener_invalid'); const key = rendererListenerKey(kind, type); rendererListeners.set(key, listener); ensureRendererDispatch(); return Object.freeze({ dispose() { if (rendererListeners.get(key) === listener) rendererListeners.delete(key); } }); }",
           "const renderer = Object.freeze({",
           "async getSource(context) { const response = await request('renderer.getSource', {}, rendererRequestOptions(context)); if (!response || typeof response !== 'object') return ''; const source = response.source; return typeof source === 'string' ? source : String(source ?? ''); },",
           "async setHeight(context, height) { if (!Number.isFinite(height) || height < 0) throw new Error('renderer_height_invalid'); return request('renderer.setHeight', { execution_context_id: context && context.executionContextId, height: Math.ceil(height) }, rendererRequestOptions(context)); },",
           "register_block(type, listener) { if (typeof type !== 'string' || type.length === 0) throw new Error('renderer_block_type_required'); return registerRendererListener('block', type, listener); },",
           "register_inline_code(listener) { return registerRendererListener('inline', 'code', listener); },",
           "});",
           "Object.defineProperty(globalThis, 'refmd', { value: Object.freeze({ runtime: runtimeInfo, onload, onunload, resources, renderer, documents, editor, storage, network, credential, commands, ui }), configurable: false, enumerable: false, writable: false });",
           "window.addEventListener('message', (event) => {",
           "const data = event.data;",
           "if (!data || data.protocol !== protocol || data.version !== version || data.kind !== 'boot-port') return;",
           "if (event.source !== window.parent || data.frame_generation !== frameGeneration) return;",
           "event.stopImmediatePropagation();",
           "event.stopPropagation();",
           "const port = event.ports && event.ports[0];",
           "if (!port || (typeof MessagePort !== 'undefined' && !(port instanceof MessagePort))) return;",
           "if (hostPort) return;",
           "stopBootReady();",
           "hostPort = port;",
           "connectedFrameGeneration = data.frame_generation;",
           "hostPort.addEventListener('message', (portEvent) => {",
           "const portData = portEvent.data;",
           "if (!portData || portData.protocol !== protocol || portData.version !== version) return;",
           "if (portData.kind === 'boot-context' && portData.frame_generation === frameGeneration) { rpcContext = portData.runtime_context || null; resourceApiActive = true; fireLoad(); return; }",
           "if ((portData.kind === 'response' || portData.kind === 'error') && pendingRequests.has(portData.request_id)) { const pending = pendingRequests.get(portData.request_id); pendingRequests.delete(portData.request_id); clearTimeout(pending.timeoutId); if (portData.kind === 'response') pending.resolve(portData.payload); else { const error = new Error(portData.error && portData.error.message || 'plugin_rpc_error'); error.code = portData.error && portData.error.code; pending.reject(error); } return; }",
           "if (portData.kind === 'host-lifecycle' && portData.lifecycle === 'close') { fireUnload(); hostPort = null; pendingPortListeners.length = 0; rejectPendingRequests('session_closed', portData.reason || 'plugin session is closed'); deactivateResources(); }",
           "});",
           "for (const entry of pendingPortListeners) hostPort.addEventListener(entry.type, entry.listener);",
           "hostPort.start();",
           "hostPort.postMessage({ protocol, version, kind: 'boot-ack', boot_nonce: bootNonce, frame_generation: frameGeneration });",
           "});",
           "window.addEventListener('pagehide', () => { fireUnload(); deactivateResources(); });",
           "window.addEventListener('unload', () => { fireUnload(); deactivateResources(); });",
           "function sendBootReady() { if (hostPort) { stopBootReady(); return; } window.parent.postMessage({ protocol, version, kind: 'boot-ready' }, '*'); }",
           "function stopBootReady() { if (bootReadyTimer !== null) { clearInterval(bootReadyTimer); bootReadyTimer = null; } }",
           "function startBootReady() { if (bootReadyTimer !== null || hostPort) return; sendBootReady(); bootReadyTimer = setInterval(sendBootReady, 250); }",
           "if (document.readyState === 'loading') window.addEventListener('DOMContentLoaded', startBootReady, { once: true }); else queueMicrotask(startBootReady);",
           "})();"
         ])
      |> Enum.join("\n")

    safe_script_source(script)
    |> case do
      :ok -> {:ok, script}
      error -> error
    end
  end

  defp resource_hash_script_lines do
    [
      "function blake3Base64Url(bytes) {",
      "const IV = [0x6A09E667,0xBB67AE85,0x3C6EF372,0xA54FF53A,0x510E527F,0x9B05688C,0x1F83D9AB,0x5BE0CD19];",
      "const PERM = [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8];",
      "const CHUNK_START = 1, CHUNK_END = 2, PARENT = 4, ROOT = 8;",
      "function rotr(value, bits) { return (value >>> bits) | (value << (32 - bits)); }",
      "function blockWords(block) {",
      "const words = new Array(16).fill(0);",
      "for (let index = 0; index < block.length; index += 1) words[index >> 2] = (words[index >> 2] | (block[index] << (8 * (index & 3)))) >>> 0;",
      "return words;",
      "}",
      "function compress(cv, block, counter, blockLength, flags) {",
      "const state = [...cv, ...IV.slice(0, 4), counter >>> 0, Math.floor(counter / 0x100000000) >>> 0, blockLength >>> 0, flags >>> 0];",
      "let message = block.slice();",
      "function mix(a, b, c, d, x, y) {",
      "state[a] = (state[a] + state[b] + x) >>> 0; state[d] = rotr((state[d] ^ state[a]) >>> 0, 16) >>> 0;",
      "state[c] = (state[c] + state[d]) >>> 0; state[b] = rotr((state[b] ^ state[c]) >>> 0, 12) >>> 0;",
      "state[a] = (state[a] + state[b] + y) >>> 0; state[d] = rotr((state[d] ^ state[a]) >>> 0, 8) >>> 0;",
      "state[c] = (state[c] + state[d]) >>> 0; state[b] = rotr((state[b] ^ state[c]) >>> 0, 7) >>> 0;",
      "}",
      "for (let round = 0; round < 7; round += 1) {",
      "mix(0,4,8,12,message[0],message[1]); mix(1,5,9,13,message[2],message[3]); mix(2,6,10,14,message[4],message[5]); mix(3,7,11,15,message[6],message[7]);",
      "mix(0,5,10,15,message[8],message[9]); mix(1,6,11,12,message[10],message[11]); mix(2,7,8,13,message[12],message[13]); mix(3,4,9,14,message[14],message[15]);",
      "message = PERM.map((index) => message[index]);",
      "}",
      "return [state[0] ^ state[8], state[1] ^ state[9], state[2] ^ state[10], state[3] ^ state[11], state[4] ^ state[12], state[5] ^ state[13], state[6] ^ state[14], state[7] ^ state[15], state[8] ^ cv[0], state[9] ^ cv[1], state[10] ^ cv[2], state[11] ^ cv[3], state[12] ^ cv[4], state[13] ^ cv[5], state[14] ^ cv[6], state[15] ^ cv[7]].map((word) => word >>> 0);",
      "}",
      "function digestBytes(words) {",
      "const digest = new Uint8Array(32);",
      "for (let index = 0; index < 8; index += 1) { const word = words[index]; digest[index * 4] = word & 255; digest[index * 4 + 1] = (word >>> 8) & 255; digest[index * 4 + 2] = (word >>> 16) & 255; digest[index * 4 + 3] = (word >>> 24) & 255; }",
      "return digest;",
      "}",
      "function chunkOutput(chunk, chunkIndex) {",
      "let cv = IV.slice();",
      "let output = null;",
      "for (let offset = 0, blockIndex = 0; offset < chunk.length || (chunk.length === 0 && offset === 0); offset += 64, blockIndex += 1) {",
      "const block = chunk.slice(offset, Math.min(offset + 64, chunk.length));",
      "const isLast = offset + 64 >= chunk.length;",
      "const flags = (blockIndex === 0 ? CHUNK_START : 0) | (isLast ? CHUNK_END : 0);",
      "const words = blockWords(block);",
      "output = { cv: cv.slice(), block: words, counter: chunkIndex, blockLength: block.length, flags };",
      "if (!isLast) cv = compress(cv, words, chunkIndex, 64, flags).slice(0, 8);",
      "if (chunk.length === 0) break;",
      "}",
      "return output;",
      "}",
      "function encodeBase64Url(data) { return btoa(String.fromCharCode(...data)).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/g, ''); }",
      "const outputs = [];",
      "const chunkCount = Math.max(1, Math.ceil(bytes.length / 1024));",
      "for (let index = 0; index < chunkCount; index += 1) outputs.push(chunkOutput(bytes.slice(index * 1024, Math.min((index + 1) * 1024, bytes.length)), index));",
      "if (outputs.length === 1) return encodeBase64Url(digestBytes(compress(outputs[0].cv, outputs[0].block, outputs[0].counter, outputs[0].blockLength, outputs[0].flags | ROOT)));",
      "let cvs = outputs.map((output) => compress(output.cv, output.block, output.counter, output.blockLength, output.flags).slice(0, 8));",
      "function parentOutput(left, right, root) { return compress(IV, [...left, ...right], 0, 64, PARENT | (root ? ROOT : 0)); }",
      "while (cvs.length > 2) { const next = []; for (let index = 0; index < cvs.length; index += 2) next.push(index + 1 < cvs.length ? parentOutput(cvs[index], cvs[index + 1], false).slice(0, 8) : cvs[index]); cvs = next; }",
      "return encodeBase64Url(digestBytes(parentOutput(cvs[0], cvs[1], true)));",
      "}"
    ]
  end

  defp wasm_resource_script_lines(:default) do
    ["async instantiateWasm() { throw new Error('plugin_wasm_resource_unavailable'); },"]
  end

  defp wasm_resource_script_lines(:wasm_capable) do
    [
      "async instantiateWasm(path, imports) {",
      "const { bytes } = resourceEntry(path, 'wasm');",
      "if (!NativeWebAssembly || typeof NativeWebAssembly.instantiate !== 'function') throw new Error('plugin_wasm_runtime_unavailable');",
      "const result = await NativeWebAssembly.instantiate(bytes, imports || {});",
      "return result && result.instance ? result.instance : result;",
      "},"
    ]
  end

  defp resource_context(%{resources: []}, _session, _variant_context), do: %{}

  defp resource_context(payload, session, variant_context) do
    context = %{
      capabilityGrantId: session.capability_grant_id,
      applicationId: payload.application_id,
      consentEpoch: payload.consent_epoch,
      frameGeneration: session.frame_generation,
      bundleHash: payload.bundle_hash,
      manifestHash: payload.manifest_hash,
      resourceManifestHash: payload.resource_manifest_hash
    }

    case variant_context do
      %{variant: :wasm_capable, browser_target: browser_target} ->
        Map.put(context, :browserTarget, browser_target)

      _context ->
        context
    end
  end

  defp resource_record(resource) do
    %{
      path: resource.path,
      kind: resource.kind,
      mediaType: resource.media_type,
      byteLength: resource.byte_length,
      hash: resource.hash,
      executable: resource.kind == "wasm",
      bytes: Base.encode64(resource.bytes)
    }
  end

  defp runtime_csp(script_hashes, variant) do
    script_src =
      ["script-src" | Enum.map(script_hashes, &"'sha256-#{&1}'")]
      |> append_wasm_csp_source(variant)
      |> Enum.join(" ")

    [
      "default-src 'none'",
      "sandbox allow-scripts",
      script_src,
      "style-src 'unsafe-inline'",
      "img-src blob: data:",
      "font-src blob: data:",
      "connect-src 'none'",
      "media-src blob: data:",
      "frame-src 'none'",
      "child-src 'none'",
      "worker-src 'none'",
      "object-src 'none'",
      "base-uri 'none'",
      "form-action 'none'",
      "manifest-src 'none'",
      "frame-ancestors 'self'"
    ]
    |> Enum.join("; ")
  end

  defp append_wasm_csp_source(tokens, :wasm_capable), do: tokens ++ ["'wasm-unsafe-eval'"]
  defp append_wasm_csp_source(tokens, _variant), do: tokens

  defp sandbox_html(root_id, styles_css, boot_script, main_script) do
    style_el = if styles_css == "", do: "", else: "<style>#{styles_css}</style>"

    [
      "<!doctype html>",
      "<html>",
      "<head>",
      style_el,
      "</head>",
      "<body>",
      ~s(<div id="#{escape_html_attribute(root_id)}"></div>),
      "<script>#{boot_script}</script>",
      ~s(<script type="module">#{main_script}</script>),
      "</body>",
      "</html>"
    ]
    |> Enum.join()
  end

  defp script_sha256(script_text) do
    :sha256
    |> :crypto.hash(script_text)
    |> Base.encode64()
  end

  defp escape_html_attribute(value) do
    value
    |> String.replace("&", "&amp;")
    |> String.replace(~s("), "&quot;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
  end
end
