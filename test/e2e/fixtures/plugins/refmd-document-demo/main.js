const WORKSPACE_QUERY_LIMIT = 20;
const WORKSPACE_QUERY_MAX_BYTES = 256 * 1024;

const root = document.createElement("main");
root.setAttribute("aria-label", "RefMD document demo plugin");
root.innerHTML = `
  <h1>RefMD Document Demo Plugin</h1>
  <p data-role="status">Waiting for RefMD runtime</p>
  <p data-role="background-status">Waiting for background guard</p>
`;
document.body.append(root);

const statusEl = root.querySelector('[data-role="status"]');
const backgroundStatusEl = root.querySelector('[data-role="background-status"]');

function setStatus(value) {
  if (statusEl) statusEl.textContent = value;
}

function setBackgroundStatus(value) {
  if (backgroundStatusEl) backgroundStatusEl.textContent = value;
}

function errorCode(error) {
  return error && typeof error === "object" && typeof error.code === "string"
    ? error.code
    : error instanceof Error
      ? error.message
      : String(error);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function eventPayload(event) {
  return isRecord(event?.payload) && isRecord(event.payload.payload) ? event.payload.payload : {};
}

function eventLocalId(event) {
  return isRecord(event?.payload) && typeof event.payload.local_id === "string"
    ? event.payload.local_id
    : "";
}

function documentResourceFromEvent(event) {
  const payload = eventPayload(event);
  const resource = isRecord(payload.resource) ? payload.resource : event?.resource;
  if (!isRecord(resource) || typeof resource.document_id !== "string") return null;
  return { document_id: resource.document_id };
}

function workspaceQueryResourceFromEvent(event) {
  const payload = eventPayload(event);
  const query = isRecord(payload.document_query) ? payload.document_query : {};
  return {
    max_documents: Number.isSafeInteger(query.max_documents)
      ? query.max_documents
      : WORKSPACE_QUERY_LIMIT,
    max_bytes: Number.isSafeInteger(query.max_bytes)
      ? query.max_bytes
      : WORKSPACE_QUERY_MAX_BYTES,
  };
}

function requestOptions(event, resource) {
  const options = {};
  if (typeof event?.executionContextId === "string") {
    options.executionContextId = event.executionContextId;
  }
  if (resource) options.resource = resource;
  return options;
}

function appendSection(value, lines) {
  return `${String(value ?? "").trimEnd()}\n\n${lines.join("\n")}\n`;
}

async function setDocumentValue(runtime, event, value) {
  const resource = documentResourceFromEvent(event);
  if (!resource) throw new Error("document_resource_unavailable");
  await runtime.editor.setValue(
    { document_id: resource.document_id, value },
    requestOptions(event, resource),
  );
}

async function handleActiveRead(runtime, event) {
  const resource = documentResourceFromEvent(event);
  if (!resource) throw new Error("active_document_resource_unavailable");
  const document = await runtime.documents.getActiveDocument({}, requestOptions(event, resource));
  const plaintext = typeof document?.plaintext === "string" ? document.plaintext : "";
  const hasSource = plaintext.includes("active-source-token");
  await runtime.editor.setValue(
    {
      document_id: resource.document_id,
      value: appendSection(plaintext, [
        `ACTIVE_READ_OK: ${hasSource}`,
        `ACTIVE_SOURCE: ${hasSource ? "active-source-token" : "missing"}`,
      ]),
    },
    { resource },
  );
  setStatus("Active read completed");
}

async function handleWorkspaceQuery(runtime, event) {
  const queryResource = workspaceQueryResourceFromEvent(event);
  const result = await runtime.documents.queryWorkspaceDocuments(
    { limit: queryResource.max_documents },
    requestOptions(event, queryResource),
  );
  const documents = Array.isArray(result?.documents) ? result.documents : [];
  const hasSource = documents.some(
    (document) =>
      isRecord(document) &&
      typeof document.plaintext === "string" &&
      document.plaintext.includes("workspace-source-token"),
  );
  await setDocumentValue(
    runtime,
    event,
    [
      "# Document Demo Active Target",
      "",
      "active-source-token",
      "ACTIVE_READ_OK: true",
      "ACTIVE_SOURCE: active-source-token",
      `WORKSPACE_QUERY_OK: ${hasSource}`,
      `WORKSPACE_SOURCE: ${hasSource ? "workspace-source-token" : "missing"}`,
      "",
    ].join("\n"),
  );
  setStatus("Workspace query completed");
}

async function handleMetadataRejected(runtime, event) {
  const resource = documentResourceFromEvent(event);
  if (!resource) throw new Error("document_resource_unavailable");
  try {
    await runtime.editor.setValue(
      {
        document_id: resource.document_id,
        title: "Forbidden Document Demo Title",
        value: "# Forbidden metadata write\n",
      },
      { resource },
    );
    setStatus("Metadata write unexpectedly succeeded");
  } catch (error) {
    setStatus(`Metadata write rejected: ${errorCode(error)}`);
  }
}

async function handleDocumentWrite(runtime, event) {
  await setDocumentValue(
    runtime,
    event,
    [
      "# Document Demo Active Target",
      "",
      "DOCUMENT_DEMO_WRITE_OK",
      "persistent-document-write-token",
      "",
    ].join("\n"),
  );
  setStatus("Document write completed");
}

async function handleCommand(runtime, event) {
  const localId = eventLocalId(event);
  try {
    if (localId === "document-demo-active-read") {
      await handleActiveRead(runtime, event);
    } else if (localId === "document-demo-workspace-query") {
      await handleWorkspaceQuery(runtime, event);
    } else if (localId === "document-demo-metadata-rejected") {
      await handleMetadataRejected(runtime, event);
    } else if (localId === "document-demo-write") {
      await handleDocumentWrite(runtime, event);
    }
    event.respond({ handled: true });
  } catch (error) {
    setStatus(`Document command failed: ${errorCode(error)}`);
    event.respond({ handled: false, error: errorCode(error) });
  }
}

async function verifyBackgroundWorkspaceRead(runtime) {
  try {
    await runtime.documents.queryWorkspaceDocuments({ limit: 1 });
    setBackgroundStatus("Background workspace read unexpectedly succeeded");
  } catch (error) {
    setBackgroundStatus(`Background workspace read rejected: ${errorCode(error)}`);
  }
}

let registered = false;

async function registerDocumentCommands(runtime) {
  if (registered) return;
  registered = true;

  runtime.commands.onInvoke((event) => {
    void handleCommand(runtime, event);
  });

  await runtime.commands.register({
    localId: "document-demo-active-read",
    title: "Document Demo Active Read",
    plaintextRequest: "active_document",
  });
  await runtime.commands.register({
    localId: "document-demo-workspace-query",
    title: "Document Demo Workspace Query",
    documentQuery: {
      scope: "workspace",
      max_documents: WORKSPACE_QUERY_LIMIT,
      max_bytes: WORKSPACE_QUERY_MAX_BYTES,
      reason: "Document demo workspace query",
    },
  });
  await runtime.commands.register({
    localId: "document-demo-metadata-rejected",
    title: "Document Demo Metadata Rejected",
    plaintextRequest: "none",
  });
  await runtime.commands.register({
    localId: "document-demo-write",
    title: "Document Demo Write",
    plaintextRequest: "none",
  });

  setStatus("Document commands registered");
  await verifyBackgroundWorkspaceRead(runtime);
}

function waitForRuntime() {
  const runtime = globalThis.refmd;
  if (!runtime) {
    setStatus("Waiting for RefMD runtime: missing");
    window.setTimeout(waitForRuntime, 25);
    return;
  }

  const register = () => {
    void registerDocumentCommands(runtime).catch((error) => {
      setStatus(`Document command registration failed: ${errorCode(error)}`);
    });
  };

  if (typeof runtime.onload === "function") {
    runtime.onload(register);
    return;
  }

  if (runtime.runtime?.connected === true) {
    register();
    return;
  }

  setStatus("Waiting for RefMD runtime: disconnected");
  window.setTimeout(waitForRuntime, 25);
}

waitForRuntime();

export default {};
