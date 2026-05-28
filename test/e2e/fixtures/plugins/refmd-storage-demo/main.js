const STORAGE_KEY = "storage-demo-values";
const CACHE_KEY = "storage-demo-cache";
const WORKSPACE_KEY = "storage-demo-workspace";
const DOCUMENT_KEY = "storage-demo-document";
const WORKSPACE_RECORD_KIND = "storage-demo-workspace-record";
const DOCUMENT_RECORD_KIND = "storage-demo-document-record";

const root = document.createElement("main");
root.setAttribute("aria-label", "RefMD storage demo plugin");
root.innerHTML = `
  <h1>RefMD Storage Demo Plugin</h1>
  <p data-role="status">Waiting for RefMD runtime</p>
`;
document.body.append(root);

const statusEl = root.querySelector('[data-role="status"]');
let statusHandle = null;
let registered = false;

function setStatus(value) {
  if (statusEl) statusEl.textContent = value;
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function errorCode(error) {
  return error && typeof error === "object" && typeof error.code === "string"
    ? error.code
    : error instanceof Error
      ? error.message
      : String(error);
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

function requestOptions(event, resource) {
  const options = {};
  if (typeof event?.executionContextId === "string") {
    options.executionContextId = event.executionContextId;
  }
  if (resource) options.resource = resource;
  return options;
}

function storageValue(response) {
  return isRecord(response) && isRecord(response.value) ? response.value : null;
}

function recordValue(response) {
  return isRecord(response) && isRecord(response.value) ? response.value : null;
}

function hasOkValue(value) {
  return isRecord(value) && value.ok === true;
}

async function setHostStatus(runtime, value) {
  const descriptor = {
    localId: "storage-demo-status",
    label: "Storage Demo Status",
    zone: "normal",
    value: { kind: "text", text: value },
    maxWidth: 560,
  };
  if (!statusHandle) {
    statusHandle = await runtime.ui.status.registerItem(descriptor);
    return;
  }
  await runtime.ui.status.updateItem(descriptor);
}

async function runStorageStep(label, task) {
  setStatus(`Storage ${label} started`);
  try {
    return await task();
  } catch (error) {
    throw new Error(`${label}:${errorCode(error)}`);
  }
}

async function writeStorageValues(runtime, event) {
  const resource = documentResourceFromEvent(event);
  if (!resource) throw new Error("document_resource_unavailable");
  const options = requestOptions(event, resource);
  setStatus("Storage write started");

  const workspaceRecord = await runStorageStep("workspace_record_create", () =>
    runtime.storage.workspace.recordCreate({
      kind: WORKSPACE_RECORD_KIND,
      value: { ok: true, surface: "workspace-record" },
    }),
  );
  const documentRecord = await runStorageStep("document_record_create", () =>
    runtime.storage.document.recordCreate(
      {
        document_id: resource.document_id,
        kind: DOCUMENT_RECORD_KIND,
        value: { ok: true, surface: "document-record" },
      },
      options,
    ),
  );
  const value = {
    ok: true,
    workspaceRecordId: workspaceRecord.record_id,
    documentRecordId: documentRecord.record_id,
  };

  await runStorageStep("user_local_set", () =>
    runtime.storage.userLocal.set({ key: STORAGE_KEY, value }),
  );
  await runStorageStep("cache_set", () =>
    runtime.storage.cache.set({ key: CACHE_KEY, value: { ok: true } }),
  );
  await runStorageStep("workspace_set", () =>
    runtime.storage.workspace.set({ key: WORKSPACE_KEY, value }),
  );
  await runStorageStep("document_set", () =>
    runtime.storage.document.set(
      {
        document_id: resource.document_id,
        key: DOCUMENT_KEY,
        value,
      },
      options,
    ),
  );
  setStatus("Storage write stored values");
  await setHostStatus(runtime, "STORAGE_WRITE_OK");
  setStatus("Storage write completed");
}

async function readStorageValues(runtime, event) {
  const resource = documentResourceFromEvent(event);
  if (!resource) throw new Error("document_resource_unavailable");
  const options = requestOptions(event, resource);
  setStatus("Storage read started");

  const userLocal = storageValue(
    await runStorageStep("user_local_get", () => runtime.storage.userLocal.get({ key: STORAGE_KEY })),
  );
  const cache = storageValue(
    await runStorageStep("cache_get", () => runtime.storage.cache.get({ key: CACHE_KEY })),
  );
  const workspace = storageValue(
    await runStorageStep("workspace_get", () => runtime.storage.workspace.get({ key: WORKSPACE_KEY })),
  );
  const documentValue = storageValue(
    await runStorageStep("document_get", () =>
      runtime.storage.document.get(
      {
        document_id: resource.document_id,
        key: DOCUMENT_KEY,
      },
      options,
      ),
    ),
  );
  setStatus("Storage read loaded values");
  const refs = workspace ?? userLocal;
  const workspaceRecordId = isRecord(refs) ? refs.workspaceRecordId : null;
  const documentRecordId = isRecord(refs) ? refs.documentRecordId : null;
  const workspaceRecord =
    typeof workspaceRecordId === "string"
      ? recordValue(
          await runStorageStep("workspace_record_get", () =>
            runtime.storage.workspace.recordGet({ record_id: workspaceRecordId }),
          ),
        )
      : null;
  const documentRecord =
    typeof documentRecordId === "string"
      ? recordValue(
          await runStorageStep("document_record_get", () =>
            runtime.storage.document.recordGet(
              {
                document_id: resource.document_id,
                record_id: documentRecordId,
              },
              options,
            ),
          ),
        )
      : null;

  const userLocalOk = hasOkValue(userLocal);
  const cacheOk = hasOkValue(cache);
  const workspaceOk = hasOkValue(workspace);
  const documentOk = hasOkValue(documentValue);
  const workspaceRecordOk = hasOkValue(workspaceRecord);
  const documentRecordOk = hasOkValue(documentRecord);
  const localOk = userLocalOk && cacheOk;
  const serverOk = workspaceOk && documentOk;
  const localRecordOk =
    isRecord(userLocal) &&
    typeof userLocal.workspaceRecordId === "string" &&
    typeof userLocal.documentRecordId === "string";
  const readOk =
    localOk && serverOk && localRecordOk && workspaceRecordOk && documentRecordOk;
  const tokens = [
    userLocalOk ? "UL" : "NO_UL",
    cacheOk ? "CACHE" : "NO_CACHE",
    workspaceOk ? "WS" : "NO_WS",
    documentOk ? "DOC" : "NO_DOC",
    workspaceRecordOk ? "WREC" : "NO_WREC",
    documentRecordOk ? "DREC" : "NO_DREC",
  ].join(" ");
  const value = `STORAGE_READ_OK: ${readOk} LOCAL_OK: ${localOk} SERVER_OK: ${serverOk} LOCAL_RECORD_OK: ${localRecordOk} ${tokens}`;
  setStatus(value);
  await setHostStatus(runtime, value);
}

async function handleCommand(runtime, event) {
  try {
    const localId = eventLocalId(event);
    if (localId === "storage-demo-write") {
      await writeStorageValues(runtime, event);
    } else if (localId === "storage-demo-read") {
      await readStorageValues(runtime, event);
    }
    event.respond({ handled: true });
  } catch (error) {
    const code = errorCode(error);
    const value = `Storage command failed: ${code}`;
    setStatus(value);
    await setHostStatus(runtime, value).catch(() => undefined);
    event.respond({ handled: false, error: code });
  }
}

async function registerRuntime(runtime) {
  if (registered) return;
  registered = true;

  runtime.commands.onInvoke((event) => {
    void handleCommand(runtime, event);
  });
  await runtime.commands.register({
    localId: "storage-demo-write",
    title: "Storage Demo Write Values",
    plaintextRequest: "none",
  });
  await runtime.commands.register({
    localId: "storage-demo-read",
    title: "Storage Demo Read Values",
    plaintextRequest: "none",
  });
  setStatus("Storage commands registered");
  await setHostStatus(runtime, "Storage Demo Ready");
}

function waitForRuntime() {
  const runtime = globalThis.refmd;
  if (!runtime) {
    setStatus("Waiting for RefMD runtime: missing");
    window.setTimeout(waitForRuntime, 25);
    return;
  }

  const register = () => {
    void registerRuntime(runtime).catch((error) => {
      setStatus(`Storage command registration failed: ${errorCode(error)}`);
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
