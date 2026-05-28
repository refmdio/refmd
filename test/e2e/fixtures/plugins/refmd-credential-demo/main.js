const root = document.createElement("main");
root.setAttribute("aria-label", "Handle demo plugin");
root.innerHTML = `
  <h1>Handle Demo Plugin</h1>
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

function eventLocalId(event) {
  return isRecord(event?.payload) && typeof event.payload.local_id === "string"
    ? event.payload.local_id
    : "";
}

async function setHostStatus(runtime, value) {
  const descriptor = {
    localId: "credential-demo-status",
    label: "Handle Demo Status",
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

async function setPluginStatus(runtime, frameValue, hostValue = frameValue) {
  setStatus(frameValue);
  await setHostStatus(runtime, hostValue);
}

function responseOk(response) {
  return (
    isRecord(response) &&
    response.status === 200 &&
    response.body_text === "credential-demo-response"
  );
}

function secretVisible(handleResponse) {
  if (!isRecord(handleResponse)) return false;
  if ("secret" in handleResponse || "token" in handleResponse || "value" in handleResponse) {
    return true;
  }
  return JSON.stringify(handleResponse).includes("refmd-e2e-secret");
}

async function runCredentialFetch(runtime) {
  setStatus("Handle request started");
  let handleResponse;
  try {
    handleResponse = await runtime.credential.use({
      credential_id: "api-key",
      audience: "api.refmd-e2e.example",
      endpoint: "https://api.refmd-e2e.example/v1/credential-demo",
      method: "POST",
    });
  } catch (error) {
    const code = errorCode(error);
    if (code === "credential_not_found") {
      await setPluginStatus(
        runtime,
        `Handle failed: missing handle (${code})`,
        "Handle failed: missing handle",
      );
    } else {
      await setPluginStatus(runtime, `Handle failed: ${code}`);
    }
    return;
  }

  const handle = isRecord(handleResponse) ? handleResponse.handle : null;
  if (typeof handle !== "string") {
    await setPluginStatus(
      runtime,
      "Handle failed: missing handle (credential_handle_missing)",
      "Handle failed: missing handle",
    );
    return;
  }

  const response = await runtime.network.fetch({
    endpoint_id: "credential-demo-api",
    route: "proxy",
    method: "POST",
    headers: { "content-type": "application/json" },
    body_json: { demo: "credential" },
    credential_handle: handle,
  });
  const value = `HANDLE_OK: ${responseOk(response)} secretVisible=${secretVisible(handleResponse)}`;
  setStatus(value);
  await setHostStatus(runtime, value);
}

async function handleCommand(runtime, event) {
  try {
    const localId = eventLocalId(event);
    if (localId === "credential-demo-run") {
      await runCredentialFetch(runtime);
    }
    event.respond({ handled: true });
  } catch (error) {
    const code = errorCode(error);
    const value = `Handle failed: ${code}`;
    const hostValue =
      code === "credential_not_found" ? "Handle failed: missing handle" : value;
    setStatus(value);
    await setHostStatus(runtime, hostValue).catch(() => undefined);
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
    localId: "credential-demo-run",
    title: "Handle Demo Run",
    plaintextRequest: "none",
  });
  setStatus("Handle command registered");
  await setHostStatus(runtime, "Handle Demo Ready");
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
      setStatus(`Handle command registration failed: ${errorCode(error)}`);
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
