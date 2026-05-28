const root = document.createElement("main");
root.setAttribute("aria-label", "RefMD network demo plugin");
root.innerHTML = `
  <h1>RefMD Network Demo Plugin</h1>
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
    localId: "network-demo-status",
    label: "Network Demo Status",
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

function networkFetchPayload(overrides = {}) {
  return {
    endpoint_id: "network-demo-api",
    route: "proxy",
    method: "POST",
    headers: { "content-type": "application/json" },
    body_json: { demo: "network" },
    ...overrides,
  };
}

async function runProxyFetch(runtime) {
  const response = await runtime.network.fetch(networkFetchPayload());
  const ok =
    isRecord(response) &&
    response.status === 200 &&
    response.body_text === "network-demo-response";
  await setHostStatus(runtime, `NETWORK_PROXY_OK: ${ok}`);
}

async function runRejectedRoutes(runtime) {
  let routeCode = "missing";
  let proxyCode = "missing";
  try {
    await runtime.network.fetch(networkFetchPayload({ route: "direct" }));
  } catch (error) {
    routeCode = errorCode(error);
  }
  try {
    await runtime.network.fetch(networkFetchPayload({ proxy_url: "https://proxy.invalid/refmd" }));
  } catch (error) {
    proxyCode = errorCode(error);
  }
  const ok = routeCode === "network_route_unavailable" && proxyCode === "plugin_proxy_forbidden";
  const value = `NETWORK_REJECT_OK: ${ok} ${routeCode} ${proxyCode}`;
  setStatus(value);
  await setHostStatus(runtime, value);
}

async function runPendingFetch(runtime) {
  setStatus("NETWORK_PENDING_STARTED");
  await setHostStatus(runtime, "NETWORK_PENDING_STARTED");
  void runtime.network
    .fetch(networkFetchPayload({ body_json: { demo: "pending" } }))
    .then((response) => {
      const ok =
        isRecord(response) &&
        response.status === 200 &&
        response.body_text === "network-demo-response";
      setStatus(`NETWORK_PENDING_COMPLETED: ${ok}`);
    })
    .catch((error) => {
      setStatus(`NETWORK_PENDING_CLOSED: ${errorCode(error)}`);
    });
}

async function handleCommand(runtime, event) {
  try {
    const localId = eventLocalId(event);
    if (localId === "network-demo-proxy-fetch") {
      await runProxyFetch(runtime);
    } else if (localId === "network-demo-rejected-routes") {
      await runRejectedRoutes(runtime);
    } else if (localId === "network-demo-pending-fetch") {
      await runPendingFetch(runtime);
    }
    event.respond({ handled: true });
  } catch (error) {
    const code = errorCode(error);
    const value = `Network command failed: ${code}`;
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
    localId: "network-demo-proxy-fetch",
    title: "Network Demo Proxy Fetch",
    plaintextRequest: "none",
  });
  await runtime.commands.register({
    localId: "network-demo-rejected-routes",
    title: "Network Demo Rejected Routes",
    plaintextRequest: "none",
  });
  await runtime.commands.register({
    localId: "network-demo-pending-fetch",
    title: "Network Demo Pending Fetch",
    plaintextRequest: "none",
  });
  setStatus("Network commands registered");
  await setHostStatus(runtime, "Network Demo Ready");
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
      setStatus(`Network command registration failed: ${errorCode(error)}`);
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
