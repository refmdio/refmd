const root = document.createElement("main");
root.setAttribute("aria-label", "RefMD isolation demo plugin");
root.innerHTML = `
  <h1>RefMD Isolation Demo Plugin</h1>
  <p data-role="status">Waiting for isolation checks</p>
`;
document.body.append(root);

const TARGET_URL = "/__refmd-e2e/plugin-sandbox-isolation-targets/probe";
const STATUS_PREFIX = "Isolation checks complete: ";
const PASSIVE_CHECKS = [
  "popup",
  "sandboxLocalStorageAccess",
  "sandboxIndexedDbAccess",
  "sandboxCacheAccess",
  "parentLocalStorageAccess",
  "parentCryptoWorkerAccess",
  "pluginIframeFetch",
  "appOriginSubresourceExfil",
];
const STATUS_KEYS = {
  download: "dl",
  popup: "po",
  formSubmit: "fs",
  sandboxLocalStorageAccess: "sl",
  sandboxIndexedDbAccess: "si",
  sandboxCacheAccess: "sc",
  parentLocalStorageAccess: "pl",
  parentCryptoWorkerAccess: "pc",
  pluginIframeFetch: "pf",
  appOriginSubresourceExfil: "ae",
};
const statusEl = root.querySelector('[data-role="status"]');

function setStatus(value) {
  if (statusEl) statusEl.textContent = value;
}

function result(status, detail) {
  return { status, detail: detail ? String(detail) : "" };
}

function delay(ms) {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

function passWhenRejected(value) {
  return Promise.resolve(value).then(
    () => result("fail", "resolved"),
    (error) => result("pass", error && error.message ? error.message : error),
  );
}

function scheduleDownload() {
  const anchor = document.createElement("a");
  anchor.href = "data:text/plain,plugin-download";
  anchor.download = "plugin-download.txt";
  document.body.append(anchor);
  window.setTimeout(() => anchor.click(), 50);
}

async function checkPopup() {
  const popup = window.open("https://example.invalid/refmd-plugin-popup", "_blank");
  if (popup) {
    popup.close();
    return result("fail", "popup opened");
  }
  return result("pass");
}

function scheduleFormSubmit() {
  const form = document.createElement("form");
  form.method = "POST";
  form.action = TARGET_URL;
  document.body.append(form);
  window.setTimeout(() => form.submit(), 50);
}

async function checkSandboxLocalStorageAccess() {
  try {
    localStorage.setItem("refmd-isolation-demo", "x");
    localStorage.removeItem("refmd-isolation-demo");
    return result("fail", "localStorage writable");
  } catch (error) {
    return result("pass", error && error.message ? error.message : error);
  }
}

async function checkSandboxIndexedDbAccess() {
  try {
    return await new Promise((resolve) => {
      const request = indexedDB.open("refmd-isolation-demo");
      const timeoutId = window.setTimeout(() => resolve(result("pass", "timeout")), 1_000);
      request.onsuccess = () => {
        window.clearTimeout(timeoutId);
        try {
          request.result.close();
          indexedDB.deleteDatabase("refmd-isolation-demo");
        } catch (_) {}
        resolve(result("fail", "indexedDB opened"));
      };
      request.onerror = () => {
        window.clearTimeout(timeoutId);
        resolve(result("pass", request.error && request.error.message));
      };
      request.onblocked = () => {
        window.clearTimeout(timeoutId);
        resolve(result("pass", "blocked"));
      };
    });
  } catch (error) {
    return result("pass", error && error.message ? error.message : error);
  }
}

async function checkSandboxCacheAccess() {
  try {
    if (!("caches" in self)) return result("pass", "cache api unavailable");
    const cacheStorage = self.caches;
    return passWhenRejected(
      cacheStorage.open("refmd-isolation-demo").then((cache) =>
        cacheStorage.delete("refmd-isolation-demo").then(() => cache),
      ),
    );
  } catch (error) {
    return result("pass", error && error.message ? error.message : error);
  }
}

async function checkParentLocalStorageAccess() {
  try {
    const store = window.parent.localStorage;
    store.getItem("refmd-isolation-demo");
    return result("fail", "parent localStorage readable");
  } catch (error) {
    return result("pass", error && error.message ? error.message : error);
  }
}

async function checkParentCryptoWorkerAccess() {
  try {
    const candidate =
      window.parent.cryptoWorkerReady ||
      window.parent.__refmdCryptoWorker ||
      window.parent.__REFMD_CRYPTO_WORKER__;
    if (candidate) return result("fail", "parent worker reference visible");
    return result("pass", "parent worker reference absent");
  } catch (error) {
    return result("pass", error && error.message ? error.message : error);
  }
}

async function checkPluginIframeFetch() {
  return passWhenRejected(fetch(TARGET_URL, { method: "GET", credentials: "omit" }));
}

async function checkAppOriginSubresourceExfil() {
  return await new Promise((resolve) => {
    const image = new Image();
    const timeoutId = window.setTimeout(() => resolve(result("fail", "timeout")), 1_000);
    image.onload = () => {
      window.clearTimeout(timeoutId);
      resolve(result("fail", "image loaded"));
    };
    image.onerror = () => {
      window.clearTimeout(timeoutId);
      resolve(result("pass"));
    };
    image.src = TARGET_URL;
  });
}

async function runCheck(check) {
  if (check === "popup") return checkPopup();
  if (check === "sandboxLocalStorageAccess") return checkSandboxLocalStorageAccess();
  if (check === "sandboxIndexedDbAccess") return checkSandboxIndexedDbAccess();
  if (check === "sandboxCacheAccess") return checkSandboxCacheAccess();
  if (check === "parentLocalStorageAccess") return checkParentLocalStorageAccess();
  if (check === "parentCryptoWorkerAccess") return checkParentCryptoWorkerAccess();
  if (check === "pluginIframeFetch") return checkPluginIframeFetch();
  if (check === "appOriginSubresourceExfil") return checkAppOriginSubresourceExfil();
  return result("fail", "unknown check");
}

async function runCheckWithTimeout(check) {
  return await Promise.race([
    runCheck(check).catch((error) =>
      result("pass", error && error.message ? error.message : error),
    ),
    new Promise((resolve) =>
      window.setTimeout(() => resolve(result("fail", `${check} timed out`)), 3_000),
    ),
  ]);
}

function compactResults(results) {
  return Object.fromEntries(
    Object.entries(results).map(([check, value]) => [
      STATUS_KEYS[check] || check,
      value && value.status,
    ]),
  );
}

async function runChecks(runtime) {
  const results = {};
  for (const check of PASSIVE_CHECKS) {
    setStatus(`Running ${check}`);
    results[check] = await runCheckWithTimeout(check);
    setStatus(`Completed ${check}: ${results[check].status}`);
  }
  results.download = result("attempted");
  results.formSubmit = result("attempted");
  const finalStatus = `${STATUS_PREFIX}${JSON.stringify(compactResults(results))}`;
  setStatus(finalStatus);
  await runtime.ui.status.registerItem({
    localId: "isolation-status",
    label: "Isolation Demo Status",
    zone: "normal",
    value: { kind: "text", text: finalStatus },
    maxWidth: 640,
  });
  await delay(100);
  scheduleDownload();
  scheduleFormSubmit();
}

function waitForRuntime() {
  const runtime = globalThis.refmd;
  if (!runtime || typeof runtime.onload !== "function") {
    window.setTimeout(waitForRuntime, 25);
    return;
  }
  runtime.onload(() => {
    void runChecks(runtime).catch((error) => {
      const message = error && error.message ? error.message : String(error);
      setStatus(`Isolation checks failed: ${message}`);
    });
  });
}

waitForRuntime();

export default {};
