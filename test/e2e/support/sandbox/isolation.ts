import {
  type Page,
  type Response,
  type Route,
} from "@playwright/test";
import { safePageFrames } from "../plugin/diagnostics";
import { E2E_DELAYS } from "../timeouts";

export const PLUGIN_SANDBOX_ISOLATION_CHECKS = [
  "download",
  "popup",
  "formSubmit",
  "sandboxLocalStorageAccess",
  "sandboxIndexedDbAccess",
  "sandboxCacheAccess",
  "parentLocalStorageAccess",
  "parentCryptoWorkerAccess",
  "pluginIframeFetch",
  "appOriginSubresourceExfil",
] as const;

export const PLUGIN_SANDBOX_ISOLATION_PLUGIN_ID = "io.refmd.isolation-demo";
export const PLUGIN_SANDBOX_ISOLATION_FIXTURE = "refmd-isolation-demo";

const PLUGIN_SANDBOX_ISOLATION_TARGET_PATTERN =
  /\/__refmd-e2e\/plugin-sandbox-isolation-targets\/probe(?:\?|$)/;
const PLUGIN_SANDBOX_ISOLATION_STATUS_PREFIX = "Isolation checks complete: ";
const PLUGIN_SANDBOX_ISOLATION_STATUS_ALIASES: Record<
  string,
  PluginSandboxIsolationCheck
> = {
  dl: "download",
  po: "popup",
  fs: "formSubmit",
  sl: "sandboxLocalStorageAccess",
  si: "sandboxIndexedDbAccess",
  sc: "sandboxCacheAccess",
  pl: "parentLocalStorageAccess",
  pc: "parentCryptoWorkerAccess",
  pf: "pluginIframeFetch",
  ae: "appOriginSubresourceExfil",
};

export type PluginSandboxIsolationCheck = (typeof PLUGIN_SANDBOX_ISOLATION_CHECKS)[number];

export type PluginSandboxIsolationResults = Record<PluginSandboxIsolationCheck, boolean>;

type ProbeStatus = "attempted" | "pass" | "fail";

type ProbeResult = {
  status?: ProbeStatus;
  detail?: string;
};

type SandboxDocumentResponse = {
  status: number;
  url: string;
  contentSecurityPolicy: string;
  cacheControl: string;
  referrerPolicy: string;
  xFrameOptions?: string;
};

export type PluginSandboxIsolationObservation = {
  consoleMessages: string[];
  documents: SandboxDocumentResponse[];
  downloaded: boolean;
  popupOpened: boolean;
  probeResults: Partial<Record<PluginSandboxIsolationCheck, ProbeResult>>;
  requests: string[];
  results: PluginSandboxIsolationResults;
  sandboxFrameUrls: string[];
  statusText: string;
  unexpectedConsoleErrors: string[];
};

export type PluginSandboxIsolationWatcher = {
  diagnostic: () => string;
  result: () => Promise<PluginSandboxIsolationObservation>;
  stop: () => Promise<void>;
};

export function emptyPluginSandboxIsolationResults(): PluginSandboxIsolationResults {
  return {
    download: false,
    popup: false,
    formSubmit: false,
    sandboxLocalStorageAccess: false,
    sandboxIndexedDbAccess: false,
    sandboxCacheAccess: false,
    parentLocalStorageAccess: false,
    parentCryptoWorkerAccess: false,
    pluginIframeFetch: false,
    appOriginSubresourceExfil: false,
  };
}

export async function watchRealPluginSandboxIsolation(
  page: Page,
): Promise<PluginSandboxIsolationWatcher> {
  const requests: string[] = [];
  const documents: SandboxDocumentResponse[] = [];
  const consoleMessages: string[] = [];
  const unexpectedConsoleErrors: string[] = [];
  let downloaded = false;
  let popupOpened = false;

  const routeHandler = (route: Route) => {
    requests.push(route.request().url());
    void route.abort();
  };
  await page.route(PLUGIN_SANDBOX_ISOLATION_TARGET_PATTERN, routeHandler);

  const consoleHandler = (message: { type(): string; text(): string }) => {
    consoleMessages.push(`${message.type()} ${message.text()}`);
    if (consoleMessages.length > 80) consoleMessages.shift();
    if (message.type() !== "error") return;
    const text = message.text();
    if (isExpectedIsolationConsole(text)) return;
    if (
      text.includes("Content Security Policy") ||
      text.includes("Content-Security-Policy") ||
      text.includes("PluginSandboxRuntimeError") ||
      text.includes("Plugin runtime boundary could not be started")
    ) {
      unexpectedConsoleErrors.push(text);
    }
  };
  page.on("console", consoleHandler);
  const pageErrorHandler = (error: Error) => {
    consoleMessages.push(`pageerror ${error.message}`);
    if (consoleMessages.length > 80) consoleMessages.shift();
  };
  page.on("pageerror", pageErrorHandler);

  const responseHandler = (response: Response) => {
    const url = response.url();
    if (!/\/api\/plugin-runtime\/sandbox-documents\/[^/?]+$/.test(new URL(url).pathname)) {
      return;
    }
    const headers = response.headers();
    documents.push({
      status: response.status(),
      url,
      contentSecurityPolicy: headers["content-security-policy"] ?? "",
      cacheControl: headers["cache-control"] ?? "",
      referrerPolicy: headers["referrer-policy"] ?? "",
      xFrameOptions: headers["x-frame-options"],
    });
  };
  page.on("response", responseHandler);

  const downloadHandler = () => {
    downloaded = true;
  };
  page.on("download", downloadHandler);

  const popupHandler = (popup: Page) => {
    popupOpened = true;
    void popup.close().catch(() => undefined);
  };
  page.on("popup", popupHandler);

  const diagnostic = () =>
    JSON.stringify(
      {
        consoleMessages,
        documents,
        downloaded,
        popupOpened,
        requests,
        unexpectedConsoleErrors,
      },
      null,
      2,
    );

  return {
    diagnostic,
    async result() {
      const statusProbe = await waitForStatusProbeResults(page);
      const probeResults = statusProbe.results;
      await page.waitForTimeout(E2E_DELAYS.editorSettle);
      const sandboxFrameUrls = safePageFrames(page)
        .map((frame) => frame.url())
        .filter((url) => url.includes("/api/plugin-runtime/sandbox-documents/"));
      const results = computeIsolationResults({
        downloaded,
        popupOpened,
        probeResults,
        requests,
        sandboxFrameUrls,
      });
      return {
        consoleMessages,
        documents,
        downloaded,
        popupOpened,
        probeResults,
        requests,
        results,
        sandboxFrameUrls,
        statusText: statusProbe.text,
        unexpectedConsoleErrors,
      };
    },
    async stop() {
      page.off("console", consoleHandler);
      page.off("pageerror", pageErrorHandler);
      page.off("response", responseHandler);
      page.off("download", downloadHandler);
      page.off("popup", popupHandler);
      await page.unroute(PLUGIN_SANDBOX_ISOLATION_TARGET_PATTERN, routeHandler).catch(() => {});
    },
  };
}

async function waitForStatusProbeResults(
  page: Page,
): Promise<{
  results: Partial<Record<PluginSandboxIsolationCheck, ProbeResult>>;
  text: string;
}> {
  const deadline = Date.now() + 120_000;
  let lastText = "";
  while (Date.now() < deadline) {
    const texts = await currentIsolationStatusTexts(page);
    lastText = texts.find(Boolean) ?? lastText;
    for (const text of texts) {
      const index = text.indexOf(PLUGIN_SANDBOX_ISOLATION_STATUS_PREFIX);
      if (index >= 0) {
        return {
          results: parseStatusProbeResults(
            text.slice(index + PLUGIN_SANDBOX_ISOLATION_STATUS_PREFIX.length),
          ),
          text,
        };
      }
    }
    await page.waitForTimeout(E2E_DELAYS.uiSettle);
  }
  return { results: {}, text: lastText };
}

async function currentIsolationStatusTexts(page: Page): Promise<string[]> {
  const texts: string[] = [];
  const status = page.locator('.status-bar-item[aria-label="Isolation Demo Status"]');
  const statusBarText = await status.textContent({ timeout: 100 }).catch(() => "");
  if (statusBarText) texts.push(statusBarText);

  for (const frame of safePageFrames(page)) {
    if (!frame.url().includes("/api/plugin-runtime/sandbox-documents/")) continue;
    const frameStatusText = await frame
      .locator('[data-role="status"]')
      .textContent({ timeout: 100 })
      .catch(() => "");
    if (frameStatusText) texts.push(frameStatusText);
  }

  return texts;
}

function parseStatusProbeResults(
  value: string,
): Partial<Record<PluginSandboxIsolationCheck, ProbeResult>> {
  try {
    const decoded = JSON.parse(value) as Partial<Record<PluginSandboxIsolationCheck, ProbeStatus>>;
    return Object.fromEntries(
      Object.entries(decoded).map(([check, status]) => [
        PLUGIN_SANDBOX_ISOLATION_STATUS_ALIASES[check] ?? check,
        { status },
      ]),
    ) as Partial<Record<PluginSandboxIsolationCheck, ProbeResult>>;
  } catch {
    return {};
  }
}

export function assertServedSandboxDocumentResponses(
  documents: SandboxDocumentResponse[],
): string[] {
  const failures: string[] = [];
  if (documents.length === 0) {
    failures.push("no sandbox document response was observed");
    return failures;
  }

  for (const document of documents) {
    if (document.status !== 200) {
      failures.push(`${document.url} status=${document.status}`);
    }
    if (document.xFrameOptions !== undefined) {
      failures.push(`${document.url} x-frame-options=${document.xFrameOptions}`);
    }
    if (!document.cacheControl.includes("no-store")) {
      failures.push(`${document.url} cache-control=${document.cacheControl}`);
    }
    if (document.referrerPolicy !== "no-referrer") {
      failures.push(`${document.url} referrer-policy=${document.referrerPolicy}`);
    }
    if (!document.contentSecurityPolicy.includes("sandbox allow-scripts")) {
      failures.push(`${document.url} missing sandbox allow-scripts`);
    }
    if (!document.contentSecurityPolicy.includes("frame-ancestors 'self'")) {
      failures.push(`${document.url} missing frame-ancestors 'self'`);
    }
    if (!document.contentSecurityPolicy.includes("connect-src 'none'")) {
      failures.push(`${document.url} missing connect-src 'none'`);
    }
    if (!document.contentSecurityPolicy.includes("frame-src 'none'")) {
      failures.push(`${document.url} missing frame-src 'none'`);
    }
    if (!document.contentSecurityPolicy.includes("form-action 'none'")) {
      failures.push(`${document.url} missing form-action 'none'`);
    }
    if (!document.contentSecurityPolicy.includes("worker-src 'none'")) {
      failures.push(`${document.url} missing worker-src 'none'`);
    }
    if (!document.contentSecurityPolicy.includes("script-src 'sha256-")) {
      failures.push(`${document.url} missing hashed script-src`);
    }
  }
  return failures;
}

function computeIsolationResults(input: {
  downloaded: boolean;
  popupOpened: boolean;
  probeResults: Partial<Record<PluginSandboxIsolationCheck, ProbeResult>>;
  requests: string[];
  sandboxFrameUrls: string[];
}): PluginSandboxIsolationResults {
  const results = emptyPluginSandboxIsolationResults();
  const probeStatus = (check: PluginSandboxIsolationCheck) => input.probeResults[check]?.status;
  const noTargetRequests = input.requests.length === 0;
  const realSandboxFrameStillLoaded = input.sandboxFrameUrls.length > 0;

  results.download = probeStatus("download") === "attempted" && !input.downloaded;
  results.popup = probeStatus("popup") === "pass" && !input.popupOpened;
  results.formSubmit =
    probeStatus("formSubmit") === "attempted" && noTargetRequests && realSandboxFrameStillLoaded;
  results.sandboxLocalStorageAccess = probeStatus("sandboxLocalStorageAccess") === "pass";
  results.sandboxIndexedDbAccess = probeStatus("sandboxIndexedDbAccess") === "pass";
  results.sandboxCacheAccess = probeStatus("sandboxCacheAccess") === "pass";
  results.parentLocalStorageAccess = probeStatus("parentLocalStorageAccess") === "pass";
  results.parentCryptoWorkerAccess = probeStatus("parentCryptoWorkerAccess") === "pass";
  results.pluginIframeFetch = probeStatus("pluginIframeFetch") === "pass" && noTargetRequests;
  results.appOriginSubresourceExfil =
    probeStatus("appOriginSubresourceExfil") === "pass" && noTargetRequests;

  return results;
}

function isExpectedIsolationConsole(text: string): boolean {
  return (
    (text.includes("data:text/plain,plugin-download") &&
      (text.includes("frame-src 'self'") || text.includes("frame-src 'none'"))) ||
    (text.includes("/__refmd-e2e/plugin-sandbox-isolation-targets/probe") &&
      (text.includes("connect-src 'none'") ||
        text.includes("img-src blob: data:") ||
        text.includes("form-action 'none'") ||
        text.includes("frame-src 'none'") ||
        text.includes("Refused to connect") ||
        text.includes("Refused to load the image") ||
        text.includes("Refused to send form data")))
  );
}
