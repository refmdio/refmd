import { type Page } from "@playwright/test";

export async function pluginRuntimeDiagnostic(page: Page): Promise<string> {
  return page
    .evaluate(() => {
      const dialogText = Array.from(document.querySelectorAll('[role="dialog"]'))
        .map((node) => node.textContent?.replace(/\s+/g, " ").trim())
        .filter(Boolean)
        .join(" | ");
      const debug = window.__refmdPluginRuntimeDebug;
      const e2eNetworkFailures = (window as Window & {
        __refmdE2ENetworkFailures?: string[];
      }).__refmdE2ENetworkFailures;
      return JSON.stringify({
        applications: debug?.applications ?? null,
        boundary: window.__refmdPluginRuntimeBoundaryDebug ?? null,
        dialogText: dialogText || null,
        networkFailures: e2eNetworkFailures ?? null,
        registry: debug?.rendererRegistry ?? null,
        url: location.href,
      });
    })
    .catch((error) => `diagnostic_failed:${error instanceof Error ? error.message : String(error)}`);
}

export function safePageFrames(page: Page) {
  try {
    return page.frames();
  } catch {
    return [];
  }
}

export function isPluginRuntimeFailureResponse(response: { url: () => string; status: () => number }) {
  if (response.status() < 400) return false;
  const url = response.url();
  if (url.includes("/api/plugin-runtime/")) return true;
  if (url.includes("/plugin-runtime-audit")) return true;
  return /\/api\/workspaces\/[^/]+\/plugin-runtime(?:\/|\?|$)/.test(url);
}

export async function pluginRuntimeFailureText(response: {
  url: () => string;
  status: () => number;
  text: () => Promise<string>;
}): Promise<string> {
  let body = "";
  try {
    body = await response.text();
  } catch {
    body = "";
  }
  return [response.status(), response.url(), body].filter(Boolean).join(" ");
}

function isBrowserCancelledRequestFailure(errorText: string): boolean {
  return errorText.includes("net::ERR_ABORTED") || errorText.includes("NS_BINDING_ABORTED");
}

export function summarizeRuntimeAuditBody(body: string): string {
  if (!body) return "";
  try {
    const audit = JSON.parse(body) as {
      type?: unknown;
      frame_scope?: unknown;
      frame_generation?: unknown;
      application_id?: unknown;
      state_head_hash?: unknown;
      consent_head_hash?: unknown;
      action?: { operation?: unknown; result?: unknown; reason_code?: unknown };
    };
    return [
      typeof audit.type === "string" ? `type=${audit.type}` : "",
      typeof audit.frame_scope === "string" ? `frame_scope=${audit.frame_scope}` : "",
      typeof audit.frame_generation === "number"
        ? `frame_generation=${audit.frame_generation}`
        : "",
      typeof audit.application_id === "string" ? `application_id=${audit.application_id}` : "",
      typeof audit.state_head_hash === "string"
        ? `state=${audit.state_head_hash.slice(0, 12)}`
        : "",
      typeof audit.consent_head_hash === "string"
        ? `consent=${audit.consent_head_hash.slice(0, 12)}`
        : "",
      typeof audit.action?.operation === "string" ? `operation=${audit.action.operation}` : "",
      typeof audit.action?.result === "string" ? `result=${audit.action.result}` : "",
      typeof audit.action?.reason_code === "string"
        ? `reason_code=${audit.action.reason_code}`
        : "",
    ]
      .filter(Boolean)
      .join(" ");
  } catch {
    return body.slice(0, 1_000);
  }
}

export async function watchPluginRuntimeFailures(page: Page): Promise<() => string[]> {
  const failures: string[] = [];
  const requestBodies = new WeakMap<object, string>();
  const recentAuditBodies: string[] = [];
  const recentSandboxSessions: string[] = [];
  const rememberDiagnostic = (entry: string) => {
    void page
      .evaluate((value) => {
        const target = window as Window & { __refmdE2ENetworkFailures?: string[] };
        target.__refmdE2ENetworkFailures = [...(target.__refmdE2ENetworkFailures ?? []), value].slice(
          -20,
        );
      }, entry)
      .catch(() => undefined);
  };
  const rememberFailure = (entry: string) => {
    failures.push(entry);
    rememberDiagnostic(entry);
  };

  await page.route(/\/plugin-runtime-audit(?:\?.*)?$/, async (route) => {
    const request = route.request();
    const body = request.postData() ?? "";
    requestBodies.set(request, body);
    recentAuditBodies.push(body);
    if (recentAuditBodies.length > 8) recentAuditBodies.shift();
    await route.fallback();
  });

  page.on("request", (request) => {
    if (!request.url().includes("/plugin-runtime-audit")) return;
    const body = request.postData() ?? "";
    requestBodies.set(request, body);
    recentAuditBodies.push(body);
    if (recentAuditBodies.length > 8) recentAuditBodies.shift();
  });

  page.on("console", (message) => {
    const text = message.text();
    if (message.type() !== "error") return;
    if (
      text.includes("Plugin runtime boundary could not be started") ||
      text.includes("PluginSandboxRuntimeError") ||
      text.includes("plugin capability issuance audit event could not be recorded") ||
      text.includes("approval_authority_") ||
      text.includes("Content Security Policy") ||
      text.includes("Content-Security-Policy") ||
      text.includes("violates the following Content Security Policy directive") ||
      text.includes("Refused to execute")
    ) {
      rememberFailure(text);
    }
  });

  page.on("requestfailed", (request) => {
    const errorText = request.failure()?.errorText ?? "";
    const entry = `requestfailed ${request.url()} ${errorText}`;
    rememberDiagnostic(entry);
    if (isBrowserCancelledRequestFailure(errorText)) return;
    if (
      request.url().includes("/api/plugin-runtime/") ||
      /\/api\/workspaces\/[^/]+\/plugin-runtime(?:\/|\?|$)/.test(request.url())
    ) {
      failures.push(entry);
    }
  });

  page.on("response", (response) => {
    if (
      response.request().method() === "POST" &&
      response.url().includes("/sandbox-documents")
    ) {
      void response
        .json()
        .then((body: unknown) => {
          const requestBody = response.request().postDataJSON() as
            | {
                state_head_hash?: unknown;
                consent_head_hash?: unknown;
                frame_scope?: unknown;
              }
            | null;
          const session = body as {
            frame_scope?: unknown;
            frame_generation?: unknown;
            application_id?: unknown;
            state_head_hash?: unknown;
            consent_head_hash?: unknown;
          };
          recentSandboxSessions.push(
            [
              typeof session.frame_scope === "string" ? `session_scope=${session.frame_scope}` : "",
              typeof session.frame_generation === "number"
                ? `session_frame=${session.frame_generation}`
                : "",
              typeof session.application_id === "string"
                ? `session_application=${session.application_id}`
                : "",
              typeof requestBody?.frame_scope === "string"
                ? `request_scope=${requestBody.frame_scope}`
                : "",
              typeof requestBody?.state_head_hash === "string"
                ? `request_state=${requestBody.state_head_hash.slice(0, 12)}`
                : "",
              typeof requestBody?.consent_head_hash === "string"
                ? `request_consent=${requestBody.consent_head_hash.slice(0, 12)}`
                : "",
            ]
              .filter(Boolean)
              .join(" "),
          );
          if (recentSandboxSessions.length > 8) recentSandboxSessions.shift();
        })
        .catch(() => {});
      return;
    }

    if (isPluginRuntimeFailureResponse(response)) {
      const requestBody =
        requestBodies.get(response.request()) ??
        response.request().postData() ??
        recentAuditBodies.at(-1) ??
        "";
      const requestSummary = summarizeRuntimeAuditBody(requestBody);
      const sessionSummary = recentSandboxSessions.join(" | ");
      const pendingFailure = [
        response.status(),
        response.url(),
        requestSummary,
        sessionSummary,
      ]
        .filter(Boolean)
        .join(" ");
      rememberFailure(pendingFailure);
      void pluginRuntimeFailureText(response).then((failure) => {
        const index = failures.indexOf(pendingFailure);
        if (index >= 0) {
          const expandedFailure = [failure, requestSummary, sessionSummary].filter(Boolean).join(" ");
          failures[index] = expandedFailure;
          rememberDiagnostic(expandedFailure);
        }
      });
    }
  });

  return () => failures;
}
