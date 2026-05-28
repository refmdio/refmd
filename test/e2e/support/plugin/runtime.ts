import { type Page } from "@playwright/test";
import { E2E_DELAYS } from "../timeouts";
import { pluginRuntimeDiagnostic } from "./diagnostics";

export type PluginRuntimeWaitOptions = {
  timeout: number;
  message: string;
  extraDiagnostic?: () => Promise<string> | string;
};

export async function waitForPluginRuntimeApplication(
  page: Page,
  pluginId: string,
  options: PluginRuntimeWaitOptions,
): Promise<void> {
  const deadline = Date.now() + options.timeout;
  while (Date.now() < deadline) {
    if (await pluginRuntimeApplicationLoaded(page, pluginId)) return;
    await page.waitForTimeout(E2E_DELAYS.uiSettle);
  }

  const diagnostic = await pluginRuntimeDiagnostic(page);
  const extraDiagnostic = options.extraDiagnostic ? await options.extraDiagnostic() : "";
  throw new Error(
    `${options.message}: ${diagnostic}${extraDiagnostic ? `\n${extraDiagnostic}` : ""}`,
  );
}

export function installPluginRuntimeApiCapture(page: Page): { summary: () => string } {
  const entries: Array<Record<string, unknown>> = [];
  page.on("response", async (response) => {
    const url = response.url();
    if (
      !/\/api\/workspaces\/[^/]+\/plugin-runtime(?:\/consent-required)?(?:\?|$)/.test(url) &&
      !/\/api\/workspaces\/[^/]+\/plugin-runtime\/sandbox-documents(?:\/|$)/.test(url) &&
      !/\/api\/workspaces\/[^/]+\/plugin-applications(?:\?|$)/.test(url) &&
      !/\/api\/workspaces\/[^/]+\/plugin-applications\/[^/]+\/consent-events(?:\?|$)/.test(url)
    ) {
      return;
    }

    const request = response.request();
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      try {
        body = (await response.text()).slice(0, 1_000);
      } catch {
        body = "body_unavailable";
      }
    }
    entries.push({
      body,
      method: request.method(),
      status: response.status(),
      url: url.replace(/[?].*$/, ""),
    });
    if (entries.length > 80) entries.shift();
  });

  return {
    summary: () => JSON.stringify({ pluginRuntimeApi: entries.slice(-30) }, null, 2),
  };
}

export async function pluginRuntimeApplicationLoaded(page: Page, pluginId: string): Promise<boolean> {
  return page
    .evaluate((id) => {
      return (
        window.__refmdPluginRuntimeDebug?.applications.some((entry) => entry.pluginId === id) ===
        true
      );
    }, pluginId)
    .catch(() => false);
}
