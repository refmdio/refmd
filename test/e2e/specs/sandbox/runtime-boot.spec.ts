import { expect, test } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { openDocument } from "../../support/documents";
import { waitForPluginRuntimeApplicationWithConsent } from "../../support/plugin/consent";
import {
  pluginRuntimeDiagnostic,
  watchPluginRuntimeFailures,
} from "../../support/plugin/diagnostics";
import { createDocument } from "../../support/plugin/documents";
import { installPluginFromSettings } from "../../support/plugin/install";
import { E2E_TIMEOUTS } from "../../support/timeouts";

test("sandbox document runtime reaches Host RPC boot handshake under served app CSP", async ({
  page,
}) => {
  test.setTimeout(E2E_TIMEOUTS.pluginLifecycle);
  await page.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });

  const cspViolations: string[] = [];
  const consoleHandler = (message: { type(): string; text(): string }) => {
    if (message.type() !== "error") return;
    const text = message.text();
    if (
      (text.includes("Content Security Policy") ||
        text.includes("Content-Security-Policy") ||
        text.includes("violates the following Content Security Policy directive")) &&
      !isExpectedSandboxCspConsole(text)
    ) {
      cspViolations.push(text);
    }
  };
  page.on("console", consoleHandler);
  const runtimeFailures = await watchPluginRuntimeFailures(page);
  const sandboxDocumentResponsePromise = page.waitForResponse(
    (response) =>
      response.request().method() === "GET" &&
      /\/api\/plugin-runtime\/sandbox-documents\/[^/?]+$/.test(new URL(response.url()).pathname),
    { timeout: 180_000 },
  );

  try {
    await registerAccount(page);
    await installPluginFromSettings(page, {
      fixtureName: "refmd-ui-demo",
      pluginId: "io.refmd.ui-demo",
    });
    await createDocument(page, "Strict Sandbox Runtime Boot");
    await openDocument(page, "Strict Sandbox Runtime Boot");
    await waitForPluginRuntimeApplicationWithConsent(page, "io.refmd.ui-demo", {
      timeout: 180_000,
      message: "UI demo plugin runtime application was not loaded under strict CSP",
      extraDiagnostic: () => `runtimeFailures=${JSON.stringify(runtimeFailures())}`,
    });

    const documentResponse = await sandboxDocumentResponsePromise;
    expect(documentResponse.status()).toBe(200);
    expect(documentResponse.headers()["x-frame-options"]).toBeUndefined();
    expect(documentResponse.headers()["cache-control"] ?? "").toContain("no-store");
    expect(documentResponse.headers()["referrer-policy"]).toBe("no-referrer");
    const csp = documentResponse.headers()["content-security-policy"] ?? "";
    expect(csp).toContain("sandbox allow-scripts");
    expect(csp).toContain("frame-ancestors 'self'");
    expect(csp).toContain("script-src 'sha256-");

    await expect(page.locator('.status-bar-item[aria-label="UI Demo Status"]'))
      .toHaveText("UI Demo Ready", { timeout: 90_000 })
      .catch(async (error) => {
        throw new Error(
          `UI demo Host RPC status did not render under strict CSP:\n${await pluginRuntimeDiagnostic(
            page,
          )}\nruntimeFailures=${JSON.stringify(runtimeFailures())}\n${String(error)}`,
        );
      });
    expect(runtimeFailures()).toEqual([]);
    expect(cspViolations).toEqual([]);
  } finally {
    page.off("console", consoleHandler);
  }
});

function isExpectedSandboxCspConsole(text: string): boolean {
  void text;
  return false;
}
