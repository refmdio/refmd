import { expect, test } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { openDocument } from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import { allowPluginConsentIfPresent } from "../../support/plugin/consent";
import { watchPluginRuntimeFailures } from "../../support/plugin/diagnostics";
import { documentDemoFrameState } from "../../support/plugin/document-rpc";
import { createDocument } from "../../support/plugin/documents";
import {
  expectCommandPaletteCommandAbsent,
  flushCurrentDocumentSync,
  replaceEditorMarkdown,
  runCommandPaletteCommand,
} from "../../support/plugin/editor";
import { installPluginFromSettings } from "../../support/plugin/install";
import {
  removePluginActivationFromSettings,
  revokePluginConsentFromSettings,
} from "../../support/plugin/policy";
import { pluginRuntimeApplicationLoaded } from "../../support/plugin/runtime";
import { PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS } from "../../support/plugin/types";
import { E2E_TIMEOUTS } from "../../support/timeouts";

test("installed plugin document read and write commands run through Host RPC", async ({
  browser,
}) => {
  test.setTimeout(E2E_TIMEOUTS.pluginInstall);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);

  try {
    await registerAccount(page);
    await installPluginFromSettings(page, {
      fixtureName: "refmd-document-demo",
      pluginId: "io.refmd.document-demo",
    });

    await createDocument(page, "Document Demo Workspace Source");
    await openDocument(page, "Document Demo Workspace Source");
    await allowPluginConsentIfPresent(page);
    await replaceEditorMarkdown(
      page,
      "# Document Demo Workspace Source\n\nworkspace-source-token\n",
      "workspace-source-token",
    );

    await createDocument(page, "Document Demo Active Target");
    await openDocument(page, "Document Demo Active Target");

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.document-demo"), {
        timeout: 90_000,
        message: "document demo plugin runtime application was not loaded",
      })
      .toBe(true);
    try {
      await expect
        .poll(() => documentDemoFrameState(page), {
          timeout: 90_000,
          message: "document demo plugin sandbox did not register document commands",
        })
        .toEqual(
          expect.objectContaining({
            status: "Document commands registered",
            backgroundStatus: "Background workspace read rejected: execution_context_required",
          }),
        );
    } catch (error) {
      throw new Error(
        `${error instanceof Error ? error.message : String(error)}\nRuntime failures:\n${runtimeFailures().join("\n")}`,
      );
    }

    await replaceEditorMarkdown(
      page,
      "# Document Demo Active Target\n\nactive-source-token\n",
      "active-source-token",
    );

    await runCommandPaletteCommand(page, "Document Demo Active Read");
    await expect
      .poll(() => documentDemoFrameState(page), {
        timeout: 30_000,
        message: "active document read command did not complete in the plugin sandbox",
      })
      .toEqual(expect.objectContaining({ status: expect.stringContaining("Active read completed") }));
    await expectEditorTextContains(page, "ACTIVE_READ_OK: true", 30_000);
    await expectEditorTextContains(page, "ACTIVE_SOURCE: active-source-token", 30_000);

    await runCommandPaletteCommand(page, "Document Demo Workspace Query");
    await expect
      .poll(() => documentDemoFrameState(page), {
        timeout: 30_000,
        message: "workspace document query command did not complete in the plugin sandbox",
      })
      .toEqual(
        expect.objectContaining({ status: expect.stringContaining("Workspace query completed") }),
      );
    await expectEditorTextContains(page, "WORKSPACE_QUERY_OK: true", 30_000);
    await expectEditorTextContains(page, "WORKSPACE_SOURCE: workspace-source-token", 30_000);

    await runCommandPaletteCommand(page, "Document Demo Metadata Rejected");
    await expect
      .poll(() => documentDemoFrameState(page), {
        timeout: 30_000,
        message: "metadata write rejection did not reach the plugin sandbox",
      })
      .toEqual(expect.objectContaining({ status: expect.stringContaining("Metadata write rejected") }));

    await runCommandPaletteCommand(page, "Document Demo Write");
    await expect
      .poll(() => documentDemoFrameState(page), {
        timeout: 30_000,
        message: "document write command did not complete in the plugin sandbox",
      })
      .toEqual(expect.objectContaining({ status: expect.stringContaining("Document write completed") }));
    await expectEditorTextContains(page, "DOCUMENT_DEMO_WRITE_OK", 30_000);
    await expectEditorTextContains(page, "persistent-document-write-token", 30_000);
    await flushCurrentDocumentSync(page);

    await page.reload({ waitUntil: "domcontentloaded" });
    await openDocument(page, "Document Demo Active Target");
    await expectEditorTextContains(page, "persistent-document-write-token", 90_000);

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin document command activation removal fails closed", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.pluginLifecycle);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);

  try {
    await registerAccount(page);
    await installPluginFromSettings(page, {
      fixtureName: "refmd-document-demo",
      pluginId: "io.refmd.document-demo",
    });

    await createDocument(page, "Document Demo Activation Removal");
    await openDocument(page, "Document Demo Activation Removal");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.document-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "document demo plugin runtime application was not loaded",
      })
      .toBe(true);
    await expect
      .poll(() => documentDemoFrameState(page), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "document demo plugin sandbox did not register document commands",
      })
      .toEqual(
        expect.objectContaining({
          status: "Document commands registered",
          backgroundStatus: "Background workspace read rejected: execution_context_required",
        }),
      );

    await runCommandPaletteCommand(page, "Document Demo Metadata Rejected");
    await expect
      .poll(() => documentDemoFrameState(page), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "metadata rejection command did not reach the document demo sandbox",
      })
      .toEqual(expect.objectContaining({ status: expect.stringContaining("Metadata write rejected") }));

    await removePluginActivationFromSettings(page, "io.refmd.document-demo");

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.document-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "deleted document demo activation runtime remained loaded",
      })
      .toBe(false);
    await expectCommandPaletteCommandAbsent(page, "Document Demo Active Read");
    await expectCommandPaletteCommandAbsent(page, "Document Demo Workspace Query");
    await expectCommandPaletteCommandAbsent(page, "Document Demo Metadata Rejected");
    await expectCommandPaletteCommandAbsent(page, "Document Demo Write");

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin document consent revoke fails closed", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.pluginLifecycle);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);

  try {
    await registerAccount(page);
    await installPluginFromSettings(page, {
      fixtureName: "refmd-document-demo",
      pluginId: "io.refmd.document-demo",
    });

    await createDocument(page, "Document Demo Consent Revoke");
    await openDocument(page, "Document Demo Consent Revoke");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.document-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "document demo plugin runtime application was not loaded before consent revoke",
      })
      .toBe(true);
    await expect
      .poll(() => documentDemoFrameState(page), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "document demo plugin sandbox did not register document commands before revoke",
      })
      .toEqual(
        expect.objectContaining({
          status: "Document commands registered",
          backgroundStatus: "Background workspace read rejected: execution_context_required",
        }),
      );

    await runCommandPaletteCommand(page, "Document Demo Metadata Rejected");
    await expect
      .poll(() => documentDemoFrameState(page), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "metadata rejection command did not reach the document demo sandbox before revoke",
      })
      .toEqual(expect.objectContaining({ status: expect.stringContaining("Metadata write rejected") }));

    await revokePluginConsentFromSettings(page, "io.refmd.document-demo");

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.document-demo"), {
        timeout: PLUGIN_LIFECYCLE_STATE_TIMEOUT_MS,
        message: "revoked document demo consent runtime remained loaded",
      })
      .toBe(false);
    await expectCommandPaletteCommandAbsent(page, "Document Demo Active Read");
    await expectCommandPaletteCommandAbsent(page, "Document Demo Workspace Query");
    await expectCommandPaletteCommandAbsent(page, "Document Demo Metadata Rejected");
    await expectCommandPaletteCommandAbsent(page, "Document Demo Write");

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});
