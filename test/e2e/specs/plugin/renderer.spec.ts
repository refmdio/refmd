import { expect, test } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { openDocument } from "../../support/documents";
import { allowPluginConsentIfPresent } from "../../support/plugin/consent";
import { watchPluginRuntimeFailures } from "../../support/plugin/diagnostics";
import { createDocument } from "../../support/plugin/documents";
import { replaceEditorMarkdown } from "../../support/plugin/editor";
import { installDemoPluginFromSettings } from "../../support/plugin/install";
import { removePluginApplicationFromSettings } from "../../support/plugin/policy";
import {
  demoPluginFrameState,
  rendererPanePlacement,
  waitForDemoPluginRuntimeState,
  watchSandboxDocumentResponses,
} from "../../support/plugin/renderer";
import { E2E_TIMEOUTS } from "../../support/timeouts";

test("renderer demo plugin installs through the UI and renders a refmd-renderer-demo block", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.pluginInstall);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);
  const sandboxResponses = watchSandboxDocumentResponses(page);

  try {
    await registerAccount(page);
    await installDemoPluginFromSettings(page);
    await allowPluginConsentIfPresent(page);
    await createDocument(page, "Demo Plugin Runtime");
    await openDocument(page, "Demo Plugin Runtime");
    await waitForDemoPluginRuntimeState(page, {
      application: true,
      blockRendererSlot: true,
      inlineRendererSlot: true,
      message: "demo plugin runtime registry never exposed the demo renderer slots",
    });
    await replaceEditorMarkdown(
      page,
      "# Demo Plugin Runtime\n\nInline `inline-aiueo` value.\n\n```refmd-renderer-demo\nblock-aiueo\n```",
    );
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => demoPluginFrameState(page, "block", "refmd-renderer-demo", sandboxResponses(), runtimeFailures()), {
        timeout: 90_000,
        message: "demo plugin renderer iframe never reached mounted state",
      })
      .toEqual(
        expect.objectContaining({
          mounted: true,
          kind: "block",
          type: "refmd-renderer-demo",
          source: "block-aiueo",
        }),
      );
    await expect
      .poll(() => rendererPanePlacement(page, "block", "refmd-renderer-demo"), {
        timeout: 30_000,
        message: "block renderer slot should render in Markdown and WYSIWYG panes",
      })
      .toEqual({
        markdownSlotCount: 1,
        wysiwygSlotCount: 1,
        totalSlotCount: 2,
      });
    await expect
      .poll(() => demoPluginFrameState(page, "inline", "code", sandboxResponses(), runtimeFailures()), {
        timeout: 90_000,
        message: "demo plugin inline renderer iframe never reached mounted state",
      })
      .toEqual(
        expect.objectContaining({
          mounted: true,
          kind: "inline",
          type: "code",
          source: "inline-aiueo",
        }),
      );
    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("renderer application removal clears renderer slots", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.pluginInstall);
  const context = await newE2EContext(browser);
  await context.addInitScript(() => {
    window.__REFMD_E2E__ = true;
  });
  const page = await context.newPage();
  const runtimeFailures = await watchPluginRuntimeFailures(page);
  const sandboxResponses = watchSandboxDocumentResponses(page);

  try {
    await registerAccount(page);
    await installDemoPluginFromSettings(page);
    await createDocument(page, "Renderer Application Removal");
    await openDocument(page, "Renderer Application Removal");
    await allowPluginConsentIfPresent(page);
    await waitForDemoPluginRuntimeState(page, {
      application: true,
      blockRendererSlot: true,
      inlineRendererSlot: true,
      message: "renderer demo registry never exposed renderer slots before removal",
    });
    await replaceEditorMarkdown(
      page,
      "# Renderer Application Removal\n\nInline `inline-removal` value.\n\n```refmd-renderer-demo\nblock-removal\n```",
    );

    await expect
      .poll(() => demoPluginFrameState(page, "block", "refmd-renderer-demo", sandboxResponses(), runtimeFailures()), {
        timeout: 90_000,
        message: "block renderer iframe never mounted before removal",
      })
      .toEqual(
        expect.objectContaining({
          mounted: true,
          kind: "block",
          type: "refmd-renderer-demo",
          source: "block-removal",
        }),
      );
    await expect
      .poll(() => demoPluginFrameState(page, "inline", "code", sandboxResponses(), runtimeFailures()), {
        timeout: 90_000,
        message: "inline renderer iframe never mounted before removal",
      })
      .toEqual(
        expect.objectContaining({
          mounted: true,
          kind: "inline",
          type: "code",
          source: "inline-removal",
        }),
      );

    await removePluginApplicationFromSettings(page, "io.refmd.renderer-demo");

    await waitForDemoPluginRuntimeState(page, {
      application: false,
      blockRendererSlot: false,
      inlineRendererSlot: false,
      message: "renderer demo registry stayed registered after application removal",
    });
    await expect
      .poll(() => demoPluginFrameState(page, "block", "refmd-renderer-demo", sandboxResponses(), runtimeFailures()), {
        timeout: 90_000,
        message: "block renderer slot stayed mounted after application removal",
      })
      .toEqual(
        expect.objectContaining({
          mounted: false,
          slotCount: 0,
          editorHasFence: true,
          registryHasSlot: false,
        }),
      );
    await expect
      .poll(() => demoPluginFrameState(page, "inline", "code", sandboxResponses(), runtimeFailures()), {
        timeout: 90_000,
        message: "inline renderer slot stayed mounted after application removal",
      })
      .toEqual(
        expect.objectContaining({
          mounted: false,
          slotCount: 0,
          registryHasSlot: false,
        }),
      );
    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});
