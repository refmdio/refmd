import { expect, test, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import { openDocument } from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import { allowPluginConsentIfPresent } from "../../support/plugin/consent";
import { watchPluginRuntimeFailures } from "../../support/plugin/diagnostics";
import { createDocument } from "../../support/plugin/documents";
import {
  editorDemoFrameState,
  openEditorContextMenu,
  replaceEditorMarkdown,
  runEditorContribution,
  selectAllEditorText,
} from "../../support/plugin/editor";
import { installPluginFromSettings } from "../../support/plugin/install";
import {
  disableInstalledPluginFromSettings,
  removePluginActivationFromSettings,
  revokePluginConsentFromSettings,
} from "../../support/plugin/policy";
import { pluginRuntimeApplicationLoaded } from "../../support/plugin/runtime";
import { E2E_TIMEOUTS } from "../../support/timeouts";

async function expectEditorDemoCleanup(page: Page, message: string): Promise<void> {
  await expect
    .poll(
      async () => {
        const frameState = await editorDemoFrameState(page);
        return {
          decorationCount: await page.locator(".refmd-plugin-editor-decoration-highlight").count(),
          frameCount: frameState.frameCount,
          frameTexts: frameState.frameTexts,
          status: frameState.status,
        };
      },
      {
        timeout: E2E_TIMEOUTS.longExpectation,
        message,
      },
    )
    .toEqual(
      expect.objectContaining({
        decorationCount: 0,
        frameCount: 0,
      }),
    );
}

test("installed plugin editor contributions run through the real editor UI", async ({ browser }) => {
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
      fixtureName: "refmd-editor-demo",
      pluginId: "io.refmd.editor-demo",
    });
    await createDocument(page, "Editor Demo Plugin Runtime");
    await openDocument(page, "Editor Demo Plugin Runtime");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.editor-demo"), {
        timeout: 90_000,
        message: "editor demo plugin runtime application was not loaded",
      })
      .toBe(true);
    await expect
      .poll(() => editorDemoFrameState(page), {
        timeout: 90_000,
        message: "editor demo plugin sandbox did not register editor contributions",
      })
      .toEqual(
        expect.objectContaining({
          status: "Editor contributions registered",
        }),
      );

    await replaceEditorMarkdown(
      page,
      "# Editor Demo Plugin Runtime\n\nselect-me\n\neditor-demo-target\n",
      "editor-demo-target",
    );
    await selectAllEditorText(page);
    await runEditorContribution(page, "Editor Demo Formatter");
    await expect
      .poll(() => editorDemoFrameState(page), {
        timeout: 90_000,
        message: "formatter request did not complete in the plugin sandbox",
      })
      .toEqual(expect.objectContaining({ status: expect.stringContaining("Formatter completed") }));
    await expectEditorTextContains(page, "EDITOR DEMO FORMATTED", 30_000);
    await expectEditorTextContains(page, "editor-demo-target", 30_000);

    await runEditorContribution(page, "Editor Demo Command");
    await expect
      .poll(() => editorDemoFrameState(page), {
        timeout: 90_000,
        message: "editor command did not reach the plugin sandbox",
      })
      .toEqual(expect.objectContaining({ status: "Command invoked" }));

    await expect(page.getByText("Editor demo diagnostic", { exact: true })).toBeVisible({
      timeout: 60_000,
    });

    await expect(page.locator(".refmd-plugin-editor-decoration-highlight").first()).toBeVisible({
      timeout: 60_000,
    });

    await expect(page.getByRole("button", { name: "Apply editor demo suggestion" })).toBeVisible({
      timeout: 60_000,
    });
    await page.getByRole("button", { name: "Apply editor demo suggestion" }).click();
    await expectEditorTextContains(page, "editor-demo-suggested", 30_000);

    await disableInstalledPluginFromSettings(page, "io.refmd.editor-demo");
    await expectEditorDemoCleanup(page, "disabled editor demo contributions did not clean up");
    await openEditorContextMenu(page);
    await expect(page.getByRole("button", { name: "Editor Demo Formatter" })).toHaveCount(0, {
      timeout: 10_000,
    });
    await expect(page.getByRole("button", { name: "Editor Demo Diagnostics" })).toHaveCount(0, {
      timeout: 10_000,
    });

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin editor activation removal clears contributions", async ({ browser }) => {
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
      fixtureName: "refmd-editor-demo",
      pluginId: "io.refmd.editor-demo",
    });
    await createDocument(page, "Editor Demo Activation Removal");
    await openDocument(page, "Editor Demo Activation Removal");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.editor-demo"), {
        timeout: 90_000,
        message: "editor demo plugin runtime application was not loaded",
      })
      .toBe(true);
    await expect
      .poll(() => editorDemoFrameState(page), {
        timeout: 90_000,
        message: "editor demo plugin sandbox did not register editor contributions",
      })
      .toEqual(
        expect.objectContaining({
          status: "Editor contributions registered",
        }),
      );

    await replaceEditorMarkdown(
      page,
      "# Editor Demo Activation Removal\n\neditor-demo-target\n",
      "editor-demo-target",
    );
    await runEditorContribution(page, "Editor Demo Decoration");
    await expect(page.locator(".refmd-plugin-editor-decoration-highlight").first()).toBeVisible({
      timeout: 30_000,
    });

    await removePluginActivationFromSettings(page, "io.refmd.editor-demo");

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.editor-demo"), {
        timeout: 90_000,
        message: "deleted editor demo activation runtime remained loaded",
      })
      .toBe(false);
    await expectEditorDemoCleanup(page, "deleted editor demo contributions did not clean up");
    await openEditorContextMenu(page);
    await expect(page.getByRole("button", { name: "Editor Demo Formatter" })).toHaveCount(0, {
      timeout: 10_000,
    });
    await expect(page.getByRole("button", { name: "Editor Demo Diagnostics" })).toHaveCount(0, {
      timeout: 10_000,
    });

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});

test("installed plugin editor consent revoke clears contributions", async ({ browser }) => {
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
      fixtureName: "refmd-editor-demo",
      pluginId: "io.refmd.editor-demo",
    });
    await createDocument(page, "Editor Demo Consent Revoke");
    await openDocument(page, "Editor Demo Consent Revoke");
    await allowPluginConsentIfPresent(page);

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.editor-demo"), {
        timeout: 90_000,
        message: "editor demo plugin runtime application was not loaded before consent revoke",
      })
      .toBe(true);
    await expect
      .poll(() => editorDemoFrameState(page), {
        timeout: 90_000,
        message: "editor demo plugin sandbox did not register editor contributions before consent revoke",
      })
      .toEqual(
        expect.objectContaining({
          status: "Editor contributions registered",
        }),
      );

    await replaceEditorMarkdown(
      page,
      "# Editor Demo Consent Revoke\n\neditor-demo-target\n",
      "editor-demo-target",
    );
    await runEditorContribution(page, "Editor Demo Decoration");
    await expect(page.locator(".refmd-plugin-editor-decoration-highlight").first()).toBeVisible({
      timeout: 30_000,
    });

    await revokePluginConsentFromSettings(page, "io.refmd.editor-demo");

    await expect
      .poll(() => pluginRuntimeApplicationLoaded(page, "io.refmd.editor-demo"), {
        timeout: 90_000,
        message: "revoked editor demo consent runtime remained loaded",
      })
      .toBe(false);
    await expectEditorDemoCleanup(page, "revoked editor demo contributions did not clean up");
    await openEditorContextMenu(page);
    await expect(page.getByRole("button", { name: "Editor Demo Command" })).toHaveCount(0, {
      timeout: 10_000,
    });
    await expect(page.getByRole("button", { name: "Editor Demo Formatter" })).toHaveCount(0, {
      timeout: 10_000,
    });
    await expect(page.getByRole("button", { name: "Editor Demo Diagnostics" })).toHaveCount(0, {
      timeout: 10_000,
    });
    await expect(page.getByRole("button", { name: "Editor Demo Decoration" })).toHaveCount(0, {
      timeout: 10_000,
    });
    await expect(page.getByRole("button", { name: "Editor Demo Suggestion" })).toHaveCount(0, {
      timeout: 10_000,
    });

    expect(runtimeFailures()).toEqual([]);
  } finally {
    await context.close();
  }
});
