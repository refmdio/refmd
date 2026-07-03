import { test, expect, type Locator, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { expectEditorTextContains } from "../../support/editor";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

let sharedPage: Page;

type CodeBlockVisualStyle = {
  backgroundColor: string;
  borderRadius: string;
  codeBackgroundColor: string;
  codeBorderRadius: string;
  codeFontSize: string;
  codePadding: string;
  fontFamily: string;
  fontSize: string;
  lineHeight: string;
  overflowX: string;
  padding: string;
};

type SurfacePadding = {
  paddingBottom: string;
  paddingLeft: string;
  paddingRight: string;
  paddingTop: string;
};

type SurfaceWidth = {
  maxWidth: number;
  panelWidth: number;
  surfaceWidth: number;
};

type HorizontalOverflow = {
  clientWidth: number;
  scrollWidth: number;
};

const LONG_MARKDOWN_TOKEN = `LongMarkdownToken${"0123456789abcdefghijklmnopqrstuvwxyz".repeat(16)}`;

async function readCodeBlockVisualStyle(locator: Locator): Promise<CodeBlockVisualStyle> {
  return locator.evaluate((pre) => {
    const preStyle = getComputedStyle(pre);
    const code = pre.querySelector("code");
    const codeStyle = code ? getComputedStyle(code) : preStyle;

    return {
      backgroundColor: preStyle.backgroundColor,
      borderRadius: preStyle.borderRadius,
      codeBackgroundColor: codeStyle.backgroundColor,
      codeBorderRadius: codeStyle.borderRadius,
      codeFontSize: codeStyle.fontSize,
      codePadding: codeStyle.padding,
      fontFamily: preStyle.fontFamily,
      fontSize: preStyle.fontSize,
      lineHeight: preStyle.lineHeight,
      overflowX: preStyle.overflowX,
      padding: preStyle.padding,
    };
  });
}

async function readEditorSurfaceWidth(locator: Locator): Promise<SurfaceWidth> {
  return locator.evaluate((node) => {
    const panel = node.closest("[data-panel-id]") ?? node.parentElement ?? node;
    const style = getComputedStyle(node);

    return {
      maxWidth: Number.parseFloat(style.maxWidth),
      panelWidth: panel.getBoundingClientRect().width,
      surfaceWidth: node.getBoundingClientRect().width,
    };
  });
}

async function expectReadableEditorSurface(locator: Locator): Promise<void> {
  const widths = await readEditorSurfaceWidth(locator);

  expect(Number.isFinite(widths.maxWidth)).toBe(true);
  expect(widths.surfaceWidth).toBeLessThanOrEqual(widths.maxWidth + 1);
  if (widths.panelWidth > widths.maxWidth + 80) {
    expect(widths.surfaceWidth).toBeLessThan(widths.panelWidth - 40);
  }
}

async function expectCodeMirrorUsesPanelWidth(locator: Locator): Promise<void> {
  const widths = await readEditorSurfaceWidth(locator);

  expect(widths.surfaceWidth).toBeGreaterThanOrEqual(widths.panelWidth - 80);
}

async function readCodeMirrorHorizontalOverflow(locator: Locator): Promise<HorizontalOverflow> {
  return locator.evaluate((node) => {
    const editor = node.closest(".cm-editor") ?? node;
    const scroller = editor.querySelector(".cm-scroller") ?? node.closest(".cm-scroller") ?? node;

    return {
      clientWidth: scroller.clientWidth,
      scrollWidth: scroller.scrollWidth,
    };
  });
}

async function expectNoCodeMirrorHorizontalOverflow(locator: Locator): Promise<void> {
  const overflow = await readCodeMirrorHorizontalOverflow(locator);

  expect(overflow.scrollWidth).toBeLessThanOrEqual(overflow.clientWidth + 1);
}

async function readSurfacePadding(locator: Locator): Promise<SurfacePadding> {
  return locator.evaluate((node) => {
    const style = getComputedStyle(node);

    return {
      paddingBottom: style.paddingBottom,
      paddingLeft: style.paddingLeft,
      paddingRight: style.paddingRight,
      paddingTop: style.paddingTop,
    };
  });
}

async function dragSelectMarkdownPreviewText(page: Page, text: string): Promise<void> {
  const selectionBox = await page
    .locator('[data-testid="markdown-preview"]')
    .evaluate((root, expectedText) => {
      const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
      while (walker.nextNode()) {
        const node = walker.currentNode as Text;
        const textOffset = (node.textContent ?? "").indexOf(expectedText);
        if (textOffset < 0) continue;

        const range = document.createRange();
        range.setStart(node, textOffset);
        range.setEnd(node, textOffset + expectedText.length);
        const rect = [...range.getClientRects()].find(
          (candidate) => candidate.width > 0 && candidate.height > 0,
        );
        if (rect) {
          return {
            startX: rect.left + 1,
            endX: rect.right - 1,
            y: rect.top + rect.height / 2,
          };
        }
      }
      throw new Error(`Markdown preview text was not rendered: ${expectedText}`);
    }, text);

  await page.evaluate(() => window.getSelection()?.removeAllRanges());
  await page.mouse.move(selectionBox.startX, selectionBox.y);
  await page.mouse.down();
  await page.mouse.move(selectionBox.endX, selectionBox.y, { steps: 8 });
  await page.mouse.up();
}

test.describe.serial("Editor Modes", () => {
  test.beforeAll(async ({ browser }) => {
    sharedPage = await (await newE2EContext(browser, { bypassCSP: true })).newPage();
  });

  test.afterAll(async () => {
    await sharedPage.context().close();
  });

  test.beforeAll(async ({}, testInfo) => {
    testInfo.setTimeout(E2E_TIMEOUTS.accountSetup);
    await registerAccount(sharedPage);
    await createDocument(sharedPage, "Mode Test Doc");
    await openDocument(sharedPage, "Mode Test Doc");
  });

  test("editor content survives Markdown, WYSIWYG, and Split mode transitions", async () => {
    test.setTimeout(E2E_TIMEOUTS.mediumScenario);
    let wysiwygCodeBlockStyle: CodeBlockVisualStyle | undefined;
    let wysiwygSurfacePadding: SurfacePadding | undefined;

    await sharedPage.setViewportSize({ width: 2200, height: 1200 });

    await test.step("default editor is Markdown with CodeMirror visible", async () => {
      const markdown = sharedPage.locator(".cm-content");
      await expect(markdown).toBeVisible({ timeout: 5_000 });
      await expectCodeMirrorUsesPanelWidth(markdown);
    });

    await test.step("type content in Markdown mode", async () => {
      const editor = sharedPage.locator(".cm-content");
      await editor.click();
      await sharedPage.keyboard.insertText(
        `Hello from Markdown\n\n${LONG_MARKDOWN_TOKEN}\n\n\`\`\`sh\nprintf "styled block"\n\`\`\``,
      );
      await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);
      await expectCodeMirrorUsesPanelWidth(editor);
      await expectNoCodeMirrorHorizontalOverflow(editor);
    });

    await test.step("switch to WYSIWYG mode via panel menu", async () => {
      const trigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
      await trigger.waitFor({ state: "visible", timeout: 10_000 });
      await trigger.click();

      const content = sharedPage.locator('[data-slot="dropdown-menu-content"]');
      await content.waitFor({ state: "visible", timeout: 5_000 });

      await content.locator('[data-slot="dropdown-menu-item"]', { hasText: "WYSIWYG" }).click();
      await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);

      await expect(sharedPage.locator(".ProseMirror")).toBeVisible({ timeout: 10_000 });
      await expect(sharedPage.locator(".cm-content")).not.toBeVisible({ timeout: 5_000 });
      const wysiwyg = sharedPage.locator(".ProseMirror");
      await expectReadableEditorSurface(wysiwyg);
      const wysiwygCodeBlock = wysiwyg.locator("pre").first();
      await expect(wysiwygCodeBlock).toBeVisible({ timeout: 10_000 });
      wysiwygCodeBlockStyle = await readCodeBlockVisualStyle(wysiwygCodeBlock);
      wysiwygSurfacePadding = await readSurfacePadding(wysiwyg);
      await expectEditorTextContains(sharedPage, "Hello from Markdown", 10_000);
    });

    await test.step("switch to Split mode", async () => {
      const trigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
      await trigger.waitFor({ state: "visible", timeout: 10_000 });
      await trigger.click();
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);

      const splitContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
      await splitContent.waitFor({ state: "visible", timeout: 5_000 });
      await splitContent.getByRole("menuitem", { name: "Switch to Split" }).click();
      await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);

      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
      await expect(sharedPage.locator('[data-testid="markdown-preview"]')).toBeVisible({
        timeout: 10_000,
      });
      const preview = sharedPage.locator('[data-testid="markdown-preview"]');
      const previewSurface = preview.locator(".refmd-editor-readable-surface").first();
      await expect(previewSurface).toBeVisible({ timeout: 10_000 });
      const previewCodeBlock = preview.locator("pre").first();
      await expect(previewCodeBlock).toBeVisible({ timeout: 10_000 });
      expect(await readCodeBlockVisualStyle(previewCodeBlock)).toEqual(wysiwygCodeBlockStyle);
      expect(await readSurfacePadding(previewSurface)).toEqual(wysiwygSurfacePadding);
      await expectCodeMirrorUsesPanelWidth(sharedPage.locator(".cm-content"));
      await expectNoCodeMirrorHorizontalOverflow(sharedPage.locator(".cm-content"));
      await expectReadableEditorSurface(previewSurface);
      await expect(sharedPage.locator(".cm-content")).toHaveAttribute("contenteditable", "true");
      await expect(sharedPage.locator(".ProseMirror")).not.toBeVisible({ timeout: 5_000 });
      await expectEditorTextContains(sharedPage, "Hello from Markdown", 10_000);
      await dragSelectMarkdownPreviewText(sharedPage, "Hello from Markdown");
      await expect
        .poll(() => sharedPage.evaluate(() => window.getSelection()?.toString() ?? ""), {
          timeout: 5_000,
        })
        .toContain("Hello from Markdown");
    });

    await test.step("collapse to Markdown only from Split", async () => {
      const trigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
      await trigger.waitFor({ state: "visible", timeout: 10_000 });
      await trigger.click();
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);

      const mdContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
      await mdContent.waitFor({ state: "visible", timeout: 5_000 });
      await mdContent
        .locator('[data-slot="dropdown-menu-item"]', { hasText: "Markdown only" })
        .click();
      await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);

      await expect(sharedPage.locator(".cm-content")).toBeVisible({ timeout: 10_000 });
      await expectCodeMirrorUsesPanelWidth(sharedPage.locator(".cm-content"));
      await expectNoCodeMirrorHorizontalOverflow(sharedPage.locator(".cm-content"));
      await expect(sharedPage.locator(".cm-content")).toHaveAttribute("contenteditable", "true");
      await expect(sharedPage.locator(".ProseMirror")).not.toBeVisible({ timeout: 5_000 });
    });

    await test.step("content preserved through all mode switches", async () => {
      await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
      await openDocument(sharedPage, "Mode Test Doc");
      await expectEditorTextContains(sharedPage, "Hello from Markdown", 10_000);
    });
  });
});
