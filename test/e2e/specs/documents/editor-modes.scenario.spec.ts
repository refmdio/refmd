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

type RectSnapshot = {
  bottom: number;
  height: number;
  left: number;
  right: number;
  top: number;
  width: number;
};

type HandleGeometry = RectSnapshot & {
  dragging: boolean;
  opacity: number;
  pointerEvents: string;
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

async function switchCurrentPaneToWysiwyg(page: Page): Promise<void> {
  if (await page.locator('.ProseMirror[contenteditable="true"]').isVisible().catch(() => false)) {
    return;
  }

  const trigger = page.locator('[data-slot="dropdown-menu-trigger"]').last();
  await trigger.waitFor({ state: "visible", timeout: 10_000 });
  await trigger.click();
  await page.waitForTimeout(E2E_DELAYS.poll);

  const menuContent = page.locator('[data-slot="dropdown-menu-content"]');
  await menuContent.waitFor({ state: "visible", timeout: 5_000 });
  const wysiwygOnly = menuContent.getByRole("menuitem", { name: "WYSIWYG only" });
  if (await wysiwygOnly.isVisible({ timeout: 500 }).catch(() => false)) {
    await wysiwygOnly.click();
  } else {
    await menuContent.locator('[data-slot="dropdown-menu-item"]', { hasText: "WYSIWYG" }).click();
  }
  await page.waitForTimeout(E2E_DELAYS.editorSettle);

  await expect(page.locator('.ProseMirror[contenteditable="true"]')).toBeVisible({
    timeout: 10_000,
  });
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

async function readWysiwygTextRect(page: Page, text: string): Promise<RectSnapshot> {
  return page.locator(".ProseMirror").evaluate((root, expectedText) => {
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
      range.detach();
      if (!rect) continue;

      return {
        bottom: rect.bottom,
        height: rect.height,
        left: rect.left,
        right: rect.right,
        top: rect.top,
        width: rect.width,
      };
    }
    throw new Error(`WYSIWYG text was not rendered: ${expectedText}`);
  }, text);
}

async function readWysiwygBlockRect(page: Page, text: string): Promise<RectSnapshot> {
  return page.locator(".ProseMirror").evaluate((root, expectedText) => {
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode as Text;
      if (!(node.textContent ?? "").includes(expectedText)) continue;

      let block = node.parentElement;
      while (block?.parentElement && block.parentElement !== root) {
        block = block.parentElement;
      }
      if (!block) continue;

      const rect = block.getBoundingClientRect();
      return {
        bottom: rect.bottom,
        height: rect.height,
        left: rect.left,
        right: rect.right,
        top: rect.top,
        width: rect.width,
      };
    }
    throw new Error(`WYSIWYG block was not rendered: ${expectedText}`);
  }, text);
}

async function readBlockHandleGeometry(page: Page): Promise<HandleGeometry> {
  return page.locator(".pm-block-handle").evaluate((handle) => {
    const rect = handle.getBoundingClientRect();
    const style = getComputedStyle(handle);
    return {
      bottom: rect.bottom,
      dragging: handle.classList.contains("dragging"),
      height: rect.height,
      left: rect.left,
      opacity: Number.parseFloat(style.opacity),
      pointerEvents: style.pointerEvents,
      right: rect.right,
      top: rect.top,
      width: rect.width,
    };
  });
}

async function readDropCursorGeometry(page: Page): Promise<RectSnapshot & { color: string }> {
  return page.locator(".refmd-wysiwyg-dropcursor").evaluate((cursor) => {
    const rect = cursor.getBoundingClientRect();
    const style = getComputedStyle(cursor);
    return {
      bottom: rect.bottom,
      color: style.backgroundColor,
      height: rect.height,
      left: rect.left,
      right: rect.right,
      top: rect.top,
      width: rect.width,
    };
  });
}

async function readSelectedNodeOutline(page: Page): Promise<{ style: string; width: string }> {
  return page.locator(".ProseMirror-selectednode").first().evaluate((node) => {
    const style = getComputedStyle(node);
    return {
      style: style.outlineStyle,
      width: style.outlineWidth,
    };
  });
}

async function readElementRect(locator: Locator): Promise<RectSnapshot> {
  return locator.evaluate((element) => {
    const rect = element.getBoundingClientRect();
    return {
      bottom: rect.bottom,
      height: rect.height,
      left: rect.left,
      right: rect.right,
      top: rect.top,
      width: rect.width,
    };
  });
}

async function readWysiwygBlockTexts(page: Page): Promise<string[]> {
  return page.locator(".ProseMirror").evaluate((root) =>
    Array.from(root.children)
      .filter((child) => !child.classList.contains("ProseMirror-yjs-cursor"))
      .map((child) => {
        const clone = child.cloneNode(true) as HTMLElement;
        for (const chrome of clone.querySelectorAll(
          ".ProseMirror-yjs-cursor, [data-refmd-editor-chrome], .refmd-plugin-renderer-source-hidden",
        )) {
          chrome.remove();
        }
        return clone.textContent?.replace(/\s+/g, " ").trim() ?? "";
      })
      .filter((text) => text.length > 0),
  );
}

async function readWysiwygBlockSummary(page: Page): Promise<Array<{ tag: string; text: string }>> {
  return page.locator(".ProseMirror").evaluate((root) =>
    Array.from(root.children)
      .filter((child) => !child.classList.contains("ProseMirror-yjs-cursor"))
      .map((child) => {
        const clone = child.cloneNode(true) as HTMLElement;
        for (const chrome of clone.querySelectorAll(
          ".ProseMirror-yjs-cursor, [data-refmd-editor-chrome], .refmd-plugin-renderer-source-hidden",
        )) {
          chrome.remove();
        }
        return {
          tag: child.tagName.toLowerCase(),
          text: clone.textContent?.replace(/\s+/g, " ").trim() ?? "",
        };
      })
      .filter((entry) => entry.text.length > 0),
  );
}

async function expectNoDocumentFailure(page: Page): Promise<void> {
  await expect(page.locator("body")).not.toContainText(
    /verification_failed|reconnect_failed|initial_load_failed|Failed to load document/i,
    { timeout: 1_000 },
  );
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
      if (!(await sharedPage.locator(".cm-content").isVisible().catch(() => false))) {
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
      }

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

    await test.step("collapse to WYSIWYG only from Split preview menu after Markdown cursor activity", async () => {
      const splitTrigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
      await splitTrigger.waitFor({ state: "visible", timeout: 10_000 });
      await splitTrigger.click();
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);

      const splitContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
      await splitContent.waitFor({ state: "visible", timeout: 5_000 });
      await splitContent.getByRole("menuitem", { name: "Switch to Split" }).click();
      await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);

      const markdown = sharedPage.locator(".cm-content");
      await expect(markdown).toBeVisible({ timeout: 10_000 });
      await markdown.click();
      await sharedPage.keyboard.press("End");
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);

      const trigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
      await trigger.waitFor({ state: "visible", timeout: 10_000 });
      await trigger.click();
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);

      const menuContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
      await menuContent.waitFor({ state: "visible", timeout: 5_000 });
      await menuContent.getByRole("menuitem", { name: "WYSIWYG only" }).click();
      await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);

      await expect(sharedPage.locator(".ProseMirror")).toBeVisible({ timeout: 10_000 });
      await expect(sharedPage.locator('.ProseMirror[contenteditable="true"]')).toBeVisible({
        timeout: 10_000,
      });
      await expect(sharedPage.locator(".cm-content")).not.toBeVisible({ timeout: 5_000 });
      await expect(sharedPage.locator('[data-testid="markdown-preview"]')).not.toBeVisible({
        timeout: 5_000,
      });
      await expectEditorTextContains(sharedPage, "Hello from Markdown", 10_000);
    });

    await test.step("collapse to WYSIWYG only from Split markdown menu after Markdown cursor activity", async () => {
      const splitTrigger = sharedPage.locator('[data-slot="dropdown-menu-trigger"]').last();
      await splitTrigger.waitFor({ state: "visible", timeout: 10_000 });
      await splitTrigger.click();
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);

      const splitContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
      await splitContent.waitFor({ state: "visible", timeout: 5_000 });
      await splitContent.getByRole("menuitem", { name: "Switch to Split" }).click();
      await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);

      const markdown = sharedPage.locator(".cm-content");
      await expect(markdown).toBeVisible({ timeout: 10_000 });
      await markdown.click();
      await sharedPage.keyboard.press("End");
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);

      const paneMenuTriggers = sharedPage.locator('[data-slot="dropdown-menu-trigger"]');
      const trigger = paneMenuTriggers.nth((await paneMenuTriggers.count()) - 2);
      await trigger.waitFor({ state: "visible", timeout: 10_000 });
      await trigger.click();
      await sharedPage.waitForTimeout(E2E_DELAYS.poll);

      const menuContent = sharedPage.locator('[data-slot="dropdown-menu-content"]');
      await menuContent.waitFor({ state: "visible", timeout: 5_000 });
      await menuContent.getByRole("menuitem", { name: "WYSIWYG only" }).click();
      await sharedPage.waitForTimeout(E2E_DELAYS.editorSettle);

      await expect(sharedPage.locator(".ProseMirror")).toBeVisible({ timeout: 10_000 });
      await expect(sharedPage.locator('.ProseMirror[contenteditable="true"]')).toBeVisible({
        timeout: 10_000,
      });
      await expect(sharedPage.locator(".cm-content")).not.toBeVisible({ timeout: 5_000 });
      await expect(sharedPage.locator('[data-testid="markdown-preview"]')).not.toBeVisible({
        timeout: 5_000,
      });
      await expectEditorTextContains(sharedPage, "Hello from Markdown", 10_000);
    });

    await test.step("content preserved through all mode switches", async () => {
      await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
      await openDocument(sharedPage, "Mode Test Doc");
      await expectEditorTextContains(sharedPage, "Hello from Markdown", 10_000);
    });
  });

  test("WYSIWYG slash menu opens and applies a command in a blank document", async () => {
    test.setTimeout(E2E_TIMEOUTS.mediumScenario);

    const title = `Slash Menu ${Date.now()}`;
    await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
    await createDocument(sharedPage, title);
    await openDocument(sharedPage, title);
    await switchCurrentPaneToWysiwyg(sharedPage);

    const editor = sharedPage.locator('.ProseMirror[contenteditable="true"]').last();
    await expect(editor).toBeVisible({ timeout: 10_000 });
    await editor.click();
    await sharedPage.keyboard.insertText("/");

    const slashMenu = sharedPage.getByRole("listbox", { name: "Block commands" });
    await expect(slashMenu).toBeVisible({ timeout: 5_000 });
    await sharedPage.keyboard.insertText("h1");
    const headingOption = slashMenu.getByRole("option", { name: /Heading 1/ });
    await expect(headingOption).toBeVisible({
      timeout: 5_000,
    });
    await sharedPage.keyboard.press("Enter");
    await expect(slashMenu).not.toBeVisible({ timeout: 5_000 });

    await expect(editor).toBeFocused({ timeout: 5_000 });
    await sharedPage.keyboard.insertText("Heading from slash");
    await expect(editor.locator("h1", { hasText: "Heading from slash" })).toBeVisible({
      timeout: 5_000,
    });
  });

  test("WYSIWYG slash menu opens after typing a title and pressing Enter", async () => {
    test.setTimeout(E2E_TIMEOUTS.mediumScenario);

    const title = `Slash After Title ${Date.now()}`;
    await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
    await createDocument(sharedPage, title);
    await openDocument(sharedPage, title);
    await switchCurrentPaneToWysiwyg(sharedPage);

    const editor = sharedPage.locator('.ProseMirror[contenteditable="true"]').last();
    await expect(editor).toBeVisible({ timeout: 10_000 });
    await editor.click();
    await sharedPage.keyboard.insertText("ドキュメントタイトル");
    await sharedPage.keyboard.press("Enter");
    await sharedPage.keyboard.insertText("/");

    const slashMenu = sharedPage.getByRole("listbox", { name: "Block commands" });
    await expect(slashMenu).toBeVisible({ timeout: 5_000 });
    await sharedPage.keyboard.insertText("h2");
    const headingOption = slashMenu.getByRole("option", { name: /Heading 2/ });
    await expect(headingOption).toBeVisible({
      timeout: 5_000,
    });
    await sharedPage.keyboard.press("Space");
    await expect(slashMenu).not.toBeVisible({ timeout: 5_000 });

    await expect(editor).toBeFocused({ timeout: 5_000 });
    await sharedPage.keyboard.insertText("Section from slash");
    await expect(editor.locator("h2", { hasText: "Section from slash" })).toBeVisible({
      timeout: 5_000,
    });
  });

  test("WYSIWYG block handle stays adjacent and opens a selectable block menu", async () => {
    test.setTimeout(E2E_TIMEOUTS.mediumScenario);

    const title = `WYSIWYG Block Menu ${Date.now()}`;
    await sharedPage.setViewportSize({ width: 1800, height: 1000 });
    await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
    await createDocument(sharedPage, title);
    await openDocument(sharedPage, title);
    await switchCurrentPaneToWysiwyg(sharedPage);

    const editor = sharedPage.locator('.ProseMirror[contenteditable="true"]').last();
    await expect(editor).toBeVisible({ timeout: 10_000 });
    await editor.click();
    const wrappedFirstBlock = `First block ${"wrapped ".repeat(48).trim()}`;
    await sharedPage.keyboard.insertText(wrappedFirstBlock);
    await sharedPage.keyboard.press("Enter");
    await sharedPage.keyboard.insertText("Second block");

    const firstLine = await readWysiwygTextRect(sharedPage, "First block");
    const firstBlock = await readWysiwygBlockRect(sharedPage, "First block");
    expect(firstBlock.height).toBeGreaterThan(firstLine.height + 8);
    await sharedPage.mouse.move(firstLine.left + 4, firstLine.top + firstLine.height / 2);

    await expect
      .poll(() => readBlockHandleGeometry(sharedPage), {
        timeout: 5_000,
        message: "WYSIWYG block handle did not become visible beside the hovered row",
      })
      .toMatchObject({ opacity: 1, pointerEvents: "auto" });

    const handle = await readBlockHandleGeometry(sharedPage);
    const lineCenterY = firstLine.top + firstLine.height / 2;
    const handleCenterY = handle.top + handle.height / 2;
    expect(handle.right).toBeLessThanOrEqual(firstLine.left);
    expect(Math.abs(handleCenterY - lineCenterY)).toBeLessThanOrEqual(8);

    await sharedPage.mouse.move(
      firstLine.left - 5,
      handle.top + handle.height / 2,
    );
    await sharedPage.waitForTimeout(250);
    await expect
      .poll(() => readBlockHandleGeometry(sharedPage), {
        timeout: 5_000,
        message: "WYSIWYG block handle disappeared while moving from text to the handle",
      })
      .toMatchObject({ opacity: 1, pointerEvents: "auto" });

    await sharedPage.mouse.move(handle.left + 8, handle.top + handle.height / 2);
    await sharedPage.locator(".pm-block-handle-add").click();
    const slashMenu = sharedPage.getByRole("listbox", { name: "Block commands" });
    await expect(slashMenu).toBeVisible({ timeout: 5_000 });
    await expect
      .poll(async () => (await readElementRect(slashMenu)).top, {
        timeout: 5_000,
        message: "plus menu was not anchored below the handled block",
      })
      .toBeGreaterThanOrEqual(firstBlock.bottom - 4);
    const slashMenuRect = await readElementRect(slashMenu);
    expect(slashMenuRect.left).toBeLessThanOrEqual(firstLine.left + 8);
    expect(slashMenuRect.left).toBeGreaterThanOrEqual(firstLine.left - 8);

    const editorRect = await readElementRect(editor);
    await sharedPage.mouse.click(editorRect.left + 24, editorRect.top - 24);
    await expect(slashMenu).not.toBeVisible({ timeout: 5_000 });
    await expect
      .poll(() => readWysiwygBlockTexts(sharedPage), {
        timeout: 5_000,
        message: "outside-dismissed plus menu changed the document",
      })
      .toEqual([wrappedFirstBlock, "Second block"]);

    await sharedPage.mouse.move(firstLine.left + 4, firstLine.top + firstLine.height / 2);
    await sharedPage.locator(".pm-block-handle-add").click();
    await expect(slashMenu).toBeVisible({ timeout: 5_000 });
    await slashMenu.getByRole("option", { name: /Heading 2/ }).focus();
    await sharedPage.keyboard.press("Escape");
    await expect(slashMenu).not.toBeVisible({ timeout: 5_000 });
    await expect
      .poll(() => editor.evaluate((node) => node.textContent ?? ""), {
        timeout: 5_000,
        message: "dismissed plus menu left slash text in the document",
      })
      .not.toContain("/");

    await sharedPage.mouse.move(firstLine.left + 4, firstLine.top + firstLine.height / 2);
    await sharedPage.locator(".pm-block-handle-add").click();
    await expect(slashMenu).toBeVisible({ timeout: 5_000 });
    const headingOption = slashMenu.getByRole("option", { name: /Heading 2/ });
    await headingOption.click();
    await expect(slashMenu).not.toBeVisible({ timeout: 5_000 });

    await sharedPage.keyboard.insertText("Inserted heading");
    await expect(editor.locator("h2", { hasText: "Inserted heading" })).toBeVisible({
      timeout: 5_000,
    });
    await expect
      .poll(() => readWysiwygBlockTexts(sharedPage), {
        timeout: 5_000,
        message: "block-handle menu did not preserve block order",
      })
      .toEqual([wrappedFirstBlock, "Inserted heading", "Second block"]);
    await expectNoDocumentFailure(sharedPage);
  });

  test("WYSIWYG block handle does not overlap text in a narrow pane", async () => {
    test.setTimeout(E2E_TIMEOUTS.mediumScenario);

    const title = `WYSIWYG Narrow Handle ${Date.now()}`;
    await sharedPage.setViewportSize({ width: 920, height: 900 });
    await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
    await createDocument(sharedPage, title);
    await openDocument(sharedPage, title);
    await switchCurrentPaneToWysiwyg(sharedPage);

    const editor = sharedPage.locator('.ProseMirror[contenteditable="true"]').last();
    await expect(editor).toBeVisible({ timeout: 10_000 });
    await editor.click();
    await sharedPage.keyboard.insertText("Narrow row");

    const textRect = await readWysiwygTextRect(sharedPage, "Narrow row");
    await sharedPage.mouse.move(textRect.left + 4, textRect.top + textRect.height / 2);

    await expect
      .poll(() => readBlockHandleGeometry(sharedPage), {
        timeout: 5_000,
        message: "narrow WYSIWYG block handle did not remain reachable",
      })
      .toMatchObject({ opacity: 1, pointerEvents: "auto" });

    const handle = await readBlockHandleGeometry(sharedPage);
    expect(handle.right).toBeLessThanOrEqual(textRect.left);

    await sharedPage.setViewportSize({ width: 520, height: 900 });
    await expect(editor).toBeVisible({ timeout: 10_000 });
    const constrainedTextRect = await readWysiwygTextRect(sharedPage, "Narrow row");
    await sharedPage.mouse.move(
      constrainedTextRect.left + 4,
      constrainedTextRect.top + constrainedTextRect.height / 2,
    );

    await expect
      .poll(() => readBlockHandleGeometry(sharedPage), {
        timeout: 5_000,
        message: "constrained WYSIWYG block handle did not remain reachable",
      })
      .toMatchObject({ opacity: 1, pointerEvents: "auto" });

    const constrainedHandle = await readBlockHandleGeometry(sharedPage);
    expect(constrainedHandle.right).toBeLessThanOrEqual(constrainedTextRect.left);
  });

  test("WYSIWYG block handle drags blocks with stable feedback", async () => {
    test.setTimeout(E2E_TIMEOUTS.mediumScenario);

    const title = `WYSIWYG Drag Handle ${Date.now()}`;
    await sharedPage.setViewportSize({ width: 1600, height: 1000 });
    await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
    await createDocument(sharedPage, title);
    await openDocument(sharedPage, title);
    await switchCurrentPaneToWysiwyg(sharedPage);

    const editor = sharedPage.locator('.ProseMirror[contenteditable="true"]').last();
    await expect(editor).toBeVisible({ timeout: 10_000 });
    await editor.click();
    await sharedPage.keyboard.insertText("First draggable");
    await sharedPage.keyboard.press("Enter");
    await sharedPage.keyboard.insertText("Second draggable");
    await sharedPage.keyboard.press("Enter");
    await sharedPage.keyboard.insertText("Third draggable");

    const firstText = await readWysiwygTextRect(sharedPage, "First draggable");
    await sharedPage.mouse.move(firstText.left + 4, firstText.top + firstText.height / 2);
    await expect
      .poll(() => readBlockHandleGeometry(sharedPage), {
        timeout: 5_000,
        message: "drag handle did not appear before starting a real drag",
      })
      .toMatchObject({ opacity: 1, pointerEvents: "auto" });

    const dragButton = sharedPage.locator(".pm-block-handle-drag");
    const dragRect = await readElementRect(dragButton);
    const thirdBlock = await readWysiwygBlockRect(sharedPage, "Third draggable");
    const editorRect = await readElementRect(editor);
    const dropY = Math.min(editorRect.bottom - 32, thirdBlock.bottom + 72);
    await sharedPage.mouse.move(dragRect.left + dragRect.width / 2, dragRect.top + dragRect.height / 2);
    await sharedPage.mouse.down();
    await sharedPage.mouse.move(thirdBlock.left + 12, dropY, { steps: 14 });

    await expect
      .poll(() => readBlockHandleGeometry(sharedPage), {
        timeout: 5_000,
        message: "drag handle was not locked visible while dragging",
      })
      .toMatchObject({ dragging: true, opacity: 1, pointerEvents: "auto" });

    await expect
      .poll(() => readDropCursorGeometry(sharedPage), {
        timeout: 5_000,
        message: "dragging did not show the WYSIWYG drop target",
      })
      .toMatchObject({ color: /rgb|color/ });
    const dropCursor = await readDropCursorGeometry(sharedPage);
    expect(dropCursor.width).toBeGreaterThan(20);
    expect(dropCursor.height).toBeGreaterThanOrEqual(4);
    expect(dropCursor.top).toBeGreaterThanOrEqual(thirdBlock.bottom - 4);
    await expect
      .poll(() => readSelectedNodeOutline(sharedPage), {
        timeout: 5_000,
        message: "dragging still showed the ProseMirror default selected-node outline",
      })
      .toMatchObject({ style: "none", width: "0px" });

    await sharedPage.mouse.up();
    await expect
      .poll(() => readWysiwygBlockTexts(sharedPage), {
        timeout: 5_000,
        message: "dragging the block handle did not reorder the blocks",
      })
      .toEqual(["Second draggable", "Third draggable", "First draggable"]);
    await expectNoDocumentFailure(sharedPage);
  });

  test("WYSIWYG block handle does not offer unsupported nested list drag", async () => {
    test.setTimeout(E2E_TIMEOUTS.mediumScenario);

    const title = `WYSIWYG List Drag Handle ${Date.now()}`;
    await sharedPage.setViewportSize({ width: 1600, height: 1000 });
    await sharedPage.goto("/dashboard", { waitUntil: "domcontentloaded" });
    await createDocument(sharedPage, title);
    await openDocument(sharedPage, title);
    await switchCurrentPaneToWysiwyg(sharedPage);

    const editor = sharedPage.locator('.ProseMirror[contenteditable="true"]').last();
    await expect(editor).toBeVisible({ timeout: 10_000 });
    await editor.click();
    await sharedPage.keyboard.insertText("-");
    await sharedPage.keyboard.press("Space");
    await sharedPage.keyboard.insertText("Alpha item");
    await sharedPage.keyboard.press("Enter");
    await sharedPage.keyboard.insertText("Beta item");
    await sharedPage.keyboard.press("Enter");
    await sharedPage.keyboard.press("Enter");
    await sharedPage.keyboard.insertText("After list");

    await expect(editor.locator("ul li", { hasText: "Alpha item" })).toBeVisible({
      timeout: 5_000,
    });
    await expect(editor.locator("ul li", { hasText: "Beta item" })).toBeVisible({
      timeout: 5_000,
    });
    await expect
      .poll(() => readWysiwygBlockSummary(sharedPage), {
        timeout: 5_000,
        message: "list setup did not produce a top-level list followed by a paragraph",
      })
      .toEqual([
        { tag: "ul", text: "Alpha itemBeta item" },
        { tag: "p", text: "After list" },
      ]);

    const alphaText = await readWysiwygTextRect(sharedPage, "Alpha item");
    await sharedPage.mouse.move(alphaText.left + 4, alphaText.top + alphaText.height / 2);
    await expect
      .poll(async () => {
        const handle = await readBlockHandleGeometry(sharedPage);
        return handle.opacity <= 0.05 && handle.pointerEvents === "none";
      }, {
        timeout: 5_000,
        message: "unsupported list item hover exposed a WYSIWYG drag handle",
      })
      .toBe(true);

    await expect
      .poll(() => readWysiwygBlockSummary(sharedPage), {
        timeout: 5_000,
        message: "unsupported list hover changed the document structure",
      })
      .toEqual([
        { tag: "ul", text: "Alpha itemBeta item" },
        { tag: "p", text: "After list" },
      ]);
    await expect(editor.locator("ul li", { hasText: "Alpha item" })).toBeVisible({
      timeout: 5_000,
    });
    await expect(editor.locator("ul li", { hasText: "Beta item" })).toBeVisible({
      timeout: 5_000,
    });
    await expectNoDocumentFailure(sharedPage);
  });
});
