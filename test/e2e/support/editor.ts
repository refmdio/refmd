import { expect, type Page } from "@playwright/test";

export async function readEditorText(page: Page): Promise<string> {
  return page.evaluate(() => {
    const fragments: string[] = [];
    const pushText = (value: string | null | undefined) => {
      const normalized = value?.replace(/\s+/g, " ").trim() ?? "";
      if (normalized.length > 0) fragments.push(normalized);
    };

    for (const node of document.querySelectorAll<HTMLElement>(".ProseMirror")) {
      pushText(node.innerText);
      pushText(node.textContent);
    }
    for (const node of document.querySelectorAll<HTMLElement>('[data-testid="markdown-preview"]')) {
      pushText(node.innerText);
      pushText(node.textContent);
    }
    for (const node of document.querySelectorAll<HTMLElement>(".cm-content")) {
      pushText(node.innerText);
      pushText(node.textContent);
    }
    for (const node of document.querySelectorAll<HTMLElement>(".cm-editor")) {
      pushText(node.innerText);
      pushText(node.textContent);
    }
    for (const node of document.querySelectorAll<HTMLElement>(".cm-line")) {
      pushText(node.textContent);
    }
    for (const node of document.querySelectorAll<HTMLElement>('[role="textbox"]')) {
      pushText(node.innerText);
      pushText(node.textContent);
    }

    pushText(document.querySelector("main")?.textContent);
    pushText(document.body?.innerText);
    pushText(document.body?.textContent);

    return fragments.join("\n");
  });
}

export async function expectEditorTextContains(
  page: Page,
  snippet: string,
  timeout = 30_000,
): Promise<void> {
  await expect
    .poll(() => readEditorText(page), {
      timeout,
      message: `editor never contained expected text: ${snippet}`,
    })
    .toContain(snippet);
}
