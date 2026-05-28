import { expect, test, type Page } from "@playwright/test";
import { registerAccount } from "../../support/auth";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import { E2E_TIMEOUTS } from "../../support/timeouts";

async function editorLines(page: Page): Promise<string[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll<HTMLElement>(".cm-line")).map(
      (line) => line.textContent ?? "",
    ),
  );
}

test("Markdown editor preserves additional Enter on trailing blank line", async ({ page }) => {
  test.setTimeout(E2E_TIMEOUTS.accountSetup);
  await registerAccount(page);
  await createDocument(page, "Trailing Newline Doc");
  await openDocument(page, "Trailing Newline Doc");

  const editor = page.locator(".cm-content");
  await expect(editor).toBeVisible({ timeout: 10_000 });
  await editor.click();

  await page.keyboard.insertText("# uuu");
  await page.keyboard.press("Enter");
  await page.keyboard.insertText("aaa");
  await page.keyboard.press("Enter");

  await expect.poll(() => editorLines(page), { timeout: 10_000 }).toEqual(["# uuu", "aaa", ""]);

  await page.keyboard.press("Enter");

  await expect.poll(() => editorLines(page), { timeout: 10_000 }).toEqual([
    "# uuu",
    "aaa",
    "",
    "",
  ]);
});
