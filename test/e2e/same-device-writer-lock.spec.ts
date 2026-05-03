import { expect, test } from "@playwright/test";
import {
  createDocument,
  expectToast,
  expectEditorTextContains,
  login,
  openDocument,
  readEditorText,
  registerAccount,
  newE2EContext,
} from "./helpers";

test("same device opens one writable editor per document", async ({ browser }) => {
  test.setTimeout(180_000);

  const context = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
  const pageA = await context.newPage();

  try {
    const email = await registerAccount(pageA);
    await createDocument(pageA, "Same Device Writer Lock Doc");
    await openDocument(pageA, "Same Device Writer Lock Doc");

    const editorA = pageA.locator(".cm-content").first();
    await expect(editorA).toBeVisible({ timeout: 30_000 });
    await editorA.click();
    await pageA.keyboard.insertText("primary writer baseline");
    await expectEditorTextContains(pageA, "primary writer baseline", 30_000);

    const documentUrl = pageA.url();
    expect(documentUrl).toContain("/document/");

    const pageBErrors: string[] = [];
    const pageB = await context.newPage();
    pageB.on("pageerror", (error) => pageBErrors.push(error.message));
    pageB.on("console", (message) => {
      if (message.type() === "error") {
        pageBErrors.push(message.text());
      }
    });
    await login(pageB, email);
    await pageB.goto(documentUrl, { waitUntil: "domcontentloaded" });

    const editorB = pageB.locator(".cm-content, .ProseMirror").first();
    const editorBVisible = await expect(editorB)
      .toBeVisible({ timeout: 45_000 })
      .then(() => true)
      .catch(() => false);
    if (!editorBVisible) {
      const diagnostics = await pageB.evaluate(() => ({
        url: location.href,
        workspaceId: localStorage.getItem("refmd_workspace_id"),
        body: document.body.innerText.slice(0, 1000),
        readyState: document.readyState,
        html: document.body.innerHTML.slice(0, 1000),
      }));
      throw new Error(
        `second tab editor did not render: ${JSON.stringify({ ...diagnostics, errors: pageBErrors })}`,
      );
    }
    await expectEditorTextContains(pageB, "primary writer baseline", 30_000);

    const lockDiagnostics = await pageB.evaluate(() =>
      Object.fromEntries(
        Object.keys(localStorage)
          .filter((key) => key.startsWith("refmd:document-writer-lock:"))
          .map((key) => [key, localStorage.getItem(key)]),
      ),
    );
    expect(Object.keys(lockDiagnostics).length).toBeGreaterThan(0);
    await expectToast(pageB, "Editing is paused in this tab.");
    await expect(editorB).toHaveAttribute("contenteditable", "false", { timeout: 10_000 });
    await editorB.click();
    await pageB.keyboard.press("End");
    await pageB.keyboard.press("Enter");
    await pageB.keyboard.insertText("secondary writer must not apply");
    await pageB.waitForTimeout(1_000);

    expect(await readEditorText(pageB)).not.toContain("secondary writer must not apply");

    await pageA.close();
    await expectToast(pageB, "Editing is available in this tab.");
    await expect(editorB).toHaveAttribute("contenteditable", "true", { timeout: 10_000 });
    await editorB.click();
    await pageB.keyboard.press("End");
    await pageB.keyboard.press("Enter");
    await pageB.keyboard.insertText("secondary writer after release");
    await expectEditorTextContains(pageB, "secondary writer after release", 30_000);
  } finally {
    await context.close();
  }
});
