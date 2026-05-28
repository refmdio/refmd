import { expect, test } from "@playwright/test";
import {
  login,
  registerAccount,
} from "../../support/auth";
import { newE2EContext } from "../../support/context";
import {
  createDocument,
  openDocument,
} from "../../support/documents";
import {
  expectEditorTextContains,
  readEditorText,
} from "../../support/editor";
import { E2E_DELAYS, E2E_TIMEOUTS } from "../../support/timeouts";

test("same device opens one writable editor per document", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.accountSetup);

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
    await expect(editorB).toHaveAttribute("contenteditable", "false", { timeout: 30_000 });
    await editorB.click();
    await pageB.keyboard.press("End");
    await pageB.keyboard.press("Enter");
    await pageB.keyboard.insertText("secondary writer must not apply");
    await pageB.waitForTimeout(E2E_DELAYS.uiSettle);

    expect(await readEditorText(pageB)).not.toContain("secondary writer must not apply");

    await pageA.close();
    await expect(editorB).toHaveAttribute("contenteditable", "true", { timeout: 25_000 });
    await editorB.click();
    await pageB.keyboard.press("End");
    await pageB.keyboard.press("Enter");
    await pageB.keyboard.insertText("secondary writer after release");
    await expectEditorTextContains(pageB, "secondary writer after release", 30_000);
  } finally {
    await context.close();
  }
});

test("duplicated same-device tab does not keep two writable editors", async ({ browser }) => {
  test.setTimeout(E2E_TIMEOUTS.accountSetup);

  const context = await newE2EContext(browser, { bypassCSP: true, acceptDownloads: true });
  const pageA = await context.newPage();

  try {
    await registerAccount(pageA);
    await createDocument(pageA, "Duplicated Writer Lock Doc");
    await openDocument(pageA, "Duplicated Writer Lock Doc");

    const editorA = pageA.locator(".cm-content").first();
    await expect(editorA).toBeVisible({ timeout: 30_000 });
    await editorA.click();
    await pageA.keyboard.insertText("duplicate baseline");
    await expectEditorTextContains(pageA, "duplicate baseline", 30_000);

    const documentUrl = pageA.url();
    const sessionEntries = await pageA.evaluate(() =>
      Object.fromEntries(
        Object.keys(sessionStorage).map((key) => [key, sessionStorage.getItem(key)]),
      ),
    );

    const pageB = await context.newPage();
    await pageB.addInitScript((entries) => {
      for (const [key, value] of Object.entries(entries as Record<string, string | null>)) {
        if (value !== null) sessionStorage.setItem(key, value);
      }
    }, sessionEntries);
    await pageB.goto(documentUrl, { waitUntil: "domcontentloaded" });

    const editorB = pageB.locator(".cm-content").first();
    await expect(editorB).toBeVisible({ timeout: 45_000 });
    await expectEditorTextContains(pageB, "duplicate baseline", 30_000);

    await expect
      .poll(
        async () => {
          const states = await Promise.all([
            editorA.getAttribute("contenteditable"),
            editorB.getAttribute("contenteditable"),
          ]);
          return states.filter((state) => state === "true").length;
        },
        {
          timeout: 10_000,
          message: "duplicated same-device tabs both remained writable",
        },
      )
      .toBe(1);
  } finally {
    await context.close();
  }
});
