import { expect, test, type Page } from "@playwright/test";
import {
  createDocument,
  openContextMenu,
  openDocument,
  openSettings,
  registerAccount,
  selectSettingsTab,
  newE2EContext,
} from "./helpers";

async function typeInEditor(page: Page, text: string): Promise<void> {
  const editor = page
    .locator('.cm-content[contenteditable="true"], .ProseMirror[contenteditable="true"]')
    .first();
  await expect(editor).toBeVisible({ timeout: 30_000 });
  await editor.click({ force: true });
  await page.keyboard.insertText(text);
}

async function closeDialog(page: Page): Promise<void> {
  const dialog = page.locator('[role="dialog"]');
  if (!(await dialog.isVisible({ timeout: 2_000 }).catch(() => false))) return;

  await dialog.locator('[data-slot="dialog-close"]').last().click();
  await expect(dialog).not.toBeVisible({ timeout: 10_000 });
}

async function enablePublicPublishing(page: Page): Promise<void> {
  await openSettings(page);
  await selectSettingsTab(page, "Workspace");
  const publicSection = page
    .locator("section")
    .filter({ has: page.getByText("Public Publishing", { exact: true }) })
    .last();
  await publicSection.locator('[data-slot="switch"]').first().click({ force: true });
  await expect(publicSection.getByRole("switch").first()).toBeChecked({ timeout: 30_000 });

  const authorNameInput = publicSection.getByPlaceholder("Author name");
  const authorSlugInput = publicSection.getByPlaceholder("author-slug-base");
  await authorNameInput.fill("Public Route Author");
  await authorSlugInput.fill("public-route-author");
  await expect(authorNameInput).toHaveValue("Public Route Author", { timeout: 10_000 });
  await expect(authorSlugInput).toHaveValue("public-route-author", { timeout: 10_000 });

  const saveButton = publicSection.getByRole("button", { name: "Save" });
  const saveResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "PATCH" &&
      response.url().includes("/api/workspaces/") &&
      response.url().endsWith("/features"),
  );
  await expect(saveButton).toBeEnabled({ timeout: 10_000 });
  await saveButton.click();
  await saveResponse;
  await expect(publicSection.getByPlaceholder("author-slug-base")).toHaveValue(
    /^public-route-author-[0-9a-f]{8}$/,
    { timeout: 30_000 },
  );
  await closeDialog(page);
}

async function publishArticle(
  page: Page,
  options: {
    title: string;
    slug: string;
    body: string;
  },
): Promise<string> {
  await createDocument(page, options.title);
  await openDocument(page, options.title);
  await typeInEditor(page, `# ${options.title}\n\n${options.body}`);

  let menu = await openContextMenu(page, options.title);
  await expect(menu.getByRole("menuitem", { name: "Share" })).toBeVisible();
  await expect(menu.getByRole("menuitem", { name: "Publish" })).toHaveCount(0);
  await page.keyboard.press("Escape");

  await enablePublicPublishing(page);

  menu = await openContextMenu(page, options.title);
  await menu.getByRole("menuitem", { name: "Publish" }).click();

  const dialog = page.locator('[role="dialog"]');
  await expect(dialog.getByRole("heading", { name: "Publish" })).toBeVisible({
    timeout: 10_000,
  });
  await dialog.locator("#publication-slug").fill(options.slug);
  await dialog.getByRole("button", { name: "Publish" }).click();

  const publicUrlInput = dialog.locator("input[readonly]").first();
  await expect(publicUrlInput).toHaveValue(
    new RegExp(`/@public-route-author-[0-9a-f]{8}/${options.slug}$`),
    { timeout: 60_000 },
  );
  const publicUrl = await publicUrlInput.inputValue();
  await closeDialog(page);
  return publicUrl;
}

async function renameDocumentFromSidebar(
  page: Page,
  currentTitle: string,
  nextTitle: string,
): Promise<void> {
  const menu = await openContextMenu(page, currentTitle);
  await menu.getByRole("menuitem", { name: "Rename" }).click();
  const renameDialog = page.locator('[role="dialog"]');
  await expect(renameDialog.getByRole("heading", { name: "Rename" })).toBeVisible({
    timeout: 10_000,
  });
  await renameDialog.locator("input").fill(nextTitle);
  await renameDialog.getByRole("button", { name: "Rename" }).click();
  await expect(renameDialog).not.toBeVisible({ timeout: 30_000 });
}

async function expectPublicArticle(
  page: Page,
  publicUrl: string,
  options: {
    title: string;
    body: string;
  },
): Promise<void> {
  await page.goto(publicUrl, { waitUntil: "domcontentloaded" });
  await expect(page.getByRole("heading", { name: options.title }).first()).toBeVisible({
    timeout: 30_000,
  });
  await expect(page.getByRole("link", { name: /Public Route Author/ })).toBeVisible({
    timeout: 30_000,
  });
  await expect(page.getByText("Contents")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByText(options.body)).toBeVisible({ timeout: 30_000 });
}

test("public author document route renders the published article", async ({ browser }) => {
  test.setTimeout(300_000);

  const ownerContext = await newE2EContext(browser, {
    bypassCSP: true,
    acceptDownloads: true,
  });
  const ownerPage = await ownerContext.newPage();
  const publicContext = await newE2EContext(browser, {
    bypassCSP: true,
    ignoreHTTPSErrors: true,
  });
  const publicPage = await publicContext.newPage();

  try {
    await registerAccount(ownerPage);
    const publicUrl = await publishArticle(ownerPage, {
      title: "Public Route Article",
      slug: "public-route-article",
      body: "Published public route body.",
    });

    expect(publicUrl).toMatch(/\/@public-route-author-[0-9a-f]{8}\/public-route-article$/);
    await expectPublicArticle(publicPage, publicUrl, {
      title: "Public Route Article",
      body: "Published public route body.",
    });
  } finally {
    await publicContext.close();
    await ownerContext.close();
  }
});

test("published article hero title follows document rename", async ({ browser }) => {
  test.setTimeout(300_000);

  const ownerContext = await newE2EContext(browser, {
    bypassCSP: true,
    acceptDownloads: true,
  });
  const ownerPage = await ownerContext.newPage();
  const publicContext = await newE2EContext(browser, {
    bypassCSP: true,
    ignoreHTTPSErrors: true,
  });
  const publicPage = await publicContext.newPage();

  try {
    await registerAccount(ownerPage);
    const publicUrl = await publishArticle(ownerPage, {
      title: "Public Rename Source",
      slug: "public-rename-source",
      body: "Published body remains visible after rename.",
    });

    expect(publicUrl).toMatch(/\/@public-route-author-[0-9a-f]{8}\/public-rename-source$/);
    await expectPublicArticle(publicPage, publicUrl, {
      title: "Public Rename Source",
      body: "Published body remains visible after rename.",
    });

    await renameDocumentFromSidebar(ownerPage, "Public Rename Source", "Public Rename Target");

    await expect(async () => {
      await publicPage.goto(publicUrl, { waitUntil: "domcontentloaded" });
      await expect(
        publicPage.getByRole("heading", { name: "Public Rename Target" }).first(),
      ).toBeVisible({ timeout: 5_000 });
    }).toPass({ timeout: 60_000, intervals: [1_000, 2_000, 5_000] });
    await expect(publicPage.getByText("Published body remains visible after rename.")).toBeVisible({
      timeout: 30_000,
    });
  } finally {
    await publicContext.close();
    await ownerContext.close();
  }
});
