import {
  expect,
  type Page,
} from "@playwright/test";
import { safePageFrames } from "./diagnostics";

export async function expectUiDemoModal(page: Page): Promise<void> {
  const modal = page.locator('[role="dialog"]').filter({ hasText: "UI Demo Modal" });
  await expect(modal.getByRole("heading", { name: "UI Demo Modal" })).toBeVisible({
    timeout: 30_000,
  });
  await expect(modal.getByText("UI Demo Message", { exact: true })).toBeVisible({
    timeout: 30_000,
  });
}

export async function openDocumentTileMenu(page: Page): Promise<void> {
  const tile = page.locator('[data-panel-id*=":"]').first();
  const windowRoot = tile.locator(
    'xpath=ancestor::*[contains(@class,"mosaic-window-body")]/parent::*[contains(@class,"mosaic-window")]',
  );
  await tile.click();
  await windowRoot.locator('[data-slot="dropdown-menu-trigger"]').click();
}

export async function closeUiDemoModal(page: Page): Promise<void> {
  const modal = page.locator('[role="dialog"]').filter({ hasText: "UI Demo Modal" });
  await modal.locator('[data-slot="dialog-close"]').last().click();
  await expect(modal).toHaveCount(0, { timeout: 10_000 });
}

export async function collectPluginHostUiDiagnostics(page: Page): Promise<string> {
  const pageState = await page
    .evaluate(() => {
      return {
        url: window.location.href,
        runtimeDebug: window.__refmdPluginRuntimeDebug ?? null,
        statusItems: Array.from(document.querySelectorAll(".status-bar-item")).map((element) => ({
          ariaLabel: element.getAttribute("aria-label"),
          text: element.textContent,
        })),
        sidebarButtons: Array.from(document.querySelectorAll("button")).map((element) => ({
          ariaLabel: element.getAttribute("aria-label"),
          text: element.textContent,
          title: element.getAttribute("title"),
        })),
        dialogs: Array.from(document.querySelectorAll('[role="dialog"]')).map((element) => ({
          text: element.textContent?.slice(0, 500) ?? "",
          hidden: element.getAttribute("aria-hidden"),
        })),
        iframes: Array.from(document.querySelectorAll("iframe")).map((element) => ({
          title: element.getAttribute("title"),
          src: element.getAttribute("src")?.slice(0, 200) ?? "",
        })),
        uiIframeMounts: Array.from(
          document.querySelectorAll<HTMLElement>("[data-refmd-plugin-ui-iframe-state]"),
        ).map((element) => ({
          state: element.dataset.refmdPluginUiIframeState,
          reason: element.dataset.refmdPluginUiIframeReason,
          error: element.dataset.refmdPluginUiIframeError,
          text: element.textContent?.slice(0, 200) ?? "",
        })),
      };
    })
    .catch((error) => ({ error: String(error) }));
  const frameTexts: string[] = [];
  for (const frame of safePageFrames(page)) {
    const state = await frame
      .evaluate(() => {
        const bodyText = document.body?.innerText ?? "";
        return {
          url: window.location.href,
          bodyText,
          status: document.querySelector('[data-role="status"]')?.textContent ?? null,
          hasRefmdFacade: Boolean(globalThis.refmd),
          refmdConnected: globalThis.refmd?.runtime?.connected ?? null,
          frameScope: globalThis.refmd?.runtime?.context?.frame_scope ?? null,
        };
      })
      .catch(() => null);
    if (!state?.bodyText.includes("RefMD UI Demo Plugin")) continue;
    frameTexts.push(JSON.stringify({ ...state, bodyText: state.bodyText.slice(0, 500) }));
  }
  return JSON.stringify({ pageState, frameTexts }, null, 2);
}

export async function expectUiDemoFrameRendered(
  page: Page,
  title: string,
  options: {
    timeout?: number;
    runtimeFailures?: () => string[];
    runtimeApi?: () => string;
  } = {},
): Promise<void> {
  await expect(page.frameLocator(`iframe[title="${title}"]`).locator("body"))
    .toContainText("RefMD UI Demo Plugin", { timeout: options.timeout ?? 90_000 })
    .catch(async (error) => {
      throw new Error(
        `${title} iframe did not render the UI demo plugin:\nruntimeFailures=${JSON.stringify(
          options.runtimeFailures?.() ?? [],
        )}\nruntimeApi=${options.runtimeApi?.() ?? ""}\n${await collectPluginHostUiDiagnostics(
          page,
        )}\n${String(error)}`,
      );
    });
}
