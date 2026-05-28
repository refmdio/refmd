import { type Page } from "@playwright/test";
import { safePageFrames } from "./diagnostics";

export async function storageDemoFrameState(page: Page): Promise<{
  status: string | null;
  frameCount: number;
  frameTexts: string[];
}> {
  const frameTexts: string[] = [];
  let status: string | null = null;
  for (const frame of safePageFrames(page)) {
    const state = await frame
      .evaluate(() => {
        const bodyText = document.body?.innerText ?? "";
        return {
          bodyText,
          status: document.querySelector('[data-role="status"]')?.textContent ?? null,
        };
      })
      .catch(() => null);
    if (!state?.bodyText.includes("RefMD Storage Demo Plugin")) continue;
    frameTexts.push(state.bodyText.slice(0, 500));
    status = state.status;
  }
  return { status, frameCount: frameTexts.length, frameTexts };
}
