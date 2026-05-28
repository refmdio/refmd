import { type Page } from "@playwright/test";
import { safePageFrames } from "./diagnostics";

export async function documentDemoFrameState(page: Page): Promise<{
  status: string | null;
  backgroundStatus: string | null;
  frameCount: number;
  frameTexts: string[];
}> {
  const frameTexts: string[] = [];
  let status: string | null = null;
  let backgroundStatus: string | null = null;
  for (const frame of safePageFrames(page)) {
    const state = await frame
      .evaluate(() => {
        const bodyText = document.body?.innerText ?? "";
        return {
          bodyText,
          status: document.querySelector('[data-role="status"]')?.textContent ?? null,
          backgroundStatus:
            document.querySelector('[data-role="background-status"]')?.textContent ?? null,
        };
      })
      .catch(() => null);
    if (!state?.bodyText.includes("RefMD Document Demo Plugin")) continue;
    frameTexts.push(state.bodyText.slice(0, 500));
    status = state.status;
    backgroundStatus = state.backgroundStatus;
  }
  return { status, backgroundStatus, frameCount: frameTexts.length, frameTexts };
}
