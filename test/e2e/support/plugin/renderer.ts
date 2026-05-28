import { type Page } from "@playwright/test";
import { safePageFrames } from "./diagnostics";
import { pluginRuntimeDiagnostic } from "./diagnostics";

export async function demoPluginRuntimeState(page: Page): Promise<{
  application: boolean;
  blockRendererSlot: boolean;
  inlineRendererSlot: boolean;
}> {
  return page.evaluate(() => {
    const debug = window.__refmdPluginRuntimeDebug;
    const application = debug?.applications.some((entry) => entry.pluginId === "io.refmd.renderer-demo");
    const blockRendererSlot = debug?.rendererRegistry.some(
      (entry) =>
        entry.pluginId === "io.refmd.renderer-demo" &&
        entry.slots.some((slot) => slot.kind === "block" && slot.type === "refmd-renderer-demo"),
    );
    const inlineRendererSlot = debug?.rendererRegistry.some(
      (entry) =>
        entry.pluginId === "io.refmd.renderer-demo" &&
        entry.slots.some((slot) => slot.kind === "inline" && slot.type === "code"),
    );
    return {
      application: application === true,
      blockRendererSlot: blockRendererSlot === true,
      inlineRendererSlot: inlineRendererSlot === true,
    };
  });
}

export async function waitForDemoPluginRuntimeState(
  page: Page,
  expected: {
    application: boolean;
    blockRendererSlot: boolean;
    inlineRendererSlot: boolean;
    message: string;
    timeout?: number;
  },
): Promise<void> {
  await page
    .waitForFunction(
      ([applicationExpected, blockExpected, inlineExpected]) => {
        const debug = window.__refmdPluginRuntimeDebug;
        const application =
          debug?.applications.some((entry) => entry.pluginId === "io.refmd.renderer-demo") === true;
        const blockRendererSlot =
          debug?.rendererRegistry.some(
            (entry) =>
              entry.pluginId === "io.refmd.renderer-demo" &&
              entry.slots.some(
                (slot) => slot.kind === "block" && slot.type === "refmd-renderer-demo",
              ),
          ) === true;
        const inlineRendererSlot =
          debug?.rendererRegistry.some(
            (entry) =>
              entry.pluginId === "io.refmd.renderer-demo" &&
              entry.slots.some((slot) => slot.kind === "inline" && slot.type === "code"),
          ) === true;
        return (
          application === applicationExpected &&
          blockRendererSlot === blockExpected &&
          inlineRendererSlot === inlineExpected
        );
      },
      [expected.application, expected.blockRendererSlot, expected.inlineRendererSlot] as const,
      { timeout: expected.timeout ?? 90_000 },
    )
    .catch(async (error) => {
      throw new Error(`${expected.message}:\n${await pluginRuntimeDiagnostic(page)}\n${String(error)}`);
    });
}

export async function demoPluginFrameState(
  page: Page,
  kind: "block" | "inline",
  type: string,
  sandboxResponses: string[],
  runtimeFailures: string[],
): Promise<{
  mounted: boolean;
  kind: string | null;
  type: string | null;
  source: string | null;
  slotCount: number;
  editorHasFence: boolean;
  registryHasSlot: boolean;
  frameTexts: string[];
  frameUrls: string[];
  sandboxResponses: string[];
  runtimeFailures: string[];
  slotDiagnostics: Array<Record<string, unknown>>;
  frameDom: Array<Record<string, unknown>>;
}> {
  const selector = `.refmd-plugin-renderer-slot[data-renderer-kind="${kind}"][data-renderer-type="${type}"]`;
  const slot = page
    .locator(selector)
    .first();
  const slotCount = await page
    .locator(selector)
    .count()
    .catch(() => 0);
  const editorHasFence = await page
    .locator(".cm-content, .ProseMirror")
    .first()
    .innerText({ timeout: 1_000 })
    .then((text) => text.includes("```refmd-renderer-demo"))
    .catch(() => false);
  const registryHasSlot = await page
    .evaluate(
      ([slotKind, slotType]) =>
        window.__refmdPluginRuntimeDebug?.rendererRegistry.some(
          (entry) =>
            entry.pluginId === "io.refmd.renderer-demo" &&
            entry.slots.some((slot) => slot.kind === slotKind && slot.type === slotType),
        ) === true,
      [kind, type],
    )
    .catch(() => false);
  const frameTexts: string[] = [];
  const frameUrls: string[] = [];
  const frameDom: Array<Record<string, unknown>> = [];
  const slotDiagnostics = await page
    .locator(selector)
    .evaluateAll((slots) =>
      slots.map((slot, index) => {
        const iframe = slot.querySelector("iframe");
        return {
          index,
          className: (slot as HTMLElement).className,
          childElementCount: slot.childElementCount,
          iframeCount: slot.querySelectorAll("iframe").length,
          iframeSrc: iframe?.getAttribute("src") ?? null,
          html: slot.innerHTML.slice(0, 500),
        };
      }),
    )
    .catch(() => []);
  for (const frame of safePageFrames(page)) {
    frameUrls.push(frame.url());
    const text = await frame
      .locator("body")
      .innerText({ timeout: 500 })
      .catch(() => "");
    frameDom.push({
      url: frame.url(),
      bodyText: text.slice(0, 500),
    });
    if (text.includes("RefMD Renderer Demo Plugin")) frameTexts.push(text.slice(0, 200));
  }

  if (!(await slot.isVisible({ timeout: 1_000 }).catch(() => false))) {
    return {
      mounted: false,
      kind: null,
      type: null,
      source: null,
      slotCount,
      editorHasFence,
      registryHasSlot,
      frameTexts,
      frameUrls,
      sandboxResponses,
      runtimeFailures,
      slotDiagnostics,
      frameDom,
    };
  }

  const frameHandle = await slot.locator("iframe").elementHandle({ timeout: 1_000 }).catch(() => null);
  const frame = await frameHandle?.contentFrame();
  if (!frame) {
    return {
      mounted: false,
      kind: null,
      type: null,
      source: null,
      slotCount,
      editorHasFence,
      registryHasSlot,
      frameTexts,
      frameUrls,
      sandboxResponses,
      runtimeFailures,
      slotDiagnostics,
      frameDom,
    };
  }

  const text = await frame
    .locator("body")
    .innerText({ timeout: 1_000 })
    .catch(() => "");
  const rendered = {
    kind: await frame.locator('[data-role="kind"]').textContent({ timeout: 500 }).catch(() => null),
    type: await frame.locator('[data-role="type"]').textContent({ timeout: 500 }).catch(() => null),
    source: await frame
      .locator('[data-role="source"]')
      .textContent({ timeout: 500 })
      .catch(() => null),
  };
  return {
    mounted:
      text.includes("RefMD Renderer Demo Plugin") &&
      text.includes("Renderer Invocation") &&
      text.includes("Mounted"),
    kind: rendered.kind,
    type: rendered.type,
    source: rendered.source,
    slotCount,
    editorHasFence,
    registryHasSlot,
    frameTexts,
    frameUrls,
    sandboxResponses,
    runtimeFailures,
    slotDiagnostics,
    frameDom,
  };
}

export async function rendererPanePlacement(
  page: Page,
  kind: "block" | "inline",
  type: string,
): Promise<{
  markdownSlotCount: number;
  wysiwygSlotCount: number;
  totalSlotCount: number;
}> {
  return page.evaluate(
    ([slotKind, slotType]) => {
      const selector = `.refmd-plugin-renderer-slot[data-renderer-kind="${slotKind}"][data-renderer-type="${slotType}"]`;
      return {
        markdownSlotCount: document.querySelectorAll(`.cm-content ${selector}`).length,
        wysiwygSlotCount: document.querySelectorAll(`.ProseMirror ${selector}`).length,
        totalSlotCount: document.querySelectorAll(selector).length,
      };
    },
    [kind, type],
  );
}

export function watchSandboxDocumentResponses(page: Page): () => string[] {
  const responses: string[] = [];
  page.on("response", (response) => {
    if (!response.url().includes("sandbox-documents")) return;
    const headers = response.headers();
    responses.push(
      [
        response.status(),
        response.url(),
        headers["content-type"] ?? "",
        headers["content-security-policy"] ?? "",
      ].join(" "),
    );
  });
  return () => responses.slice(-8);
}
