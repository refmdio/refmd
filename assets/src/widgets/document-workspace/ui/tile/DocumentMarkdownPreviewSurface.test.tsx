import { render } from "solid-js/web";
import { afterEach, describe, expect, it } from "vitest";
import { DocumentMarkdownPreviewSurface } from "./DocumentMarkdownPreviewSurface";

afterEach(() => {
  document.body.replaceChildren();
});

describe("DocumentMarkdownPreviewSurface", () => {
  it("renders fallback document text as Markdown, not raw source", () => {
    const root = document.createElement("div");
    document.body.append(root);
    const dispose = render(
      () => <DocumentMarkdownPreviewSurface markdown={"# Title\n\nBody"} />,
      root,
    );

    expect(root.querySelector("h1")?.textContent).toBe("Title");
    expect(root.textContent).not.toContain("# Title");
    expect(root.textContent).toContain("Body");

    dispose();
  });
});
