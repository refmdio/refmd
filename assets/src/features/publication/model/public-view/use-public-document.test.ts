import { createRoot, createSignal } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getDocument: vi.fn(),
}));

vi.mock("@/shared/api", () => ({
  publicApi: {
    getDocument: mocks.getDocument,
  },
}));

import { usePublicDocument } from "./use-public-document";

describe("usePublicDocument", () => {
  let dispose: (() => void) | undefined;

  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    dispose?.();
    dispose = undefined;
  });

  it("loads a public document for the current slug", async () => {
    const response = {
      title: "Published Doc",
      content: "# Published",
      author_name: "Author",
      updated_at: "2026-01-01T00:00:00Z",
    };
    mocks.getDocument.mockResolvedValue(response);

    const state = createRoot((rootDispose) => {
      dispose = rootDispose;
      return usePublicDocument(
        () => "author",
        () => "published-doc",
      );
    });

    await vi.waitFor(() => {
      expect(state.document()).toEqual(response);
    });
    expect(state.error()).toBeNull();
    expect(mocks.getDocument).toHaveBeenCalledWith("author", "published-doc");
  });

  it("sets an error without fetching when the slug is missing", () => {
    const state = createRoot((rootDispose) => {
      dispose = rootDispose;
      return usePublicDocument(
        () => "author",
        () => undefined,
      );
    });

    expect(state.document()).toBeNull();
    expect(state.error()).toBe("Public document not found.");
    expect(mocks.getDocument).not.toHaveBeenCalled();
  });

  it("ignores stale responses after the slug changes", async () => {
    let resolveOld!: (value: unknown) => void;
    mocks.getDocument.mockImplementation((_author: string, slug: string) => {
      if (slug === "old") {
        return new Promise((resolve) => {
          resolveOld = resolve;
        });
      }

      return Promise.resolve({
        title: "New Doc",
        content: "new",
        author_name: "Author",
        updated_at: "2026-01-02T00:00:00Z",
      });
    });

    let setSlug!: (value: string) => void;
    const state = createRoot((rootDispose) => {
      dispose = rootDispose;
      const [slug, writeSlug] = createSignal("old");
      setSlug = writeSlug;
      const hook = usePublicDocument(() => "author", slug);
      return hook;
    });

    await vi.waitFor(() => {
      expect(mocks.getDocument).toHaveBeenCalledWith("author", "old");
    });

    setSlug("new");

    await vi.waitFor(() => {
      expect(state.document()?.title).toBe("New Doc");
    });

    resolveOld({
      title: "Old Doc",
      content: "old",
      author_name: "Author",
      updated_at: "2026-01-01T00:00:00Z",
    });

    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(state.document()?.title).toBe("New Doc");
  });
});
