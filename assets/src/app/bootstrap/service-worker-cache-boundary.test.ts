import { describe, expect, it, vi } from "vite-plus/test";
import serviceWorkerSource from "../../../public/sw.js?raw";

type FetchEventHandler = (event: {
  request: { method: string; url: string; mode?: string };
  respondWith: (response: Promise<Response | undefined>) => void;
}) => void;

interface LoadedServiceWorker {
  cache: {
    delete: ReturnType<typeof vi.fn>;
    keys: ReturnType<typeof vi.fn>;
    put: ReturnType<typeof vi.fn>;
  };
  fetchHandler: FetchEventHandler;
}

class ServiceWorkerTestRequest extends Request {
  constructor(input: string | URL | Request, init?: RequestInit) {
    const value =
      typeof input === "string" && input.startsWith("/")
        ? `https://app.example.test${input}`
        : input;
    super(value, init);
  }
}

async function flushAsyncWork(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
}

function loadServiceWorker(
  response = new Response("app shell"),
  cacheKeys: readonly Request[] = [],
): LoadedServiceWorker {
  const listeners = new Map<string, unknown>();
  const cache = {
    add: vi.fn(() => Promise.resolve()),
    delete: vi.fn(() => Promise.resolve(true)),
    keys: vi.fn(() => Promise.resolve(cacheKeys)),
    match: vi.fn(() => Promise.resolve(undefined)),
    put: vi.fn(() => Promise.resolve()),
  };
  const cacheStorage = {
    delete: vi.fn(() => Promise.resolve(true)),
    keys: vi.fn(() => Promise.resolve([])),
    match: vi.fn(() => Promise.resolve(undefined)),
    open: vi.fn(() => Promise.resolve(cache)),
  };
  const fetchMock = vi.fn(() => Promise.resolve(response));
  const scope = {
    location: { origin: "https://app.example.test" },
    skipWaiting: vi.fn(),
    clients: { claim: vi.fn() },
    addEventListener: vi.fn((type: string, handler: unknown) => {
      listeners.set(type, handler);
    }),
  };

  const runServiceWorker = new Function("self", "caches", "fetch", "Request", serviceWorkerSource);
  runServiceWorker(scope, cacheStorage, fetchMock, ServiceWorkerTestRequest);

  const handler = listeners.get("fetch");
  if (typeof handler !== "function") throw new Error("service_worker_fetch_handler_missing");
  return { cache, fetchHandler: handler as FetchEventHandler };
}

describe("service worker cache boundary", () => {
  it("does not app-shell-handle network executor navigations", () => {
    const { fetchHandler } = loadServiceWorker();
    const respondWith = vi.fn();

    fetchHandler({
      request: {
        method: "GET",
        mode: "navigate",
        url: "https://app.example.test/plugin-network-executor?session_token=session-one",
      },
      respondWith,
    });

    expect(respondWith).not.toHaveBeenCalled();
  });

  it("still handles normal app-shell navigations", async () => {
    const { fetchHandler } = loadServiceWorker();
    const respondWith = vi.fn();

    fetchHandler({
      request: {
        method: "GET",
        mode: "navigate",
        url: "https://app.example.test/dashboard",
      },
      respondWith,
    });

    expect(respondWith).toHaveBeenCalledTimes(1);
    await respondWith.mock.calls[0]?.[0];
  });

  it("does not persist no-store navigation responses as the app shell", async () => {
    const { cache, fetchHandler } = loadServiceWorker(
      new Response("executor", { headers: { "cache-control": "no-store" } }),
    );
    const respondWith = vi.fn();

    fetchHandler({
      request: {
        method: "GET",
        mode: "navigate",
        url: "https://app.example.test/dashboard",
      },
      respondWith,
    });

    await respondWith.mock.calls[0]?.[0];
    expect(cache.put).not.toHaveBeenCalled();
  });

  it("trims app-shell cache to the design cap while preserving index", async () => {
    const cacheKeys = [
      new ServiceWorkerTestRequest("/index.html"),
      ...Array.from(
        { length: 51 },
        (_, index) => new ServiceWorkerTestRequest(`/assets/chunk-${index}.js`),
      ),
    ];
    const { cache, fetchHandler } = loadServiceWorker(new Response("asset"), cacheKeys);
    const respondWith = vi.fn();

    fetchHandler({
      request: {
        method: "GET",
        url: "https://app.example.test/assets/new-chunk.js",
      },
      respondWith,
    });

    await respondWith.mock.calls[0]?.[0];
    await flushAsyncWork();

    const deletedUrls = cache.delete.mock.calls.map(([request]) => (request as Request).url);
    expect(cache.delete).toHaveBeenCalledTimes(2);
    expect(deletedUrls).toEqual([
      "https://app.example.test/assets/chunk-0.js",
      "https://app.example.test/assets/chunk-1.js",
    ]);
    expect(deletedUrls).not.toContain("https://app.example.test/index.html");
  });
});
