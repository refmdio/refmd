import { afterEach, describe, expect, it, vi } from "vitest";
import {
  client,
  initializeApiClient,
  isPasswordChallengeEndpoint,
  shouldUseShareSessionScopeHeader,
} from "./core";
import {
  notifyAuthUnauthorized,
  setAuthUnauthorizedHandler,
  type AuthSessionScope,
} from "@/shared/lib/auth/unauthorized";

describe("shouldUseShareSessionScopeHeader", () => {
  it("marks share-owned routes as share scoped", () => {
    expect(shouldUseShareSessionScopeHeader("/api/auth/ws-token")).toBe(true);
    expect(shouldUseShareSessionScopeHeader("/api/shares/share-slug")).toBe(true);
    expect(shouldUseShareSessionScopeHeader("/api/shares/share-slug/bootstrap")).toBe(true);
    expect(shouldUseShareSessionScopeHeader("/api/shares/share-slug/challenge")).toBe(true);
    expect(shouldUseShareSessionScopeHeader("/api/shares/d/document-token")).toBe(true);
    expect(shouldUseShareSessionScopeHeader("/api/shares/f/folder-token")).toBe(true);
  });

  it("does not mark user-owned routes as share scoped", () => {
    expect(shouldUseShareSessionScopeHeader("/api/shares/share-slug/mounts")).toBe(false);
    expect(shouldUseShareSessionScopeHeader("/api/mounts?workspace_id=workspace-id")).toBe(false);
    expect(shouldUseShareSessionScopeHeader("/api/auth/logout")).toBe(false);
    expect(shouldUseShareSessionScopeHeader("/api/documents/doc-id")).toBe(false);
  });
});

describe("isPasswordChallengeEndpoint", () => {
  it("matches share link and mounted share challenge endpoints", () => {
    expect(isPasswordChallengeEndpoint("/api/shares/share-slug/challenge")).toBe(true);
    expect(isPasswordChallengeEndpoint("/api/mounts/mount-id/challenge")).toBe(true);
    expect(isPasswordChallengeEndpoint("/api/shares/share-slug/bootstrap")).toBe(false);
    expect(isPasswordChallengeEndpoint("/api/mounts/mount-id")).toBe(false);
  });
});

describe("auth unauthorized handler", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    setAuthUnauthorizedHandler(null);
    initializeApiClient({ getDeviceId: () => null });
  });

  it("dispatches session expiration by scope", () => {
    const seen: AuthSessionScope[] = [];
    setAuthUnauthorizedHandler((scope) => seen.push(scope));

    notifyAuthUnauthorized("user");
    notifyAuthUnauthorized("share");
    setAuthUnauthorizedHandler(null);

    expect(seen).toEqual(["user", "share"]);
  });

  it("notifies on API 401 responses", async () => {
    const seen: AuthSessionScope[] = [];
    initializeApiClient({
      getDeviceId: () => null,
      onUnauthorized: (scope) => seen.push(scope),
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 })),
    );

    await client.GET("/api/auth/me", {
      baseUrl: "http://localhost",
    } as Parameters<typeof client.GET>[1]);

    expect(seen).toEqual(["user"]);
  });

  it("does not treat API 403 responses as session expiration", async () => {
    const seen: AuthSessionScope[] = [];
    initializeApiClient({
      getDeviceId: () => null,
      onUnauthorized: (scope) => seen.push(scope),
    });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response(JSON.stringify({ error: "forbidden" }), { status: 403 })),
    );

    await client.GET("/api/auth/me", {
      baseUrl: "http://localhost",
    } as Parameters<typeof client.GET>[1]);

    expect(seen).toEqual([]);
  });

  it("does not auto-retry password challenge rate limits", async () => {
    initializeApiClient({ getDeviceId: () => null });
    const fetchMock = vi.fn(
      async () =>
        new Response(JSON.stringify({ error: "rate_limit_exceeded", retry_after: 30 }), {
          status: 429,
          headers: { "Content-Type": "application/json", "Retry-After": "30" },
        }),
    );
    vi.stubGlobal("fetch", fetchMock);

    await client.GET("/api/shares/{share_slug}/challenge", {
      baseUrl: "http://localhost",
      params: { path: { share_slug: "share-slug" } },
    } as Parameters<typeof client.GET>[1]);

    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("replays request bodies with a fresh Request across rate-limit retries", async () => {
    initializeApiClient({ getDeviceId: () => null });
    const bodies: string[] = [];
    const fetchMock = vi
      .fn()
      .mockImplementationOnce(async (request: Request) => {
        bodies.push(await request.text());
        return new Response(JSON.stringify({ error: "rate_limit_exceeded", retry_after: 1 }), {
          status: 429,
          headers: { "Content-Type": "application/json", "Retry-After": "1" },
        });
      })
      .mockImplementationOnce(async (request: Request) => {
        bodies.push(await request.text());
        return new Response(JSON.stringify({ ok: true }), {
          status: 201,
          headers: { "Content-Type": "application/json" },
        });
      });
    vi.stubGlobal("fetch", fetchMock);

    await client.POST("/api/auth/register", {
      baseUrl: "http://localhost",
      body: {
        email: "retry@example.com",
        password: "correct horse battery staple",
      },
    } as Parameters<typeof client.POST>[1]);

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(bodies).toHaveLength(2);
    expect(JSON.parse(bodies[0] ?? "{}")).toMatchObject({ email: "retry@example.com" });
    expect(JSON.parse(bodies[1] ?? "{}")).toMatchObject({ email: "retry@example.com" });
  });
});
