const CACHE_NAME = "app-shell-v1";
const MAX_CACHE_ENTRIES = 50;
const APP_SHELL_NAVIGATION_EXCLUDE_PATHS = new Set(["/plugin-network-executor"]);

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then(async (cache) => {
      // Pre-cache index.html
      await cache.add(new Request("/index.html", { credentials: "same-origin" })).catch(() => {});
      // Pre-cache linked JS/CSS assets from index.html
      try {
        const html = await fetch("/index.html").then((r) => r.text());
        const assetUrls = new Set();
        const scriptMatches = html.matchAll(/src="(\/assets\/[^"]+)"/g);
        for (const m of scriptMatches) assetUrls.add(m[1]);
        const linkMatches = html.matchAll(/href="(\/assets\/[^"]+)"/g);
        for (const m of linkMatches) assetUrls.add(m[1]);
        const assetList = Array.from(assetUrls);
        await Promise.all(assetList.map((url) => cache.add(url).catch(() => {})));

        // Pre-cache crypto worker script (loaded dynamically, not in HTML tags).
        // Vite emits it as a separate chunk referenced in the main bundle.
        for (const jsUrl of assetList.filter((u) => u.endsWith(".js"))) {
          try {
            const jsText = await fetch(jsUrl).then((r) => r.text());
            const workerRefs = jsText.matchAll(/new Worker\(new URL\("(\/assets\/[^"]+)"/g);
            for (const wm of workerRefs) {
              await cache.add(wm[1]).catch(() => {});
            }
            // Also match Vite's compiled worker pattern: new Worker("url", ...)
            const workerRefs2 = jsText.matchAll(/new Worker\("(\/assets\/[^"]+)"/g);
            for (const wm of workerRefs2) {
              await cache.add(wm[1]).catch(() => {});
            }
          } catch {
            // Best effort
          }
        }
      } catch {
        // Best effort — assets will be cached lazily on first navigation
      }
      await trimCache(cache);
    }),
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((names) =>
        Promise.all(
          names
            .filter((name) => name.startsWith("app-shell-") && name !== CACHE_NAME)
            .map((name) => caches.delete(name)),
        ),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;

  // Only handle GET requests
  if (request.method !== "GET") return;

  const url = new URL(request.url);

  // Skip API, WebSocket, and extension requests
  if (url.pathname.startsWith("/api/")) return;
  if (APP_SHELL_NAVIGATION_EXCLUDE_PATHS.has(url.pathname)) return;
  if (url.protocol !== "http:" && url.protocol !== "https:") return;

  // Navigation requests: network-first, always cache as /index.html for offline fallback
  if (request.mode === "navigate") {
    event.respondWith(
      fetch(request)
        .then((response) => {
          const cacheControl = response.headers.get("cache-control") || "";
          if (response.ok && !cacheControl.toLowerCase().includes("no-store")) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(new Request("/index.html"), clone).then(() => trimCache(cache));
            });
          }
          return response;
        })
        .catch(() => caches.match("/index.html")),
    );
    return;
  }

  // App shell assets only: hashed JS/CSS, worker scripts, fonts, icons
  const isAppShellAsset =
    url.pathname.startsWith("/assets/") ||
    url.pathname.endsWith(".woff2") ||
    url.pathname.endsWith(".woff") ||
    url.pathname.endsWith(".ttf") ||
    url.pathname.endsWith(".svg") ||
    url.pathname.endsWith(".ico") ||
    url.pathname.endsWith(".png");
  if (isAppShellAsset && url.origin === self.location.origin) {
    event.respondWith(
      caches.open(CACHE_NAME).then((cache) =>
        cache.match(request).then((cached) => {
          if (cached) {
            // LRU: re-put to move to end of insertion order
            cache.put(request, cached.clone()).catch(() => {});
            return cached;
          }
          return fetch(request).then((response) => {
            if (response.ok) {
              cache.put(request, response.clone()).then(() => trimCache(cache));
            }
            return response;
          });
        }),
      ),
    );
    return;
  }
});

async function trimCache(cache) {
  const keys = await cache.keys();
  if (keys.length <= MAX_CACHE_ENTRIES) return;
  const evictable = keys.filter((req) => new URL(req.url).pathname !== "/index.html");
  const excess = keys.length - MAX_CACHE_ENTRIES;
  const toDelete = evictable.slice(0, excess);
  await Promise.all(toDelete.map((key) => cache.delete(key)));
}
