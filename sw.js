/* 只缓存程序文件，绝不缓存用户文件。 */

const CACHE = "gitbb-v4";
const ASSETS = [
  "./",
  "./index.html",
  "./manifest.webmanifest",
  "./css/app.css",
  "./js/app.js",
  "./js/util.js",
  "./js/crypto.js",
  "./js/backup.js",
  "./js/queue.js",
  "./js/storage.js",
  "./js/webauthn.js",
  "./js/export.js",
  "./js/pinflow.js",
  "./js/recovery.js",
];

const ASSET_PATHS = new Set(ASSETS.map((path) => new URL(path, self.location).pathname));

function isAppShell(url) {
  return ASSET_PATHS.has(url.pathname);
}

async function precache() {
  const cache = await caches.open(CACHE);
  await Promise.all(
    ASSETS.map(async (path) => {
      const request = new Request(new URL(path, self.location), { cache: "reload" });
      const response = await fetch(request);
      if (!response.ok) throw new Error(`无法缓存 ${path}`);
      await cache.put(path, response);
    })
  );
}

async function networkFirst(request) {
  const cache = await caches.open(CACHE);
  try {
    const fresh = await fetch(request);
    if (fresh && fresh.ok) {
      await cache.put(request, fresh.clone());
    }
    if (fresh) return fresh;
  } catch {
    /* 离线时使用已缓存的程序文件 */
  }
  const cached = await caches.match(request, { ignoreSearch: true });
  if (cached) return cached;
  if (request.mode === "navigate") {
    const fallback = await caches.match("./index.html");
    if (fallback) return fallback;
  }
  return new Response("离线且没有可用的程序缓存", { status: 503 });
}

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      await precache();
      await self.skipWaiting();
    })()
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      await Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key)));
      await self.clients.claim();
    })()
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.protocol === "blob:" || url.protocol === "data:") return;
  if (url.pathname.endsWith("/sw.js")) return;

  if (!isAppShell(url)) return;

  event.respondWith(networkFirst(request));
});
