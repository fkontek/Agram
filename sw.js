const CACHE_NAME = "agram-pilates-v3";
const ASSETS = [
  "./",
  "./index.html",
  "./prijava.html",
  "./dashboard.html",
  "./admin.html",
  "./style.css",
  "./app.js",
  "./ScrollEditor.js",
  "./manifest.json",
  "./agram.ico",
  "./img/logo.jpg"
];

// Install Event
self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log("Caching assets...");
      return cache.addAll(ASSETS);
    })
  );
  self.skipWaiting();
});

// Activate Event
self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => {
      return Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) {
            return caches.delete(key);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch Event
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);

  // Bypass cache for API calls to Cloudflare Worker
  if (url.pathname.includes("/api/") || url.host.includes("workers.dev")) {
    return; // Let browser handle it over the network
  }

  // Network-first strategy for HTML pages, cache-first for assets (images, CSS)
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        // Clone response to put it in cache
        const resClone = res.clone();
        caches.open(CACHE_NAME).then((cache) => {
          cache.put(e.request, resClone);
        });
        return res;
      })
      .catch(() => caches.match(e.request))
  );
});
