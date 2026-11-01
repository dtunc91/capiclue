/* Capiclue offline helper.
   Pages: always try the internet first so players get updates straight away; use the saved copy only when offline.
   Fonts and icons: use the saved copy first (they never change). */
const CACHE = "capiclue-v1";
const CORE = ["/", "/manifest.webmanifest", "/favicon.svg", "/icon-192.png", "/icon-512.png", "/apple-touch-icon.png"];

self.addEventListener("install", e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(CORE)).then(() => self.skipWaiting()));
});
self.addEventListener("activate", e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
    .then(() => self.clients.claim()));
});
self.addEventListener("fetch", e => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  const isFont = url.hostname === "fonts.googleapis.com" || url.hostname === "fonts.gstatic.com";
  const isPage = req.mode === "navigate";
  if (isPage) {   // network first, fall back to the saved game page
    e.respondWith(fetch(req).then(res => { const copy = res.clone(); caches.open(CACHE).then(c => c.put("/", copy)); return res; })
      .catch(() => caches.match("/")));
  } else if (isFont || (url.origin === location.origin && /\.(png|svg|webmanifest)$/.test(url.pathname))) {   // cache first
    e.respondWith(caches.match(req).then(hit => hit || fetch(req).then(res => {
      const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); return res; })));
  }
});
