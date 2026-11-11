/* Capiclue offline helper and daily reminder notifications.
   Pages: always try the internet first so players get updates straight away; use the saved copy only when offline.
   Fonts and icons: use the saved copy first (they never change). */
const CACHE = "capiclue-v2";
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
  const isGamePage = isPage && url.origin === location.origin && (url.pathname === "/" || url.pathname === "/index.html");
  if (isGamePage) {   // network first, fall back to the saved game page (only the game itself is saved)
    e.respondWith(fetch(req).then(res => {
      if (res.ok && (res.headers.get("content-type") || "").includes("text/html")) { const copy = res.clone(); caches.open(CACHE).then(c => c.put("/", copy)); }
      return res;
    }).catch(() => caches.match("/")));
  } else if (isPage) {   // other pages (privacy, calendar files): just the internet, never overwrite the game
    return;
  } else if (isFont || (url.origin === location.origin && /\.(png|svg|webmanifest)$/.test(url.pathname))) {   // cache first
    e.respondWith(caches.match(req).then(hit => hit || fetch(req).then(res => {
      const copy = res.clone(); caches.open(CACHE).then(c => c.put(req, copy)); return res; })));
  }
});

/* Daily reminders: show the notification the server sent, and open the game when it is tapped. */
self.addEventListener("push", e => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch (err) {}
  e.waitUntil(self.registration.showNotification(d.title || "Capiclue", {
    body: d.body || "Today’s 5 capitals are ready.", icon: "/icon-192.png", tag: d.tag || "capiclue", data: { url: d.url || "/" } }));
});
self.addEventListener("notificationclick", e => {
  e.notification.close();
  const url = new URL((e.notification.data && e.notification.data.url) || "/", location.origin).href;
  e.waitUntil(self.clients.matchAll({ type: "window", includeUncontrolled: true }).then(list => {
    for (const c of list) if (new URL(c.url).origin === location.origin && "focus" in c) return c.navigate(url).then(w => (w || c).focus()).catch(() => c.focus());
    return self.clients.openWindow(url);
  }));
});
