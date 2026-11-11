/* Daily reminder notifications (web push).

   A player's browser gives us an anonymous "push address" (endpoint + two keys). We store it with the
   reminder time they chose, their time zone, and the day they last played, so we never nag someone who
   has already played. No names or emails.

   Routes:
     GET  /api/push/key                                  -> {key}  public key the browser needs to subscribe
     POST /api/push/subscribe   {sub, hour, tz, evening, lastPlayed, streak}
     POST /api/push/unsubscribe {endpoint}
     POST /api/push/played      {endpoint, day, streak}  (after a finished game, and on each visit)

   Every hour (Cloudflare cron) sendDueReminders() sends:
     - the daily reminder at the player's chosen hour, unless they've played today;
     - at 20:00 their time, "your streak ends at midnight" if they have a streak of 2+ days and haven't played today.

   Messages are encrypted for the browser (RFC 8291) and signed with our VAPID key (RFC 8292),
   using only the Web Crypto API available in Workers. The VAPID key pair lives in the config table. */

const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
const bad = (msg, status = 400) => json({ error: msg }, status);
const EVENING_HOUR = 20;

const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const concat = (...arrs) => { const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0)); let i = 0; for (const a of arrs) { out.set(a, i); i += a.length; } return out; };

async function body(request) {
  const text = await request.text();
  if (text.length > 4000) return {};
  try { return JSON.parse(text) || {}; } catch (e) { return {}; }
}
async function sha256hex(s) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
const validDay = (d) => typeof d === "string" && /^\d{4}-\d{2}-\d{2}$/.test(d);
function validTz(tz) {
  if (typeof tz !== "string" || tz.length > 64) return false;
  try { new Intl.DateTimeFormat("en-GB", { timeZone: tz }); return true; } catch (e) { return false; }
}
function validSub(s) {
  return s && typeof s.endpoint === "string" && /^https:\/\//.test(s.endpoint) && s.endpoint.length < 1000
    && s.keys && typeof s.keys.p256dh === "string" && typeof s.keys.auth === "string"
    && s.keys.p256dh.length < 200 && s.keys.auth.length < 100;
}

/* ---------- VAPID keys ---------- */
let vapidCache = null;
async function vapid(env) {
  if (vapidCache) return vapidCache;
  const row = await env.DB.prepare("SELECT v FROM config WHERE k='vapid_jwk'").first("v");
  if (!row) return null;
  const jwk = JSON.parse(row);
  const key = await crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y, d: jwk.d, ext: true },
    { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const pub = b64u(concat(new Uint8Array([4]), unb64u(jwk.x), unb64u(jwk.y)));
  return (vapidCache = { key, pub });
}
async function vapidHeader(endpoint, v) {
  const aud = new URL(endpoint).origin;
  const head = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: "https://capiclue.com" })));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, v.key, enc.encode(head + "." + claims));
  return `vapid t=${head}.${claims}.${b64u(sig)}, k=${v.pub}`;
}

/* ---------- message encryption (aes128gcm) ---------- */
async function hkdf(salt, ikm, info, bytes) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, bytes * 8));
}
export async function encryptPayload(p256dh, authSecret, payload) {
  const uaPublic = unb64u(p256dh), auth = unb64u(authSecret);
  const local = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await crypto.subtle.exportKey("raw", local.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdh = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, local.privateKey, 256));
  const ikm = await hkdf(auth, ecdh, concat(enc.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const plain = concat(enc.encode(payload), new Uint8Array([2]));   // 0x02 = last (only) record
  const cipher = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, plain));
  const rs = new Uint8Array([0, 0, 16, 0]);   // record size 4096
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, cipher);
}
export async function sendPush(sub, message, v, ttl = 6 * 3600) {
  const bodyBytes = await encryptPayload(sub.p256dh, sub.auth, JSON.stringify(message));
  return fetch(sub.endpoint, {
    method: "POST",
    headers: { Authorization: await vapidHeader(sub.endpoint, v), "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream", TTL: String(ttl), Urgency: "normal" },
    body: bodyBytes,
  });
}

/* ---------- local time helpers ---------- */
function localNow(tz, now = new Date()) {
  const parts = Object.fromEntries(new Intl.DateTimeFormat("en-GB", { timeZone: tz, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", hourCycle: "h23" })
    .formatToParts(now).map((p) => [p.type, p.value]));
  return { day: `${parts.year}-${parts.month}-${parts.day}`, hour: parseInt(parts.hour, 10) };
}
const prevDay = (d) => new Date(Date.parse(d + "T00:00:00Z") - 864e5).toISOString().slice(0, 10);

/* ---------- routes ---------- */
export async function pushRoutes(request, env, url) {
  const p = url.pathname, m = request.method;
  if (p === "/api/push/key" && m === "GET") {
    const v = await vapid(env);
    return v ? json({ key: v.pub }) : bad("Reminders aren't available right now.", 503);
  }
  if (p === "/api/push/subscribe" && m === "POST") {
    const d = await body(request), s = d.sub;
    const hour = Number.isInteger(d.hour) && d.hour >= 0 && d.hour <= 23 ? d.hour : null;
    if (!validSub(s) || hour === null || !validTz(d.tz)) return bad("Invalid request.");
    const id = await sha256hex(s.endpoint), now = Date.now();
    await env.DB.prepare(
      `INSERT INTO push_subs (id, endpoint, p256dh, auth, hour, tz, evening, last_played, streak, created, updated)
       VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?10)
       ON CONFLICT(id) DO UPDATE SET p256dh=?3, auth=?4, hour=?5, tz=?6, evening=?7,
         last_played=COALESCE(?8, last_played), streak=COALESCE(?9, streak), updated=?10, fails=0`)
      .bind(id, s.endpoint, s.keys.p256dh, s.keys.auth, hour, d.tz, d.evening ? 1 : 0,
        validDay(d.lastPlayed) ? d.lastPlayed : null, Number.isInteger(d.streak) ? Math.min(d.streak, 9999) : null, now).run();
    return json({ ok: true });
  }
  if (p === "/api/push/unsubscribe" && m === "POST") {
    const d = await body(request);
    if (typeof d.endpoint !== "string") return bad("Invalid request.");
    await env.DB.prepare("DELETE FROM push_subs WHERE id=?").bind(await sha256hex(d.endpoint)).run();
    return json({ ok: true });
  }
  if (p === "/api/push/played" && m === "POST") {
    const d = await body(request);
    if (typeof d.endpoint !== "string" || !validDay(d.day)) return bad("Invalid request.");
    const r = await env.DB.prepare(
      `UPDATE push_subs SET last_played=?2, streak=?3, updated=?4 WHERE id=?1 AND (last_played IS NULL OR last_played<=?2)`)
      .bind(await sha256hex(d.endpoint), d.day, Number.isInteger(d.streak) ? Math.min(d.streak, 9999) : 0, Date.now()).run();
    return json({ ok: true, known: (r.meta?.changes || 0) > 0 });
  }
  return bad("Not found", 404);
}

/* ---------- the hourly job ---------- */
export function reminderFor(row, now = new Date()) {
  let t;
  try { t = localNow(row.tz, now); } catch (e) { return null; }
  if (row.last_played === t.day) return null;                       // already played today
  const alive = row.last_played === prevDay(t.day) ? row.streak || 0 : 0;
  if (row.evening && t.hour === EVENING_HOUR && alive >= 2 && row.last_evening !== t.day) {
    return { kind: "evening", day: t.day, msg: { title: `⏳ Your ${alive}-day streak ends at midnight`, body: "Play today’s 5 capitals to keep it going.", tag: "capiclue-evening", url: "/?r=push_evening" } };
  }
  if (t.hour === row.hour && row.last_sent !== t.day) {
    return { kind: "daily", day: t.day, msg: { title: "🌍 Today’s 5 capitals are ready",
      body: alive >= 1 ? `Keep your 🔥 ${alive}-day streak going!` : "Can you name them from fun facts?", tag: "capiclue-daily", url: "/?r=push" } };
  }
  return null;
}
export async function sendDueReminders(env, now = new Date()) {
  const v = await vapid(env);
  if (!v) return { sent: 0 };
  const rows = (await env.DB.prepare("SELECT * FROM push_subs").all()).results;
  let sent = 0, removed = 0;
  for (const row of rows) {
    const r = reminderFor(row, now);
    if (!r) continue;
    let res;
    try { res = await sendPush(row, r.msg, v); } catch (e) { res = null; }
    if (res && (res.status === 404 || res.status === 410)) {          // the browser unsubscribed: forget it
      await env.DB.prepare("DELETE FROM push_subs WHERE id=?").bind(row.id).run(); removed++; continue;
    }
    if (res && res.ok) {
      sent++;
      await env.DB.prepare(r.kind === "evening"
        ? "UPDATE push_subs SET last_evening=?2, fails=0 WHERE id=?1"
        : "UPDATE push_subs SET last_sent=?2, fails=0 WHERE id=?1").bind(row.id, r.day).run();
      if (r.kind === "evening" && row.hour === EVENING_HOUR) await env.DB.prepare("UPDATE push_subs SET last_sent=?2 WHERE id=?1").bind(row.id, r.day).run();
    } else {
      await env.DB.prepare("UPDATE push_subs SET fails=fails+1 WHERE id=?").bind(row.id).run();
      await env.DB.prepare("DELETE FROM push_subs WHERE id=? AND fails>=5").bind(row.id).run();
    }
  }
  return { sent, removed };
}
