/* Capiclue Cloudflare program.
   - POST /api/event : stores one anonymous game moment (no names, emails or IP addresses are stored)
   - GET  /api/stats : totals for the private stats page (needs the stats password)
   - everything else : the normal website files, unchanged */

const EVENTS = new Set(["visit", "start", "city", "finish", "lucky", "share", "remind", "install", "level"]);
const LEVELS = new Set(["easy", "medium", "hard"]);
const WORD = /^[a-z0-9_-]{1,24}$/;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/api/event" && request.method === "POST") return saveEvent(request, env, ctx);
    if (url.pathname === "/api/stats" && request.method === "GET") return stats(request, env, url);
    if (url.pathname.startsWith("/api/")) return new Response("Not found", { status: 404 });
    return env.ASSETS.fetch(request);
  },
};

const word = (v) => (typeof v === "string" && WORD.test(v) ? v : null);
const int = (v, min, max) => (Number.isInteger(v) && v >= min && v <= max ? v : null);
const flag = (v) => (v === true ? 1 : v === false ? 0 : null);

async function saveEvent(request, env, ctx) {
  const ok = new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  try {
    if (/bot|crawl|spider|preview/i.test(request.headers.get("user-agent") || "")) return ok;
    const text = await request.text();
    if (text.length > 1500) return ok;
    const d = JSON.parse(text);
    if (!EVENTS.has(d.ev)) return ok;
    const now = Date.now();
    const row = [
      now, new Date(now).toISOString().slice(0, 10), d.ev,
      LEVELS.has(d.level) ? d.level : null,
      int(d.city, 1, 5), int(d.facts, 1, 4), word(d.result), int(d.score, 0, 100), word(d.app),
      word(d.gid), flag(d.ret), flag(d.inst), d.dev === "phone" || d.dev === "desktop" ? d.dev : null,
      word((request.cf && request.cf.country) ? String(request.cf.country).toLowerCase() : null),
    ];
    ctx.waitUntil(env.DB.prepare(
      "INSERT INTO events (ts,day,ev,level,city,facts,result,score,app,gid,ret,inst,dev,country) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(...row).run().catch(() => {}));
  } catch (e) { /* ignore bad input */ }
  return ok;
}

async function sha256(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function stats(request, env, url) {
  const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
    status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
  const key = request.headers.get("x-stats-key") || "";
  const saved = await env.DB.prepare("SELECT v FROM config WHERE k='stats_pw_sha256'").first("v");
  if (!saved || (await sha256("capiclue-stats:" + key)) !== saved) return json({ error: "Wrong password" }, 401);

  const days = Math.min(Math.max(parseInt(url.searchParams.get("days") || "7", 10) || 7, 1), 365);
  const since = new Date(Date.now() - (days - 1) * 864e5).toISOString().slice(0, 10);
  const q = (sql) => env.DB.prepare(sql).bind(since);
  const [daily, funnel, results, scores, shares, reminders, lucky, visits, countries, levels] = await env.DB.batch([
    q(`SELECT day,
         SUM(ev='visit') visits, SUM(ev='visit' AND ret=1) returning_visits,
         COUNT(DISTINCT CASE WHEN ev='start' THEN gid END) games_started,
         COUNT(DISTINCT CASE WHEN ev='finish' THEN gid END) games_finished,
         SUM(ev='share') shares
       FROM events WHERE day>=? GROUP BY day ORDER BY day`),
    q(`SELECT level, 0 city, COUNT(DISTINCT gid) players FROM events WHERE day>=? AND ev='start' GROUP BY level
       UNION ALL SELECT level, city, COUNT(DISTINCT gid) FROM events WHERE day>=?1 AND ev='city' GROUP BY level, city
       UNION ALL SELECT level, 6, COUNT(DISTINCT gid) FROM events WHERE day>=?1 AND ev='finish' GROUP BY level`),
    q(`SELECT level, result, facts, COUNT(*) n FROM events WHERE day>=? AND ev='city' GROUP BY level, result, facts`),
    q(`SELECT level, COUNT(*) games, ROUND(AVG(score),1) avg_score, SUM(score=100) perfect FROM events WHERE day>=? AND ev='finish' GROUP BY level`),
    q(`SELECT app, COUNT(*) n FROM events WHERE day>=? AND ev='share' GROUP BY app ORDER BY n DESC`),
    q(`SELECT app, result time, COUNT(*) n FROM events WHERE day>=? AND ev='remind' GROUP BY app, result ORDER BY n DESC`),
    q(`SELECT level, result, COUNT(*) n FROM events WHERE day>=? AND ev='lucky' GROUP BY level, result`),
    q(`SELECT dev, inst, ret, COUNT(*) n FROM events WHERE day>=? AND ev='visit' GROUP BY dev, inst, ret`),
    q(`SELECT country, COUNT(*) n FROM events WHERE day>=? AND ev='visit' GROUP BY country ORDER BY n DESC LIMIT 15`),
    q(`SELECT level, COUNT(*) n FROM events WHERE day>=? AND ev='level' GROUP BY level`),
  ]);
  const r = (x) => x.results;
  return json({ days, since, daily: r(daily), funnel: r(funnel), results: r(results), scores: r(scores),
    shares: r(shares), reminders: r(reminders), lucky: r(lucky), visits: r(visits), countries: r(countries), levels: r(levels) });
}
