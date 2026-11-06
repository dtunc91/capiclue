/* Friend leagues.
   A player is a nickname plus a private random token kept on their device (no email, no password).
   Only a scrambled version (SHA-256) of the token is stored here.

   POST /api/player          {name}                        -> {id, token, name}
   POST /api/player/rename   {name}            (token)     -> {name}
   POST /api/player/link                       (token)     -> {code, expires}   one-time code for another device (10 min)
   GET  /api/player/peek?code=XXXXXXXX                     -> {name}
   POST /api/player/claim    {code}                        -> {id, token, name}   that device becomes the same player
   GET  /api/leagues                           (token)     -> {player, leagues:[{code,name,members}]}
   POST /api/league/create   {name}            (token)     -> {code, name}
   GET  /api/league/info?code=ABC123                       -> {code, name, members}   (public: for the invite screen)
   POST /api/league/join     {code}            (token)     -> {code, name}
   POST /api/league/leave    {code}            (token)     -> {ok}
   POST /api/league/rename   {code, name}      (token)     -> {code, name}   (creator only)
   GET  /api/league/table?code&day&level       (token)     -> today + this week tables
   POST /api/score           {day, level, score, pattern} (token)
   The token travels in the "x-player-token" header. */

const LEVELS = new Set(["easy", "medium", "hard"]);
const MAX_LEAGUES_PER_PLAYER = 20;
const MAX_MEMBERS = 50;
const CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";   // no 0/O, 1/I to avoid typos

const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
  status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store" } });
const bad = (msg, status = 400) => json({ error: msg }, status);

async function sha256(s) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function randomString(len, chars) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return [...bytes].map((b) => chars[b % chars.length]).join("");
}
function cleanName(s, max) {
  if (typeof s !== "string") return null;
  const t = s.replace(/[\u0000-\u001f\u007f<>]/g, "").replace(/\s+/g, " ").trim().slice(0, max);
  return t.length >= 1 ? t : null;
}
const validDay = (d) => typeof d === "string" && /^\d{4}-\d{2}-\d{2}$/.test(d) && !isNaN(Date.parse(d + "T00:00:00Z"));
function dayWithinReach(d) {      // players' local day can be a day ahead/behind UTC
  const diff = (Date.parse(d + "T00:00:00Z") - Date.parse(new Date().toISOString().slice(0, 10) + "T00:00:00Z")) / 864e5;
  return diff >= -2 && diff <= 1;
}
function weekRange(d) {           // Monday..Sunday containing day d
  const t = new Date(d + "T00:00:00Z"), dow = (t.getUTCDay() + 6) % 7;
  const mon = new Date(t.getTime() - dow * 864e5), sun = new Date(mon.getTime() + 6 * 864e5);
  return [mon.toISOString().slice(0, 10), sun.toISOString().slice(0, 10)];
}
async function body(request) {
  const text = await request.text();
  if (text.length > 2000) return {};
  try { return JSON.parse(text) || {}; } catch (e) { return {}; }
}
async function currentPlayer(request, env) {
  const token = request.headers.get("x-player-token") || "";
  if (!/^[A-Za-z0-9]{32,64}$/.test(token)) return null;
  const h = await sha256("capiclue-player:" + token);
  // a player's first device, or any extra device linked with "Play on another device"
  return (await env.DB.prepare("SELECT id, name FROM players WHERE token_hash=?").bind(h).first())
      || (await env.DB.prepare("SELECT p.id, p.name FROM player_tokens t JOIN players p ON p.id=t.player WHERE t.token_hash=?").bind(h).first());
}
const LINK_MINUTES = 10;
const newToken = () => randomString(40, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
async function findLinkCode(env, raw) {
  const code = String(raw || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (code.length !== 8) return null;
  return env.DB.prepare("SELECT l.code, l.player, p.name FROM link_codes l JOIN players p ON p.id=l.player WHERE l.code=? AND l.expires>?")
    .bind(code, Date.now()).first();
}

export async function leagueRoutes(request, env, url) {
  const p = url.pathname, m = request.method;

  if (p === "/api/player" && m === "POST") {
    const d = await body(request); const name = cleanName(d.name, 20);
    if (!name) return bad("Please choose a nickname.");
    const id = randomString(12, CODE_CHARS.toLowerCase() + "abcdefghijkmnpqrstuvwxyz");
    const token = newToken();
    await env.DB.prepare("INSERT INTO players (id, token_hash, name, created) VALUES (?,?,?,?)")
      .bind(id, await sha256("capiclue-player:" + token), name, Date.now()).run();
    return json({ id, token, name });
  }

  if (p === "/api/league/info" && m === "GET") {          // public, for "You're invited to …"
    const code = (url.searchParams.get("code") || "").toUpperCase();
    const lg = await env.DB.prepare("SELECT code, name FROM leagues WHERE code=?").bind(code).first();
    if (!lg) return bad("This league doesn’t exist.", 404);
    const n = await env.DB.prepare("SELECT COUNT(*) n FROM members WHERE league=?").bind(code).first("n");
    return json({ ...lg, members: n });
  }

  /* "Play on another device": the second device previews and then redeems a one-time code (no sign-in needed). */
  if (p === "/api/player/peek" && m === "GET") {
    const lc = await findLinkCode(env, url.searchParams.get("code"));
    return lc ? json({ name: lc.name }) : bad("This code has expired or was already used. Make a new one on your other device.", 404);
  }
  if (p === "/api/player/claim" && m === "POST") {
    const lc = await findLinkCode(env, (await body(request)).code);
    if (!lc) return bad("This code has expired or was already used. Make a new one on your other device.", 404);
    const token = newToken(), now = Date.now();
    await env.DB.batch([
      env.DB.prepare("DELETE FROM link_codes WHERE code=?").bind(lc.code),          // works once
      env.DB.prepare("INSERT INTO player_tokens (token_hash, player, created) VALUES (?,?,?)").bind(await sha256("capiclue-player:" + token), lc.player, now),
    ]);
    return json({ id: lc.player, token, name: lc.name });
  }

  const me = await currentPlayer(request, env);
  if (!me) return bad("Not signed in.", 401);

  if (p === "/api/player/link" && m === "POST") {      // make a one-time code for another device
    const code = randomString(8, CODE_CHARS), expires = Date.now() + LINK_MINUTES * 60e3;
    await env.DB.batch([
      env.DB.prepare("DELETE FROM link_codes WHERE expires<? OR player=?").bind(Date.now(), me.id),   // one live code per player
      env.DB.prepare("INSERT INTO link_codes (code, player, expires) VALUES (?,?,?)").bind(code, me.id, expires),
    ]);
    return json({ code, expires });
  }

  if (p === "/api/player/rename" && m === "POST") {
    const name = cleanName((await body(request)).name, 20);
    if (!name) return bad("Please choose a nickname.");
    await env.DB.prepare("UPDATE players SET name=? WHERE id=?").bind(name, me.id).run();
    return json({ name });
  }

  if (p === "/api/leagues" && m === "GET") {
    const rows = await env.DB.prepare(
      `SELECT l.code, l.name, (SELECT COUNT(*) FROM members x WHERE x.league=l.code) members
       FROM members mb JOIN leagues l ON l.code=mb.league WHERE mb.player=? ORDER BY mb.joined`).bind(me.id).all();
    return json({ player: me, leagues: rows.results });
  }

  if (p === "/api/league/create" && m === "POST") {
    const name = cleanName((await body(request)).name, 30);
    if (!name) return bad("Please give your league a name.");
    const count = await env.DB.prepare("SELECT COUNT(*) n FROM members WHERE player=?").bind(me.id).first("n");
    if (count >= MAX_LEAGUES_PER_PLAYER) return bad("You’re in the maximum number of leagues.");
    let code;
    for (let i = 0; i < 5; i++) {
      code = randomString(6, CODE_CHARS);
      if (!(await env.DB.prepare("SELECT 1 FROM leagues WHERE code=?").bind(code).first())) break;
    }
    const now = Date.now();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO leagues (code, name, owner, created) VALUES (?,?,?,?)").bind(code, name, me.id, now),
      env.DB.prepare("INSERT INTO members (league, player, joined) VALUES (?,?,?)").bind(code, me.id, now),
    ]);
    return json({ code, name });
  }

  if (p === "/api/league/join" && m === "POST") {
    const code = String((await body(request)).code || "").toUpperCase();
    const lg = await env.DB.prepare("SELECT code, name FROM leagues WHERE code=?").bind(code).first();
    if (!lg) return bad("This league doesn’t exist.", 404);
    const already = await env.DB.prepare("SELECT 1 FROM members WHERE league=? AND player=?").bind(code, me.id).first();
    if (!already) {
      const [mine, size] = await Promise.all([
        env.DB.prepare("SELECT COUNT(*) n FROM members WHERE player=?").bind(me.id).first("n"),
        env.DB.prepare("SELECT COUNT(*) n FROM members WHERE league=?").bind(code).first("n"),
      ]);
      if (mine >= MAX_LEAGUES_PER_PLAYER) return bad("You’re in the maximum number of leagues.");
      if (size >= MAX_MEMBERS) return bad("This league is full.");
      await env.DB.prepare("INSERT INTO members (league, player, joined) VALUES (?,?,?)").bind(code, me.id, Date.now()).run();
    }
    return json(lg);
  }

  if (p === "/api/league/rename" && m === "POST") {      // only the person who created the league
    const d = await body(request), code = String(d.code || "").toUpperCase(), name = cleanName(d.name, 30);
    if (!name) return bad("Please give your league a name.");
    const lg = await env.DB.prepare("SELECT owner FROM leagues WHERE code=?").bind(code).first();
    if (!lg) return bad("This league doesn’t exist.", 404);
    if (lg.owner !== me.id) return bad("Only the person who created this league can rename it.", 403);
    await env.DB.prepare("UPDATE leagues SET name=? WHERE code=?").bind(name, code).run();
    return json({ code, name });
  }

  if (p === "/api/league/leave" && m === "POST") {
    const code = String((await body(request)).code || "").toUpperCase();
    await env.DB.prepare("DELETE FROM members WHERE league=? AND player=?").bind(code, me.id).run();
    return json({ ok: true });
  }

  if (p === "/api/score" && m === "POST") {
    const d = await body(request);
    const score = Number.isInteger(d.score) && d.score >= 0 && d.score <= 100 && d.score % 5 === 0 ? d.score : null;
    const pattern = typeof d.pattern === "string" && /^[0-9]{5}$/.test(d.pattern) ? d.pattern : null;
    if (!validDay(d.day) || !dayWithinReach(d.day) || !LEVELS.has(d.level) || score === null || !pattern) return bad("Invalid score.");
    // first finished game of the day counts; replays don't overwrite it
    await env.DB.prepare("INSERT OR IGNORE INTO scores (player, day, level, score, pattern, ts) VALUES (?,?,?,?,?,?)")
      .bind(me.id, d.day, d.level, score, pattern, Date.now()).run();
    return json({ ok: true });
  }

  if (p === "/api/league/table" && m === "GET") {
    const code = (url.searchParams.get("code") || "").toUpperCase(), day = url.searchParams.get("day") || "", level = url.searchParams.get("level") || "";
    if (!validDay(day) || !(LEVELS.has(level) || level === "all")) return bad("Invalid request.");
    const lg = await env.DB.prepare("SELECT code, name, owner FROM leagues WHERE code=?").bind(code).first();
    if (!lg) return bad("This league doesn’t exist.", 404);
    if (!(await env.DB.prepare("SELECT 1 FROM members WHERE league=? AND player=?").bind(code, me.id).first())) return bad("You’re not in this league.", 403);
    const [mon, sun] = weekRange(day);
    // League points: Easy x1, Medium x2, Hard x3. "all" adds every level together.
    const MULT = "(CASE s.level WHEN 'easy' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END)";
    const LV = "(?3='all' OR s.level=?3)";
    const rows = await env.DB.prepare(
      `SELECT p.id, p.name,
         (SELECT SUM(s.score*${MULT}) FROM scores s WHERE s.player=p.id AND s.day=?2 AND ${LV}) today,
         (SELECT s.pattern FROM scores s WHERE s.player=p.id AND s.day=?2 AND s.level=?3) pattern,
         (SELECT s.score FROM scores s WHERE s.player=p.id AND s.day=?2 AND s.level='easy') easy,
         (SELECT s.score FROM scores s WHERE s.player=p.id AND s.day=?2 AND s.level='medium') medium,
         (SELECT s.score FROM scores s WHERE s.player=p.id AND s.day=?2 AND s.level='hard') hard,
         (SELECT SUM(s.score*${MULT}) FROM scores s WHERE s.player=p.id AND ${LV} AND s.day BETWEEN ?4 AND ?5) week,
         (SELECT COUNT(DISTINCT s.day) FROM scores s WHERE s.player=p.id AND ${LV} AND s.day BETWEEN ?4 AND ?5) days
       FROM members mb JOIN players p ON p.id=mb.player WHERE mb.league=?1`).bind(code, day, level, mon, sun).all();
    return json({ code: lg.code, name: lg.name, isOwner: lg.owner === me.id, me: me.id, day, level, week: [mon, sun], members: rows.results });
  }

  return bad("Not found", 404);
}
