// 회원가입 / 로그인 / 관리자 승인 + 정적 파일 접근 제어 (Cloudflare Workers + D1)
//
// - 모든 요청이 이 Worker를 먼저 거치며(run_worker_first), 로그인한 '승인된' 사용자에게만
//   index.html / config.js(API 키) 등을 내려줍니다.
// - 공개 경로: /login, /login.html, /api/auth/*
// - 관리자(ADMIN_EMAIL)만: /admin, /api/admin/*

const enc = new TextEncoder();
const COOKIE = 'tp_session';
const SESSION_SECONDS = 60 * 60 * 24 * 30;
const PBKDF2_ITERATIONS = 100000; // Workers의 PBKDF2 최대 반복 횟수
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]+\.[^\s@]{2,}$/;

/* ---------- 유틸 ---------- */
const hex = buf => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
const unhex = s => Uint8Array.from(s.match(/../g) || [], h => parseInt(h, 16));
const now = () => Math.floor(Date.now() / 1000);
const randomHex = bytes => hex(crypto.getRandomValues(new Uint8Array(bytes)));
const sha256hex = async s => hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS }, key, 256);
  return new Uint8Array(bits);
}

const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers },
  });

function securityHeaders(h) {
  h.set('Cache-Control', 'private, no-store');
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('X-Frame-Options', 'DENY');
  h.set('Referrer-Policy', 'same-origin');
  return h;
}

function getCookie(request, name) {
  const m = (request.headers.get('Cookie') || '').match(new RegExp('(?:^|;\\s*)' + name + '=([^;]+)'));
  return m ? m[1] : null;
}

function sessionCookie(value, maxAge, url) {
  return `${COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}` + (url.protocol === 'https:' ? '; Secure' : '');
}

/* ---------- DB ---------- */
let schemaReady = null;
function ensureSchema(env) {
  if (!env.DB) throw new Error('D1 바인딩(DB)이 설정되지 않았습니다.');
  schemaReady ??= env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      pw_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      role TEXT NOT NULL DEFAULT 'user',
      created_at INTEGER NOT NULL
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id INTEGER NOT NULL,
      expires_at INTEGER NOT NULL
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS attempts (
      k TEXT PRIMARY KEY,
      n INTEGER NOT NULL,
      ts INTEGER NOT NULL
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS trips (
      id TEXT PRIMARY KEY,
      owner_id INTEGER NOT NULL,
      title TEXT NOT NULL DEFAULT '',
      data TEXT NOT NULL,
      stop_count INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      version INTEGER NOT NULL DEFAULT 1,
      updated_by INTEGER,
      day_count INTEGER NOT NULL DEFAULT 1,
      date_from TEXT NOT NULL DEFAULT '',
      date_to TEXT NOT NULL DEFAULT ''
    )`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS trip_shares (
      trip_id TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      created_at INTEGER NOT NULL,
      PRIMARY KEY (trip_id, user_id)
    )`),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_trips_owner ON trips (owner_id, updated_at)'),
    env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_shares_user ON trip_shares (user_id, created_at)'),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS usage_daily (
      day TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      kind TEXT NOT NULL,
      n INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (day, user_id, kind)
    )`),
    env.DB.prepare('CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)'),
    // 앱 집계 도입 전 사용량: 구글 콘솔에서 읽은 최근 30일 요청 수(관리자가 고칠 수 있음)
    env.DB.prepare('INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)').bind('console_baseline',
      JSON.stringify({ day: '2026-10-24', counts: { places: 286, routes: 180, maps_js: 102, geocoding: 27 } })),
  ]).then(async () => {
    // 공동 편집 도입 전에 만들어진 trips 테이블에는 새 컬럼을 추가합니다.
    const { results } = await env.DB.prepare('PRAGMA table_info(trips)').all();
    const cols = results.map(c => c.name), alters = [];
    if (!cols.includes('version')) alters.push(env.DB.prepare('ALTER TABLE trips ADD COLUMN version INTEGER NOT NULL DEFAULT 1'));
    if (!cols.includes('updated_by')) alters.push(env.DB.prepare('ALTER TABLE trips ADD COLUMN updated_by INTEGER'));
    if (!cols.includes('day_count')) alters.push(env.DB.prepare('ALTER TABLE trips ADD COLUMN day_count INTEGER NOT NULL DEFAULT 1'));
    if (!cols.includes('date_from')) alters.push(env.DB.prepare("ALTER TABLE trips ADD COLUMN date_from TEXT NOT NULL DEFAULT ''"));
    if (!cols.includes('date_to')) alters.push(env.DB.prepare("ALTER TABLE trips ADD COLUMN date_to TEXT NOT NULL DEFAULT ''"));
    if (alters.length) await env.DB.batch(alters);
  }).catch(err => { schemaReady = null; throw err; });
  return schemaReady;
}

async function attemptCount(env, key, windowSec) {
  const row = await env.DB.prepare('SELECT n, ts FROM attempts WHERE k = ?').bind(key).first();
  return row && row.ts >= now() - windowSec ? row.n : 0;
}
async function bumpAttempt(env, key, windowSec) {
  const t = now(), cutoff = t - windowSec;
  await env.DB.prepare(
    `INSERT INTO attempts (k, n, ts) VALUES (?, 1, ?)
     ON CONFLICT(k) DO UPDATE SET
       n = CASE WHEN ts < ? THEN 1 ELSE n + 1 END,
       ts = CASE WHEN ts < ? THEN ? ELSE ts END`
  ).bind(key, t, cutoff, cutoff, t).run();
}

/* ---------- 세션 ---------- */
async function getSession(request, env) {
  const token = getCookie(request, COOKIE);
  if (!token || !/^[0-9a-f]{64}$/.test(token)) return null;
  const row = await env.DB.prepare(
    `SELECT u.id, u.email, u.role, u.status, s.expires_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?`
  ).bind(await sha256hex(token)).first();
  if (!row || row.expires_at < now() || row.status !== 'approved') return null;
  return { id: row.id, email: row.email, role: row.role };
}

async function createSession(env, userId) {
  const token = randomHex(32);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now()),
    env.DB.prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
      .bind(await sha256hex(token), userId, now() + SESSION_SECONDS),
  ]);
  return token;
}

/* ---------- 인증 API ---------- */
async function readJson(request) {
  if (!(request.headers.get('Content-Type') || '').includes('application/json')) return null;
  try { return await request.json(); } catch { return null; }
}

async function signup(request, env) {
  const body = await readJson(request);
  const email = String(body?.email ?? '').trim().toLowerCase();
  const password = String(body?.password ?? '');
  if (!EMAIL_RE.test(email) || email.length > 254) return json({ error: '올바른 이메일 주소를 입력하세요.' }, 400);
  if (password.length < 8 || password.length > 128) return json({ error: '비밀번호는 8자 이상 128자 이하로 입력하세요.' }, 400);

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  if (await attemptCount(env, 'signup:' + ip, 3600) >= 5) return json({ error: '가입 요청이 너무 많습니다. 잠시 후 다시 시도하세요.' }, 429);
  await bumpAttempt(env, 'signup:' + ip, 3600);

  // 관리자 계정은 서버 비밀 코드(ADMIN_SETUP_CODE)를 아는 사람만 만들 수 있습니다.
  let role = 'user', status = 'pending';
  if (email === String(env.ADMIN_EMAIL || '').trim().toLowerCase()) {
    // 붙여넣기로 섞인 앞뒤 공백/줄바꿈은 무시합니다.
    const expected = String(env.ADMIN_SETUP_CODE || '').trim();
    if (!expected) return json({ error: '관리자 설정 코드(ADMIN_SETUP_CODE)가 서버에 설정되지 않았습니다.' }, 503);
    const givenText = String(body?.setupCode ?? '').trim();
    if (!givenText) return json({ error: '관리자 설정 코드를 입력하세요. (“관리자 계정 만들기”를 눌러 코드 칸을 여세요)' }, 403);
    const given = enc.encode(givenText);
    const want = enc.encode(expected);
    if (!safeEqual(given, want)) return json({ error: '관리자 설정 코드가 올바르지 않습니다.' }, 403);
    role = 'admin'; status = 'approved';
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(password, salt);
  try {
    await env.DB.prepare('INSERT INTO users (email, pw_hash, salt, status, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(email, hex(hash), hex(salt), status, role, now()).run();
  } catch (err) {
    if (String(err?.message).includes('UNIQUE')) return json({ error: '이미 가입된 이메일입니다.' }, 409);
    throw err;
  }
  return json({ ok: true, status }, 201);
}

async function login(request, env, url) {
  const body = await readJson(request);
  const email = String(body?.email ?? '').trim().toLowerCase();
  const password = String(body?.password ?? '');
  if (!email || !password || password.length > 128) return json({ error: '이메일과 비밀번호를 입력하세요.' }, 400);

  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const kEmail = 'login:' + email, kIp = 'loginip:' + ip;
  if (await attemptCount(env, kEmail, 900) >= 5 || await attemptCount(env, kIp, 900) >= 30) {
    return json({ error: '로그인 시도가 너무 많습니다. 15분 후 다시 시도하세요.' }, 429);
  }

  const user = await env.DB.prepare('SELECT id, pw_hash, salt, status FROM users WHERE email = ?').bind(email).first();
  // 계정이 없어도 같은 비용의 해시를 계산해 응답 시간 차이로 가입 여부를 알 수 없게 합니다.
  const salt = user ? unhex(user.salt) : new Uint8Array(16);
  const hash = await hashPassword(password, salt);
  const ok = user && safeEqual(hash, unhex(user.pw_hash));
  if (!ok) {
    await Promise.all([bumpAttempt(env, kEmail, 900), bumpAttempt(env, kIp, 900)]);
    return json({ error: '이메일 또는 비밀번호가 올바르지 않습니다.' }, 401);
  }
  if (user.status === 'pending') return json({ error: '관리자 승인 대기 중입니다. 승인 후 로그인할 수 있습니다.', code: 'pending' }, 403);
  if (user.status !== 'approved') return json({ error: '가입이 승인되지 않았습니다. 관리자에게 문의하세요.', code: 'rejected' }, 403);

  await env.DB.prepare('DELETE FROM attempts WHERE k = ?').bind(kEmail).run();
  const token = await createSession(env, user.id);
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie(token, SESSION_SECONDS, url) });
}

async function logout(request, env, url) {
  const token = getCookie(request, COOKIE);
  if (token && /^[0-9a-f]{64}$/.test(token)) {
    await env.DB.prepare('DELETE FROM sessions WHERE token_hash = ?').bind(await sha256hex(token)).run();
  }
  return json({ ok: true }, 200, { 'Set-Cookie': sessionCookie('', 0, url) });
}

/* ---------- 관리자 API ---------- */
/* ---------- 구글 지도 API 사용량 집계 ---------- */
// 앱이 보낸 구글 요청 수를 날짜·사용자·종류별로 누적합니다. 구글 과금 기준일(미국 태평양시 자정)에 맞춰 날짜를 나눕니다.
// 앱이 직접 센 추정치입니다(사용자가 조작할 수 있으므로 참고용).
const USAGE_KINDS = ['map_load', 'place_details', 'place_details_rich', 'place_photo', 'geocode', 'route_leg', 'autocomplete_select'];
const CONSOLE_APIS = ['places', 'routes', 'maps_js', 'geocoding'];
const pacificDay = (d = new Date()) => d.toLocaleDateString('en-CA', { timeZone: 'America/Los_Angeles' });   // YYYY-MM-DD
function shiftDay(day, n) { const d = new Date(day + 'T00:00:00Z'); d.setUTCDate(d.getUTCDate() + n); return d.toISOString().slice(0, 10); }

async function recordUsage(request, env, session) {
  if (!session) return json({ error: '로그인이 필요합니다.' }, 401);
  // 과도한 요청 방지: 사용자당 1분에 6번까지
  const key = 'usage:' + session.id;
  if (await attemptCount(env, key, 60) >= 6) return json({ ok: true, skipped: true });
  await bumpAttempt(env, key, 60);

  const body = await readJson(request);
  const counts = body?.counts;
  if (!counts || typeof counts !== 'object') return json({ error: '올바르지 않은 요청입니다.' }, 400);
  const day = pacificDay(), stmts = [];
  for (const kind of USAGE_KINDS) {
    const n = Math.floor(Number(counts[kind]));
    if (!Number.isFinite(n) || n <= 0) continue;
    stmts.push(env.DB.prepare(
      'INSERT INTO usage_daily (day, user_id, kind, n) VALUES (?, ?, ?, ?) ON CONFLICT(day, user_id, kind) DO UPDATE SET n = n + excluded.n'
    ).bind(day, session.id, kind, Math.min(n, 500)));   // 한 번에 보낼 수 있는 값에 상한
  }
  if (stmts.length) await env.DB.batch(stmts);
  if (Math.random() < 0.02) await env.DB.prepare('DELETE FROM usage_daily WHERE day < ?').bind(shiftDay(day, -400)).run();   // 오래된 기록 정리
  return json({ ok: true });
}

async function usageReport(env) {
  const today = pacificDay(), monthStart = today.slice(0, 8) + '01', from14 = shiftDay(today, -13);
  const [tod, mon, daily, perUser] = await Promise.all([
    env.DB.prepare('SELECT kind, SUM(n) AS n FROM usage_daily WHERE day = ? GROUP BY kind').bind(today).all(),
    env.DB.prepare('SELECT kind, SUM(n) AS n FROM usage_daily WHERE day >= ? GROUP BY kind').bind(monthStart).all(),
    env.DB.prepare('SELECT day, SUM(n) AS n FROM usage_daily WHERE day >= ? GROUP BY day').bind(from14).all(),
    env.DB.prepare(
      `SELECT u.email AS email, d.kind AS kind, SUM(d.n) AS n FROM usage_daily d JOIN users u ON u.id = d.user_id
        WHERE d.day >= ? GROUP BY d.user_id, d.kind`
    ).bind(monthStart).all(),
  ]);
  const toMap = rows => Object.fromEntries(rows.map(x => [x.kind, x.n]));
  const base = await env.DB.prepare('SELECT value FROM app_settings WHERE key = ?').bind('console_baseline').first();
  const byDay = Object.fromEntries(daily.results.map(x => [x.day, x.n]));
  const users = {};
  for (const x of perUser.results) (users[x.email] ??= { email: x.email, counts: {}, total: 0 }, users[x.email].counts[x.kind] = x.n, users[x.email].total += x.n);
  return {
    today, month: today.slice(0, 7),
    baseline: base ? JSON.parse(base.value) : null,
    kinds: USAGE_KINDS,
    today_counts: toMap(tod.results), month_counts: toMap(mon.results),
    daily: Array.from({ length: 14 }, (_, i) => { const d = shiftDay(from14, i); return { day: d, n: byDay[d] || 0 }; }),
    users: Object.values(users).sort((a, b) => b.total - a.total),
  };
}

async function adminApi(request, env, url, session) {
  if (!session || session.role !== 'admin') return json({ error: '권한이 없습니다.' }, 403);

  if (request.method === 'GET' && url.pathname === '/api/admin/usage') return json(await usageReport(env));
  if (request.method === 'POST' && url.pathname === '/api/admin/usage/baseline') {
    const body = await request.json().catch(() => ({}));
    const day = /^\d{4}-\d{2}-\d{2}$/.test(body.day) ? body.day : pacificDay();
    const counts = {};
    for (const k of CONSOLE_APIS) {
      const v = Number(body.counts?.[k]);
      if (!Number.isInteger(v) || v < 0 || v > 1e9) return json({ error: '요청 수는 0 이상의 정수여야 합니다.' }, 400);
      counts[k] = v;
    }
    await env.DB.prepare('INSERT INTO app_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
      .bind('console_baseline', JSON.stringify({ day, counts })).run();
    return json({ ok: true, baseline: { day, counts } });
  }

  if (request.method === 'GET' && url.pathname === '/api/admin/users') {
    const { results } = await env.DB.prepare(
      `SELECT id, email, status, role, created_at FROM users
        ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, created_at DESC`
    ).all();
    return json({ users: results });
  }

  const m = url.pathname.match(/^\/api\/admin\/users\/(\d+)\/(approve|reject|delete)$/);
  if (request.method === 'POST' && m) {
    const id = Number(m[1]), action = m[2];
    const target = await env.DB.prepare('SELECT id, role FROM users WHERE id = ?').bind(id).first();
    if (!target) return json({ error: '사용자를 찾을 수 없습니다.' }, 404);
    if (target.role === 'admin') return json({ error: '관리자 계정은 변경할 수 없습니다.' }, 400);

    if (action === 'approve') {
      await env.DB.prepare("UPDATE users SET status = 'approved' WHERE id = ?").bind(id).run();
    } else if (action === 'reject') {
      await env.DB.batch([
        env.DB.prepare("UPDATE users SET status = 'rejected' WHERE id = ?").bind(id),
        env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id),
      ]);
    } else {
      await env.DB.batch([
        env.DB.prepare('DELETE FROM trip_shares WHERE user_id = ? OR trip_id IN (SELECT id FROM trips WHERE owner_id = ?)').bind(id, id),
        env.DB.prepare('DELETE FROM trips WHERE owner_id = ?').bind(id),
        env.DB.prepare('DELETE FROM usage_daily WHERE user_id = ?').bind(id),
        env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(id),
        env.DB.prepare('DELETE FROM users WHERE id = ?').bind(id),
      ]);
    }
    return json({ ok: true });
  }
  return json({ error: 'Not found' }, 404);
}

/* ---------- 여행 저장 / 공유 API ---------- */
const MODES = ['WALKING', 'TRANSIT', 'DRIVING', 'BICYCLING'];
const MAX_TRIPS_PER_USER = 100, MAX_SHARES_PER_TRIP = 50, MAX_BODY_BYTES = 300000;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const clip = (v, max) => String(v ?? '').slice(0, max);
const inRange = (v, min, max) => typeof v === 'number' && Number.isFinite(v) && v >= min && v <= max;

const MAX_DAYS = 30, MAX_STOPS_PER_TRIP = 200;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

function cleanStops(raw) {
  if (!Array.isArray(raw)) return null;
  const stops = [];
  for (const st of raw) {
    if (!inRange(st?.lat, -90, 90) || !inRange(st?.lng, -180, 180)) return null;
    stops.push({ id: clip(st.id, 64) || crypto.randomUUID(), name: clip(st.name, 200), address: clip(st.address, 300), memo: clip(st.memo, 500), lat: st.lat, lng: st.lng,
                 placeId: clip(st.placeId, 200), category: clip(st.category, 40) });
  }
  return stops;
}

// 저장된 데이터를 항상 { mode, days:[{id,date,stops,legModes}], v:2 } 형태로 맞춥니다.
// - 일자 도입 전 데이터(stops만 있음)는 Day 1로 변환
// - v:2 이전에는 기본 이동수단(mode)이 모든 구간에 적용됐으므로, 구간별 설정(legModes)으로 변환해 기존 경로를 그대로 유지
//   (v:2부터는 구간의 기본값이 '직선'이고 mode는 쓰이지 않음)
function normalizeData(data) {
  const mode = MODES.includes(data?.mode) ? data.mode : 'WALKING';
  let days = Array.isArray(data?.days) && data.days.length ? data.days : [{ id: 'day-1', date: '', stops: Array.isArray(data?.stops) ? data.stops : [] }];
  if (data?.v !== 2) {
    days = days.map(d => {
      const stops = Array.isArray(d.stops) ? d.stops : [], legModes = { ...(d.legModes || {}) };
      stops.slice(0, -1).forEach((st, i) => { const k = `${st.id}>${stops[i + 1].id}`; if (!legModes[k]) legModes[k] = mode; });
      return { ...d, legModes };
    });
  }
  return { mode, days, v: 2 };
}

// 클라이언트가 보낸 여행 데이터를 검증/정리합니다. 잘못되면 null. (days 또는 예전 형식의 stops 모두 허용)
function sanitizeTrip(body) {
  if (!body || typeof body !== 'object') return null;
  const rawDays = Array.isArray(body.days) ? body.days : (Array.isArray(body.stops) ? [{ stops: body.stops }] : null);
  if (!rawDays || !rawDays.length || rawDays.length > MAX_DAYS) return null;
  const days = [], seen = new Set();
  let count = 0;
  for (const d of rawDays) {
    const stops = cleanStops(d?.stops);
    if (!stops) return null;
    count += stops.length;
    let id = clip(d?.id, 64) || crypto.randomUUID();
    if (seen.has(id)) id = crypto.randomUUID();
    seen.add(id);
    // 구간별 이동수단: { "출발장소id>도착장소id": "WALKING" | ... }  (기본 이동수단과 다른 구간만 저장)
    const legModes = {};
    if (d?.legModes && typeof d.legModes === 'object') {
      for (const [k, v] of Object.entries(d.legModes).slice(0, 300)) {
        if (/^[^>]{1,64}>[^>]{1,64}$/.test(k) && MODES.includes(v)) legModes[k] = v;
      }
    }
    days.push({ id, date: DATE_RE.test(String(d?.date)) ? d.date : '', stops, legModes });
  }
  if (count > MAX_STOPS_PER_TRIP) return null;
  const dates = days.map(d => d.date).filter(Boolean).sort();
  return {
    title: clip(body.title, 100).trim(),
    data: JSON.stringify({ mode: MODES.includes(body.mode) ? body.mode : 'WALKING', days, v: 2 }),
    count, dayCount: days.length, dateFrom: dates[0] || '', dateTo: dates[dates.length - 1] || '',
  };
}

// 소유자이거나 공유받은 사용자(공동 편집자)만 접근할 수 있습니다.
async function loadTrip(env, id, session) {
  const t = await env.DB.prepare(
    `SELECT t.id, t.owner_id, t.title, t.data, t.updated_at, t.version, u.email AS owner_email, uu.email AS updated_by_email
       FROM trips t JOIN users u ON u.id = t.owner_id LEFT JOIN users uu ON uu.id = t.updated_by WHERE t.id = ?`
  ).bind(id).first();
  if (!t) return null;
  if (t.owner_id === session.id) return { ...t, role: 'owner' };
  const sh = await env.DB.prepare('SELECT 1 AS ok FROM trip_shares WHERE trip_id = ? AND user_id = ?').bind(id, session.id).first();
  return sh ? { ...t, role: 'editor' } : null;
}

async function createTrip(env, ownerId, clean, titleOverride) {
  const c = await env.DB.prepare('SELECT COUNT(*) AS c FROM trips WHERE owner_id = ?').bind(ownerId).first();
  if (c.c >= MAX_TRIPS_PER_USER) return null;
  const id = crypto.randomUUID(), t = now();
  await env.DB.prepare('INSERT INTO trips (id, owner_id, title, data, stop_count, created_at, updated_at, version, updated_by, day_count, date_from, date_to) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)')
    .bind(id, ownerId, titleOverride ?? clean.title, clean.data, clean.count, t, t, ownerId, clean.dayCount, clean.dateFrom, clean.dateTo).run();
  return { id, updated_at: t, version: 1 };
}

async function tripsApi(request, env, url, session) {
  if (!session) return json({ error: '로그인이 필요합니다.' }, 401);
  const parts = url.pathname.split('/').filter(Boolean);   // ['api', 'trips', id?, action?]
  const id = parts[2], action = parts[3], method = request.method;
  if (id && !UUID_RE.test(id)) return json({ error: '여행을 찾을 수 없습니다.' }, 404);
  if (method !== 'GET' && Number(request.headers.get('Content-Length') || 0) > MAX_BODY_BYTES) return json({ error: '데이터가 너무 큽니다.' }, 413);

  // 목록 / 생성
  if (!id) {
    if (method === 'GET') {
      const [mine, shared] = await Promise.all([
        env.DB.prepare(
          `SELECT t.id, t.title, t.stop_count, t.day_count, t.date_from, t.date_to, t.updated_at,
                  (SELECT COUNT(*) FROM trip_shares s WHERE s.trip_id = t.id) AS share_count
             FROM trips t WHERE t.owner_id = ? ORDER BY t.updated_at DESC`
        ).bind(session.id).all(),
        env.DB.prepare(
          `SELECT t.id, t.title, t.stop_count, t.day_count, t.date_from, t.date_to, t.updated_at, u.email AS owner_email, s.created_at AS shared_at
             FROM trip_shares s JOIN trips t ON t.id = s.trip_id JOIN users u ON u.id = t.owner_id
            WHERE s.user_id = ? ORDER BY s.created_at DESC`
        ).bind(session.id).all(),
      ]);
      return json({ mine: mine.results, shared: shared.results });
    }
    if (method === 'POST') {
      const clean = sanitizeTrip(await readJson(request));
      if (!clean) return json({ error: '여행 데이터가 올바르지 않습니다.' }, 400);
      const created = await createTrip(env, session.id, clean);
      return created ? json(created, 201) : json({ error: `여행은 최대 ${MAX_TRIPS_PER_USER}개까지 저장할 수 있습니다.` }, 409);
    }
    return json({ error: 'Not found' }, 404);
  }

  const trip = await loadTrip(env, id, session);
  if (!trip) return json({ error: '여행을 찾을 수 없습니다.' }, 404);   // 없음/권한 없음을 구분하지 않음
  const isOwner = trip.role === 'owner';

  // 열람
  if (!action && method === 'GET') {
    // 공동 편집 중 변경 확인(폴링): 버전이 같으면 본문 없이 응답
    if (url.searchParams.get('since') === String(trip.version)) return json({ unchanged: true, version: trip.version });
    const { results } = await env.DB.prepare(
      'SELECT u.id, u.email FROM trip_shares s JOIN users u ON u.id = s.user_id WHERE s.trip_id = ? ORDER BY s.created_at'
    ).bind(id).all();
    return json({ id: trip.id, title: trip.title, role: trip.role, owner_email: trip.owner_email, updated_at: trip.updated_at,
                  version: trip.version, updated_by_email: trip.updated_by_email, shared_with: results, ...normalizeData(JSON.parse(trip.data)) });
  }

  // 복사 (소유자/공유받은 사용자 모두 자기 여행으로 복사 가능)
  if (action === 'copy' && method === 'POST') {
    const data = normalizeData(JSON.parse(trip.data));
    const clean = sanitizeTrip({ title: '', mode: data.mode, days: data.days });
    const created = await createTrip(env, session.id, clean, clip((trip.title || '여행') + ' (복사본)', 100));
    return created ? json(created, 201) : json({ error: `여행은 최대 ${MAX_TRIPS_PER_USER}개까지 저장할 수 있습니다.` }, 409);
  }

  // 공유받은 목록에서 빼기
  if (action === 'leave' && method === 'POST') {
    if (isOwner) return json({ error: '내가 만든 여행입니다.' }, 400);
    await env.DB.prepare('DELETE FROM trip_shares WHERE trip_id = ? AND user_id = ?').bind(id, session.id).run();
    return json({ ok: true });
  }

  // 수정 (소유자 + 공동 편집자). 내가 본 버전(base_version)이 최신일 때만 저장하고, 아니면 충돌로 응답합니다.
  if (!action && method === 'PUT') {
    const body = await readJson(request);
    const clean = sanitizeTrip(body);
    if (!clean || !Number.isInteger(body.base_version)) return json({ error: '여행 데이터가 올바르지 않습니다.' }, 400);
    const t = now();
    const res = await env.DB.prepare(
      `UPDATE trips SET title = ?, data = ?, stop_count = ?, day_count = ?, date_from = ?, date_to = ?,
              updated_at = ?, version = version + 1, updated_by = ? WHERE id = ? AND version = ?`
    ).bind(clean.title, clean.data, clean.count, clean.dayCount, clean.dateFrom, clean.dateTo, t, session.id, id, body.base_version).run();
    if (!res?.meta?.changes) {
      const cur = await loadTrip(env, id, session);
      if (!cur) return json({ error: '여행을 찾을 수 없습니다.' }, 404);
      return json({ error: '다른 사람이 먼저 수정했어요.', conflict: true,
                    trip: { title: cur.title, version: cur.version, updated_by_email: cur.updated_by_email, ...normalizeData(JSON.parse(cur.data)) } }, 409);
    }
    return json({ ok: true, version: body.base_version + 1, updated_at: t });
  }

  // 이하는 소유자만
  if (!isOwner) return json({ error: '소유자만 할 수 있어요.' }, 403);

  if (!action && method === 'DELETE') {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM trip_shares WHERE trip_id = ?').bind(id),
      env.DB.prepare('DELETE FROM trips WHERE id = ? AND owner_id = ?').bind(id, session.id),
    ]);
    return json({ ok: true });
  }

  if (action === 'share' && method === 'POST') {
    const body = await readJson(request);
    const email = String(body?.email ?? '').trim().toLowerCase();
    if (!EMAIL_RE.test(email)) return json({ error: '올바른 이메일 주소를 입력하세요.' }, 400);
    if (email === session.email) return json({ error: '본인에게는 공유할 수 없습니다.' }, 400);
    const target = await env.DB.prepare("SELECT id, email FROM users WHERE email = ? AND status = 'approved'").bind(email).first();
    if (!target) return json({ error: '승인된 사용자 중에서 해당 이메일을 찾을 수 없습니다.' }, 404);
    const c = await env.DB.prepare('SELECT COUNT(*) AS c FROM trip_shares WHERE trip_id = ?').bind(id).first();
    if (c.c >= MAX_SHARES_PER_TRIP) return json({ error: `한 여행은 최대 ${MAX_SHARES_PER_TRIP}명에게 공유할 수 있습니다.` }, 409);
    await env.DB.prepare('INSERT OR IGNORE INTO trip_shares (trip_id, user_id, created_at) VALUES (?, ?, ?)').bind(id, target.id, now()).run();
    return json({ ok: true, user: target });
  }

  if (action === 'unshare' && method === 'POST') {
    const body = await readJson(request);
    await env.DB.prepare('DELETE FROM trip_shares WHERE trip_id = ? AND user_id = ?').bind(id, Number(body?.userId) || 0).run();
    return json({ ok: true });
  }

  return json({ error: 'Not found' }, 404);
}

/* ---------- 라우팅 ---------- */
// 화면(index.html) 버전: 배포가 바뀌면 달라지는 값. 정적 파일의 ETag를 쓰고, 없으면 내용 해시를 씁니다.
async function assetVersionOf(res) {
  const etag = res.headers.get('ETag');
  if (etag) return etag.replace(/^W\//, '').replace(/"/g, '');
  return hex(await crypto.subtle.digest('SHA-256', await res.clone().arrayBuffer())).slice(0, 16);
}
let versionCache = { v: '', t: 0 };
async function currentVersion(env, url) {
  if (versionCache.v && Date.now() - versionCache.t < 30000) return versionCache.v;   // 30초 동안은 다시 계산하지 않음
  const res = await env.ASSETS.fetch(new Request(new URL('/index.html', url), { method: 'GET' }));
  versionCache = { v: res.ok ? await assetVersionOf(res) : '', t: Date.now() };
  return versionCache.v;
}

async function serveAsset(env, url, assetPath) {
  const res = await env.ASSETS.fetch(new Request(new URL(assetPath, url), { method: 'GET' }));
  if (assetPath === '/index.html' && res.ok) {
    // 내려 주는 HTML에 이 화면의 버전을 박아 둡니다 → 앱이 "내가 열린 시점의 버전"을 정확히 알 수 있음
    const version = await assetVersionOf(res);
    versionCache = { v: version, t: Date.now() };
    const html = (await res.text()).replace('<meta name="app-version" content="">', `<meta name="app-version" content="${version}">`);
    const headers = securityHeaders(new Headers(res.headers));
    ['content-length', 'etag', 'content-encoding'].forEach(h => headers.delete(h));
    return new Response(html, { status: res.status, headers });
  }
  return new Response(res.body, { status: res.status, headers: securityHeaders(new Headers(res.headers)) });
}

const redirect = (to, url) => new Response(null, { status: 302, headers: securityHeaders(new Headers({ Location: new URL(to, url).toString() })) });

async function handleApi(request, env, url) {
  const p = url.pathname;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    // CSRF 방어: 다른 사이트에서 온 상태 변경 요청 차단
    const origin = request.headers.get('Origin');
    if (!origin || new URL(origin).host !== url.host) return json({ error: '잘못된 요청 출처입니다.' }, 403);
  }

  if (request.method === 'GET' && p === '/api/version') return json({ v: await currentVersion(env, url) });   // 새 화면이 배포됐는지 확인용(공개)
  if (request.method === 'POST' && p === '/api/auth/signup') return signup(request, env);
  if (request.method === 'POST' && p === '/api/auth/login') return login(request, env, url);
  if (request.method === 'POST' && p === '/api/auth/logout') return logout(request, env, url);

  const session = await getSession(request, env);
  if (p === '/api/auth/me' && request.method === 'GET') {
    return session ? json({ email: session.email, role: session.role }) : json({ error: '로그인이 필요합니다.' }, 401);
  }
  if (p === '/api/usage' && request.method === 'POST') return recordUsage(request, env, session);
  if (p.startsWith('/api/admin/')) return adminApi(request, env, url, session);
  if (p === '/api/trips' || p.startsWith('/api/trips/')) return tripsApi(request, env, url, session);
  return json({ error: 'Not found' }, 404);
}

async function handlePage(request, env, url) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return new Response('Method Not Allowed', { status: 405 });
  const p = url.pathname;
  const session = await getSession(request, env);

  if (p === '/login' || p === '/login.html') {
    return session ? redirect('/', url) : serveAsset(env, url, '/login.html');
  }
  if (!session) {
    // 확인 불가한 파일은 존재 여부를 숨기고, 페이지 요청은 로그인 화면으로 보냅니다.
    return p === '/' || p === '/index.html' || p === '/admin' || p === '/admin.html' || p === '/admin/usage'
      ? redirect('/login', url)
      : new Response('Unauthorized', { status: 401, headers: securityHeaders(new Headers()) });
  }
  if (p === '/' || p === '/index.html') return serveAsset(env, url, '/index.html');
  if (p === '/admin' || p === '/admin.html') {
    return session.role === 'admin' ? serveAsset(env, url, '/admin.html') : redirect('/', url);
  }
  if (p === '/admin/usage' || p === '/admin-usage.html') {
    return session.role === 'admin' ? serveAsset(env, url, '/admin-usage.html') : redirect('/', url);
  }
  return serveAsset(env, url, p);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      await ensureSchema(env);
      return url.pathname.startsWith('/api/') ? await handleApi(request, env, url) : await handlePage(request, env, url);
    } catch (err) {
      console.error(err);
      const msg = String(err?.message || '').includes('D1 바인딩') ? err.message : '서버 오류가 발생했습니다.';
      return url.pathname.startsWith('/api/')
        ? json({ error: msg }, 500)
        : new Response(msg, { status: 500, headers: securityHeaders(new Headers({ 'Content-Type': 'text/plain; charset=utf-8' })) });
    }
  },
};
