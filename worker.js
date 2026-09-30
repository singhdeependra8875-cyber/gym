const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
};

const encoder = new TextEncoder();
const fails = new Map();
const PASSWORD_RECORD_KEY = 'auth:owner-password';
const SESSION_VERSION_KEY = 'auth:session-version';
const PASSWORD_ITERATIONS = 310000;
const MAX_PASSWORD_LENGTH = 256;

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, ...extra },
  });
}

function headersFor(request, isApi = false) {
  const h = new Headers();
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('X-Frame-Options', 'DENY');
  h.set('Referrer-Policy', 'same-origin');
  h.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  h.set('Cross-Origin-Opener-Policy', 'same-origin');
  if (isApi) h.set('Cache-Control', 'no-store');
  if (new URL(request.url).protocol === 'https:') {
    h.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  return h;
}

function withSecurity(response, request, isApi = false) {
  const h = new Headers(response.headers);
  for (const [k, v] of headersFor(request, isApi)) h.set(k, v);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers: h });
}

function hex(bytes) {
  return [...new Uint8Array(bytes)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function hmac(secret, value) {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return hex(await crypto.subtle.sign('HMAC', key, encoder.encode(value)));
}

async function sameSecret(a, b) {
  const aa = await hmac(b, String(a));
  const bb = await hmac(b, String(b));
  return aa === bb;
}

function constantTimeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  let mismatch = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) mismatch |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return mismatch === 0;
}

async function getSessionVersion(env) {
  const row = await env.DB.prepare('SELECT v FROM kv WHERE k=?').bind(SESSION_VERSION_KEY).first();
  if (!row) return 0;
  if (!/^\d+$/.test(String(row.v))) throw new Error('Invalid session version');
  const version = Number(row.v);
  if (!Number.isSafeInteger(version)) throw new Error('Invalid session version');
  return version;
}

async function getPasswordRecord(env) {
  const row = await env.DB.prepare('SELECT v FROM kv WHERE k=?').bind(PASSWORD_RECORD_KEY).first();
  if (!row) return null;
  let record;
  try { record = JSON.parse(row.v); } catch { throw new Error('Invalid password record'); }
  if (!record || record.algorithm !== 'PBKDF2-SHA-256' || !Number.isInteger(record.iterations) || record.iterations < 100000 || record.iterations > 1000000 || record.keyLength !== 256 || !/^[0-9a-f]{32}$/.test(record.salt) || !/^[0-9a-f]{64}$/.test(record.hash)) {
    throw new Error('Invalid password record');
  }
  return record;
}

async function derivePasswordHash(password, salt, iterations) {
  const key = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, 256);
  return hex(bits);
}

async function verifyPasswordRecord(password, record) {
  const salt = Uint8Array.from(record.salt.match(/../g), byte => parseInt(byte, 16));
  return constantTimeEqual(await derivePasswordHash(password, salt, record.iterations), record.hash);
}

async function makePasswordRecord(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return {
    algorithm: 'PBKDF2-SHA-256',
    iterations: PASSWORD_ITERATIONS,
    keyLength: 256,
    salt: hex(salt),
    hash: await derivePasswordHash(password, salt, PASSWORD_ITERATIONS),
  };
}

async function verifyCurrentPassword(password, env, record) {
  if (record) return verifyPasswordRecord(password, record);
  if (typeof env.OWNER_PASSWORD !== 'string' || !env.OWNER_PASSWORD) throw new Error('Bootstrap password unavailable');
  return sameSecret(password, env.OWNER_PASSWORD);
}

async function sessionCookie(request, env, version) {
  const exp = String(Date.now() + 30 * 864e5);
  const payload = `${exp}.${version}`;
  const sig = await hmac(env.SESSION_SECRET, payload);
  const secure = new URL(request.url).protocol === 'https:' ? '; Secure' : '';
  return `gd=${encodeURIComponent(payload + '.' + sig)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${30 * 86400}${secure}`;
}

function parseCookies(request) {
  const out = {};
  const raw = request.headers.get('Cookie') || '';
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

async function authenticated(request, env) {
  if (typeof env.SESSION_SECRET !== 'string' || !env.SESSION_SECRET) return false;
  const { gd = '' } = parseCookies(request);
  const parts = String(gd).split('.');
  const [exp, sessionOrSig, sig] = parts;
  if (!/^\d+$/.test(exp) || Number(exp) <= Date.now()) return false;
  let version, payload, signature;
  if (parts.length === 2) {
    version = 0;
    payload = exp;
    signature = sessionOrSig;
  } else if (parts.length === 3 && /^\d+$/.test(sessionOrSig)) {
    version = Number(sessionOrSig);
    payload = `${exp}.${sessionOrSig}`;
    signature = sig;
  } else return false;
  if (!signature) return false;
  try {
    if (version !== await getSessionVersion(env)) return false;
    return constantTimeEqual(await hmac(env.SESSION_SECRET, payload), signature);
  } catch {
    return false;
  }
}

function validDate(v) {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
  const [y, m, d] = v.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
}

function text(v, max, required = true) {
  return typeof v === 'string' && v.length <= max && (!required || v.trim().length > 0);
}

function validPhone(v) { return typeof v === 'string' && /^\d{10}$/.test(v); }
function validMode(v) { return v === 'Cash' || v === 'UPI' || v === 'Card'; }

function validData(d) {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return false;
  if (!Array.isArray(d.members) || !Array.isArray(d.plans) || d.members.length > 10000 || d.plans.length > 100) return false;
  if (!text(d.gym, 100) || !/^\d{1,4}$/.test(String(d.cc || ''))) return false;
  if (!d.t || typeof d.t !== 'object' || Array.isArray(d.t)) return false;
  for (const k of ['soon', 'exp', 'back']) if (!text(d.t[k], 2000)) return false;
  if (d.reminderDays != null && (!Number.isInteger(d.reminderDays) || d.reminderDays < 0 || d.reminderDays > 60)) return false;

  const planIds = new Set();
  for (const p of d.plans) {
    if (!p || typeof p !== 'object' || !text(p.id, 80) || !text(p.name, 100)) return false;
    if (planIds.has(p.id) || !Number.isInteger(p.m) || p.m < 1 || p.m > 120) return false;
    if (!Number.isFinite(Number(p.price)) || Number(p.price) < 0 || Number(p.price) > 1e8) return false;
    planIds.add(p.id);
  }
  if (!d.plans.length) return false;

  const memberIds = new Set();
  for (const m of d.members) {
    if (!m || typeof m !== 'object' || !text(m.id, 100) || !text(m.name, 150) || !validPhone(m.phone) || !planIds.has(m.plan) || !validDate(m.end)) return false;
    if (memberIds.has(m.id)) return false;
    memberIds.add(m.id);
    if (m.joined && !validDate(m.joined)) return false;
    if (m.rem != null && !validDate(m.rem)) return false;
    if (m.reminders != null) {
      if (!m.reminders || typeof m.reminders !== 'object' || Array.isArray(m.reminders) || Object.keys(m.reminders).some(k => !['soon', 'exp', 'back'].includes(k))) return false;
      for (const reminder of Object.values(m.reminders)) if (!reminder || typeof reminder !== 'object' || Array.isArray(reminder) || !validDate(reminder.date) || !validDate(reminder.end)) return false;
    }
    if (m.h && (!Array.isArray(m.h) || m.h.length > 1000)) return false;
    if (Array.isArray(m.h)) for (const h of m.h) {
      if (!h || typeof h !== 'object' || !validDate(h.date) || !text(h.plan, 100) || (h.mode != null && !validMode(h.mode)) || !Number.isFinite(Number(h.amt)) || Number(h.amt) < 0 || Number(h.amt) > 1e8) return false;
    }
  }
  return true;
}

async function api(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === 'POST' && path === '/api/login') {
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const now = Date.now();
    const f = fails.get(ip) || { n: 0, t: now };
    if (now - f.t > 15 * 60e3) { f.n = 0; f.t = now; }
    if (f.n >= 10) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);

    let body;
    try { body = await request.json(); } catch { body = {}; }
    const pw = typeof body?.password === 'string' ? body.password : '';
    if (pw.length > MAX_PASSWORD_LENGTH) {
      f.n++; f.t = now; fails.set(ip, f);
      return json({ error: 'Wrong password' }, 401);
    }
    if (typeof env.SESSION_SECRET !== 'string' || !env.SESSION_SECRET) return json({ error: 'Authentication is unavailable' }, 503);
    let record, valid;
    try {
      record = await getPasswordRecord(env);
      valid = await verifyCurrentPassword(pw, env, record);
    } catch {
      return json({ error: 'Authentication is unavailable' }, 503);
    }
    if (!valid) {
      f.n++; f.t = now; fails.set(ip, f);
      return json({ error: 'Wrong password' }, 401);
    }
    fails.delete(ip);
    let version, cookie;
    try {
      version = await getSessionVersion(env);
      cookie = await sessionCookie(request, env, version);
    } catch {
      return json({ error: 'Authentication is unavailable' }, 503);
    }
    return json({ ok: true }, 200, {
      'Set-Cookie': cookie,
    });
  }

  if (request.method === 'POST' && path === '/api/logout') {
    return json({ ok: true }, 200, {
      'Set-Cookie': 'gd=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
    });
  }

  if (request.method === 'POST' && path === '/api/change-password') {
    if (request.headers.get('Origin') !== url.origin) return json({ error: 'Request origin is not allowed' }, 403);
    if (!(await authenticated(request, env))) return json({ error: 'Login required' }, 401);
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const failKey = `password-change:${ip}`;
    const now = Date.now();
    const f = fails.get(failKey) || { n: 0, t: now };
    if (now - f.t > 15 * 60e3) { f.n = 0; f.t = now; }
    if (f.n >= 5) return json({ error: 'Too many attempts. Try again in 15 minutes.' }, 429);

    let body;
    try { body = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    const currentPassword = body?.currentPassword;
    const newPassword = body?.newPassword;
    const confirmationPassword = body?.confirmationPassword;
    if (typeof currentPassword !== 'string' || currentPassword.length > MAX_PASSWORD_LENGTH) return json({ error: 'Enter a valid current password' }, 400);
    if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > MAX_PASSWORD_LENGTH) return json({ error: 'New password must be 8 to 256 characters' }, 400);
    if (newPassword !== confirmationPassword) return json({ error: 'New password and confirmation do not match' }, 400);
    if (newPassword === currentPassword) return json({ error: 'Choose a password different from the current password' }, 400);

    let record, valid;
    try {
      record = await getPasswordRecord(env);
      valid = await verifyCurrentPassword(currentPassword, env, record);
    } catch {
      return json({ error: 'Password change is unavailable' }, 503);
    }
    if (!valid) {
      f.n++; f.t = now; fails.set(failKey, f);
      return json({ error: 'Current password is incorrect' }, 401);
    }
    fails.delete(failKey);

    try {
      const newRecord = await makePasswordRecord(newPassword);
      const updated = new Date().toISOString();
      await env.DB.batch([
        env.DB.prepare('INSERT INTO kv(k,v,updated) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated=excluded.updated').bind(PASSWORD_RECORD_KEY, JSON.stringify(newRecord), updated),
        env.DB.prepare('INSERT INTO kv(k,v,updated) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=CAST(kv.v AS INTEGER)+1, updated=excluded.updated').bind(SESSION_VERSION_KEY, '1', updated),
      ]);
    } catch {
      return json({ error: 'Could not change the password. Try again.' }, 500);
    }
    return json({ ok: true }, 200, {
      'Set-Cookie': 'gd=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
    });
  }

  if ((request.method === 'GET' || request.method === 'PUT') && path === '/api/data') {
    if (!(await authenticated(request, env))) return json({ error: 'Login required' }, 401);

    if (request.method === 'GET') {
      const r = await env.DB.prepare("SELECT v FROM kv WHERE k='data'").first();
      if (!r) return json(null);
      try {
        const data = JSON.parse(r.v);
        if (!validData(data)) return json({ error: 'Stored data is invalid' }, 500);
        return json(data);
      } catch {
        return json({ error: 'Stored data is corrupted' }, 500);
      }
    }

    let data;
    try { data = await request.json(); } catch { return json({ error: 'Invalid JSON' }, 400); }
    if (!validData(data)) return json({ error: 'Invalid data' }, 400);

    const now = new Date().toISOString();
    const day = 'snap-' + now.slice(0, 10);
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO kv(k,v,updated) VALUES('data',?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated=excluded.updated").bind(JSON.stringify(data), now),
        env.DB.prepare("INSERT INTO kv(k,v,updated) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated=excluded.updated").bind(day, JSON.stringify(data), now),
        env.DB.prepare("DELETE FROM kv WHERE k LIKE 'snap-%' AND k NOT IN (SELECT k FROM kv WHERE k LIKE 'snap-%' ORDER BY k DESC LIMIT 30)")
      ]);
    } catch (e) {
      console.error('D1 save error', e);
      return json({ error: 'Could not save data' }, 500);
    }
    return json({ ok: true });
  }

  return json({ error: 'Not found' }, 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      return withSecurity(await api(request, env), request, true);
    }
    return withSecurity(await env.ASSETS.fetch(request), request, false);
  }
};
