const express = require('express');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const PASS = String(process.env.OWNER_PASSWORD || '');
if (!PASS) { console.error('Set the OWNER_PASSWORD environment variable.'); process.exit(1); }
if (PASS.length > 256) { console.error('OWNER_PASSWORD is too long.'); process.exit(1); }

const SECRET = process.env.SECRET || crypto.createHash('sha256').update('gd:' + PASS).digest('hex');
const db = new Database(process.env.DB_PATH || 'gymdesk.db');
db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');
db.exec('create table if not exists kv(k text primary key, v text not null, updated text)');

const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const same = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const cookie = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')) .filter(p => p[0]));
const fails = new Map();

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '5mb', strict: true }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  if (req.secure) res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  if (req.path.startsWith('/api/')) res.setHeader('Cache-Control', 'no-store');
  next();
});

const validDate = v => {
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return false;
  const [y, m, d] = v.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === m - 1 && dt.getUTCDate() === d;
};
const text = (v, max, required = true) => typeof v === 'string' && v.length <= max && (!required || v.trim().length > 0);
const validPhone = v => typeof v === 'string' && /^\d{10}$/.test(v);
const validMode = v => v === 'Cash' || v === 'UPI' || v === 'Card';

const validData = d => {
  if (!d || typeof d !== 'object' || Array.isArray(d)) return false;
  if (!Array.isArray(d.members) || !Array.isArray(d.plans) || d.members.length > 10000 || d.plans.length > 100) return false;
  if (!text(d.gym, 100) || !/^\d{1,4}$/.test(String(d.cc || ''))) return false;
  if (!d.t || typeof d.t !== 'object' || Array.isArray(d.t)) return false;
  for (const k of ['soon', 'exp', 'back']) if (!text(d.t[k], 2000)) return false;

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
    if (m.h && (!Array.isArray(m.h) || m.h.length > 1000)) return false;
    if (Array.isArray(m.h)) for (const h of m.h) {
      if (!h || typeof h !== 'object' || !validDate(h.date) || !text(h.plan, 100) || (h.mode != null && !validMode(h.mode)) || !Number.isFinite(Number(h.amt)) || Number(h.amt) < 0 || Number(h.amt) > 1e8) return false;
    }
  }
  return true;
};

app.post('/api/login', (req, res) => {
  const ip = req.ip;
  const f = fails.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - f.t > 15 * 60e3) { f.n = 0; f.t = Date.now(); }
  if (f.n >= 10) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const pw = String((req.body || {}).password || '');
  if (pw.length > 256 || !same(sign(pw), sign(PASS))) {
    f.n++; f.t = Date.now(); fails.set(ip, f);
    return res.status(401).json({ error: 'Wrong password' });
  }
  fails.delete(ip);
  const exp = String(Date.now() + 30 * 864e5);
  const secure = req.secure ? '; Secure' : '';
  res.setHeader('Set-Cookie', `gd=${exp}.${sign(exp)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${30 * 86400}${secure}`);
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'gd=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ ok: true });
});

const auth = (req, res, next) => {
  const [exp, sig] = String(cookie(req).gd || '').split('.');
  if (/^\d+$/.test(exp) && sig && Number(exp) > Date.now() && same(sig, sign(exp))) return next();
  res.status(401).json({ error: 'Login required' });
};

app.get('/api/data', auth, (req, res) => {
  const r = db.prepare("select v from kv where k='data'").get();
  if (!r) return res.json(null);
  try {
    const data = JSON.parse(r.v);
    if (!validData(data)) return res.status(500).json({ error: 'Stored data is invalid' });
    return res.json(data);
  } catch {
    return res.status(500).json({ error: 'Stored data is corrupted' });
  }
});

app.put('/api/data', auth, (req, res) => {
  if (!validData(req.body)) return res.status(400).json({ error: 'Invalid data' });
  const now = new Date().toISOString();
  const tx = db.transaction(data => {
    db.prepare("insert into kv(k,v,updated) values('data',?,?) on conflict(k) do update set v=excluded.v, updated=excluded.updated")
      .run(JSON.stringify(data), now);
    const day = 'snap-' + now.slice(0, 10);
    db.prepare('insert or replace into kv(k,v,updated) values(?,?,?)').run(day, JSON.stringify(data), now);
    const old = db.prepare("select k from kv where k like 'snap-%' order by k desc limit -1 offset 30").all();
    old.forEach(o => db.prepare('delete from kv where k=?').run(o.k));
  });
  try { tx(req.body); } catch { return res.status(500).json({ error: 'Could not save data' }); }
  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, 'public'), { etag: true, maxAge: '1h' }));
const port = process.env.PORT || 3000;
app.listen(port, () => console.log('GymDesk running on port ' + port));
