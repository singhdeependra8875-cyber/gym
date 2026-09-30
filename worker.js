const JSON_HEADERS = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
};

const encoder = new TextEncoder();
const fails = new Map();

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
  h.set(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()'
  );
  h.set('Cross-Origin-Opener-Policy', 'same-origin');

  if (isApi) {
    h.set('Cache-Control', 'no-store');
  }

  if (new URL(request.url).protocol === 'https:') {
    h.set(
      'Strict-Transport-Security',
      'max-age=31536000; includeSubDomains'
    );
  }

  return h;
}

function withSecurity(response, request, isApi = false) {
  const h = new Headers(response.headers);

  for (const [k, v] of headersFor(request, isApi)) {
    h.set(k, v);
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: h,
  });
}

function hex(bytes) {
  return [...new Uint8Array(bytes)]
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

async function hmac(secret, value) {
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    {
      name: 'HMAC',
      hash: 'SHA-256',
    },
    false,
    ['sign']
  );

  return hex(
    await crypto.subtle.sign(
      'HMAC',
      key,
      encoder.encode(value)
    )
  );
}

/*
 * Password comparison.
 *
 * Both values must be strings.
 * The actual password is never logged or returned.
 */
async function sameSecret(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') {
    return false;
  }

  return a === b;
}

function parseCookies(request) {
  const out = {};
  const raw = request.headers.get('Cookie') || '';

  for (const part of raw.split(';')) {
    const i = part.indexOf('=');

    if (i > 0) {
      out[part.slice(0, i).trim()] =
        decodeURIComponent(part.slice(i + 1).trim());
    }
  }

  return out;
}

async function authenticated(request, env) {
  const { gd = '' } = parseCookies(request);

  const [exp, sig] = String(gd).split('.');

  if (
    !/^\d+$/.test(exp) ||
    !sig ||
    Number(exp) <= Date.now()
  ) {
    return false;
  }

  if (!env.SESSION_SECRET) {
    return false;
  }

  const expected = await hmac(
    env.SESSION_SECRET,
    exp
  );

  return expected === sig;
}

function validDate(v) {
  if (
    typeof v !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}$/.test(v)
  ) {
    return false;
  }

  const [y, m, d] = v.split('-').map(Number);

  const dt = new Date(
    Date.UTC(y, m - 1, d)
  );

  return (
    dt.getUTCFullYear() === y &&
    dt.getUTCMonth() === m - 1 &&
    dt.getUTCDate() === d
  );
}

function text(v, max, required = true) {
  return (
    typeof v === 'string' &&
    v.length <= max &&
    (!required || v.trim().length > 0)
  );
}

function validPhone(v) {
  return (
    typeof v === 'string' &&
    /^\d{10}$/.test(v)
  );
}

function validMode(v) {
  return (
    v === 'Cash' ||
    v === 'UPI' ||
    v === 'Card'
  );
}

function validData(d) {
  if (
    !d ||
    typeof d !== 'object' ||
    Array.isArray(d)
  ) {
    return false;
  }

  if (
    !Array.isArray(d.members) ||
    !Array.isArray(d.plans) ||
    d.members.length > 10000 ||
    d.plans.length > 100
  ) {
    return false;
  }

  if (
    !text(d.gym, 100) ||
    !/^\d{1,4}$/.test(String(d.cc || ''))
  ) {
    return false;
  }

  if (
    !d.t ||
    typeof d.t !== 'object' ||
    Array.isArray(d.t)
  ) {
    return false;
  }

  for (const k of ['soon', 'exp', 'back']) {
    if (!text(d.t[k], 2000)) {
      return false;
    }
  }

  const planIds = new Set();

  for (const p of d.plans) {
    if (
      !p ||
      typeof p !== 'object' ||
      !text(p.id, 80) ||
      !text(p.name, 100)
    ) {
      return false;
    }

    if (
      planIds.has(p.id) ||
      !Number.isInteger(p.m) ||
      p.m < 1 ||
      p.m > 120
    ) {
      return false;
    }

    if (
      !Number.isFinite(Number(p.price)) ||
      Number(p.price) < 0 ||
      Number(p.price) > 1e8
    ) {
      return false;
    }

    planIds.add(p.id);
  }

  if (!d.plans.length) {
    return false;
  }

  const memberIds = new Set();

  for (const m of d.members) {
    if (
      !m ||
      typeof m !== 'object' ||
      !text(m.id, 100) ||
      !text(m.name, 150) ||
      !validPhone(m.phone) ||
      !planIds.has(m.plan) ||
      !validDate(m.end)
    ) {
      return false;
    }

    if (memberIds.has(m.id)) {
      return false;
    }

    memberIds.add(m.id);

    if (m.joined && !validDate(m.joined)) {
      return false;
    }

    if (
      m.rem != null &&
      !validDate(m.rem)
    ) {
      return false;
    }

    if (
      m.h &&
      (!Array.isArray(m.h) || m.h.length > 1000)
    ) {
      return false;
    }

    if (Array.isArray(m.h)) {
      for (const h of m.h) {
        if (
          !h ||
          typeof h !== 'object' ||
          !validDate(h.date) ||
          !text(h.plan, 100) ||
          (h.mode != null && !validMode(h.mode)) ||
          !Number.isFinite(Number(h.amt)) ||
          Number(h.amt) < 0 ||
          Number(h.amt) > 1e8
        ) {
          return false;
        }
      }
    }
  }

  return true;
}

async function api(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  /*
   * LOGIN
   */
  if (
    request.method === 'POST' &&
    path === '/api/login'
  ) {
    const ip =
      request.headers.get('CF-Connecting-IP') ||
      'unknown';

    const now = Date.now();

    const f =
      fails.get(ip) || {
        n: 0,
        t: now,
      };

    if (now - f.t > 15 * 60e3) {
      f.n = 0;
      f.t = now;
    }

    if (f.n >= 10) {
      return json(
        {
          error:
            'Too many attempts. Try again in 15 minutes.',
        },
        429
      );
    }

    let body;

    try {
      body = await request.json();
    } catch {
      body = {};
    }

    const pw = String(
      body?.password || ''
    );

    if (
      pw.length > 256 ||
      !env.OWNER_PASSWORD ||
      !(await sameSecret(
        pw,
        env.OWNER_PASSWORD
      ))
    ) {
      f.n++;
      f.t = now;
      fails.set(ip, f);

      return json(
        {
          error: 'Wrong password',
        },
        401
      );
    }

    fails.delete(ip);

    if (!env.SESSION_SECRET) {
      return json(
        {
          error:
            'Server session configuration is missing',
        },
        500
      );
    }

    const exp = String(
      now + 30 * 864e5
    );

    const sig = await hmac(
      env.SESSION_SECRET,
      exp
    );

    const secure =
      new URL(request.url).protocol === 'https:'
        ? '; Secure'
        : '';

    return json(
      {
        ok: true,
      },
      200,
      {
        'Set-Cookie':
          `gd=${encodeURIComponent(
            exp + '.' + sig
          )}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${30 * 86400}${secure}`,
      }
    );
  }

  /*
   * LOGOUT
   */
  if (
    request.method === 'POST' &&
    path === '/api/logout'
  ) {
    return json(
      {
        ok: true,
      },
      200,
      {
        'Set-Cookie':
          'gd=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
      }
    );
  }

  /*
   * GET / PUT DATA
   */
  if (
    (request.method === 'GET' ||
      request.method === 'PUT') &&
    path === '/api/data'
  ) {
    if (
      !(await authenticated(request, env))
    ) {
      return json(
        {
          error: 'Login required',
        },
        401
      );
    }

    /*
     * GET DATA
     */
    if (request.method === 'GET') {
      const r = await env.DB
        .prepare(
          "SELECT v FROM kv WHERE k='data'"
        )
        .first();

      if (!r) {
        return json(null);
      }

      try {
        const data = JSON.parse(r.v);

        if (!validData(data)) {
          return json(
            {
              error:
                'Stored data is invalid',
            },
            500
          );
        }

        return json(data);
      } catch {
        return json(
          {
            error:
              'Stored data is corrupted',
          },
          500
        );
      }
    }

    /*
     * PUT DATA
     */
    let data;

    try {
      data = await request.json();
    } catch {
      return json(
        {
          error: 'Invalid JSON',
        },
        400
      );
    }

    if (!validData(data)) {
      return json(
        {
          error: 'Invalid data',
        },
        400
      );
    }

    const now =
      new Date().toISOString();

    const day =
      'snap-' + now.slice(0, 10);

    try {
      await env.DB.batch([
        env.DB
          .prepare(
            "INSERT INTO kv(k,v,updated) VALUES('data',?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated=excluded.updated"
          )
          .bind(
            JSON.stringify(data),
            now
          ),

        env.DB
          .prepare(
            "INSERT INTO kv(k,v,updated) VALUES(?,?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v, updated=excluded.updated"
          )
          .bind(
            day,
            JSON.stringify(data),
            now
          ),

        env.DB.prepare(
          "DELETE FROM kv WHERE k LIKE 'snap-%' AND k NOT IN (SELECT k FROM kv WHERE k LIKE 'snap-%' ORDER BY k DESC LIMIT 30)"
        ),
      ]);
    } catch (e) {
      console.error(
        'D1 save error',
        e
      );

      return json(
        {
          error:
            'Could not save data',
        },
        500
      );
    }

    return json({
      ok: true,
    });
  }

  return json(
    {
      error: 'Not found',
    },
    404
  );
}

export default {
  async fetch(request, env) {
    const url = new URL(
      request.url
    );

    if (
      url.pathname.startsWith('/api/')
    ) {
      return withSecurity(
        await api(request, env),
        request,
        true
      );
    }

    return withSecurity(
      await env.ASSETS.fetch(request),
      request,
      false
    );
  },
};