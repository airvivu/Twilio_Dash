// Twilio live-call dashboard backend (for Render).
// Stateless: every request reads straight from Twilio, so nothing is lost when the free instance sleeps.
const express = require('express');
const crypto = require('crypto');

const SID = process.env.TWILIO_ACCOUNT_SID;
const AUTH = process.env.TWILIO_AUTH_TOKEN;
const PASSWORD = process.env.DASHBOARD_PASSWORD;
const ALLOWED = (process.env.ALLOWED_ORIGIN || '*').split(',').map(s => s.trim().replace(/\/$/, ''));
const FALLBACK_RATE = parseFloat(process.env.EST_RATE_PER_MIN || '0.014'); // used until real prices are seen
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;

if (!SID || !AUTH || !PASSWORD) {
  console.error('Missing env vars. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and DASHBOARD_PASSWORD.');
  process.exit(1);
}
const SECRET = process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update(`${PASSWORD}|${AUTH}`).digest('hex');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '10kb' }));

// ---- CORS: only your Netlify site may call this API ----
app.use((req, res, next) => {
  const origin = (req.headers.origin || '').replace(/\/$/, '');
  if (ALLOWED.includes('*')) res.setHeader('Access-Control-Allow-Origin', '*');
  else if (ALLOWED.includes(origin)) res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ---- Password login -> signed, expiring token ----
const sign = v => crypto.createHmac('sha256', SECRET).update(String(v)).digest('hex');
const safeEq = (a, b) => {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
};
const attempts = new Map(); // ip -> { count, resetAt }

app.post('/api/login', (req, res) => {
  const now = Date.now();
  const a = attempts.get(req.ip);
  if (a && a.resetAt > now && a.count >= 10) {
    return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  }
  if (!safeEq(req.body && req.body.password || '', PASSWORD)) {
    const cur = a && a.resetAt > now ? a : { count: 0, resetAt: now + 15 * 60 * 1000 };
    cur.count++;
    attempts.set(req.ip, cur);
    return res.status(401).json({ error: 'Wrong password.' });
  }
  attempts.delete(req.ip);
  const exp = now + TOKEN_TTL_MS;
  res.json({ token: `${exp}.${sign(exp)}`, expiresAt: exp });
});

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  const [exp, sig] = token.split('.');
  if (!exp || !sig || !safeEq(sig, sign(exp)) || Number(exp) < Date.now()) {
    return res.status(401).json({ error: 'Not signed in.' });
  }
  next();
}

// ---- Twilio REST helpers ----
const BASIC = 'Basic ' + Buffer.from(`${SID}:${AUTH}`).toString('base64');
const BASE = `/2010-04-01/Accounts/${SID}`;

async function twilio(path) {
  const r = await fetch('https://api.twilio.com' + path, { headers: { Authorization: BASIC } });
  if (!r.ok) {
    const body = await r.text();
    throw new Error(`Twilio ${r.status}: ${body.slice(0, 200)}`);
  }
  return r.json();
}

async function listCalls(query, maxPages = 6) {
  let path = `${BASE}/Calls.json?PageSize=500&${query}`;
  const out = [];
  for (let i = 0; path && i < maxPages; i++) {
    const page = await twilio(path);
    out.push(...page.calls);
    path = page.next_page_uri;
  }
  return out;
}

const dirOf = c => (String(c.direction || '').startsWith('outbound') ? 'outbound' : 'inbound');
const slim = c => ({
  sid: c.sid,
  parentSid: c.parent_call_sid || null,
  from: c.from_formatted || c.from,
  to: c.to_formatted || c.to,
  status: c.status,
  direction: dirOf(c),
  startTime: c.start_time ? new Date(c.start_time).toISOString() : null,
  endTime: c.end_time ? new Date(c.end_time).toISOString() : null,
  created: c.date_created ? new Date(c.date_created).toISOString() : null,
  duration: c.duration != null ? Number(c.duration) : null,
  price: c.price != null ? Math.abs(Number(c.price)) : null,
  priceUnit: c.price_unit || 'USD',
});

// Real average cost per billed minute, learned from completed calls. Used to estimate live calls.
const rates = { inbound: null, outbound: null };
function learnRates(calls) {
  for (const dir of ['inbound', 'outbound']) {
    let cost = 0, mins = 0;
    for (const c of calls) {
      if (c.direction === dir && c.price > 0 && c.duration > 0) {
        cost += c.price;
        mins += Math.ceil(c.duration / 60);
      }
    }
    if (mins > 0) rates[dir] = cost / mins;
  }
}
const rateFor = dir => rates[dir] ?? FALLBACK_RATE;

// ---- Live calls (queued / ringing / in-progress) ----
app.get('/api/live', requireAuth, async (req, res) => {
  try {
    const groups = await Promise.all(
      ['queued', 'ringing', 'in-progress'].map(s => listCalls(`Status=${s}`, 2))
    );
    const calls = groups.flat().map(slim).map(c => ({ ...c, ratePerMin: rateFor(c.direction) }));
    res.json({
      calls,
      rates: { inbound: rateFor('inbound'), outbound: rateFor('outbound') },
      ratesAreLearned: { inbound: rates.inbound != null, outbound: rates.outbound != null },
      fetchedAt: new Date().toISOString(),
    });
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: e.message });
  }
});

// ---- History + spend totals ----
const cache = new Map(); // days -> { at, data }

async function usage(period, category) {
  try {
    const r = await twilio(`${BASE}/Usage/Records/${period}.json?Category=${category}`);
    const u = r.usage_records && r.usage_records[0];
    return u ? { price: Math.abs(Number(u.price) || 0), count: Number(u.count) || 0, unit: (u.price_unit || 'usd').toUpperCase() } : null;
  } catch (e) { console.error(e.message); return null; }
}

app.get('/api/history', requireAuth, async (req, res) => {
  const days = Math.min(31, Math.max(1, parseInt(req.query.days, 10) || 1));
  const hit = cache.get(days);
  if (hit && Date.now() - hit.at < 20000 && !req.query.fresh) return res.json(hit.data);
  try {
    const since = new Date(Date.now() - (days - 1) * 86400000).toISOString().slice(0, 10);
    const [raw, todayCalls, monthCalls, todayTotal, monthTotal, balance] = await Promise.all([
      listCalls(`StartTime%3E=${since}`),
      usage('Today', 'calls'),
      usage('ThisMonth', 'calls'),
      usage('Today', 'totalprice'),
      usage('ThisMonth', 'totalprice'),
      twilio(`${BASE}/Balance.json`).catch(() => null),
    ]);
    const calls = raw.map(slim);
    learnRates(calls);
    const data = {
      days, since, calls,
      truncated: raw.length >= 3000,
      usage: { todayCalls, monthCalls, todayTotal, monthTotal },
      balance: balance ? { amount: Number(balance.balance), unit: balance.currency } : null,
      fetchedAt: new Date().toISOString(),
    };
    cache.set(days, { at: Date.now(), data });
    res.json(data);
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: e.message });
  }
});

app.get('/', (req, res) => res.json({ ok: true, service: 'twilio-dashboard-backend' }));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on ${port}`));
