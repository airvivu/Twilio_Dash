// Twilio dashboard + call-routing backend (for Render).
// - Dashboard data is read straight from Twilio on each request.
// - Routing rules are saved on the phone number itself (inside its Voice URL),
//   so nothing is lost when the free instance sleeps or restarts.
const express = require('express');
const crypto = require('crypto');

const SID = process.env.TWILIO_ACCOUNT_SID;
const AUTH = process.env.TWILIO_AUTH_TOKEN;
const PASSWORD = process.env.DASHBOARD_PASSWORD;
const ALLOWED = (process.env.ALLOWED_ORIGIN || '*').split(',').map(s => s.trim().replace(/\/$/, ''));
const FALLBACK_RATE = parseFloat(process.env.EST_RATE_PER_MIN || '0.014');
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000;
const API = process.env.TWILIO_API_BASE || 'https://api.twilio.com';
const SKIP_SIG = process.env.SKIP_TWILIO_SIGNATURE === '1';
const DEFAULT_HOLD = 'http://com.twilio.music.classical.s3.amazonaws.com/BusyStrings.mp3';

if (!SID || !AUTH || !PASSWORD) {
  console.error('Missing env vars. Set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN and DASHBOARD_PASSWORD.');
  process.exit(1);
}
const SECRET = process.env.SESSION_SECRET ||
  crypto.createHash('sha256').update(`${PASSWORD}|${AUTH}`).digest('hex');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));

// ---- CORS: only your Netlify site may call the dashboard API ----
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
const attempts = new Map();

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

async function twilio(path, { form } = {}) {
  const opts = { headers: { Authorization: BASIC } };
  if (form) {
    opts.method = 'POST';
    opts.headers['Content-Type'] = 'application/x-www-form-urlencoded';
    opts.body = new URLSearchParams(form).toString();
  }
  const r = await fetch(API + path, opts);
  if (!r.ok) {
    const body = await r.text();
    let msg = body.slice(0, 200);
    try { msg = JSON.parse(body).message || msg; } catch {}
    throw new Error(`Twilio ${r.status}: ${msg}`);
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

// Open calls (queued/ringing/in-progress), cached briefly so bursts of calls share one lookup.
let liveCache = { at: 0, p: null };
function liveCalls(force) {
  if (!force && liveCache.p && Date.now() - liveCache.at < 1500) return liveCache.p;
  liveCache.at = Date.now();
  liveCache.p = Promise.all(['queued', 'ringing', 'in-progress'].map(s => listCalls(`Status=${s}`, 2)))
    .then(g => g.flat())
    .catch(e => { console.error('Live call lookup failed:', e.message); liveCache.at = 0; return null; });
  return liveCache.p;
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

// =====================================================================
// Dashboard: live calls, history, spend
// =====================================================================
app.get('/api/live', requireAuth, async (req, res) => {
  const raw = await liveCalls(true);
  if (!raw) return res.status(502).json({ error: 'Could not reach Twilio. Check your Account SID and Auth Token.' });
  const calls = raw.map(slim).map(c => ({ ...c, ratePerMin: rateFor(c.direction) }));
  res.json({
    calls,
    rates: { inbound: rateFor('inbound'), outbound: rateFor('outbound') },
    ratesAreLearned: { inbound: rates.inbound != null, outbound: rates.outbound != null },
    fetchedAt: new Date().toISOString(),
  });
});

const cache = new Map();
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

// =====================================================================
// Call routing
// =====================================================================
const digits = s => String(s || '').replace(/\D/g, '');
const xml = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;' }[c]));
const twiml = (res, body) => res.type('text/xml').send(`<?xml version="1.0" encoding="UTF-8"?><Response>${body}</Response>`);
const publicBase = req => (process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL ||
  `${req.protocol}://${req.get('host')}`).replace(/\/+$/, '');
const queueName = to => 'cc' + digits(to);

// --- Rules: validated on save, packed compactly into the number's Voice URL ---
const clampInt = (v, lo, hi, d) => { const n = parseInt(v, 10); return isNaN(n) ? d : Math.min(hi, Math.max(lo, n)); };

function validateCfg(inp, lineNumber) {
  if (!inp || typeof inp !== 'object') return { error: 'Missing settings.' };
  const list = Array.isArray(inp.agents) ? inp.agents : [];
  if (!list.length) return { error: 'Add at least one agent number.' };
  if (list.length > 10) return { error: 'Up to 10 agents per number.' };
  const seen = new Set(), agents = [];
  for (const a of list) {
    const number = String(a && a.number || '').replace(/[\s().-]/g, '');
    if (!/^\+[1-9]\d{6,14}$/.test(number)) {
      return { error: `"${a && a.number || ''}" is not a valid number. Use international format, e.g. +14155550123.` };
    }
    if (digits(number) === digits(lineNumber)) return { error: 'An agent number cannot be the line itself.' };
    if (seen.has(number)) return { error: `${number} is listed twice.` };
    seen.add(number);
    const sendDigits = String(a.sendDigits || '').replace(/\s/g, '');
    if (!/^[0-9wW*#]{0,32}$/.test(sendDigits)) return { error: `Extension digits for ${number} can only use 0-9, *, # and w (half-second pause).` };
    agents.push({ number, name: String(a.name || '').trim().slice(0, 30), active: a.active !== false,
      capacity: clampInt(a.capacity, 1, 50, 1), sendDigits });
  }
  const holdMusic = String(inp.holdMusic || '').trim();
  if (holdMusic && (!/^https?:\/\/\S+$/.test(holdMusic) || holdMusic.length > 200)) {
    return { error: 'Hold music must be a link to an .mp3 or .wav file (http/https).' };
  }
  return {
    cfg: {
      agents,
      mode: inp.mode === 'rotate' ? 'rotate' : 'priority',
      ringTimeout: clampInt(inp.ringTimeout, 5, 60, 20),
      screen: !!inp.screen,
      callerId: inp.callerId === 'twilio' ? 'twilio' : 'caller',
      whenBusy: ['queue', 'voicemail', 'hangup'].includes(inp.whenBusy) ? inp.whenBusy : 'queue',
      maxWait: clampInt(inp.maxWait, 30, 1800, 300),
      afterWait: inp.afterWait === 'hangup' ? 'hangup' : 'voicemail',
      message: String(inp.message || '').trim().slice(0, 200),
      holdMusic,
      prev: '',
    },
  };
}

const BUSY = ['queue', 'voicemail', 'hangup'];
function pack(c) {
  const p = {
    a: c.agents.map(a => [a.number, a.name, a.active ? 1 : 0, a.capacity, a.sendDigits || '']),
    m: c.mode === 'rotate' ? 1 : 0, r: c.ringTimeout, s: c.screen ? 1 : 0, k: c.callerId === 'twilio' ? 1 : 0,
    b: BUSY.indexOf(c.whenBusy), w: c.maxWait, o: c.afterWait === 'hangup' ? 1 : 0,
  };
  if (c.message) p.g = c.message;
  if (c.holdMusic) p.h = c.holdMusic;
  if (c.prev) p.p = c.prev;
  return Buffer.from(JSON.stringify(p)).toString('base64url');
}
function unpack(s) {
  try {
    const p = JSON.parse(Buffer.from(String(s || ''), 'base64url').toString());
    if (!Array.isArray(p.a) || !p.a.length) return null;
    return {
      agents: p.a.map(([number, name, on, cap, sd]) => ({ number: String(number), name: String(name || ''), active: !!on,
        capacity: Math.max(1, Number(cap) || 1), sendDigits: String(sd || '') })),
      mode: p.m ? 'rotate' : 'priority', ringTimeout: p.r || 20, screen: !!p.s, callerId: p.k ? 'twilio' : 'caller',
      whenBusy: BUSY[p.b] || 'queue', maxWait: p.w || 300, afterWait: p.o ? 'hangup' : 'voicemail',
      message: p.g || '', holdMusic: p.h || '', prev: p.p || '',
    };
  } catch { return null; }
}
const cfgFromUrl = u => { const m = /\/voice\/incoming\?c=([A-Za-z0-9_-]+)/.exec(u || ''); return m ? unpack(m[1]) : null; };

// --- Short-lived memory (safe to lose on restart) ---
const reserved = new Map();    // destination digits -> Map(callerCallSid -> expiry): sent a call, not yet visible in Twilio
const cooldown = new Map();    // destination digits -> expiry: gave busy / no answer, skip briefly
const accepted = new Map();    // parentCallSid:agentIndex -> expiry: agent pressed 1
const queuedSince = new Map(); // callSid -> first time the caller was put on hold
const queues = new Map();      // queueSid -> { c, to, base, size, at }
const rr = new Map();          // line digits -> last destination index (rotate mode)

setInterval(() => {
  const now = Date.now();
  for (const m of [cooldown, accepted]) for (const [k, v] of m) if (v < now) m.delete(k);
  for (const [d, m] of reserved) { for (const [k, v] of m) if (v < now) m.delete(k); if (!m.size) reserved.delete(d); }
  for (const [k, v] of queuedSince) if (now - v > 3 * 3600e3) queuedSince.delete(k);
}, 60000).unref();

// Each destination (a phone, or a PBX / toll-free line) has a number of lines = calls it may hold at once.
// Lines in use = open calls Twilio reports to that number + calls we've just sent that Twilio doesn't show yet.
// Both are keyed by the caller's CallSid, so a call is never counted twice.
function agentStates(cfg, calls) {
  const now = Date.now();
  const open = new Map(); // digits -> Map(callerSid -> line)
  for (const c of calls || []) {
    const d = digits(c.to);
    if (!open.has(d)) open.set(d, new Map());
    const key = c.parent_call_sid || c.sid, prev = open.get(d).get(key);
    if (!prev || c.status === 'in-progress') open.get(d).set(key, {
      with: c.from_formatted || c.from, status: c.status,
      startTime: c.start_time ? new Date(c.start_time).toISOString() : null,
    });
  }
  return cfg.agents.map((a, i) => {
    const d = digits(a.number);
    const lines = new Map(open.get(d) || []);
    const resv = reserved.get(d);
    if (resv && calls) for (const [k, exp] of resv) {
      if (lines.has(k) || exp <= now) resv.delete(k); // Twilio shows it now, so stop counting our placeholder
      else lines.set(k, { status: 'ringing' });
    }
    if (resv && !calls) for (const [k, exp] of resv) if (exp > now && !lines.has(k)) lines.set(k, { status: 'ringing' });
    const all = [...lines.values()];
    const talking = all.filter(l => l.status === 'in-progress');
    let state = 'free';
    if (!a.active) state = 'paused';
    else if ((cooldown.get(d) || 0) > now) state = 'cooldown';
    else if (lines.size >= a.capacity) state = 'full';
    return {
      index: i, number: a.number, name: a.name, active: a.active, capacity: a.capacity, sendDigits: a.sendDigits,
      state, inUse: lines.size, onCall: talking.length, ringing: lines.size - talking.length,
      freeLines: state === 'free' ? a.capacity - lines.size : 0,
      calls: talking.map(l => ({ with: l.with, startTime: l.startTime })),
    };
  });
}

function pickAgent(cfg, line, tried, calls) {
  const free = agentStates(cfg, calls).filter(s => s.state === 'free' && !tried.includes(s.index));
  if (!free.length) return null;
  if (cfg.mode === 'rotate') {
    const last = rr.has(line) ? rr.get(line) : -1;
    const pick = free.find(s => s.index > last) || free[0];
    rr.set(line, pick.index);
    return pick;
  }
  return free[0];
}

function waitingFor(to) {
  for (const q of queues.values()) if (digits(q.to) === digits(to) && Date.now() - q.at < 60000) return q.size;
  return 0;
}

// --- Twilio webhook security: reject anything not signed with your Auth Token ---
function verifyTwilio(req, res, next) {
  if (SKIP_SIG) return next();
  const url = publicBase(req) + req.originalUrl;
  const params = req.body || {};
  const data = url + Object.keys(params).sort().map(k => k + params[k]).join('');
  const expected = crypto.createHmac('sha1', AUTH).update(Buffer.from(data, 'utf-8')).digest('base64');
  const got = req.get('X-Twilio-Signature') || '';
  if (!got || !safeEq(got, expected)) {
    console.warn('Rejected webhook with bad signature:', url);
    return res.status(403).send('Invalid signature');
  }
  next();
}

// --- TwiML builders ---
function dialAgent(res, cfg, base, c, agent, tried, body) {
  const d = digits(agent.number);
  if (!reserved.has(d)) reserved.set(d, new Map());
  reserved.get(d).set(body.CallSid, Date.now() + (cfg.ringTimeout + 20) * 1000);
  const tr = [...tried, agent.index].join('.');
  const action = `${base}/voice/dial-done?c=${c}&ag=${agent.index}&tr=${tr}`;
  const cid = cfg.callerId === 'twilio' ? ` callerId="${xml(body.To)}"` : '';
  const screen = cfg.screen ? ` url="${xml(`${base}/voice/screen?ag=${agent.index}`)}" method="POST"` : '';
  return twiml(res, `<Dial timeout="${cfg.ringTimeout}" answerOnBridge="true"${cid} action="${xml(action)}" method="POST">` +
    `<Number${screen}${agent.sendDigits ? ` sendDigits="${xml(agent.sendDigits)}"` : ''}>${xml(agent.number)}</Number></Dial>`);
}

function voicemail(res, base) {
  return twiml(res, '<Say>Sorry, no one is available to take your call. Please leave a message after the tone.</Say>' +
    `<Record maxLength="120" playBeep="true" timeout="5" action="${xml(base + '/voice/vm-done')}" method="POST"/>`);
}

function enqueue(res, cfg, base, c, body) {
  const first = !queuedSince.has(body.CallSid);
  if (first) queuedSince.set(body.CallSid, Date.now());
  const say = first ? `<Say>${xml(cfg.message || 'All of our agents are busy. Please hold and the next available agent will be with you.')}</Say>` : '';
  return twiml(res, `${say}<Enqueue waitUrl="${xml(`${base}/voice/wait?c=${c}`)}" waitUrlMethod="POST" ` +
    `action="${xml(`${base}/voice/queue-done?c=${c}`)}" method="POST">${queueName(body.To)}</Enqueue>`);
}

function overflow(res, cfg, base, callSid) {
  queuedSince.delete(callSid);
  if (cfg.afterWait === 'voicemail') return voicemail(res, base);
  return twiml(res, '<Say>Sorry, no one is available right now. Please call back later. Goodbye.</Say><Hangup/>');
}

function allBusy(res, cfg, base, c, body) {
  if (cfg.whenBusy === 'queue') return enqueue(res, cfg, base, c, body);
  if (cfg.whenBusy === 'voicemail') return voicemail(res, base);
  return twiml(res, `<Say>${xml(cfg.message || 'Sorry, all of our agents are busy. Please call back later.')}</Say><Hangup/>`);
}

async function route(req, res, { fresh }) {
  const c = req.query.c, cfg = unpack(c), b = req.body, base = publicBase(req);
  if (!cfg) return twiml(res, '<Say>Sorry, this line is not set up correctly.</Say><Hangup/>');
  const tried = String(req.query.tr || '').split('.').filter(Boolean).map(Number);
  const since = queuedSince.get(b.CallSid);
  if (cfg.whenBusy === 'queue' && since && Date.now() - since >= cfg.maxWait * 1000) return overflow(res, cfg, base, b.CallSid);
  const calls = await liveCalls();
  // If callers are already on hold for this line, a new caller joins the back of the line.
  if (fresh && cfg.whenBusy === 'queue' && waitingFor(b.To) > 0) return enqueue(res, cfg, base, c, b);
  const agent = pickAgent(cfg, digits(b.To), tried, calls || []);
  if (agent) return dialAgent(res, cfg, base, c, agent, tried, b);
  return allBusy(res, cfg, base, c, b);
}

const handle = fn => (req, res) => Promise.resolve(fn(req, res)).catch(e => {
  console.error('Webhook error:', e);
  twiml(res, '<Say>Sorry, something went wrong. Please call back.</Say><Hangup/>');
});

// New inbound call on a routed number
app.post('/voice/incoming', verifyTwilio, handle((req, res) => route(req, res, { fresh: true })));

// A held caller released from the queue (agent became free, or max wait reached)
app.post('/voice/route', verifyTwilio, handle((req, res) => route(req, res, { fresh: false })));

// The agent's leg ended: either the conversation finished, or the agent didn't pick up
app.post('/voice/dial-done', verifyTwilio, handle(async (req, res) => {
  const cfg = unpack(req.query.c), b = req.body, i = Number(req.query.ag);
  const agent = cfg && cfg.agents[i];
  if (agent && reserved.has(digits(agent.number))) reserved.get(digits(agent.number)).delete(b.CallSid);
  const key = `${b.CallSid}:${i}`;
  const bridged = b.DialBridged != null
    ? String(b.DialBridged) === 'true'
    : b.DialCallStatus === 'completed' && (!cfg || !cfg.screen || accepted.has(key));
  accepted.delete(key);
  schedulePump(500); // an agent may be free now
  if (bridged || b.CallStatus === 'completed' || !cfg) {
    queuedSince.delete(b.CallSid);
    return twiml(res, '<Hangup/>');
  }
  if (agent && b.DialCallStatus !== 'canceled') cooldown.set(digits(agent.number), Date.now() + 30000);
  return route(req, res, { fresh: false });
}));

// "Press 1 to accept" whisper played to the agent before connecting
app.post('/voice/screen', verifyTwilio, (req, res) => {
  const action = `${publicBase(req)}/voice/screen-done?ag=${encodeURIComponent(req.query.ag || '')}`;
  twiml(res, `<Gather numDigits="1" timeout="8" action="${xml(action)}" method="POST">` +
    '<Say loop="2">Incoming call. Press 1 to accept.</Say></Gather><Hangup/>');
});
app.post('/voice/screen-done', verifyTwilio, (req, res) => {
  if (req.body.Digits === '1') {
    accepted.set(`${req.body.ParentCallSid}:${req.query.ag}`, Date.now() + 3 * 3600e3);
    return twiml(res, ''); // empty response = connect the caller
  }
  twiml(res, '<Hangup/>');
});

// Hold music loop; also lets the server re-learn about waiting callers after a restart
app.post('/voice/wait', verifyTwilio, (req, res) => {
  const cfg = unpack(req.query.c), b = req.body;
  if (b.QueueSid) {
    queues.set(b.QueueSid, { c: req.query.c, to: b.To || '', base: publicBase(req), size: Number(b.CurrentQueueSize) || 1, at: Date.now() });
    schedulePump(0);
  }
  if (!queuedSince.has(b.CallSid)) queuedSince.set(b.CallSid, Date.now() - (Number(b.QueueTime) || 0) * 1000);
  if (cfg && Date.now() - queuedSince.get(b.CallSid) >= cfg.maxWait * 1000) return twiml(res, '<Leave/>');
  twiml(res, `<Play>${xml(cfg && cfg.holdMusic || DEFAULT_HOLD)}</Play>`);
});

app.post('/voice/queue-done', verifyTwilio, handle((req, res) => {
  const r = req.body.QueueResult, cfg = unpack(req.query.c);
  if (r === 'leave') return route(req, res, { fresh: false });
  if (cfg && ['queue-full', 'error', 'system-error'].includes(r)) return overflow(res, cfg, publicBase(req), req.body.CallSid);
  if (r === 'hangup') queuedSince.delete(req.body.CallSid);
  return twiml(res, '');
}));

app.post('/voice/vm-done', verifyTwilio, (req, res) => twiml(res, '<Say>Thank you. Goodbye.</Say><Hangup/>'));

// --- Queue pump: hands held callers to agents as soon as one is free ---
let pumpTimer = null, pumpDue = 0, pumping = false;
function schedulePump(delay) {
  const due = Date.now() + delay;
  if (pumpTimer && pumpDue <= due) return;
  clearTimeout(pumpTimer);
  pumpDue = due;
  pumpTimer = setTimeout(pump, delay);
}
async function pump() {
  pumpTimer = null;
  if (pumping) return schedulePump(1000);
  pumping = true;
  try {
    for (const [qsid, q] of queues) {
      const cfg = unpack(q.c);
      if (!cfg) { queues.delete(qsid); continue; }
      const members = ((await twilio(`${BASE}/Queues/${qsid}/Members.json?PageSize=100`)).queue_members || [])
        .sort((a, b) => a.position - b.position);
      q.size = members.length; q.at = Date.now();
      if (!members.length) { queues.delete(qsid); continue; }
      const release = m => twilio(`${BASE}/Queues/${qsid}/Members/${m.call_sid}.json`,
        { form: { Url: `${q.base}/voice/route?c=${q.c}`, Method: 'POST' } }).catch(e => console.error('Dequeue failed:', e.message));
      const now = Date.now();
      const overdue = members.filter(m => {
        const since = queuedSince.get(m.call_sid) ?? now - (Number(m.wait_time) || 0) * 1000;
        return now - since >= cfg.maxWait * 1000;
      });
      for (const m of overdue) await release(m); // route() sends them to voicemail / goodbye
      const waiting = members.filter(m => !overdue.includes(m));
      if (!waiting.length) continue;
      const free = agentStates(cfg, (await liveCalls(true)) || []).reduce((n, s) => n + s.freeLines, 0);
      for (const m of waiting.slice(0, free)) await release(m);
    }
  } catch (e) {
    console.error('Queue pump:', e.message);
  } finally {
    pumping = false;
    if (queues.size) schedulePump(4000);
  }
}

// --- Dashboard API for routing ---
app.get('/api/routing', requireAuth, async (req, res) => {
  try {
    const [nums, calls, qs] = await Promise.all([
      twilio(`${BASE}/IncomingPhoneNumbers.json?PageSize=100`),
      liveCalls(true),
      twilio(`${BASE}/Queues.json?PageSize=100`).catch(() => ({ queues: [] })),
    ]);
    const qByName = new Map((qs.queues || []).map(q => [q.friendly_name, q]));
    res.json({
      publicUrl: publicBase(req),
      liveOk: calls != null,
      numbers: (nums.incoming_phone_numbers || []).map(n => {
        const cfg = cfgFromUrl(n.voice_url);
        const q = qByName.get(queueName(n.phone_number));
        return {
          sid: n.sid, number: n.phone_number, name: n.friendly_name,
          voiceUrl: n.voice_url || '', fallbackUrl: n.voice_fallback_url || '',
          routing: cfg, agents: cfg ? agentStates(cfg, calls || []) : [],
          waiting: q ? Number(q.current_size) || 0 : 0,
          avgWait: q ? Number(q.average_wait_time) || 0 : 0,
        };
      }),
    });
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: e.message });
  }
});

app.post('/api/routing/:sid', requireAuth, async (req, res) => {
  const sid = req.params.sid;
  if (!/^PN[0-9a-f]{32}$/i.test(sid)) return res.status(400).json({ error: 'Unknown number.' });
  try {
    const path = `${BASE}/IncomingPhoneNumbers/${sid}.json`;
    const cur = await twilio(path);
    const existing = cfgFromUrl(cur.voice_url);
    const prev = existing ? existing.prev : (cur.voice_url || '');
    if (req.body.disable) {
      await twilio(path, { form: { VoiceUrl: prev } });
      return res.json({ ok: true, restored: prev });
    }
    const v = validateCfg(req.body.config, cur.phone_number);
    if (v.error) return res.status(400).json({ error: v.error });
    v.cfg.prev = prev.length <= 300 ? prev : '';
    const base = publicBase(req);
    if (/^http:\/\/(localhost|127\.)/.test(base)) {
      return res.status(400).json({ error: 'This server has no public address yet. Deploy it to Render first.' });
    }
    const form = { VoiceUrl: `${base}/voice/incoming?c=${pack(v.cfg)}`, VoiceMethod: 'POST' };
    if (typeof req.body.fallbackUrl === 'string') {
      const f = req.body.fallbackUrl.trim();
      if (f && (!/^https?:\/\/\S+$/.test(f) || f.length > 300)) return res.status(400).json({ error: 'Backup URL must start with https://' });
      form.VoiceFallbackUrl = f;
      form.VoiceFallbackMethod = 'POST';
    }
    await twilio(path, { form });
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: e.message });
  }
});

// --- Voicemails / recordings ---
const callInfo = new Map();
app.get('/api/voicemails', requireAuth, async (req, res) => {
  try {
    const recs = (await twilio(`${BASE}/Recordings.json?PageSize=25`)).recordings || [];
    await Promise.all(recs.filter(r => r.call_sid && !callInfo.has(r.call_sid)).map(r =>
      twilio(`${BASE}/Calls/${r.call_sid}.json`)
        .then(c => callInfo.set(r.call_sid, { from: c.from_formatted || c.from, to: c.to_formatted || c.to }))
        .catch(() => {})));
    res.json({
      recordings: recs.map(r => ({
        sid: r.sid, date: r.date_created ? new Date(r.date_created).toISOString() : null,
        duration: Number(r.duration) || 0, ...(callInfo.get(r.call_sid) || {}),
      })),
    });
  } catch (e) {
    res.status(502).json({ error: e.message });
  }
});

app.get('/api/recordings/:sid', requireAuth, async (req, res) => {
  if (!/^RE[0-9a-f]{32}$/i.test(req.params.sid)) return res.sendStatus(400);
  const r = await fetch(`${API}${BASE}/Recordings/${req.params.sid}.mp3`, { headers: { Authorization: BASIC } });
  if (!r.ok) return res.sendStatus(r.status);
  res.type('audio/mpeg').send(Buffer.from(await r.arrayBuffer()));
});

app.get('/', (req, res) => res.json({ ok: true, service: 'twilio-dashboard-backend' }));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on ${port}`));
