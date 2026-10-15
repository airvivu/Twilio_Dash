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

async function twilio(path, { form, method } = {}) {
  const opts = { headers: { Authorization: BASIC } };
  if (method) opts.method = method;
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
  return r.status === 204 ? {} : r.json();
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

function validateAgents(list, lineNumber) {
  list = Array.isArray(list) ? list : [];
  if (!list.length) return { error: 'Add at least one destination number.' };
  if (list.length > 10) return { error: 'Up to 10 destinations per number.' };
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
  return { agents };
}

function validateCfg(inp, lineNumber) {
  if (!inp || typeof inp !== 'object') return { error: 'Missing settings.' };
  const va = validateAgents(inp.agents, lineNumber);
  if (va.error) return va;
  const agents = va.agents;
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
      preset: /^AP[0-9a-f]{32}$/i.test(inp.preset || '') ? inp.preset : '',
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
  if (c.preset) p.x = c.preset;
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
      message: p.g || '', holdMusic: p.h || '', prev: p.p || '', preset: p.x || '',
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
function agentStates(cfg, calls, ignoreSid) {
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
      else if (k !== ignoreSid) lines.set(k, { status: 'ringing' });
    }
    if (resv && !calls) for (const [k, exp] of resv) if (exp > now && k !== ignoreSid && !lines.has(k)) lines.set(k, { status: 'ringing' });
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

function pickAgent(cfg, line, tried, calls, callSid) {
  const free = agentStates(cfg, calls, callSid).filter(s => s.state === 'free' && !tried.includes(s.index));
  if (!free.length) return null;
  if (cfg.mode === 'rotate') {
    const last = rr.has(line) ? rr.get(line) : -1;
    const pick = free.find(s => s.index > last) || free[0];
    rr.set(line, pick.index);
    return pick;
  }
  return free[0];
}

// Are callers already on hold (on any of your numbers) for a destination this caller could use?
// If so, a brand-new caller waits behind them instead of grabbing the next free line.
function waitingFor(cfg) {
  const mine = new Set(cfg.agents.map(a => digits(a.number)));
  for (const q of queues.values()) {
    if (!q.size || Date.now() - q.at > 60000) continue;
    const other = unpack(q.c);
    if (other && other.agents.some(a => mine.has(digits(a.number)))) return q.size;
  }
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
  for (const m of reserved.values()) m.delete(body.CallSid); // drop any line held for this caller elsewhere
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
  if (fresh && cfg.whenBusy === 'queue' && waitingFor(cfg) > 0) return enqueue(res, cfg, base, c, b);
  const agent = pickAgent(cfg, digits(b.To), tried, calls || [], b.CallSid);
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
const release = ({ qsid, q, m }) => twilio(`${BASE}/Queues/${qsid}/Members/${m.call_sid}.json`,
  { form: { Url: `${q.base}/voice/route?c=${q.c}`, Method: 'POST' } }).catch(e => console.error('Dequeue failed:', e.message));

async function pump() {
  pumpTimer = null;
  if (pumping) return schedulePump(1000);
  pumping = true;
  try {
    // Gather held callers from every one of your numbers, so shared PBX lines go to whoever waited longest.
    const waiting = [];
    for (const [qsid, q] of queues) {
      const cfg = unpack(q.c);
      if (!cfg) { queues.delete(qsid); continue; }
      const members = (await twilio(`${BASE}/Queues/${qsid}/Members.json?PageSize=100`)).queue_members || [];
      q.size = members.length; q.at = Date.now();
      if (!members.length) { queues.delete(qsid); continue; }
      const now = Date.now();
      for (const m of members) {
        const since = queuedSince.get(m.call_sid) ?? now - (Number(m.wait_time) || 0) * 1000;
        const item = { qsid, q, cfg, m, since };
        if (now - since >= cfg.maxWait * 1000) await release(item); // route() sends them to voicemail / goodbye
        else waiting.push(item);
      }
    }
    if (waiting.length) {
      const calls = (await liveCalls(true)) || [];
      const promised = new Map(); // destination digits -> lines handed out in this pass
      waiting.sort((a, b) => a.since - b.since);
      for (const item of waiting) {
        const pick = agentStates(item.cfg, calls).find(s =>
          s.state === 'free' && s.freeLines - (promised.get(digits(s.number)) || 0) > 0);
        if (!pick) continue;
        const d = digits(pick.number);
        promised.set(d, (promised.get(d) || 0) + 1);
        // Hold this line for the released caller until they reconnect and get dialed.
        if (!reserved.has(d)) reserved.set(d, new Map());
        reserved.get(d).set(item.m.call_sid, Date.now() + 30000);
        await release(item);
      }
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
          routing: cfg, agents: cfg ? agentStates(cfg, calls || []).map(a => ({ ...a, portalCode: portalCode(a.number) })) : [],
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
      routedCache.at = 0;
      return res.json({ ok: true, restored: prev });
    }
    const v = validateCfg(req.body.config, cur.phone_number);
    if (v.error) return res.status(400).json({ error: v.error });
    v.cfg.prev = prev.length <= 300 ? prev : '';
    if (v.cfg.preset) {
      const pr = (await listPresets()).find(x => x.id === v.cfg.preset);
      if (!pr || !sameDestinations(pr.agents, v.cfg.agents)) v.cfg.preset = ''; // edited by hand: no longer follows the config
    }
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
    routedCache.at = 0;

    const synced = await syncDestinations(v.cfg.agents, sid);
    res.json({ ok: true, synced });
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: e.message });
  }
});

// --- Unique callers per routed number (callers with +1 or +81 numbers) ---
let uniqCache = { at: 0, data: null };
app.get('/api/unique-callers', requireAuth, async (req, res) => {
  if (uniqCache.data && Date.now() - uniqCache.at < 60000 && !req.query.fresh) return res.json(uniqCache.data);
  try {
    const nums = (await twilio(`${BASE}/IncomingPhoneNumbers.json?PageSize=100`)).incoming_phone_numbers || [];
    const today = new Date().toISOString().slice(0, 10);
    const week = new Date(Date.now() - 6 * 86400000).toISOString().slice(0, 10);
    const out = {};
    await Promise.all(nums.filter(n => cfgFromUrl(n.voice_url)).map(async n => {
      const calls = await listCalls(`To=${encodeURIComponent(n.phone_number)}&StartTime%3E=${week}`, 10);
      const t = new Set(), w = new Set();
      let callsToday = 0;
      for (const c of calls) {
        if (c.parent_call_sid || dirOf(c) !== 'inbound') continue; // the caller's own call, not forwards
        const day = new Date(c.start_time || c.date_created).toISOString().slice(0, 10);
        if (day === today) callsToday++;
        const from = String(c.from || '');
        if (!/^\+(1|81)/.test(from)) continue;
        w.add(from);
        if (day === today) t.add(from);
      }
      const us = [...t].filter(f => f.startsWith('+1')).length;
      out[n.sid] = { today: t.size, todayUS: us, todayJP: t.size - us, week: w.size, callsToday };
    }));
    uniqCache = { at: Date.now(), data: { numbers: out, day: today } };
    res.json(uniqCache.data);
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: e.message });
  }
});

// =====================================================================
// Partner (PBX) view-only portal
// A partner signs in with their destination number + an access code you give them.
// Codes are derived from a secret, so nothing has to be stored.
// =====================================================================
const PORTAL_SECRET = process.env.PORTAL_SECRET || SECRET;
const B32 = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function portalCode(number) {
  const h = crypto.createHmac('sha256', PORTAL_SECRET).update('portal:' + digits(number)).digest();
  let s = '';
  for (let i = 0; i < 8; i++) s += B32[h[i] % 32];
  return s.slice(0, 4) + '-' + s.slice(4);
}

let routedCache = { at: 0, p: null };
function routedNumbers() {
  if (routedCache.p && Date.now() - routedCache.at < 30000) return routedCache.p;
  routedCache.at = Date.now();
  routedCache.p = twilio(`${BASE}/IncomingPhoneNumbers.json?PageSize=100`)
    .then(r => (r.incoming_phone_numbers || [])
      .map(n => ({ sid: n.sid, number: n.phone_number, cfg: cfgFromUrl(n.voice_url) })).filter(n => n.cfg))
    .catch(e => { routedCache.at = 0; throw e; });
  return routedCache.p;
}

// Every Twilio number that forwards to this destination, and how it's set up there.
async function findDest(d) {
  const uses = [];
  for (const n of await routedNumbers()) {
    const idx = n.cfg.agents.findIndex(a => digits(a.number) === d);
    if (idx >= 0) uses.push({ line: n.number, cfg: n.cfg, agent: n.cfg.agents[idx] });
  }
  if (!uses.length) return null;
  return { number: uses[0].agent.number, name: (uses.find(u => u.agent.name) || {}).agent?.name || '', uses };
}

const portalAttempts = new Map();
app.post('/portal/login', async (req, res) => {
  const now = Date.now();
  const a = portalAttempts.get(req.ip);
  if (a && a.resetAt > now && a.count >= 10) return res.status(429).json({ error: 'Too many attempts. Try again in 15 minutes.' });
  const d = digits(req.body && req.body.number);
  const code = String(req.body && req.body.code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
  const fail = () => {
    const cur = a && a.resetAt > now ? a : { count: 0, resetAt: now + 15 * 60 * 1000 };
    cur.count++; portalAttempts.set(req.ip, cur);
    res.status(401).json({ error: 'That number and access code don\'t match.' });
  };
  try {
    if (d.length < 7) return fail();
    const dest = await findDest(d);
    if (!dest || !safeEq(code, portalCode(d).replace('-', ''))) return fail();
    portalAttempts.delete(req.ip);
    const exp = now + TOKEN_TTL_MS;
    res.json({ token: `p.${d}.${exp}.${sign(`p:${d}:${exp}`)}`, expiresAt: exp });
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: 'Service unavailable. Please try again shortly.' });
  }
});

function requirePortal(req, res, next) {
  const t = (req.headers.authorization || '').replace(/^Bearer\s+/i, '').split('.');
  if (t.length !== 4 || t[0] !== 'p' || Number(t[2]) < Date.now() || !safeEq(t[3], sign(`p:${t[1]}:${t[2]}`))) {
    return res.status(401).json({ error: 'Please sign in again.' });
  }
  req.dest = t[1];
  next();
}

let queuesCache = { at: 0, p: null };
function queueList() {
  if (queuesCache.p && Date.now() - queuesCache.at < 3000) return queuesCache.p;
  queuesCache.at = Date.now();
  queuesCache.p = twilio(`${BASE}/Queues.json?PageSize=100`).then(r => r.queues || []).catch(() => []);
  return queuesCache.p;
}

app.get('/portal/live', requirePortal, async (req, res) => {
  try {
    const d = req.dest, dest = await findDest(d);
    if (!dest) return res.status(404).json({ error: 'This number is no longer set up. Contact your account manager.' });
    const [calls, qs] = await Promise.all([liveCalls(), queueList()]);
    const all = calls || [];
    const byId = new Map(all.map(c => [c.sid, c]));
    const live = all.filter(c => digits(c.to) === d && c.parent_call_sid).map(l => {
      const p = byId.get(l.parent_call_sid);
      return {
        caller: p ? (p.from_formatted || p.from) : (l.from_formatted || l.from),
        line: p ? (p.to_formatted || p.to) : null,
        status: l.status,
        startTime: l.start_time ? new Date(l.start_time).toISOString() : null,
        created: l.date_created ? new Date(l.date_created).toISOString() : null,
      };
    });
    const st = agentStates(dest.uses[0].cfg, all).find(s => digits(s.number) === d);
    const active = dest.uses.some(u => u.agent.active);
    const lineNames = new Set(dest.uses.map(u => queueName(u.line)));
    const waiting = qs.filter(q => lineNames.has(q.friendly_name)).reduce((n, q) => n + (Number(q.current_size) || 0), 0);
    res.json({
      number: dest.number, name: dest.name,
      lines: {
        capacity: Math.max(...dest.uses.map(u => u.agent.capacity)), inUse: st.inUse, talking: st.onCall, ringing: st.ringing,
        state: !active ? 'paused' : st.state === 'cooldown' ? 'free' : st.state,
      },
      waiting, live, liveOk: calls != null, fetchedAt: new Date().toISOString(),
    });
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: 'Could not load live calls. Retrying…' });
  }
});

const portalHist = new Map();
app.get('/portal/history', requirePortal, async (req, res) => {
  const d = req.dest;
  const now = Date.now();
  let to = Date.parse(req.query.to) || now, from = Date.parse(req.query.from) || now - 86400000;
  to = Math.min(to, now + 60000);
  from = Math.max(from, to - 31 * 86400000);
  const key = `${d}|${Math.floor(from / 60000)}|${Math.floor(to / 60000)}`;
  const hit = portalHist.get(key);
  if (hit && now - hit.at < 30000) return res.json(hit.data);
  try {
    const dest = await findDest(d);
    if (!dest) return res.status(404).json({ error: 'This number is no longer set up. Contact your account manager.' });
    const since = new Date(from).toISOString().slice(0, 10);
    const lines = [...new Set(dest.uses.map(u => u.line))];
    const [legs, ...parentLists] = await Promise.all([
      listCalls(`To=${encodeURIComponent(dest.number)}&StartTime%3E=${since}`, 10),
      ...lines.map(l => listCalls(`To=${encodeURIComponent(l)}&StartTime%3E=${since}`, 10).catch(() => [])),
    ]);
    const parents = new Map(parentLists.flat().map(c => [c.sid, c]));
    const rows = [];
    for (const l of legs) {
      if (!l.parent_call_sid) continue; // only calls forwarded by your routing
      const t = Date.parse(l.date_created || l.start_time);
      if (!(t >= from && t <= to)) continue;
      const p = parents.get(l.parent_call_sid);
      rows.push({
        time: new Date(t).toISOString(),
        caller: p ? (p.from_formatted || p.from) : (l.from_formatted || l.from),
        callerE164: p ? p.from : l.from,
        line: p ? (p.to_formatted || p.to) : '',
        status: l.status,
        duration: l.status === 'completed' ? Number(l.duration) || 0 : 0,
      });
    }
    rows.sort((a, b) => b.time.localeCompare(a.time));
    const data = { from: new Date(from).toISOString(), to: new Date(to).toISOString(), rows, truncated: legs.length >= 5000 };
    portalHist.set(key, { at: now, data });
    if (portalHist.size > 200) portalHist.delete(portalHist.keys().next().value);
    res.json(data);
  } catch (e) {
    console.error(e);
    res.status(502).json({ error: 'Could not load call history. Please try again.' });
  }
});

// =====================================================================
// Sellers are the same everywhere: a destination's name, lines, pause and
// extension follow its phone number across all of your Twilio numbers.
// =====================================================================
const sameDestinations = (a, b) => a.map(x => digits(x.number)).join() === b.map(x => digits(x.number)).join();

async function saveNumberCfg(n, cfg) {
  const base = n.voice_url.slice(0, n.voice_url.indexOf('/voice/incoming?c='));
  await twilio(`${BASE}/IncomingPhoneNumbers/${n.sid}.json`, { form: { VoiceUrl: `${base}/voice/incoming?c=${pack(cfg)}` } });
}

async function syncDestinations(source, exceptSid) {
  const by = new Map(source.map(a => [digits(a.number), a]));
  const synced = [];
  const all = (await twilio(`${BASE}/IncomingPhoneNumbers.json?PageSize=100`)).incoming_phone_numbers || [];
  for (const n of all) {
    if (n.sid === exceptSid) continue;
    const cfg = cfgFromUrl(n.voice_url);
    if (!cfg) continue;
    let changed = false;
    for (const a of cfg.agents) {
      const src = by.get(digits(a.number));
      if (!src) continue;
      for (const k of ['name', 'active', 'capacity', 'sendDigits']) {
        if (src[k] === undefined) continue; // only copy what the source actually sets
        if (a[k] !== src[k]) { a[k] = src[k]; changed = true; }
      }
    }
    if (!changed) continue;
    await saveNumberCfg(n, cfg);
    synced.push(n.phone_number);
  }
  routedCache.at = 0;
  return synced;
}

// =====================================================================
// Saved configs (destination lists you can reuse on any number).
// Stored in your Twilio account as TwiML Apps named "Routing config: …",
// so they survive restarts without a database.
// =====================================================================
const PRESET_PREFIX = 'Routing config: ';
let presetCache = { at: 0, p: null };
function listPresets() {
  if (presetCache.p && Date.now() - presetCache.at < 15000) return presetCache.p;
  presetCache.at = Date.now();
  presetCache.p = twilio(`${BASE}/Applications.json?PageSize=100`).then(r => (r.applications || [])
    .filter(a => String(a.friendly_name || '').startsWith(PRESET_PREFIX))
    .map(a => {
      const m = /\/voice\/config\?c=([A-Za-z0-9_-]+)/.exec(a.voice_url || '');
      let agents = [];
      try { agents = JSON.parse(Buffer.from(m[1], 'base64url').toString()).map(([number, name, cap, sd]) => ({ number, name, capacity: cap || 1, sendDigits: sd || '' })); } catch {}
      return { id: a.sid, name: a.friendly_name.slice(PRESET_PREFIX.length), agents };
    })
    .sort((a, b) => a.name.localeCompare(b.name)))
    .catch(e => { presetCache.at = 0; throw e; });
  return presetCache.p;
}

// If someone attaches a config's TwiML App to a number by mistake, just end the call politely.
app.all('/voice/config', (req, res) => twiml(res, '<Say>Sorry, this line is not set up.</Say><Hangup/>'));

app.get('/api/presets', requireAuth, async (req, res) => {
  try {
    const [presets, nums] = await Promise.all([listPresets(), routedNumbers()]);
    res.json({ presets: presets.map(p => ({ ...p, usedBy: nums.filter(n => n.cfg.preset === p.id).map(n => n.number) })) });
  } catch (e) { console.error(e); res.status(502).json({ error: e.message }); }
});

app.post('/api/presets', requireAuth, async (req, res) => {
  try {
    const name = String(req.body.name || '').trim().slice(0, 40);
    if (!name) return res.status(400).json({ error: 'Give the config a name.' });
    const va = validateAgents(req.body.agents, '');
    if (va.error) return res.status(400).json({ error: va.error });
    const id = /^AP[0-9a-f]{32}$/i.test(req.body.id || '') ? req.body.id : '';
    const existing = await listPresets();
    if (existing.some(p => p.name.toLowerCase() === name.toLowerCase() && p.id !== id)) return res.status(400).json({ error: `A config called "${name}" already exists.` });
    const packed = Buffer.from(JSON.stringify(va.agents.map(a => [a.number, a.name, a.capacity, a.sendDigits]))).toString('base64url');
    const form = { FriendlyName: PRESET_PREFIX + name, VoiceUrl: `${publicBase(req)}/voice/config?c=${packed}`, VoiceMethod: 'POST' };
    const app_ = await twilio(id ? `${BASE}/Applications/${id}.json` : `${BASE}/Applications.json`, { form });
    presetCache.at = 0;
    const presetId = app_.sid || id;

    // Numbers that follow this config get its destination list. Lines and pause keep their
    // current value where the seller is already in use; new sellers start with the config's lines.
    const updated = [];
    if (id && req.body.applyToNumbers !== false) {
      const nums = await routedNumbers();
      const current = new Map();
      for (const n of nums) for (const a of n.cfg.agents) current.set(digits(a.number), a);
      const all = (await twilio(`${BASE}/IncomingPhoneNumbers.json?PageSize=100`)).incoming_phone_numbers || [];
      for (const n of all) {
        const cfg = cfgFromUrl(n.voice_url);
        if (!cfg || cfg.preset !== id) continue;
        if (va.agents.some(a => digits(a.number) === digits(n.phone_number))) continue; // never forward a line to itself
        cfg.agents = va.agents.map(a => {
          const cur = current.get(digits(a.number));
          return { number: a.number, name: a.name, sendDigits: a.sendDigits,
            active: cur ? cur.active : true, capacity: cur ? cur.capacity : a.capacity };
        });
        await saveNumberCfg(n, cfg);
        updated.push(n.phone_number);
      }
      routedCache.at = 0;
    }
    // Names and extensions follow the config on every number; lines and pause are left as they are.
    const synced = await syncDestinations(va.agents.map(a => ({ number: a.number, name: a.name, sendDigits: a.sendDigits })), null)
      .catch(e => { console.error('Config sync:', e.message); return []; });
    res.json({ ok: true, id: presetId, updated, synced });
  } catch (e) { console.error(e); res.status(502).json({ error: e.message }); }
});

app.post('/api/presets/:id/delete', requireAuth, async (req, res) => {
  const id = req.params.id;
  if (!/^AP[0-9a-f]{32}$/i.test(id)) return res.status(400).json({ error: 'Unknown config.' });
  try {
    const p = (await listPresets()).find(x => x.id === id);
    if (!p) return res.status(404).json({ error: 'Config not found.' });
    await twilio(`${BASE}/Applications/${id}.json`, { method: 'DELETE' });
    presetCache.at = 0;
    const all = (await twilio(`${BASE}/IncomingPhoneNumbers.json?PageSize=100`)).incoming_phone_numbers || [];
    for (const n of all) {
      const cfg = cfgFromUrl(n.voice_url);
      if (cfg && cfg.preset === id) { cfg.preset = ''; await saveNumberCfg(n, cfg); }
    }
    routedCache.at = 0;
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(502).json({ error: e.message }); }
});

app.get('/', (req, res) => res.json({ ok: true, service: 'twilio-dashboard-backend' }));

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Listening on ${port}`));
