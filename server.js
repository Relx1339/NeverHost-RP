const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DB } = require('./db');

const ROOT = __dirname;
const PORT = process.env.PORT || 8080;
const PROXY_BASE = 'https://www.mtrp.gg';
const db = new DB();

function ensureAdmin() {
  const envEmail = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
  let promoted = null;
  if (envEmail) {
    const u = db.col('users').find((x) => String(x.email || '').toLowerCase() === envEmail);
    if (u) { u.role = 'admin'; u.whitelisted = true; promoted = u; }
  }
  if (!promoted && !db.col('users').some((x) => x.role === 'admin')) {
    const admin = {
      uid: db.nextUid(),
      username: 'admin',
      displayName: 'Admin',
      email: 'admin@mtrp.local',
      emailVerified: true,
      passwordHash: hashPass('admin123'),
      role: 'admin',
      whitelisted: true,
      createdAt: new Date().toISOString(),
    };
    db.addUser(admin);
    promoted = admin;
  }
  if (promoted) db.save();
}
ensureAdmin();

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.svg': 'image/svg+xml',
  '.gif': 'image/gif',
  '.avif': 'image/avif',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.mp4': 'video/mp4',
  '.mp3': 'audio/mpeg',
};

function json(res, code, obj) {
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-cache' });
  res.end(JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      try { resolve(JSON.parse(data)); } catch { resolve({}); }
    });
  });
}

function bearer(req) {
  const h = req.headers['authorization'] || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  return m ? m[1] : null;
}

function sendJSON(res, code, obj) {
  json(res, code, obj);
}

function proxy(req, res, fullUrl) {
  const upstream = new URL(PROXY_BASE + fullUrl);
  const headers = {
    'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0',
    'Accept': req.headers['accept'] || '*/*',
  };
  if (req.headers['authorization']) headers['Authorization'] = req.headers['authorization'];
  if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type'];
  if (req.headers['accept-language']) headers['Accept-Language'] = req.headers['accept-language'];
  const preq = https.request(upstream, { method: req.method, headers }, (pres) => {
    res.writeHead(pres.statusCode, pres.headers);
    pres.pipe(res);
  });
  preq.on('error', () => { json(res, 502, { error: 'proxy unavailable' }); });
  req.pipe(preq);
}

function publicUser(u) {
  return {
    uid: u.uid,
    username: u.username,
    displayName: u.displayName || u.username,
    email: u.email,
    role: u.role || 'user',
    whitelisted: !!u.whitelisted,
    discordId: u.discordId || null,
    steamId: u.steamId || null,
    onboardingStep: u.onboardingStep ?? 0,
    createdAt: u.createdAt,
  };
}

function b64url(s) {
  return Buffer.from(s).toString('base64url');
}

function makeJwt(claims) {
  const header = { alg: 'none', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: 'https://securetoken.google.com/local-mtrp',
    aud: 'local-mtrp',
    auth_time: now,
    user_id: claims.uid,
    sub: claims.uid,
    iat: now,
    exp: now + 3600,
    email: claims.email,
    email_verified: !!claims.emailVerified,
    firebase: { identities: {}, sign_in_provider: claims.provider || 'password' },
    uid: claims.uid,
  };
  return b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload)) + '.';
}

function hashPass(p) {
  return crypto.createHash('sha256').update(String(p)).digest('hex');
}

function issueSession(user) {
  const idToken = makeJwt({ uid: user.uid, email: user.email, emailVerified: user.emailVerified });
  const refreshToken = crypto.randomBytes(32).toString('hex');
  db.data.sessions.push({ token: idToken, refreshToken, uid: user.uid, createdAt: Date.now() });
  db.save();
  return { idToken, refreshToken, localId: user.uid, expiresIn: '3600', email: user.email };
}

function findUserByEmail(email) {
  return db.col('users').find((u) => String(u.email || '').toLowerCase() === String(email || '').toLowerCase());
}

async function handleFbAuth(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  const body = await readBody(req);
  const respond = (code, obj) => json(res, code, obj);

  if (p === '/__fbauth/v1/accounts:signInWithPassword') {
    const user = findUserByEmail(body.email);
    if (!user || !user.passwordHash) return respond(400, { error: { code: 400, message: 'EMAIL_NOT_FOUND' } });
    if (hashPass(body.password) !== user.passwordHash) return respond(400, { error: { code: 400, message: 'INVALID_PASSWORD' } });
    return respond(200, issueSession(user));
  }

  if (p === '/__fbauth/v1/accounts:signUp') {
    const email = String(body.email || '').trim();
    if (!email || !body.password) return respond(400, { error: { code: 400, message: 'MISSING_EMAIL' } });
    if (findUserByEmail(email)) return respond(400, { error: { code: 400, message: 'EMAIL_EXISTS' } });
    const user = {
      uid: db.nextUid(),
      username: email.split('@')[0],
      displayName: body.displayName || email.split('@')[0],
      email,
      emailVerified: true,
      passwordHash: hashPass(body.password),
      role: 'user',
      whitelisted: false,
      createdAt: new Date().toISOString(),
    };
    db.addUser(user);
    return respond(200, issueSession(user));
  }

  if (p === '/__fbauth/v1/accounts:signInWithCustomToken') {
    const tok = body.token || body.tok;
    const session = db.col('sessions').find((s) => s.token === tok || s.refreshToken === tok);
    if (!session) return respond(401, { error: { code: 401, message: 'INVALID_CUSTOM_TOKEN' } });
    const user = db.findByUid(session.uid);
    if (!user) return respond(401, { error: { code: 401, message: 'USER_NOT_FOUND' } });
    return respond(200, issueSession(user));
  }

  if (p === '/__fbauth/v1/token') {
    const session = db.col('sessions').find((s) => s.refreshToken === body.refresh_token);
    if (!session) return respond(400, { error: { code: 400, message: 'INVALID_REFRESH_TOKEN' } });
    const user = db.findByUid(session.uid);
    if (!user) return respond(400, { error: { code: 400, message: 'USER_NOT_FOUND' } });
    const s = issueSession(user);
    return respond(200, {
      id_token: s.idToken,
      refresh_token: s.refreshToken,
      expires_in: '3600',
      user_id: s.localId,
      project_id: 'local-mtrp',
    });
  }

  if (p === '/__fbauth/v1/accounts:lookup') {
    const session = db.col('sessions').find((s) => s.token === body.idToken);
    const user = session && db.findByUid(session.uid);
    if (!user) return respond(400, { error: { code: 400, message: 'USER_NOT_FOUND' } });
    return respond(200, {
      users: [{
        localId: user.uid,
        email: user.email,
        displayName: user.displayName,
        emailVerified: true,
        createdAt: new Date(user.createdAt).getTime() || Date.now(),
        lastLoginAt: Date.now(),
      }],
    });
  }

  return respond(404, { error: { code: 404, message: 'NOT_IMPLEMENTED' } });
}

async function handleApi(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  const q = url.searchParams;
  const method = req.method;
  const token = bearer(req);

  // ---------------- AUTH ----------------
  if (p === '/api/auth/me') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    if (method === 'PATCH') {
      const body = await readBody(req);
      if (typeof body.onboardingStep === 'number') user.onboardingStep = body.onboardingStep;
      if (body.discordId) user.discordId = body.discordId;
      if (body.steamId) user.steamId = body.steamId;
      if (body.displayName) user.displayName = body.displayName;
      db.save();
    }
    return json(res, 200, { user: publicUser(user) });
  }

  if (p === '/api/auth/register' && method === 'POST') {
    const body = await readBody(req);
    const email = String(body.email || '').trim();
    const username = String(body.displayName || body.username || email.split('@')[0] || '').trim();
    if (!email && !username) return json(res, 400, { error: 'email or username required' });
    if (findUserByEmail(email)) return json(res, 409, { error: 'email already registered' });
    const user = {
      uid: db.nextUid(),
      username,
      displayName: username,
      email: email || null,
      emailVerified: !!email,
      passwordHash: body.password ? hashPass(body.password) : null,
      role: 'user',
      whitelisted: false,
      createdAt: new Date().toISOString(),
    };
    db.addUser(user);
    return json(res, 200, { user: publicUser(user) });
  }

  if (p === '/api/auth/login' && method === 'POST') {
    const body = await readBody(req);
    const user = findUserByEmail(body.email || '') || db.findByUsername(body.username || '');
    const hash = user && body.password ? hashPass(body.password) : null;
    if (!user || hash !== user.passwordHash) return json(res, 401, { error: 'invalid credentials' });
    const sess = crypto.randomBytes(24).toString('hex');
    db.createSession(sess, user.uid);
    return json(res, 200, { user: publicUser(user), token: sess });
  }

  if (p.startsWith('/api/auth/') && p.endsWith('/link') && method === 'GET') {
    const provider = p.split('/')[3];
    const tok = q.get('token');
    const session = tok ? db.col('sessions').find((s) => s.token === tok) : null;
    const user = session ? db.findByUid(session.uid) : null;
    const customToken = user
      ? makeJwt({ uid: user.uid, email: user.email, provider: provider })
      : null;
    if (user) {
      db.data.sessions.push({ token: customToken, refreshToken: crypto.randomBytes(32).toString('hex'), uid: user.uid, linkedProvider: provider, createdAt: Date.now() });
      db.save();
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(
      '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
      '<title>Discord link - MTRP (local)</title></head><body style="background:#09090b;color:#e4e4e7;font-family:Inter,Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">' +
      '<div style="text-align:center;max-width:420px;padding:32px;border:1px solid #27272a;border-radius:12px">' +
      '<div style="font-size:48px;margin-bottom:12px">🎮</div>' +
      (user
        ? '<h2 style="margin:0 0 8px">Connected to Discord (simulated)</h2>' +
          '<p style="color:#a1a1aa">Account <b>' + user.displayName + '</b> linked with <b>' + provider + '</b>.</p>' +
          '<p style="color:#71717a;font-size:12px">Local backend only - no real Discord OAuth.</p>'
        : '<h2 style="margin:0 0 8px">Link failed</h2><p style="color:#a1a1aa">Session token invalid or expired. Please sign in again.</p>') +
      '<a href="/" style="display:inline-block;margin-top:16px;padding:10px 24px;background:#5865f2;color:#fff;border-radius:8px;text-decoration:none">Back to site</a>' +
      '</div></body></html>'
    );
    return;
  }

  // ---------------- PUBLIC CONTENT ----------------
  if (p === '/api/localizations') return json(res, 200, db.col('localizations'));

  if (p === '/api/stats') {
    db.data.visitCounter++;
    const s = db.col('stats');
    s.players = Math.floor(Math.random() * 300) + 100;
    s.discordOnline = Math.floor(s.discordMembers * (0.05 + Math.random() * 0.08));
    return json(res, 200, s);
  }

  if (p === '/api/servers') {
    const lang = (req.headers['accept-language'] || 'en').split(',')[0].slice(0, 2);
    const out = db.col('servers').map((s) => {
      const t = (s.translations || {})[lang] || {};
      return {
        ...s,
        name: t.name || s.name,
        description: t.description || s.description,
        translations: undefined,
      };
    });
    return json(res, 200, out);
  }

  if (p === '/api/events') {
    let items = db.col('events').slice();
    const tag = q.get('tag');
    if (tag && tag !== '') items = items.filter((e) => e.tag === tag);
    const page = Math.max(1, parseInt(q.get('page') || '1', 10));
    const limit = Math.max(1, parseInt(q.get('limit') || '12', 10));
    const total = items.length;
    const start = (page - 1) * limit;
    return json(res, 200, { events: items.slice(start, start + limit), total });
  }

  if (p === '/api/partners') return json(res, 200, db.col('partners'));
  if (p === '/api/team') return json(res, 200, db.col('team'));
  if (p === '/api/faq') return json(res, 200, db.col('faq'));
  if (p === '/api/gallery') return json(res, 200, db.col('gallery'));
  if (p === '/api/roster') return json(res, 200, db.col('roster'));
  if (p === '/api/careers') return json(res, 200, db.col('careers'));
  if (p === '/api/stream-stats') return json(res, 200, db.col('streamStats'));

  if (p === '/api/live-streams') {
    const list = db.col('liveStreams');
    return json(res, 200, list.map((s) => ({
      ...s,
      isLive: s.isLive && Math.random() > 0.3,
    })));
  }

  if (p === '/api/leaderboard') {
    const lb = db.col('leaderboard');
    const period = q.get('period') || 'all';
    if (!lb.snapshot) {
      const names = ['AlphaOne', 'NightWolf', 'Shadow_MT', 'KingSlayer', 'DriftKing', 'GhostRider', 'XxViperxX', 'SniperPro', 'MysticSam', 'TurboGG'];
      lb.snapshot = {
        lastRefreshed: new Date().toISOString(),
        entries: Array.from({ length: 50 }, (_, i) => ({
          rank: i + 1,
          username: names[i % names.length] + (i >= names.length ? i + 1 : ''),
          displayName: names[i % names.length] + (i >= names.length ? i + 1 : ''),
          points: Math.max(0, 5000 - i * 87 + ((i * 37) % 50)),
          playtimeMinutes: Math.max(60, 48000 - i * 733),
        })),
      };
      db.save();
    }
    return json(res, 200, { ...lb, requestedPeriod: period });
  }

  if (p === '/api/game-ranks') return json(res, 200, db.col('gameRanks'));

  // ---------------- CAREERS ----------------
  if (p.startsWith('/api/careers/') && p.endsWith('/apply') && method === 'POST') {
    const body = await readBody(req);
    db.data.careerApplications = db.data.careerApplications || [];
    db.data.careerApplications.push({ ...body, createdAt: new Date().toISOString() });
    db.save();
    return json(res, 200, { ok: true });
  }
  if (p.startsWith('/api/careers/') && method === 'GET') {
    const id = p.split('/')[3];
    const c = db.col('careers').find((x) => x.id === id);
    return c ? json(res, 200, c) : json(res, 404, { error: 'career not found' });
  }

  // ---------------- WHITELIST ----------------
  if (p === '/api/whitelist/forms') {
    const server = db.col('servers')[0];
    return json(res, 200, [{
      id: 'wl_' + server.id,
      serverId: server.id,
      title: server.name,
      enabled: true,
      fields: [
        { key: 'steamHex', label: 'Steam Hex / Identifier', type: 'text', required: true },
        { key: 'discordTag', label: 'Discord Tag', type: 'text', required: true },
        { key: 'age', label: 'Age', type: 'number', required: true },
        { key: 'rpExperience', label: 'Roleplay Experience', type: 'textarea', required: false },
        { key: 'whyJoin', label: 'Why do you want to join?', type: 'textarea', required: true },
      ],
    }]);
  }

  if (p === '/api/whitelist/apply' && method === 'POST') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    const body = await readBody(req);
    const app = {
      id: 'app_' + Math.random().toString(36).slice(2, 10),
      uid: user.uid,
      serverId: body.serverId || db.col('servers')[0].id,
      status: 'pending',
      data: body,
      createdAt: new Date().toISOString(),
    };
    db.data.whitelistApplications.push(app);
    db.save();
    return json(res, 200, app);
  }

  if (p === '/api/whitelist/my-application' || p === '/api/whitelist/my-applications') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    const apps = db.col('whitelistApplications').filter((a) => a.uid === user.uid);
    return json(res, 200, p.includes('my-applications') ? apps : apps[0] || null);
  }

  // ---------------- PROFILE / GAMES ----------------
  if (p === '/api/profile/games') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    return json(res, 200, db.col('servers').map((s) => ({
      serverId: s.id,
      serverName: s.name,
      serverType: s.type,
      isWhitelisted: user.whitelisted && user.joinedServerId === s.id,
      connected: user.joinedServerId === s.id,
      playtimeMinutes: user.joinedServerId === s.id ? Math.floor(Math.random() * 8000) + 120 : 0,
    })));
  }

  if (p === '/api/servers/join' && method === 'POST') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    const body = await readBody(req);
    user.joinedServerId = body.serverId || null;
    db.save();
    return json(res, 200, { ok: true });
  }

  // ---------------- REWARDS ----------------
  if (p === '/api/rewards/available') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    const lb = db.col('leaderboard');
    const tiers = (lb.config && lb.config.tiers) || [];
    const rank = Math.floor(Math.random() * 5) + 1;
    return json(res, 200, tiers.map((t) => {
      const inRange = rank >= t.minRank && rank <= t.maxRank;
      return {
        ...t,
        available: inRange,
        claimed: false,
        reason: inRange ? 'rank' : 'locked',
      };
    }));
  }

  if (p === '/api/rewards/claims') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    db.data.claims = db.data.claims || {};
    return json(res, 200, db.data.claims[user.uid] || []);
  }

  if (p === '/api/rewards/count') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    db.data.claims = db.data.claims || {};
    const claims = db.data.claims[user.uid] || [];
    return json(res, 200, { available: Math.max(0, 3 - claims.length), claimed: claims.length });
  }

  if (p === '/api/rewards/claim' && method === 'POST') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    const body = await readBody(req);
    db.data.claims = db.data.claims || {};
    db.data.claims[user.uid] = db.data.claims[user.uid] || [];
    const claim = {
      id: 'clm_' + Math.random().toString(36).slice(2, 10),
      rankId: body.rankId,
      rewardId: body.rewardId,
      type: 'rank',
      status: 'granted',
      claimedAt: new Date().toISOString(),
    };
    db.data.claims[user.uid].push(claim);
    db.save();
    return json(res, 200, claim);
  }

  if (p.startsWith('/api/rewards/claim-granted/') && method === 'POST') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    const id = p.split('/')[4];
    db.data.claims = db.data.claims || {};
    db.data.claims[user.uid] = db.data.claims[user.uid] || [];
    const claim = {
      id: 'clm_' + Math.random().toString(36).slice(2, 10),
      grantId: id,
      type: 'gift',
      status: 'granted',
      claimedAt: new Date().toISOString(),
    };
    db.data.claims[user.uid].push(claim);
    db.save();
    return json(res, 200, claim);
  }

  // ---------------- TICKETS ----------------
  if (p === '/api/tickets' && method === 'GET') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    return json(res, 200, db.col('tickets').filter((t) => t.uid === user.uid));
  }

  if (p === '/api/tickets' && method === 'POST') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    const body = await readBody(req);
    const ticket = {
      id: 'tkt_' + Math.random().toString(36).slice(2, 10),
      uid: user.uid,
      subject: body.subject || 'General support',
      category: body.category || 'general',
      status: 'open',
      createdAt: new Date().toISOString(),
    };
    db.data.tickets.push(ticket);
    db.save();
    return json(res, 200, ticket);
  }

  if (p.startsWith('/api/tickets/') && p.endsWith('/messages')) {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    const id = p.split('/')[3];
    if (method === 'POST') {
      const body = await readBody(req);
      db.data.ticketMessages = db.data.ticketMessages || {};
      db.data.ticketMessages[id] = db.data.ticketMessages[id] || [];
      const msg = {
        id: 'msg_' + Math.random().toString(36).slice(2, 10),
        from: user.uid,
        fromName: user.displayName,
        content: body.content || '',
        createdAt: new Date().toISOString(),
      };
      db.data.ticketMessages[id].push(msg);
      db.save();
      return json(res, 200, msg);
    }
    db.data.ticketMessages = db.data.ticketMessages || {};
    return json(res, 200, db.data.ticketMessages[id] || []);
  }

  // ---------------- VACATIONS ----------------
  if (p === '/api/vacations/my') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    db.data.vacations = db.data.vacations || [];
    return json(res, 200, db.data.vacations.filter((v) => v.uid === user.uid));
  }

  if (p === '/api/vacations' && method === 'POST') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    const body = await readBody(req);
    db.data.vacations = db.data.vacations || [];
    const v = {
      id: 'vac_' + Math.random().toString(36).slice(2, 10),
      uid: user.uid,
      startDate: body.startDate,
      endDate: body.endDate,
      reason: body.reason,
      status: 'pending',
      createdAt: new Date().toISOString(),
    };
    db.data.vacations.push(v);
    db.save();
    return json(res, 200, v);
  }

  // ---------------- STORE DROP ----------------
  if (p === '/api/site-settings/store-drop') {
    return json(res, 200, {
      enabled: false,
      dropAt: null,
      serverId: null,
      storeUrl: db.col('servers')[0] ? db.col('servers')[0].storeUrl : null,
    });
  }

  // ---------------- KICK CHANNEL ----------------
  if (p.startsWith('/api/kick/channel/')) {
    const channel = p.split('/')[4];
    const roster = db.col('roster').find((r) => r.kickUrl && r.kickUrl.includes(channel));
    const live = Math.random() > 0.6;
    return json(res, 200, {
      username: channel,
      displayName: roster ? roster.name : channel,
      isLive: live,
      viewerCount: live ? Math.floor(Math.random() * 500) + 20 : 0,
      avatarUrl: roster ? roster.image : null,
      title: live ? 'Live on Kick' : null,
    });
  }

  // ---------------- SITE SETTINGS ----------------
  if (p.startsWith('/api/site-settings/')) {
    const key = p.split('/').pop();
    const map = {
      hero: 'hero',
      social: 'social',
      countdown: 'countdown',
      'doom-timer': 'doomTimer',
      'end-session': 'endSession',
      season8: 'season8',
    };
    const data = db.col('siteSettings')[map[key]];
    if (data !== undefined) return json(res, 200, data);
  }

  if (p === '/api/site-settings/features') {
    return json(res, 200, {
      enabled: true,
      features: ['onboarding', 'whitelist', 'leaderboard', 'rewards', 'queue', 'store', 'discord', 'streams', 'gallery', 'events', 'tickets'],
    });
  }

  // ---------------- USER / WHITELIST / QUEUE ----------------
  if (p === '/api/whitelist/check-ready' || p.startsWith('/api/whitelist/check-ready/')) {
    const user = token ? db.sessionUser(token) : null;
    const server = db.col('servers')[0];
    return json(res, 200, {
      ready: !!user,
      message: user ? 'You are eligible' : 'Sign in to check eligibility',
      storeUrl: server ? server.storeUrl : 'https://mtrp.store',
    });
  }

  if (p === '/api/me/queue-status') {
    const user = token ? db.sessionUser(token) : null;
    const serverId = q.get('serverId');
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    const server = db.col('servers').find((s) => s.id === serverId);
    return json(res, 200, {
      serverId,
      serverName: server ? server.name : 'Unknown',
      inQueue: user.whitelisted,
      position: user.whitelisted ? Math.floor(Math.random() * 200) + 1 : null,
      whitelisted: user.whitelisted,
    });
  }

  if (p === '/api/me/server-access') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    return json(res, 200, {
      access: user.whitelisted ? 'granted' : 'denied',
      whitelisted: user.whitelisted,
      connectUrl: user.whitelisted ? db.col('servers')[0].connectUrl : null,
    });
  }

  // ---------------- AUTH: LEGACY / SOCIAL ----------------
  if (p === '/api/auth/check-legacy') {
    return json(res, 200, { exists: false, legacyUsers: [] });
  }

  if ((p === '/api/auth/discord/login' || p === '/api/auth/steam/login') && method === 'GET') {
    const provider = p.split('/')[3];
    const user = token ? db.sessionUser(token) : null;
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(
      '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
      '<title>' + provider[0].toUpperCase() + provider.slice(1) + ' - MTRP (local)</title></head>' +
      '<body style="background:#09090b;color:#e4e4e7;font-family:Inter,Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">' +
      '<div style="text-align:center;max-width:420px;padding:32px;border:1px solid #27272a;border-radius:12px">' +
      '<div style="font-size:48px;margin-bottom:12px">🎮</div>' +
      '<h2 style="margin:0 0 8px">' + provider + ' login (simulated)</h2>' +
      '<p style="color:#a1a1aa">Local backend only - no real ' + provider + ' OAuth.</p>' +
      '<p style="color:#71717a;font-size:12px">Redirecting back to the site...</p>' +
      '</div><script>setTimeout(()=>{window.location.href="/";},1200)</script></body></html>'
    );
    return;
  }

  // ---------------- PUBLIC / MISC ----------------
  if (p === '/api/detect-language') {
    const lang = (req.headers['accept-language'] || 'en').split(',')[0].slice(0, 2);
    return json(res, 200, { language: ['ar', 'en'].includes(lang) ? lang : 'en' });
  }

  if (p === '/api/game-data') {
    return json(res, 200, {
      servers: db.col('servers'),
      version: 's8',
      totalPlayers: Math.floor(Math.random() * 300) + 100,
      totalWhitelisted: Math.floor(Math.random() * 8000) + 3000,
      gameRanks: db.col('gameRanks'),
    });
  }

  if (p === '/api/kick/roster-check' || p === '/api/kick/roster-check-live') {
    return json(res, 200, {
      checkedAt: new Date().toISOString(),
      matches: db.col('roster').map((r) => ({ id: r.id, name: r.name, kickUrl: r.kickUrl || null })),
      live: db.col('roster').filter((r) => r.isLive || Math.random() > 0.7).map((r) => ({ id: r.id, name: r.name, kickUrl: r.kickUrl || null })),
    });
  }

  if (p === '/api/kick-channels') {
    return json(res, 200, db.col('roster')
      .filter((r) => r.kickUrl)
      .map((r, i) => ({
        id: r.id || 'kch_' + i,
        name: r.name,
        handle: (r.kickUrl.split('/').filter(Boolean).pop() || '').replace(/^@/, ''),
        avatarUrl: r.image || null,
        isLive: Math.random() > 0.6,
        viewerCount: Math.floor(Math.random() * 400) + 10,
      })));
  }

  if (p === '/api/me/queue-join' && method === 'POST') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated', code: 'unauthenticated' });
    const body = await readBody(req);
    if (!user.whitelisted) return json(res, 403, { error: 'not whitelisted', code: 'needs_tier' });
    user.inQueue = true;
    user.joinedServerId = body.serverId || user.joinedServerId;
    db.save();
    return json(res, 200, { ok: true, position: Math.floor(Math.random() * 200) + 1, serverId: body.serverId });
  }

  // ---------------- MY PERMISSIONS ----------------
  if (p === '/api/my-permissions') {
    const user = token ? db.sessionUser(token) : null;
    if (!user) return json(res, 401, { error: 'unauthenticated' });
    const isAdmin = user.role === 'admin';
    return json(res, 200, {
      role: user.role,
      isAdmin,
      allowedTabs: [],
      allowedServerIds: isAdmin ? db.col('servers').map((s) => s.id) : [],
      allowedActions: isAdmin ? { 'team:manage': true, 'events:manage': true, 'users:manage': true, 'settings:manage': true } : {},
    });
  }

  // ---------------- ADMIN PANEL ----------------
  if (p.startsWith('/api/admin/')) {
    const user = token ? db.sessionUser(token) : null;
    const isStaff = !!user && (user.role === 'admin' || user.role === 'moderator');
    const isAdmin = !!user && user.role === 'admin';
    const deny = (code) => json(res, code, { error: 'forbidden', code: code === 401 ? 'unauthenticated' : 'insufficient_permissions' });

    if (p === '/api/admin/verify') {
      if (!user) return deny(401);
      return json(res, 200, { verified: isStaff, role: user.role, uid: user.uid });
    }
    if (!isStaff) return deny(401);

    const colArr = (key) => {
      if (!db.data[key]) db.data[key] = [];
      return db.data[key];
    };

    if (p === '/api/my-permissions' || p === '/api/admin/permission-groups/user-counts') {
      return json(res, 200, {
        permissionGroups: colArr('permissionGroups').map((g) => ({
          ...g,
          userCount: db.col('users').filter((u) => u.role === g.role || (u.permissionGroup === g.id)).length,
        })),
      });
    }

    if (p === '/api/admin/users/lookup') {
      const email = (q.get('email') || '').toLowerCase();
      const user = db.col('users').find((u) => String(u.email || '').toLowerCase() === email) || null;
      return json(res, 200, user ? { ...publicUser(user) } : null);
    }

    if (p === '/api/admin/users/bulk-action' && method === 'POST') {
      const body = await readBody(req);
      const ids = body.userIds || [];
      ids.forEach((id) => {
        const u = db.findByUid(id);
        if (!u) return;
        if (body.action === 'set-role') u.role = body.value;
        if (body.action === 'whitelist') u.whitelisted = !!body.value;
        if (body.action === 'delete') db.data.users = db.data.users.filter((x) => x.uid !== id);
      });
      db.save();
      return json(res, 200, { ok: true, updated: ids.length });
    }

    if (p === '/api/admin/users') {
      const role = q.get('role');
      const page = Math.max(1, parseInt(q.get('page') || '1', 10));
      const limit = Math.max(1, parseInt(q.get('limit') || '100', 10));
      let list = db.col('users').slice().map((u) => ({ ...publicUser(u), whitelisted: !!u.whitelisted, lastLoginAt: u.lastLoginAt || null }));
      if (role && role !== 'all') list = list.filter((u) => u.role === role);
      const total = list.length;
      const start = (page - 1) * limit;
      return json(res, 200, { users: list.slice(start, start + limit), total, page, limit });
    }

    // Generic CRUD on collections
    const simple = {
      '/api/admin/team': 'team',
      '/api/admin/roster': 'roster',
      '/api/admin/faq': 'faq',
      '/api/admin/careers': 'careers',
      '/api/admin/servers': 'servers',
      '/api/admin/events': 'events',
      '/api/admin/partners': 'partners',
      '/api/admin/game-ranks': 'gameRanks',
      '/api/admin/localizations': 'localizations',
      '/api/admin/season8-localizations': 'localizations',
      '/api/admin/blocked-keywords': 'blockedKeywords',
      '/api/admin/keyword-blocked-streams': 'keywordBlockedStreams',
      '/api/admin/kick-channels': 'kickChannels',
      '/api/admin/stream-snapshots': 'streamSnapshots',
      '/api/admin/stream-stats': 'streamStats',
      '/api/admin/discord-servers': 'discordServers',
      '/api/admin/whitelist': 'whitelistApplications',
      '/api/admin/vacations': 'vacations',
      '/api/admin/ticket-assignments': 'ticketAssignments',
    };

    if (simple[p] && method === 'GET') {
      const items = colArr(simple[p]);
      return json(res, 200, items);
    }
    if (simple[p] && method === 'POST') {
      const body = await readBody(req);
      const arr = colArr(simple[p]);
      const item = { ...body, id: body.id || (simple[p] + '_' + Math.random().toString(36).slice(2, 8)), createdAt: new Date().toISOString() };
      arr.push(item);
      db.save();
      return json(res, 200, item);
    }
    if (simple[p] && method === 'PUT') {
      const body = await readBody(req);
      const arr = colArr(simple[p]);
      const idx = arr.findIndex((x) => x.id === body.id);
      if (idx >= 0) arr[idx] = { ...arr[idx], ...body };
      db.save();
      return json(res, 200, { ok: true });
    }
    if (simple[p] && method === 'DELETE') {
      const id = q.get('id');
      db.data[simple[p]] = colArr(simple[p]).filter((x) => x.id !== id);
      db.save();
      return json(res, 200, { ok: true });
    }

    if (p === '/api/admin/upload' && method === 'POST') {
      const body = await readBody(req);
      return json(res, 200, {
        url: body.url || 'https://storage.googleapis.com/mtrp-local/uploads/' + Math.random().toString(36).slice(2, 10),
        path: 'uploads/' + Math.random().toString(36).slice(2, 10),
      });
    }

    if (p === '/api/admin/tickets/stats') {
      const tickets = colArr('tickets');
      return json(res, 200, {
        total: tickets.length,
        open: tickets.filter((t) => t.status === 'open').length,
        pending: tickets.filter((t) => t.status === 'pending').length,
        closed: tickets.filter((t) => t.status === 'closed').length,
        assigned: tickets.filter((t) => t.assignedTo).length,
        unassigned: tickets.filter((t) => !t.assignedTo).length,
      });
    }

    if (p === '/api/admin/tickets' && method === 'GET') {
      return json(res, 200, colArr('tickets'));
    }

    if (p === '/api/admin/leaderboard/config') {
      const lb = db.col('leaderboard');
      if (method === 'PUT') {
        const body = await readBody(req);
        lb.config = body;
        db.save();
      }
      return json(res, 200, lb.config || { periodType: 'monthly', tiers: [], streakConfig: {} });
    }

    if (p === '/api/admin/leaderboard/refresh' && method === 'POST') {
      delete db.data.leaderboard.snapshot;
      db.save();
      return json(res, 200, { ok: true, refreshedAt: new Date().toISOString() });
    }

    if ((p === '/api/admin/leaderboard/distribute-rewards' || p === '/api/admin/leaderboard/distribute-streak-reward') && method === 'POST') {
      const body = await readBody(req);
      db.data.claims = db.data.claims || {};
      const winners = db.col('users').filter((u) => u.whitelisted).slice(0, 3);
      winners.forEach((w) => {
        db.data.claims[w.uid] = db.data.claims[w.uid] || [];
        db.data.claims[w.uid].push({
          id: 'clm_' + Math.random().toString(36).slice(2, 10),
          type: body.type || 'rank',
          status: 'granted',
          claimedAt: new Date().toISOString(),
          note: 'distributed by admin',
        });
      });
      db.save();
      return json(res, 200, { ok: true, granted: winners.length });
    }

    if (p === '/api/admin/site-settings') {
      if (method === 'PUT') {
        const body = await readBody(req);
        db.data.siteSettings = { ...(db.data.siteSettings || {}), ...body };
        db.save();
      }
      return json(res, 200, db.data.siteSettings);
    }

    if (p === '/api/admin/backups' && method === 'GET') {
      return json(res, 200, [{ id: 'local_1', createdAt: new Date().toISOString(), sizeBytes: JSON.stringify(db.data).length, label: 'Automatic local backup' }]);
    }

    if (p === '/api/admin/backups/restore' && method === 'POST') {
      const body = await readBody(req);
      const src = body.file || body.id;
      if (src === 'local_1') {
        db.data = { ...db.seed(), ...db.data };
        db.save();
        return json(res, 200, { ok: true });
      }
      return json(res, 400, { error: 'backup not found' });
    }

    if (p === '/api/admin/migrate-legacy-users' && method === 'POST') {
      return json(res, 200, { ok: true, migrated: 0, message: 'No legacy users found (local replica)' });
    }

    if (p === '/api/admin/permission-groups') {
      if (method === 'POST') {
        const body = await readBody(req);
        colArr('permissionGroups').push({ ...body, id: body.id || 'grp_' + Math.random().toString(36).slice(2, 8) });
        db.save();
      }
      return json(res, 200, colArr('permissionGroups'));
    }

    if (p === '/api/admin/priority-roster' || p === '/api/admin/queue-priority/add') {
      if (method === 'POST') {
        const body = await readBody(req);
        colArr('priorityRoster').push({ ...body, id: body.id || 'pr_' + Math.random().toString(36).slice(2, 8) });
        db.save();
      }
      return json(res, 200, colArr('priorityRoster'));
    }

    if (p === '/api/admin/stream-dashboard' || p === '/api/admin/streamers/status') {
      return json(res, 200, {
        streams: db.col('roster').map((r) => ({
          id: r.id,
          name: r.name,
          kickUrl: r.kickUrl || null,
          isLive: Math.random() > 0.6,
          viewerCount: Math.floor(Math.random() * 500) + 10,
        })),
      });
    }

    if (p === '/api/admin/streamers/resync' && method === 'POST') {
      return json(res, 200, { ok: true, resynced: db.col('roster').length });
    }

    if (p === '/api/admin/verify' || p === '/api/admin/analytics') {
      return json(res, 200, { verified: isStaff, role: user.role, uid: user.uid });
    }

    if (p.startsWith('/api/admin/app-analytics/') || p === '/api/admin/game-analytics' || p === '/api/admin/services/analytics' || p === '/api/admin/stats/entries' || p === '/api/admin/stats/points') {
      const days = 30;
      const labels = Array.from({ length: days }, (_, i) => new Date(Date.now() - (days - 1 - i) * 864e5).toISOString().slice(0, 10));
      const series = (base, noise) => labels.map((d, i) => Math.max(0, Math.round(base + Math.sin(i / 3) * noise + Math.random() * noise)));
      return json(res, 200, {
        labels,
        series: {
          registrations: series(40, 30),
          activeUsers: series(200, 80),
          queueJoins: series(120, 50),
          whitelistApps: series(15, 10),
          players: series(180, 60),
        },
        totals: { registrations: db.col('users').length, whitelistApps: db.col('whitelistApplications').length, tickets: colArr('tickets').length },
      });
    }

    if (p === '/api/admin/admin-action-logs' || p === '/api/admin/game-api-logs' || p === '/api/admin/kick-api-logs') {
      return json(res, 200, {
        logs: Array.from({ length: 20 }, (_, i) => ({
          id: 'log_' + i,
          at: new Date(Date.now() - i * 36e5).toISOString(),
          actor: i % 2 ? 'admin' : 'system',
          action: ['whitelist.approve', 'user.update', 'event.create', 'ticket.assign', 'queue.priority'][i % 5],
          detail: {},
        })),
      });
    }

    if (p.startsWith('/api/admin/tebex/')) {
      if (p.endsWith('/backfill') && method === 'POST') {
        return json(res, 200, { ok: true, message: 'Tebex backfill simulated (no network)' });
      }
      if (p.endsWith('/backfill/status') || p.endsWith('/backfill/push-game')) {
        return json(res, 200, { ok: true, status: 'idle', pending: 0 });
      }
      if (p === '/api/admin/tebex/mappings') {
        if (method === 'POST') {
          const body = await readBody(req);
          colArr('tebexMappings').push({ ...body, id: body.id || 'map_' + Math.random().toString(36).slice(2, 8) });
          db.save();
        }
        return json(res, 200, colArr('tebexMappings'));
      }
    }

    if (p === '/api/admin/store/overview' || p === '/api/admin/store/stats') {
      return json(res, 200, {
        revenue: Math.round(Math.random() * 4000) + 500,
        orders: Math.floor(Math.random() * 120) + 10,
        lifetimeRevenue: Math.round(Math.random() * 90000) + 20000,
        recentOrders: [],
      });
    }

    if (p === '/api/admin/store/information') {
      return json(res, 200, db.data.storeInfo || { storeUrl: db.col('servers')[0].storeUrl || null });
    }

    if (p === '/api/admin/services/categories') {
      if (method === 'POST') {
        const body = await readBody(req);
        colArr('serviceCategories').push({ ...body, id: body.id || 'sc_' + Math.random().toString(36).slice(2, 8) });
        db.save();
      }
      return json(res, 200, colArr('serviceCategories'));
    }

    if (p === '/api/admin/services/contracts' || p === '/api/admin/services/admin-list' || p === '/api/admin/services/send-reminders') {
      if (p.endsWith('/send-reminders') && method === 'POST') {
        return json(res, 200, { ok: true, sent: 0 });
      }
      return json(res, 200, colArr('services'));
    }

    if (p === '/api/admin/test-dm' && method === 'POST') {
      return json(res, 200, { ok: true, message: 'DM simulated (no Discord)' });
    }

    return json(res, 200, { ok: true, path: p, note: 'local admin endpoint' });
  }

  // ---------------- FALLBACK ----------------
  return proxy(req, res, req.url);
}

const server = http.createServer((req, res) => {
  let fullUrl = req.url;
  let urlPath = decodeURIComponent(req.url.split('?')[0]);

  if (urlPath.startsWith('/__fbauth/')) {
    handleFbAuth(req, res);
    return;
  }

  if (urlPath.startsWith('/api/')) {
    handleApi(req, res);
    return;
  }

  if (urlPath === '/') urlPath = '/index.html';
  let filePath = path.join(ROOT, urlPath);

  if (!fs.existsSync(filePath)) {
    filePath = path.join(ROOT, 'index.html');
  }

  fs.stat(filePath, (err, stat) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    if (stat.isDirectory()) filePath = path.join(filePath, 'index.html');
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': 'no-cache' });
    fs.createReadStream(filePath).pipe(res);
  });
});

server.listen(PORT, () => {
  console.log('MTRP local backend running at http://localhost:' + PORT);
});
