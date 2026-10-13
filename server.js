/**
 * 放松垂钓 · 账号服务端
 * 纯 Node 原生实现，零 npm 依赖。
 *   - 静态托管 fishing-game.html
 *   - 账号注册 / 登录 / 登出 / 会话（用户名 + 密码，scrypt 加盐哈希）
 *   - 每个账号独立存档（data/saves/<uid>.json）
 *   - 仅对外暴露 fishing-game.html 一个文件，杜绝 server.js / package.json 等源码外泄
 * 启动：node server.js      (PORT 环境变量可选，默认 3000)
 */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;

/* ---------------------------------------------------------------------------
 * 运行时数据目录：必须放在「项目目录之外」。
 *
 * 原因：发布平台每次 deploy 会把整个项目目录压缩上传并覆盖线上沙箱，
 * data/ 放在项目里就会被本地数据顶掉，线上注册的账号每次都丢。
 * 放到项目父目录后，该目录是运行时在沙箱里新建的，不参与上传，
 * 重新发布时得以保留。
 * 父目录不可写时退到系统临时目录。
 * ------------------------------------------------------------------------- */
const RUNTIME_DIR_NAME = 'moyu-fishing-runtime';
function pickDataDir() {
  const candidates = [
    path.join(ROOT, '..', RUNTIME_DIR_NAME),
    path.join(require('os').tmpdir(), RUNTIME_DIR_NAME),
  ];
  for (const d of candidates) {
    try {
      fs.mkdirSync(d, { recursive: true });
      fs.accessSync(d, fs.constants.W_OK);
      return d;
    } catch (e) { /* 试下一个 */ }
  }
  return candidates[candidates.length - 1];
}
const DATA_DIR = pickDataDir();
const SAVE_DIR = path.join(DATA_DIR, 'saves');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESS_FILE = path.join(DATA_DIR, 'sessions.json');
const PORT = Number(process.env.PORT) || 3000;

const SESSION_TTL = 7 * 24 * 3600 * 1000;   // 7 天
const MAX_SAVE_BYTES = 512 * 1024;          // 单份存档上限 512KB
const MAX_BODY_BYTES = 1024 * 1024;         // 请求体上限 1MB
const SCRYPT_KEYLEN = 64;

/* ============================ 基础设施 ============================ */

function ensureDirs() {
  for (const d of [DATA_DIR, SAVE_DIR]) {
    try { fs.mkdirSync(d, { recursive: true }); } catch (e) {}
  }
  migrateLegacyData();
}

/** 一次性迁移：老版本把数据放在项目内的 data/，会被发布覆盖，搬来新位置 */
function migrateLegacyData() {
  const legacy = path.join(ROOT, 'data');
  try {
    if (!fs.existsSync(path.join(legacy, 'users.json'))) return;
    if (fs.existsSync(USERS_FILE)) return;          // 新位置已有数据，不覆盖
    fs.cpSync(legacy, DATA_DIR, { recursive: true });
    console.log('[migrate] 旧 data/ 已迁移到', DATA_DIR);
  } catch (e) {
    console.log('[migrate] 跳过：', e.message);
  }
}
ensureDirs();

/** 原子写：先写临时文件再 rename，避免半截 JSON */
function atomicWrite(file, content) {
  const tmp = file + '.' + process.pid + '.' + Date.now() + '.tmp';
  try {
    fs.writeFileSync(tmp, content);
    fs.renameSync(tmp, file);
    return true;
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch (_) {}
    console.error('[write]', file, e.message);
    return false;
  }
}

/** 读 JSON；损坏时备份为 .bak 并返回兜底值 */
function readJSON(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    const raw = fs.readFileSync(file, 'utf8');
    if (!raw.trim()) return fallback;
    const d = JSON.parse(raw);
    return (d && typeof d === 'object') ? d : fallback;
  } catch (e) {
    console.error('[read]', file, e.message, '→ 备份为 .bak');
    try { fs.renameSync(file, file + '.bak'); } catch (_) {}
    return fallback;
  }
}
function writeJSON(file, obj) { return atomicWrite(file, JSON.stringify(obj, null, 2)); }

/* ============================ 用户与会话 ============================ */

let users = readJSON(USERS_FILE, {});          // { uid: {uid, username, salt, hash, createdAt, clients:[]} }
let sessions = readJSON(SESS_FILE, {});        // { token: {uid, expires} }

// 用户名小写索引，避免每次遍历查重
let nameIndex = {};
function rebuildIndex() {
  nameIndex = {};
  for (const uid in users) nameIndex[users[uid].username.toLowerCase()] = uid;
}
rebuildIndex();

function hashPassword(password, salt) {
  return crypto.scryptSync(String(password), salt, SCRYPT_KEYLEN).toString('hex');
}
function verifyPassword(password, salt, expectedHex) {
  const got = Buffer.from(hashPassword(password, salt), 'hex');
  let exp;
  try { exp = Buffer.from(expectedHex, 'hex'); } catch (e) { return false; }
  if (got.length !== exp.length) return false;
  return crypto.timingSafeEqual(got, exp);
}
function newUid() {
  let uid;
  do { uid = 'P' + crypto.randomBytes(4).toString('hex').toUpperCase(); } while (users[uid]);
  return uid;
}
function newToken() { return crypto.randomBytes(24).toString('hex'); }

function createSession(uid) {
  const token = newToken();
  sessions[token] = { uid, expires: Date.now() + SESSION_TTL };
  writeJSON(SESS_FILE, sessions);
  return token;
}
function dropSession(token) {
  if (token && sessions[token]) {
    delete sessions[token];
    writeJSON(SESS_FILE, sessions);
  }
}
function cleanSessions() {
  const now = Date.now();
  let changed = false;
  for (const t in sessions) {
    if (!sessions[t] || sessions[t].expires < now) { delete sessions[t]; changed = true; }
  }
  if (changed) writeJSON(SESS_FILE, sessions);
}
setInterval(cleanSessions, 3600 * 1000).unref();

function savePath(uid) { return path.join(SAVE_DIR, uid.replace(/[^A-Za-z0-9_]/g, '') + '.json'); }

/* ============================ HTTP 工具 ============================ */

function parseCookies(req) {
  const out = {};
  const raw = req.headers.cookie;
  if (!raw) return out;
  raw.split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function setCookie(res, name, value, opts) {
  const o = opts || {};
  let s = name + '=' + encodeURIComponent(value) + '; Path=' + (o.path || '/');
  if (o.maxAge != null) s += '; Max-Age=' + o.maxAge;
  if (o.httpOnly) s += '; HttpOnly';
  s += '; SameSite=' + (o.sameSite || 'Lax');
  if (o.secure) s += '; Secure';
  const prev = res.getHeader('Set-Cookie');
  const list = prev ? (Array.isArray(prev) ? prev.concat(s) : [prev, s]) : [s];
  res.setHeader('Set-Cookie', list);
}
function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY_BYTES) { reject(new Error('BODY_TOO_LARGE')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      if (!raw) return resolve({});
      try { resolve(JSON.parse(raw)); } catch (e) { reject(new Error('BAD_JSON')); }
    });
    req.on('error', reject);
  });
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.gif': 'image/gif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon',
  '.webp': 'image/webp', '.woff2': 'font/woff2', '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
};

/* 白名单：只对外暴露这些文件，杜绝 server.js / package.json / .git 等源码外泄 */
const STATIC_ALLOW = new Set(['/fishing-game.html', '/favicon.ico']);
const STATIC_ALIAS = { '/': '/fishing-game.html', '': '/fishing-game.html', '/index.html': '/fishing-game.html' };

function serveStatic(req, res, urlPath) {
  let rel = decodeURIComponent(urlPath.split('?')[0]);
  rel = STATIC_ALIAS[rel] || rel;
  if (!STATIC_ALLOW.has(rel)) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('404 Not Found');
  }
  const target = path.normalize(path.join(ROOT, rel));
  // 路径穿越防护
  if (!target.startsWith(ROOT + path.sep) && target !== ROOT) {
    return json(res, 403, { error: 'FORBIDDEN' });
  }
  // 禁止读取 data 目录
  if (target.startsWith(DATA_DIR)) return json(res, 403, { error: 'FORBIDDEN' });

  fs.stat(target, (err, st) => {
    if (err || !st.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('404 Not Found');
    }
    const ext = path.extname(target).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Content-Length': st.size,
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=300',
    });
    fs.createReadStream(target).pipe(res);
  });
}

/* ============================ 业务校验 ============================ */

const NAME_RE = /^[\u4e00-\u9fa5A-Za-z0-9_]{2,12}$/;

function validateCredentials(username, password) {
  if (typeof username !== 'string' || typeof password !== 'string') return '用户名或密码格式不正确';
  username = username.trim();
  if (!NAME_RE.test(username)) return '用户名需 2-12 位，仅限中文、字母、数字、下划线';
  if (password.length < 6) return '密码至少 6 位';
  if (password.length > 64) return '密码最多 64 位';
  return null;
}

function currentUser(req) {
  const c = parseCookies(req);
  const s = c.sid ? sessions[c.sid] : null;
  if (!s) return null;
  if (s.expires < Date.now()) { dropSession(c.sid); return null; }
  const u = users[s.uid];
  if (!u) return null;
  return { uid: u.uid, username: u.username, token: c.sid };
}

/* ============================ 路由 ============================ */

async function handleApi(req, res, urlPath) {
  const method = req.method.toUpperCase();
  const cookies = parseCookies(req);

  /* ---- 注册 ---- */
  if (urlPath === '/api/register' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch (e) { return json(res, 400, { error: '请求格式错误' }); }
    let { username, password } = body;
    username = (username || '').trim();
    const bad = validateCredentials(username, password);
    if (bad) return json(res, 400, { error: bad });

    if (nameIndex[username.toLowerCase()]) return json(res, 409, { error: '该用户名已被注册' });

    const uid = newUid();
    const salt = crypto.randomBytes(16).toString('hex');
    users[uid] = {
      uid, username, salt,
      hash: hashPassword(password, salt),
      createdAt: Date.now(),
      clients: [],
    };
    nameIndex[username.toLowerCase()] = uid;

    // 标记本机 client，用于账号快捷切换列表
    // 注意：首次请求尚无 cid，此时先生成一个并在本次请求内即刻生效
    let cid = cookies.cid;
    if (!cid) {
      cid = crypto.randomBytes(8).toString('hex');
      setCookie(res, 'cid', cid, { maxAge: 365 * 24 * 3600 });
    }
    users[uid].clients.push(cid);
    writeJSON(USERS_FILE, users);

    const token = createSession(uid);
    setCookie(res, 'sid', token, { maxAge: SESSION_TTL / 1000, httpOnly: true });
    console.log('[register]', username, uid);
    return json(res, 200, { ok: true, uid, username, isNew: true });
  }

  /* ---- 登录 ---- */
  if (urlPath === '/api/login' && method === 'POST') {
    let body;
    try { body = await readBody(req); } catch (e) { return json(res, 400, { error: '请求格式错误' }); }
    const username = (body.username || '').trim();
    const password = body.password || '';
    if (!username || !password) return json(res, 400, { error: '请输入用户名和密码' });

    const uid = nameIndex[username.toLowerCase()];
    if (!uid || !users[uid]) {
      console.log('[login-nouser]', username);
      return json(res, 401, { error: '该用户名尚未注册，请先切换到「注册」开一个新账号', code: 'NO_USER' });
    }
    const u = users[uid];
    if (!verifyPassword(password, u.salt, u.hash)) {
      console.log('[login-fail]', username);
      return json(res, 401, { error: '密码不正确（注意大小写和首尾空格），可切换到「注册」页用同样信息重注册', code: 'BAD_PASS' });
    }

    let cid2 = cookies.cid;
    if (!cid2) {
      cid2 = crypto.randomBytes(8).toString('hex');
      setCookie(res, 'cid', cid2, { maxAge: 365 * 24 * 3600 });
    }
    if (u.clients.indexOf(cid2) === -1) {
      u.clients.push(cid2);
      if (u.clients.length > 20) u.clients = u.clients.slice(-20);
      writeJSON(USERS_FILE, users);
    }
    const token = createSession(uid);
    setCookie(res, 'sid', token, { maxAge: SESSION_TTL / 1000, httpOnly: true });
    console.log('[login]', username, uid);
    return json(res, 200, { ok: true, uid, username, isNew: false });
  }

  /* ---- 登出 ---- */
  if (urlPath === '/api/logout' && method === 'POST') {
    dropSession(cookies.sid);
    setCookie(res, 'sid', '', { maxAge: 0, httpOnly: true });
    return json(res, 200, { ok: true });
  }

  /* ---- 当前用户 ---- */
  if (urlPath === '/api/me' && method === 'GET') {
    const u = currentUser(req);
    if (!u) return json(res, 401, { error: '未登录' });
    return json(res, 200, { uid: u.uid, username: u.username });
  }

  /* ---- 本机账号列表 ---- */
  if (urlPath === '/api/accounts' && method === 'GET') {
    const cid = cookies.cid;
    if (!cid) return json(res, 200, { accounts: [] });
    const list = [];
    for (const uid in users) {
      const u = users[uid];
      if (u.clients && u.clients.indexOf(cid) !== -1) {
        list.push({ uid: u.uid, username: u.username, createdAt: u.createdAt });
      }
    }
    list.sort((a, b) => b.createdAt - a.createdAt);
    return json(res, 200, { accounts: list });
  }

  /* ---- 存档读写 ---- */
  if (urlPath === '/api/save') {
    const u = currentUser(req);
    if (!u) return json(res, 401, { error: '未登录' });

    if (method === 'GET') {
      const data = readJSON(savePath(u.uid), null);
      return json(res, 200, { save: data });
    }
    if (method === 'PUT') {
      let body;
      try { body = await readBody(req); } catch (e) { return json(res, 413, { error: '存档过大或格式错误' }); }
      const payload = body && body.save ? body.save : body;
      if (!payload || typeof payload !== 'object') return json(res, 400, { error: '存档格式错误' });
      const str = JSON.stringify(payload);
      if (Buffer.byteLength(str) > MAX_SAVE_BYTES) return json(res, 413, { error: '存档超出体积上限' });
      // 防篡改归属
      payload.uid = u.uid;
      payload.name = payload.name || u.username;
      const ok = writeJSON(savePath(u.uid), payload);
      if (!ok) return json(res, 500, { error: '存档写入失败' });
      return json(res, 200, { ok: true, bytes: Buffer.byteLength(str), at: Date.now() });
    }
    return json(res, 405, { error: 'METHOD_NOT_ALLOWED' });
  }

  /* ---- 重置当前账号存档 ---- */
  if (urlPath === '/api/reset' && method === 'POST') {
    const u = currentUser(req);
    if (!u) return json(res, 401, { error: '未登录' });
    const p = savePath(u.uid);
    try { if (fs.existsSync(p)) fs.unlinkSync(p); } catch (e) { return json(res, 500, { error: '重置失败' }); }
    console.log('[reset]', u.username);
    return json(res, 200, { ok: true });
  }

  /* ---- 改名 ---- */
  if (urlPath === '/api/rename' && method === 'POST') {
    const u = currentUser(req);
    if (!u) return json(res, 401, { error: '未登录' });
    let body;
    try { body = await readBody(req); } catch (e) { return json(res, 400, { error: '请求格式错误' }); }
    const nn = (body.username || '').trim();
    if (!/^[\u4e00-\u9fa5A-Za-z0-9_]{2,12}$/.test(nn)) return json(res, 400, { error: '名字需 2-12 位，仅限中文、字母、数字、下划线' });
    const holder = nameIndex[nn.toLowerCase()];
    if (holder && holder !== u.uid) return json(res, 409, { error: '该名字已被占用' });
    const old = users[u.uid].username;
    delete nameIndex[old.toLowerCase()];
    users[u.uid].username = nn;
    nameIndex[nn.toLowerCase()] = u.uid;
    writeJSON(USERS_FILE, users);
    return json(res, 200, { ok: true, username: nn });
  }

  /* ---- 健康检查 ---- */
  if (urlPath === '/api/health') {
    return json(res, 200, { ok: true, users: Object.keys(users).length, uptime: Math.floor(process.uptime()), dataDir: DATA_DIR });
  }

  return json(res, 404, { error: 'NOT_FOUND' });
}

/* ============================ 服务器 ============================ */

const server = http.createServer((req, res) => {
  let urlPath;
  try { urlPath = new URL(req.url, 'http://localhost').pathname; }
  catch (e) { return json(res, 400, { error: 'BAD_URL' }); }

  if (urlPath.startsWith('/api/')) {
    handleApi(req, res, urlPath).catch(err => {
      console.error('[api-error]', urlPath, err && err.message);
      if (!res.headersSent) json(res, 500, { error: '服务器内部错误' });
    });
    return;
  }
  serveStatic(req, res, urlPath);
});

server.on('clientError', (err, socket) => {
  try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch (e) {}
});

process.on('uncaughtException', e => console.error('[uncaught]', e && e.stack || e));
process.on('unhandledRejection', e => console.error('[unhandled]', e));

server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  🎣 放松垂钓 · 账号服务已启动');
  console.log('  ────────────────────────────────');
  console.log('  地址：http://localhost:' + PORT);
  console.log('  账号：' + Object.keys(users).length + ' 个已注册');
  console.log('  存档：' + SAVE_DIR);
  console.log('');
});
