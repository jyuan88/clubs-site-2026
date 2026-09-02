import express from 'express';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const {
  PORT = 10000,
  GITHUB_TOKEN,
  CONTENT_REPO,          // e.g. "jyuan88/clubs-content-2026"
  SITE_PASSWORD,
  ADMIN_PASSWORD,
  SESSION_SECRET,
} = process.env;

for (const [k, v] of Object.entries({ GITHUB_TOKEN, CONTENT_REPO, SITE_PASSWORD, ADMIN_PASSWORD, SESSION_SECRET })) {
  if (!v) { console.error(`missing env ${k}`); process.exit(1); }
}

const GH = 'https://api.github.com';
const ghHeaders = (accept = 'application/vnd.github.raw') => ({
  Authorization: `Bearer ${GITHUB_TOKEN}`,
  Accept: accept,
  'User-Agent': 'clubs-site',
  'X-GitHub-Api-Version': '2022-11-28',
});

// ---------- content cache (source of truth: private GitHub content repo) ----------
const cache = {
  clubs: null,            // parsed clubs.json
  posters: new Map(),     // slug -> Buffer
  shas: new Map(),        // repo path -> blob sha (needed for updates)
  loadedAt: null,
};

async function ghGetJson(url) {
  const r = await fetch(url, { headers: ghHeaders('application/vnd.github+json') });
  if (!r.ok) throw new Error(`GitHub GET ${url} -> ${r.status}`);
  return r.json();
}
async function ghGetRaw(repoPath) {
  const r = await fetch(`${GH}/repos/${CONTENT_REPO}/contents/${repoPath}`, { headers: ghHeaders() });
  if (!r.ok) throw new Error(`GitHub raw ${repoPath} -> ${r.status}`);
  return Buffer.from(await r.arrayBuffer());
}
async function ghPut(repoPath, buf, message) {
  const body = {
    message,
    content: buf.toString('base64'),
    ...(cache.shas.has(repoPath) ? { sha: cache.shas.get(repoPath) } : {}),
  };
  const r = await fetch(`${GH}/repos/${CONTENT_REPO}/contents/${repoPath}`, {
    method: 'PUT',
    headers: { ...ghHeaders('application/vnd.github+json'), 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`GitHub PUT ${repoPath} -> ${r.status}: ${await r.text()}`);
  const j = await r.json();
  cache.shas.set(repoPath, j.content.sha);
}

async function loadContent() {
  const meta = await ghGetJson(`${GH}/repos/${CONTENT_REPO}/contents/`);
  for (const item of meta) if (item.type === 'file') cache.shas.set(item.path, item.sha);
  cache.clubs = JSON.parse((await ghGetRaw('clubs.json')).toString('utf8'));
  let posterList = [];
  try { posterList = await ghGetJson(`${GH}/repos/${CONTENT_REPO}/contents/posters`); } catch { /* no posters dir yet */ }
  for (const item of posterList) {
    if (item.type !== 'file' || !item.name.endsWith('.jpg')) continue;
    cache.shas.set(item.path, item.sha);
    const slug = item.name.replace(/\.jpg$/, '');
    cache.posters.set(slug, await ghGetRaw(item.path));
  }
  cache.loadedAt = new Date().toISOString();
  console.log(`content loaded: ${cache.clubs.clubs.length} clubs, ${cache.posters.size} posters`);
}

// ---------- auth ----------
const sign = (s) => crypto.createHmac('sha256', SESSION_SECRET).update(s).digest('base64url');
function makeToken(role) {
  const exp = Date.now() + 1000 * 60 * 60 * 24 * 14;
  const body = `${role}.${exp}`;
  return `${body}.${sign(body)}`;
}
function readToken(tok) {
  if (!tok) return null;
  const i = tok.lastIndexOf('.');
  if (i < 0) return null;
  const body = tok.slice(0, i), mac = tok.slice(i + 1);
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sign(body)), Buffer.from(mac))) return null;
  } catch { return null; }
  const [role, exp] = body.split('.');
  if (Date.now() > Number(exp)) return null;
  return role;
}
function getRole(req) {
  const m = /(?:^|;\s*)auth=([^;]+)/.exec(req.headers.cookie || '');
  return readToken(m ? m[1] : null);
}
const loginAttempts = new Map(); // ip -> {n, resetAt}
function throttled(ip) {
  const now = Date.now();
  const rec = loginAttempts.get(ip);
  if (rec && now < rec.resetAt && rec.n >= 20) return true;
  if (!rec || now >= rec.resetAt) loginAttempts.set(ip, { n: 1, resetAt: now + 15 * 60 * 1000 });
  else rec.n += 1;
  return false;
}

// ---------- templates ----------
const tpl = {
  gate: readFileSync(path.join(__dirname, 'views/gate.html'), 'utf8'),
  site: readFileSync(path.join(__dirname, 'views/site.html'), 'utf8'),
  admin: readFileSync(path.join(__dirname, 'views/admin.html'), 'utf8'),
};
const safeJson = (v) => JSON.stringify(v).replace(/</g, '\\u003c');
function renderSite() {
  const visible = cache.clubs.clubs.filter((c) => !c.hidden).map((c) => ({
    ...c, hasPoster: cache.posters.has(c.slug),
  }));
  return tpl.site
    .replace('"__CLUBS_JSON__"', safeJson(visible))
    .replace('"__POSTERS_INLINE__"', '""');
}
function renderAdmin() {
  const all = cache.clubs.clubs.map((c) => ({ ...c, hasPoster: cache.posters.has(c.slug) }));
  return tpl.admin.replace('"__CLUBS_JSON__"', safeJson(all));
}

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '256kb' }));

const setAuthCookie = (res, role) =>
  res.setHeader('Set-Cookie', `auth=${makeToken(role)}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=1209600`);

app.post('/login', (req, res) => {
  if (throttled(req.ip)) return res.status(429).json({ ok: false, error: '尝试过多，请 15 分钟后再试' });
  const pw = String(req.body.password || '');
  if (pw === ADMIN_PASSWORD) { setAuthCookie(res, 'admin'); return res.json({ ok: true, role: 'admin' }); }
  if (pw === SITE_PASSWORD) { setAuthCookie(res, 'site'); return res.json({ ok: true, role: 'site' }); }
  res.status(401).json({ ok: false, error: '密码不正确' });
});
app.get('/logout', (_req, res) => {
  res.setHeader('Set-Cookie', 'auth=; Path=/; HttpOnly; Max-Age=0');
  res.redirect('/');
});

app.get('/', (req, res) => {
  const role = getRole(req);
  if (!role) return res.type('html').send(tpl.gate.replace('__MODE__', 'site'));
  res.type('html').send(renderSite());
});

app.get('/poster/:slug.jpg', (req, res) => {
  if (!getRole(req)) return res.status(401).end();
  const buf = cache.posters.get(req.params.slug);
  if (!buf) return res.status(404).end();
  res.type('image/jpeg').setHeader('Cache-Control', 'private, max-age=300').send(buf);
});

// ---------- admin ----------
function requireAdmin(req, res, next) {
  if (getRole(req) !== 'admin') return res.status(403).json({ ok: false, error: '需要管理员登录' });
  next();
}
app.get('/admin', (req, res) => {
  if (getRole(req) !== 'admin') return res.type('html').send(tpl.gate.replace('__MODE__', 'admin'));
  res.type('html').send(renderAdmin());
});

const EDITABLE = ['name', 'group', 'color', 'motto', 'titleA', 'titleB', 'subtitle', 'venue', 'time',
  'activities', 'contact', 'join', 'joinSub', 'qrType', 'qrNote', 'president', 'vicePresidents',
  'ready', 'hidden', 'featured', 'schedule', 'leadLabel', 'deputyLabel'];
app.post('/admin/api/club/:slug', requireAdmin, async (req, res) => {
  const club = cache.clubs.clubs.find((c) => c.slug === req.params.slug);
  if (!club) return res.status(404).json({ ok: false, error: '社团不存在' });
  for (const k of EDITABLE) if (k in req.body) club[k] = req.body[k];
  try {
    await ghPut('clubs.json', Buffer.from(JSON.stringify(cache.clubs, null, 2)), `admin: update ${club.slug}`);
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(502).json({ ok: false, error: '保存到内容仓库失败，请重试' }); }
});

app.post('/admin/api/poster/:slug', requireAdmin,
  express.raw({ type: ['image/jpeg', 'image/png', 'application/octet-stream'], limit: '8mb' }),
  async (req, res) => {
    const slug = req.params.slug;
    if (!cache.clubs.clubs.some((c) => c.slug === slug)) return res.status(404).json({ ok: false, error: '社团不存在' });
    let buf = req.body;
    if (!Buffer.isBuffer(buf) || buf.length < 1000) return res.status(400).json({ ok: false, error: '文件为空或过小' });
    const isJpeg = buf[0] === 0xff && buf[1] === 0xd8;
    const isPng = buf[0] === 0x89 && buf[1] === 0x50;
    if (!isJpeg && !isPng) return res.status(400).json({ ok: false, error: '仅支持 JPG/PNG' });
    if (buf.length > 900 * 1024) return res.status(400).json({ ok: false, error: '请压缩到 900KB 以内（长边 1200px、JPG 质量 75 左右即可）' });
    try {
      await ghPut(`posters/${slug}.jpg`, buf, `admin: poster ${slug}`);
      cache.posters.set(slug, buf);
      res.json({ ok: true, size: buf.length });
    } catch (e) { console.error(e); res.status(502).json({ ok: false, error: '保存到内容仓库失败，请重试' }); }
  });

app.post('/admin/api/reload', requireAdmin, async (_req, res) => {
  try { await loadContent(); res.json({ ok: true, loadedAt: cache.loadedAt }); }
  catch (e) { console.error(e); res.status(502).json({ ok: false, error: String(e.message) }); }
});

app.get('/healthz', (_req, res) => res.json({ ok: true, loadedAt: cache.loadedAt }));

loadContent().then(() => {
  app.listen(PORT, () => console.log(`listening on :${PORT}`));
}).catch((e) => { console.error('content load failed:', e); process.exit(1); });
