/**
 * نسق — خادم إثبات تقني (PoC) v2
 * ------------------------------------------------------------------
 * الفرق عن v1: هذا الإصدار حقيقي على مستويين كان v1 يتحايل عليهما بصراحة:
 *
 *   1) التخزين: بدل Map في الذاكرة (يُمسح عند كل إعادة تشغيل)، الآن
 *      Postgres حقيقي على Render. عند الإقلاع، الخادم ينشئ الجداول
 *      تلقائياً لو ما كانت موجودة (migrate()) ويزرع المستأجرين الثلاثة
 *      التجريبيين لو ما كانوا موجودين — بدون أي أداة SQL يدوية.
 *
 *   2) المصادقة: بدل "أي شخص يسجّل مستأجر تجريبي بدون حساب"، الآن فيه
 *      تسجيل حساب حقيقي بكلمة مرور (مُجزّأة بـ scrypt + ملح عشوائي —
 *      لا شيء نص صريح يُخزَّن أبداً)، ودخول يُصدر توكن جلسة موقّع
 *      (HMAC-SHA256) — بدون جدول جلسات، التوقيع نفسه هو إثبات الصلاحية.
 *      إضافة مستأجر جديد (POST /api/tenants) صار يتطلب حساباً مسجَّلاً.
 *
 * لا يزال هذا PoC: بدون تأكيد بريد، بدون استرجاع كلمة مرور، بدون حدود
 * معدل طلبات (rate limiting). هذا مقصود — نفس فلسفة v1: أثبت أن الآلية
 * الأساسية تعمل حقيقةً قبل الاستثمار في طبقات الإنتاج الكاملة.
 *
 * تشغيل: node Server.js  (يحتاج DATABASE_URL و SESSION_SECRET في البيئة)
 */

const http = require('http');
const crypto = require('crypto');
const { URL } = require('url');
const { Pool } = require('pg');

const PORT = process.env.PORT || 4000;
const ROOT_DOMAIN = 'nasaq-platform.com';
// ملاحظة مهمة: سجل الـ DNS المضاف حالياً هو CNAME "*.nasaq-platform.com" فقط
// (wildcard) — وهذا لا يغطي النطاق الجذر العاري (nasaq-platform.com بدون أي
// نطاق فرعي)، لأن Wildcard CNAME لا يشمل الـ apex بحسب معيار DNS. لذا صفحات
// التطبيق (تسجيل/دخول/لوحة) تُخدَّم من نطاق فرعي مضمون الوصول: app.، وليس
// من الجذر العاري مباشرة.
const APP_HOST = 'app.' + ROOT_DOMAIN;
const SESSION_SECRET = process.env.SESSION_SECRET || 'dev-only-insecure-secret-change-me';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 أيام
const IS_PROD = !!process.env.RENDER;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// ---------------------------------------------------------------------
// طبقة قاعدة البيانات
// ---------------------------------------------------------------------
async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tenants (
      hostname TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      primary_color TEXT NOT NULL,
      accent_color TEXT NOT NULL,
      owner_user_id INTEGER REFERENCES users(id),
      created_at TIMESTAMPTZ DEFAULT now()
    );
  `);
  const seed = [
    ['shorooq.' + ROOT_DOMAIN, 'شركة شروق التجارية', '#286140', '#B58500'],
    ['nova.' + ROOT_DOMAIN, 'Nova Logistics', '#B58500', '#1B365D'],
    ['amal.' + ROOT_DOMAIN, 'جمعية أمل الخيرية', '#1B365D', '#6BCABA'],
  ];
  for (const [hostname, name, primary, accent] of seed) {
    await pool.query(
      `INSERT INTO tenants (hostname, name, primary_color, accent_color)
       VALUES ($1,$2,$3,$4) ON CONFLICT (hostname) DO NOTHING`,
      [hostname, name, primary, accent]
    );
  }
  console.log('DB migrated + seeded.');
}

async function findTenantByHost(hostname) {
  const r = await pool.query('SELECT * FROM tenants WHERE hostname = $1', [hostname]);
  return r.rows[0] || null;
}
async function listTenants() {
  const r = await pool.query('SELECT hostname, name, primary_color, accent_color, created_at FROM tenants ORDER BY created_at');
  return r.rows;
}
async function findUserByEmail(email) {
  const r = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  return r.rows[0] || null;
}

// ---------------------------------------------------------------------
// تجزئة كلمات المرور (scrypt — مدمج في Node، بدون أي حزمة إضافية)
// ---------------------------------------------------------------------
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
}
function verifyPassword(password, salt, hash) {
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  const a = Buffer.from(check, 'hex');
  const b = Buffer.from(hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ---------------------------------------------------------------------
// توكن جلسة موقّع (HMAC-SHA256) — بلا جدول جلسات
// ---------------------------------------------------------------------
function b64url(buf) { return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function fromB64url(str) { return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64'); }

function signSession(payloadObj) {
  const payload = b64url(Buffer.from(JSON.stringify(payloadObj)));
  const sig = b64url(crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest());
  return `${payload}.${sig}`;
}
function verifySession(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [payload, sig] = token.split('.');
  const expected = b64url(crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest());
  const a = Buffer.from(sig || '');
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(fromB64url(payload).toString());
    if (!data.exp || data.exp < Date.now()) return null;
    return data;
  } catch {
    return null;
  }
}
function getSessionFromReq(req) {
  const auth = req.headers['authorization'];
  if (auth && auth.startsWith('Bearer ')) return verifySession(auth.slice(7));
  const cookieHeader = req.headers['cookie'] || '';
  const m = cookieHeader.match(/(?:^|;\s*)nasaq_session=([^;]+)/);
  return m ? verifySession(decodeURIComponent(m[1])) : null;
}
function setSessionCookie(res, token) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  const secure = IS_PROD ? '; Secure' : '';
  res.setHeader('Set-Cookie', `nasaq_session=${encodeURIComponent(token)}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax${secure}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `nasaq_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax`);
}

// ---------------------------------------------------------------------
// أدوات مساعدة عامة
// ---------------------------------------------------------------------
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}
function normalizeHost(rawHost) {
  return String(rawHost || '').split(':')[0].trim().toLowerCase();
}
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; if (body.length > 20_000) req.destroy(); });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}
function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(obj, null, 2));
}
function pageShell(title, bodyHtml) {
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)} · نسق</title>
<style>
  body{font-family:Segoe UI, Tahoma, sans-serif; background:#f9f9f7; margin:0; color:#0b0b0b;}
  .bar{background:#1B365D; color:#fff; padding:16px 24px; display:flex; justify-content:space-between; align-items:center;}
  .bar a{color:#fff; text-decoration:none; opacity:.9; font-size:14px; margin-inline-start:14px;}
  .wrap{max-width:420px; margin:40px auto; padding:0 20px;}
  .card{background:#fff; border:1px solid rgba(11,11,11,.08); border-radius:14px; padding:26px; box-shadow:0 8px 24px rgba(20,20,15,.06);}
  h1{font-size:20px; margin:0 0 18px;}
  label{display:block; font-size:13px; color:#52514e; margin:14px 0 6px;}
  input{width:100%; box-sizing:border-box; padding:10px 12px; border-radius:8px; border:1px solid rgba(11,11,11,.15); font-size:14px;}
  button{margin-top:20px; width:100%; padding:12px; border:none; border-radius:8px; background:#286140; color:#fff; font-weight:700; cursor:pointer; font-size:14px;}
  .msg{margin-top:14px; font-size:13px; padding:10px; border-radius:8px; display:none;}
  .msg.ok{background:#e8f5ee; color:#1c5c39; display:block;}
  .msg.err{background:#fdeceb; color:#a12a24; display:block;}
  .foot{margin-top:16px; font-size:13px; text-align:center; color:#666;}
  .foot a{color:#286140;}
  table{width:100%; border-collapse:collapse; margin-top:10px;}
  td,th{padding:8px 6px; border-bottom:1px solid rgba(11,11,11,.08); font-size:13px; text-align:right;}
  code{direction:ltr; display:inline-block; background:#f2f2f4; padding:1px 6px; border-radius:6px; font-size:12px;}
</style></head>
<body>
  <div class="bar"><strong>نسق</strong><span><a href="/">الرئيسية</a><a href="/dashboard">لوحتي</a><a href="/login">دخول</a><a href="/register">تسجيل</a></span></div>
  <div class="wrap">${bodyHtml}</div>
</body></html>`;
}

function registerPageHtml() {
  return pageShell('إنشاء حساب', `
  <div class="card">
    <h1>إنشاء حساب مشترك جديد</h1>
    <form id="f">
      <label>البريد الإلكتروني</label><input type="email" id="email" required>
      <label>كلمة المرور (8 أحرف على الأقل)</label><input type="password" id="password" minlength="8" required>
      <button type="submit">إنشاء الحساب</button>
    </form>
    <div class="msg" id="msg"></div>
    <div class="foot">عندك حساب؟ <a href="/login">سجّلي دخولك</a></div>
  </div>
  <script>
    document.getElementById('f').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;
      const msg = document.getElementById('msg');
      try {
        const r = await fetch('/api/auth/register', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email, password}) });
        const data = await r.json();
        if (r.ok) { msg.className='msg ok'; msg.textContent='تم إنشاء الحساب — يتم تحويلك للوحتك...'; setTimeout(()=>location.href='/dashboard', 800); }
        else { msg.className='msg err'; msg.textContent = data.error || 'صار خطأ'; }
      } catch { msg.className='msg err'; msg.textContent='تعذّر الاتصال بالخادم'; }
    });
  </script>`);
}

function loginPageHtml() {
  return pageShell('تسجيل الدخول', `
  <div class="card">
    <h1>تسجيل الدخول</h1>
    <form id="f">
      <label>البريد الإلكتروني</label><input type="email" id="email" required>
      <label>كلمة المرور</label><input type="password" id="password" required>
      <button type="submit">دخول</button>
    </form>
    <div class="msg" id="msg"></div>
    <div class="foot">ما عندك حساب؟ <a href="/register">أنشئي واحداً</a></div>
  </div>
  <script>
    document.getElementById('f').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;
      const msg = document.getElementById('msg');
      try {
        const r = await fetch('/api/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({email, password}) });
        const data = await r.json();
        if (r.ok) { msg.className='msg ok'; msg.textContent='تم الدخول — يتم تحويلك...'; setTimeout(()=>location.href='/dashboard', 600); }
        else { msg.className='msg err'; msg.textContent = data.error || 'بيانات الدخول غير صحيحة'; }
      } catch { msg.className='msg err'; msg.textContent='تعذّر الاتصال بالخادم'; }
    });
  </script>`);
}

function dashboardPageHtml(user, tenants) {
  const rows = tenants.map(t => `<tr><td><code>${escapeHtml(t.hostname)}</code></td><td>${escapeHtml(t.name)}</td><td><a href="https://${escapeHtml(t.hostname)}" target="_blank">فتح ↗</a></td></tr>`).join('') || '<tr><td colspan="3" style="text-align:center;color:#888">ما سجّلتِ أي مستأجر بعد</td></tr>';
  return pageShell('لوحتي', `
  <div class="card">
    <h1>أهلاً، ${escapeHtml(user.email)}</h1>
    <p style="color:#666;font-size:13px">مستأجروك (النطاقات الفرعية المسجَّلة على حسابك):</p>
    <table><thead><tr><th>النطاق</th><th>الاسم</th><th></th></tr></thead><tbody>${rows}</tbody></table>
    <form id="add" style="margin-top:22px; border-top:1px solid rgba(11,11,11,.08); padding-top:18px;">
      <label>نطاق فرعي جديد (بالإنجليزي، بدون مسافات)</label><input id="sub" required pattern="[a-z0-9-]+">
      <label>اسم الجهة</label><input id="name" required>
      <label>اللون الأساسي</label><input id="primary" type="color" value="#286140">
      <label>اللون الثانوي</label><input id="accent" type="color" value="#B58500">
      <button type="submit">تسجيل مستأجر جديد</button>
    </form>
    <div class="msg" id="msg"></div>
    <div class="foot"><a href="#" id="logout">تسجيل الخروج</a></div>
  </div>
  <script>
    document.getElementById('add').addEventListener('submit', async (e) => {
      e.preventDefault();
      const body = { subdomain: document.getElementById('sub').value, name: document.getElementById('name').value, primary: document.getElementById('primary').value, accent: document.getElementById('accent').value };
      const msg = document.getElementById('msg');
      const r = await fetch('/api/tenants', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body) });
      const data = await r.json();
      if (r.ok) { msg.className='msg ok'; msg.textContent='تم التسجيل — ' + data.liveUrl; setTimeout(()=>location.reload(), 900); }
      else { msg.className='msg err'; msg.textContent = data.error || 'صار خطأ'; }
    });
    document.getElementById('logout').addEventListener('click', async (e) => {
      e.preventDefault();
      await fetch('/api/auth/logout', { method:'POST' });
      location.href = '/login';
    });
  </script>`);
}

function tenantDashboardHtml(hostname, tenant) {
  const name = escapeHtml(tenant.name);
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<title>${name} · نسق</title>
<style>
  body{font-family:Segoe UI, Tahoma, sans-serif; background:#f9f9f7; margin:0; color:#0b0b0b;}
  .bar{background:${tenant.primary_color}; color:#fff; padding:16px 24px; display:flex; justify-content:space-between; align-items:center;}
  .bar .host{font-family:Consolas, monospace; font-size:12px; opacity:.85; direction:ltr;}
  .wrap{max-width:720px; margin:32px auto; padding:0 20px;}
  .card{background:#fff; border:1px solid rgba(11,11,11,.08); border-radius:14px; padding:22px; box-shadow:0 8px 24px rgba(20,20,15,.06);}
  .badge{display:inline-block; background:${tenant.accent_color}22; color:${tenant.accent_color}; border:1px solid ${tenant.accent_color}55; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700; margin-bottom:14px;}
  h1{margin:0 0 6px; font-size:22px;}
  .meta{color:#666; font-size:13px; margin-bottom:18px;}
  .kpi-row{display:grid; grid-template-columns:repeat(3,1fr); gap:10px;}
  .kpi{background:#f9f9f7; border-radius:10px; padding:14px; text-align:center;}
  .kpi b{display:block; font-size:20px;}
  footer{max-width:720px; margin:20px auto 40px; padding:0 20px; color:#8a8a86; font-size:12px;}
</style></head>
<body>
  <div class="bar">
    <strong>نسق</strong>
    <span class="host">${escapeHtml(hostname)}</span>
  </div>
  <div class="wrap">
    <div class="card">
      <div class="badge">✓ تمّ التعرّف على المستأجر تلقائياً من اسم النطاق — من قاعدة بيانات حقيقية</div>
      <h1>لوحة ${name}</h1>
      <div class="meta">مُنشأ الحساب: ${escapeHtml(String(tenant.created_at).slice(0,10))} · مساحة عمل معزولة بالكامل عن بقية المشتركين</div>
      <div class="kpi-row">
        <div class="kpi"><b>—</b>إجمالي المبيعات</div>
        <div class="kpi"><b>—</b>عملاء نشطون</div>
        <div class="kpi"><b>—</b>معدل التحويل</div>
      </div>
    </div>
  </div>
  <footer>هذه بيانات إثبات تقني (PoC) — لا اتصال ببيانات فعلية بعد. الهوية (${tenant.primary_color} / ${tenant.accent_color}) قُرئت من صف المستأجر في Postgres المرتبط بـ ${escapeHtml(hostname)} فقط.</footer>
</body></html>`;
}

function notProvisionedHtml(hostname) {
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>دومين غير مُفعّل · نسق</title>
<style>body{font-family:Segoe UI,Tahoma,sans-serif;background:#f9f9f7;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;color:#0b0b0b;}
.box{text-align:center;max-width:420px;padding:28px;background:#fff;border-radius:14px;border:1px solid rgba(11,11,11,.08);box-shadow:0 8px 24px rgba(20,20,15,.06);}
code{direction:ltr;display:inline-block;background:#f2f2f4;padding:2px 8px;border-radius:6px;font-size:13px;}</style></head>
<body><div class="box">
  <h2>⚠ هذا النطاق غير مرتبط بأي مشترك</h2>
  <p><code>${escapeHtml(hostname)}</code></p>
  <p style="color:#666;font-size:14px">لو هذا نطاقك، سجّلي دخولك من <a href="/login">هنا</a> وأضيفي المستأجر من لوحتك.</p>
</div></body></html>`;
}

async function rootHtml() {
  const tenants = await listTenants();
  const rows = tenants.map((t) =>
    `<li><code>${escapeHtml(t.hostname)}</code> — ${escapeHtml(t.name)}</li>`).join('');
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>نسق — بيئة الإثبات التقني</title>
<style>body{font-family:Segoe UI,Tahoma,sans-serif;background:#0d0d0d;color:#eee;padding:40px;line-height:1.8}
code{direction:ltr;display:inline-block;background:#1a1a19;padding:2px 8px;border-radius:6px;color:#8fd6b8}
a{color:#8fd6b8}</style></head>
<body>
  <h1>🟢 بيئة نسق للإثبات التقني — تعمل (v2: Postgres + مصادقة حقيقية)</h1>
  <p>هذا هو النطاق الجذر (<code>${ROOT_DOMAIN}</code>). المستأجرون الحاليون:</p>
  <ul>${rows}</ul>
  <p>سجّلي حساباً جديداً وأضيفي مستأجرك الخاص من نطاق التطبيق:
  <a href="https://${APP_HOST}/register">https://${APP_HOST}/register</a> ثم
  <a href="https://${APP_HOST}/login">https://${APP_HOST}/login</a> ثم
  <a href="https://${APP_HOST}/dashboard">https://${APP_HOST}/dashboard</a>.</p>
</body></html>`;
}

// ---------------------------------------------------------------------
// الخادم
// ---------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  try {
    const hostname = normalizeHost(req.headers.host);
    const url = new URL(req.url, 'http://placeholder');
    const isAppHost = hostname === APP_HOST || hostname === ROOT_DOMAIN || hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '';

    // ---- API: تسجيل حساب جديد ----
    if (url.pathname === '/api/auth/register' && req.method === 'POST') {
      const data = await readJsonBody(req).catch(() => null);
      if (!data) return sendJson(res, 400, { error: 'JSON غير صالح' });
      const email = String(data.email || '').trim().toLowerCase();
      const password = String(data.password || '');
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return sendJson(res, 400, { error: 'بريد إلكتروني غير صالح' });
      if (password.length < 8) return sendJson(res, 400, { error: 'كلمة المرور 8 أحرف على الأقل' });
      const existing = await findUserByEmail(email);
      if (existing) return sendJson(res, 409, { error: 'هذا البريد مسجَّل مسبقاً' });
      const { hash, salt } = hashPassword(password);
      const r = await pool.query('INSERT INTO users (email, password_hash, salt) VALUES ($1,$2,$3) RETURNING id, email', [email, hash, salt]);
      const user = r.rows[0];
      const token = signSession({ uid: user.id, email: user.email, exp: Date.now() + SESSION_TTL_MS });
      setSessionCookie(res, token);
      return sendJson(res, 201, { ok: true, token, user: { email: user.email } });
    }

    // ---- API: دخول ----
    if (url.pathname === '/api/auth/login' && req.method === 'POST') {
      const data = await readJsonBody(req).catch(() => null);
      if (!data) return sendJson(res, 400, { error: 'JSON غير صالح' });
      const email = String(data.email || '').trim().toLowerCase();
      const password = String(data.password || '');
      const user = await findUserByEmail(email);
      if (!user || !verifyPassword(password, user.salt, user.password_hash)) {
        return sendJson(res, 401, { error: 'البريد أو كلمة المرور غير صحيحة' });
      }
      const token = signSession({ uid: user.id, email: user.email, exp: Date.now() + SESSION_TTL_MS });
      setSessionCookie(res, token);
      return sendJson(res, 200, { ok: true, token, user: { email: user.email } });
    }

    // ---- API: خروج ----
    if (url.pathname === '/api/auth/logout' && req.method === 'POST') {
      clearSessionCookie(res);
      return sendJson(res, 200, { ok: true });
    }

    // ---- API: من أنا ----
    if (url.pathname === '/api/me' && req.method === 'GET') {
      const session = getSessionFromReq(req);
      if (!session) return sendJson(res, 401, { error: 'غير مسجّل دخول' });
      return sendJson(res, 200, { email: session.email });
    }

    // ---- API: تسجيل مستأجر جديد (يتطلب حساباً الآن) ----
    if (url.pathname === '/api/tenants' && req.method === 'POST') {
      const session = getSessionFromReq(req);
      if (!session) return sendJson(res, 401, { error: 'سجّلي دخولك أولاً' });
      const data = await readJsonBody(req).catch(() => null);
      if (!data) return sendJson(res, 400, { error: 'JSON غير صالح' });
      const sub = String(data.subdomain || '').trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
      if (!sub) return sendJson(res, 400, { error: 'subdomain مطلوب' });
      const RESERVED = new Set(['app', 'www', 'api', 'admin', 'mail', 'ftp']);
      if (RESERVED.has(sub)) return sendJson(res, 400, { error: 'هذا النطاق الفرعي محجوز، اختاري اسماً آخر' });
      const fullHost = `${sub}.${ROOT_DOMAIN}`;
      const existing = await findTenantByHost(fullHost);
      if (existing) return sendJson(res, 409, { error: 'هذا النطاق الفرعي مستخدم مسبقاً' });
      const name = String(data.name || sub).slice(0, 80);
      const primary = /^#[0-9a-fA-F]{6}$/.test(data.primary) ? data.primary : '#286140';
      const accent = /^#[0-9a-fA-F]{6}$/.test(data.accent) ? data.accent : '#B58500';
      await pool.query(
        `INSERT INTO tenants (hostname, name, primary_color, accent_color, owner_user_id) VALUES ($1,$2,$3,$4,$5)`,
        [fullHost, name, primary, accent, session.uid]
      );
      return sendJson(res, 201, { ok: true, liveUrl: `https://${fullHost}` });
    }

    // ---- API: قائمة المستأجرين (عامة) ----
    if (url.pathname === '/api/tenants' && req.method === 'GET') {
      const tenants = await listTenants();
      return sendJson(res, 200, tenants);
    }

    // ---- صفحات التطبيق (على النطاق الجذر فقط) ----
    if (isAppHost && url.pathname === '/register' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(registerPageHtml());
    }
    if (isAppHost && url.pathname === '/login' && req.method === 'GET') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(loginPageHtml());
    }
    if (isAppHost && url.pathname === '/dashboard' && req.method === 'GET') {
      const session = getSessionFromReq(req);
      if (!session) { res.writeHead(302, { Location: '/login' }); return res.end(); }
      const r = await pool.query('SELECT hostname, name FROM tenants WHERE owner_user_id = $1 ORDER BY created_at', [session.uid]);
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(dashboardPageHtml({ email: session.email }, r.rows));
    }

    // ---- التوجيه الرئيسي حسب اسم النطاق ----
    if (isAppHost) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(await rootHtml());
    }

    const tenant = await findTenantByHost(hostname);
    if (tenant) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(tenantDashboardHtml(hostname, tenant));
    }

    res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(notProvisionedHtml(hostname));
  } catch (err) {
    console.error('Request error:', err);
    res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({ error: 'خطأ داخلي في الخادم' }));
  }
});

migrate()
  .then(() => {
    server.listen(PORT, () => {
      console.log(`نسق PoC v2 يعمل على http://localhost:${PORT}`);
      console.log(`جرّب: curl -H "Host: shorooq.${ROOT_DOMAIN}" http://localhost:${PORT}/`);
    });
  })
  .catch((err) => {
    console.error('فشل تجهيز قاعدة البيانات:', err);
    process.exit(1);
  });
