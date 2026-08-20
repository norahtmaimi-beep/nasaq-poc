/**
 * نسق — خادم إثبات تقني (PoC) v3
 * ------------------------------------------------------------------
 * إضافة عن v2: طبقة دلالية (Semantic Layer) حقيقية لمحرك BI، مو مجرد
 * استعلام SQL مكتوب مرة وحدة. المقاييس (measures) والأبعاد (dimensions)
 * تُعرَّف مرة وحدة في SALES_MEASURES / SALES_DIMENSIONS، ودالة
 * queryMeasures() تبني الاستعلام ديناميكياً حسب أي مقياس/بُعد يُطلب —
 * هذا نفس مبدأ أدوات مثل Cube.dev اللي رشّحناها بالخطة المعمارية، لكن
 * بأبسط صورة ممكنة تثبت الفكرة. كل مستأجر عنده لوحة KPI حقيقية (مو أرقام
 * وهمية "—") ورسمين بيانيين (اتجاه المبيعات + المبيعات حسب الفئة) مبنيين
 * كـ SVG مباشر من نتائج الاستعلام، بدون أي مكتبة رسوم خارجية.
 *
 * الفرق عن v1: هذا الإصدار حقيقي على مستويين كان v1 يتحايل عليهما بصراحة:
 *
 *   1) التخزين: بدل Map في الذاكرة (يُمسح عند كل إعادة تشغيل)، الآن
 *      Postgres حقيقي على Render. عند الإقلاع، الخادم ينشئ الجداول
 *      تلقائياً لو ما كانت موجودة (migrate()) ويزرع المستأجرين الثلاثة
 *      التجريبيين وبيانات مبيعات تجريبية لهم — بدون أي أداة SQL يدوية.
 *
 *   2) المصادقة: بدل "أي شخص يسجّل مستأجر تجريبي بدون حساب"، الآن فيه
 *      تسجيل حساب حقيقي بكلمة مرور (مُجزّأة بـ scrypt + ملح عشوائي —
 *      لا شيء نص صريح يُخزَّن أبداً)، ودخول يُصدر توكن جلسة موقّع
 *      (HMAC-SHA256) — بدون جدول جلسات، التوقيع نفسه هو إثبات الصلاحية.
 *      إضافة مستأجر جديد أو عملية بيع جديدة يتطلب حساباً مسجَّلاً ومالكاً
 *      فعلياً لذلك المستأجر (owner_user_id) — مو أي مستخدم مسجّل دخول.
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
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sales (
      id SERIAL PRIMARY KEY,
      tenant_hostname TEXT NOT NULL REFERENCES tenants(hostname),
      occurred_on DATE NOT NULL,
      category TEXT NOT NULL,
      customer_name TEXT NOT NULL,
      amount NUMERIC(12,2) NOT NULL,
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
  await seedSalesIfEmpty();
  console.log('DB migrated + seeded.');
}

// يزرع بيانات مبيعات تجريبية واقعية (14 يوم × 3 فئات) لكل مستأجر تجريبي —
// فقط إذا ما كان عنده أي صف مبيعات بعد (idempotent، آمن يتكرر كل إقلاع).
const DEMO_HOSTS = ['shorooq.' + ROOT_DOMAIN, 'nova.' + ROOT_DOMAIN, 'amal.' + ROOT_DOMAIN];
const DEMO_CATEGORIES = ['خدمات استشارية', 'اشتراكات', 'تدريب'];
async function seedSalesIfEmpty() {
  for (let t = 0; t < DEMO_HOSTS.length; t++) {
    const hostname = DEMO_HOSTS[t];
    const existing = await pool.query('SELECT 1 FROM sales WHERE tenant_hostname = $1 LIMIT 1', [hostname]);
    if (existing.rows.length) continue;
    const rows = [];
    for (let dayAgo = 13; dayAgo >= 0; dayAgo--) {
      const date = new Date(Date.now() - dayAgo * 86400000).toISOString().slice(0, 10);
      const dealsToday = 1 + ((dayAgo + t) % 3); // 1-3 صفقات باليوم
      for (let k = 0; k < dealsToday; k++) {
        const catIndex = (dayAgo + k + t) % DEMO_CATEGORIES.length;
        const amount = 400 + (((dayAgo * 37) + (k * 53) + (t * 91)) % 22) * 85;
        const customer = `عميل ${((dayAgo + k + t) % 7) + 1}`;
        rows.push([hostname, date, DEMO_CATEGORIES[catIndex], customer, amount]);
      }
    }
    for (const row of rows) {
      await pool.query(
        `INSERT INTO sales (tenant_hostname, occurred_on, category, customer_name, amount) VALUES ($1,$2,$3,$4,$5)`,
        row
      );
    }
  }
}

// ---------------------------------------------------------------------
// الطبقة الدلالية (Semantic Layer) — مقاييس وأبعاد تُعرَّف مرة وحدة
// ---------------------------------------------------------------------
const SALES_MEASURES = {
  total_sales: { label: 'إجمالي المبيعات', sql: 'COALESCE(SUM(amount),0)::numeric', format: 'currency' },
  active_customers: { label: 'عملاء نشطون', sql: 'COUNT(DISTINCT customer_name)', format: 'integer' },
  avg_deal: { label: 'متوسط الصفقة', sql: 'COALESCE(AVG(amount),0)::numeric', format: 'currency' },
  deal_count: { label: 'عدد الصفقات', sql: 'COUNT(*)', format: 'integer' },
};
const SALES_DIMENSIONS = {
  day: { label: 'اليوم', sql: "to_char(occurred_on, 'YYYY-MM-DD')" },
  category: { label: 'الفئة', sql: 'category' },
};

// يبني وينفّذ استعلاماً حسب أي تركيبة مقاييس/بُعد يُطلب — هذا هو جوهر
// "الطبقة الدلالية": المقاييس مُعرَّفة مرة وحدة أعلاه، والاستعلام يُبنى
// ديناميكياً، بدل ما يتكرر SQL خام بكل مكان يحتاج رقماً.
async function queryMeasures(tenantHostname, measureKeys, dimensionKey, opts = {}) {
  const measureSql = measureKeys.map((k) => `${SALES_MEASURES[k].sql} AS ${k}`).join(', ');
  const params = [tenantHostname];
  let sql;
  if (dimensionKey) {
    const dimSql = SALES_DIMENSIONS[dimensionKey].sql;
    let where = 'tenant_hostname = $1';
    if (opts.since) { params.push(opts.since); where += ` AND occurred_on >= $${params.length}`; }
    sql = `SELECT ${dimSql} AS dim, ${measureSql} FROM sales WHERE ${where} GROUP BY dim ORDER BY dim`;
    const r = await pool.query(sql, params);
    return r.rows;
  }
  sql = `SELECT ${measureSql} FROM sales WHERE tenant_hostname = $1`;
  const r = await pool.query(sql, params);
  return r.rows[0];
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

// ---------------------------------------------------------------------
// تنسيق الأرقام + رسوم SVG بسيطة (بدون أي مكتبة رسوم خارجية)
// اللوحة: التزمنا بلوحة dataviz الافتراضية المُتحقَّق منها للرسوم
// (وليس ألوان الهوية) لأن ألوان هوية نسق فشلت فحص إمكانية الوصول
// (contrast/CVD) عند استخدامها كألوان سلاسل بيانات — نفس القرار
// المُوثَّق في basaer-landing.html.
// ---------------------------------------------------------------------
function fmtNum(n) {
  const v = Math.round(Number(n) || 0);
  return v.toLocaleString('en-US');
}
function fmtCurrency(n) {
  return fmtNum(n) + ' ر.س';
}

function lineChartSvg(trend) {
  const W = 640, H = 200, padL = 8, padR = 8, padT = 28, padB = 24;
  const values = trend.map((d) => Number(d.total_sales) || 0);
  const n = values.length || 1;
  const max = Math.max(1, ...values);
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const x = (i) => padL + (n <= 1 ? plotW / 2 : (i / (n - 1)) * plotW);
  const y = (v) => padT + plotH - (v / max) * plotH;
  const points = values.map((v, i) => `${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(' ');
  const gridLines = [0, 0.5, 1].map((f) => {
    const gy = padT + plotH * (1 - f);
    return `<line x1="${padL}" y1="${gy.toFixed(1)}" x2="${W - padR}" y2="${gy.toFixed(1)}" stroke="#e1e0d9" stroke-width="1"/>`;
  }).join('');
  const lastI = n - 1;
  const lastX = x(lastI), lastY = y(values[lastI] || 0);
  const hoverDots = values.map((v, i) =>
    `<circle cx="${x(i).toFixed(1)}" cy="${y(v).toFixed(1)}" r="9" fill="transparent"><title>${escapeHtml(trend[i].dim)}: ${fmtCurrency(v)}</title></circle>`
  ).join('');
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="اتجاه المبيعات آخر 14 يوم">
    ${gridLines}
    <line x1="${padL}" y1="${(padT + plotH).toFixed(1)}" x2="${W - padR}" y2="${(padT + plotH).toFixed(1)}" stroke="#c3c2b7" stroke-width="1"/>
    <polyline points="${points}" fill="none" stroke="#2a78d6" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="${lastX.toFixed(1)}" cy="${lastY.toFixed(1)}" r="4" fill="#2a78d6"/>
    <text x="${lastX.toFixed(1)}" y="${(lastY - 12).toFixed(1)}" font-size="11" fill="#0b0b0b" text-anchor="middle">${fmtCurrency(values[lastI] || 0)}</text>
    ${hoverDots}
  </svg>`;
}

function barChartSvg(byCategory) {
  const COLORS = ['#2a78d6', '#eb6834', '#1baf7a'];
  const top = byCategory.slice(0, 3);
  const rest = byCategory.slice(3);
  const restTotal = rest.reduce((s, r) => s + (Number(r.total_sales) || 0), 0);
  const bars = restTotal > 0 ? [...top, { dim: 'أخرى', total_sales: restTotal }] : top;
  const W = 640, H = 200, padL = 8, padR = 8, padT = 28, padB = 36;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const n = Math.max(1, bars.length);
  const gap = 20;
  const barW = (plotW - gap * (n - 1)) / n;
  const max = Math.max(1, ...bars.map((b) => Number(b.total_sales) || 0));
  const parts = bars.map((b, i) => {
    const v = Number(b.total_sales) || 0;
    const bh = (v / max) * plotH;
    const bx = padL + i * (barW + gap);
    const by = padT + plotH - bh;
    const color = COLORS[i] || '#898781';
    return `<rect x="${bx.toFixed(1)}" y="${by.toFixed(1)}" width="${barW.toFixed(1)}" height="${Math.max(bh, 1).toFixed(1)}" rx="4" fill="${color}"><title>${escapeHtml(b.dim)}: ${fmtCurrency(v)}</title></rect>
      <text x="${(bx + barW / 2).toFixed(1)}" y="${(by - 8).toFixed(1)}" font-size="11" fill="#0b0b0b" text-anchor="middle">${fmtCurrency(v)}</text>
      <text x="${(bx + barW / 2).toFixed(1)}" y="${(padT + plotH + 18).toFixed(1)}" font-size="11" fill="#52514e" text-anchor="middle">${escapeHtml(b.dim)}</text>`;
  }).join('');
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" height="${H}" role="img" aria-label="المبيعات حسب الفئة">
    <line x1="${padL}" y1="${(padT + plotH).toFixed(1)}" x2="${W - padR}" y2="${(padT + plotH).toFixed(1)}" stroke="#c3c2b7" stroke-width="1"/>
    ${parts}
  </svg>`;
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
  const rows = tenants.map((t, i) => `
    <div class="tcard">
      <div class="trow">
        <code>${escapeHtml(t.hostname)}</code>
        <a href="https://${escapeHtml(t.hostname)}" target="_blank">فتح اللوحة العامة ↗</a>
      </div>
      <div class="sub" style="margin:2px 0 10px">${escapeHtml(t.name)}</div>
      <form class="salef" data-host="${escapeHtml(t.hostname)}" style="display:flex; gap:8px; flex-wrap:wrap; align-items:flex-end;">
        <div style="flex:1; min-width:110px;"><label style="margin:0 0 4px">مبلغ (ر.س)</label><input type="number" min="1" step="0.01" class="amount" required></div>
        <div style="flex:1; min-width:110px;"><label style="margin:0 0 4px">الفئة</label><input class="category" placeholder="خدمات استشارية"></div>
        <div style="flex:1; min-width:110px;"><label style="margin:0 0 4px">العميل</label><input class="customer" placeholder="اسم العميل"></div>
        <button type="submit" style="margin:0; width:auto; padding:10px 16px;">إضافة عملية بيع</button>
      </form>
      <div class="msg salemsg"></div>
    </div>`).join('') || '<p class="sub">ما سجّلتِ أي مستأجر بعد.</p>';
  return pageShell('لوحتي', `
  <div class="card">
    <h1>أهلاً، ${escapeHtml(user.email)}</h1>
    <p class="sub">مستأجروك — لكل واحد نموذج سريع لإضافة عملية بيع حقيقية، تنعكس فوراً على لوحته العامة (KPI + رسوم بيانية) عبر الطبقة الدلالية.</p>
    ${rows}
    <form id="add" style="margin-top:10px; border-top:1px solid rgba(11,11,11,.08); padding-top:18px;">
      <label>نطاق فرعي جديد (بالإنجليزي، بدون مسافات)</label><input id="sub" required pattern="[a-z0-9-]+">
      <label>اسم الجهة</label><input id="name" required>
      <label>اللون الأساسي</label><input id="primary" type="color" value="#286140">
      <label>اللون الثانوي</label><input id="accent" type="color" value="#B58500">
      <button type="submit">تسجيل مستأجر جديد</button>
    </form>
    <div class="msg" id="msg"></div>
    <div class="foot"><a href="#" id="logout">تسجيل الخروج</a></div>
  </div>
  <style>.tcard{border:1px solid rgba(11,11,11,.08); border-radius:10px; padding:14px; margin-bottom:12px;} .trow{display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:6px;} .trow a{font-size:12px; color:#286140;}</style>
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
    document.querySelectorAll('.salef').forEach((form) => {
      form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const host = form.dataset.host;
        const amount = form.querySelector('.amount').value;
        const category = form.querySelector('.category').value || 'عام';
        const customer = form.querySelector('.customer').value || 'عميل';
        const msg = form.parentElement.querySelector('.salemsg');
        const r = await fetch('/api/tenants/' + encodeURIComponent(host) + '/sales', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ amount, category, customer })
        });
        const data = await r.json();
        msg.className = 'msg ' + (r.ok ? 'ok' : 'err');
        msg.textContent = r.ok ? 'تمت الإضافة — افتحي لوحة المستأجر العامة لتشوفيها بالرسم البياني' : (data.error || 'صار خطأ');
        if (r.ok) form.reset();
      });
    });
  </script>`);
}

function tenantDashboardHtml(hostname, tenant, kpis, trend, byCategory) {
  const name = escapeHtml(tenant.name);
  const hasData = Number(kpis.deal_count) > 0;
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<title>${name} · نسق</title>
<style>
  body{font-family:Segoe UI, Tahoma, sans-serif; background:#f9f9f7; margin:0; color:#0b0b0b;}
  .bar{background:${tenant.primary_color}; color:#fff; padding:16px 24px; display:flex; justify-content:space-between; align-items:center;}
  .bar .host{font-family:Consolas, monospace; font-size:12px; opacity:.85; direction:ltr;}
  .wrap{max-width:720px; margin:32px auto; padding:0 20px;}
  .card{background:#fff; border:1px solid rgba(11,11,11,.08); border-radius:14px; padding:22px; box-shadow:0 8px 24px rgba(20,20,15,.06); margin-bottom:18px;}
  .badge{display:inline-block; background:${tenant.accent_color}22; color:${tenant.accent_color}; border:1px solid ${tenant.accent_color}55; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700; margin-bottom:14px;}
  h1{margin:0 0 6px; font-size:22px;}
  h2{font-size:15px; margin:0 0 4px; color:#0b0b0b;}
  .sub{color:#52514e; font-size:12px; margin:0 0 12px;}
  .meta{color:#666; font-size:13px; margin-bottom:18px;}
  .kpi-row{display:grid; grid-template-columns:repeat(3,1fr); gap:10px;}
  .kpi{background:#f9f9f7; border-radius:10px; padding:14px; text-align:center;}
  .kpi b{display:block; font-size:20px;}
  .kpi span{font-size:12px; color:#52514e;}
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
      <div class="meta">مُنشأ الحساب: ${escapeHtml(String(tenant.created_at).slice(0, 10))} · مساحة عمل معزولة بالكامل عن بقية المشتركين</div>
      <div class="kpi-row">
        <div class="kpi"><b>${fmtCurrency(kpis.total_sales)}</b><span>إجمالي المبيعات</span></div>
        <div class="kpi"><b>${fmtNum(kpis.active_customers)}</b><span>عملاء نشطون</span></div>
        <div class="kpi"><b>${fmtCurrency(kpis.avg_deal)}</b><span>متوسط الصفقة</span></div>
      </div>
    </div>
    ${hasData ? `
    <div class="card">
      <h2>اتجاه المبيعات — آخر 14 يوم</h2>
      <p class="sub">مجموع يومي، من طبقة دلالية حقيقية (measure: total_sales) فوق Postgres</p>
      ${lineChartSvg(trend)}
    </div>
    <div class="card">
      <h2>المبيعات حسب الفئة</h2>
      <p class="sub">نفس المقياس (total_sales) مُجمَّع على بُعد مختلف (category) — بدون أي استعلام جديد مكتوب يدوياً</p>
      ${barChartSvg(byCategory)}
    </div>` : `
    <div class="card">
      <p class="sub" style="margin:0">ما فيه بيانات مبيعات لهذا المستأجر بعد. صاحب الحساب يقدر يضيف عمليات بيع من <a href="https://${APP_HOST}/dashboard">لوحته</a>.</p>
    </div>`}
  </div>
  <footer>هذه بيانات إثبات تقني (PoC). الهوية (${tenant.primary_color} / ${tenant.accent_color}) قُرئت من صف المستأجر في Postgres المرتبط بـ ${escapeHtml(hostname)} فقط. الرسوم البيانية تستخدم لوحة ألوان محايدة مُتحقَّق منها لسهولة الوصول (عمى الألوان + التباين)، وليست ألوان الهوية — لأن الأخيرة فشلت هذا الفحص عند استخدامها كسلاسل بيانات.</footer>
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
  <h1>🟢 بيئة نسق للإثبات التقني — تعمل (v3: Postgres + مصادقة حقيقية + طبقة دلالية BI)</h1>
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

    // ---- API: إضافة عملية بيع لمستأجر (يتطلب ملكية المستأجر) ----
    const salesMatch = url.pathname.match(/^\/api\/tenants\/([a-z0-9.-]+)\/sales$/);
    if (salesMatch && req.method === 'POST') {
      const session = getSessionFromReq(req);
      if (!session) return sendJson(res, 401, { error: 'سجّلي دخولك أولاً' });
      const targetHost = salesMatch[1];
      const tenant = await findTenantByHost(targetHost);
      if (!tenant) return sendJson(res, 404, { error: 'المستأجر غير موجود' });
      if (tenant.owner_user_id !== session.uid) {
        return sendJson(res, 403, { error: tenant.owner_user_id ? 'هذا المستأجر ما هو حسابك' : 'هذا مستأجر تجريبي للعرض فقط، ما يقبل إضافات' });
      }
      const data = await readJsonBody(req).catch(() => null);
      if (!data) return sendJson(res, 400, { error: 'JSON غير صالح' });
      const amount = Number(data.amount);
      if (!Number.isFinite(amount) || amount <= 0) return sendJson(res, 400, { error: 'المبلغ غير صالح' });
      const category = String(data.category || 'عام').slice(0, 60);
      const customer = String(data.customer || 'عميل').slice(0, 80);
      const occurredOn = /^\d{4}-\d{2}-\d{2}$/.test(data.date) ? data.date : new Date().toISOString().slice(0, 10);
      await pool.query(
        `INSERT INTO sales (tenant_hostname, occurred_on, category, customer_name, amount) VALUES ($1,$2,$3,$4,$5)`,
        [targetHost, occurredOn, category, customer, amount]
      );
      return sendJson(res, 201, { ok: true });
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
      const since = new Date(Date.now() - 13 * 86400000).toISOString().slice(0, 10);
      const kpis = await queryMeasures(hostname, ['total_sales', 'active_customers', 'avg_deal', 'deal_count'], null);
      const trendRaw = await queryMeasures(hostname, ['total_sales'], 'day', { since });
      // نكمل الأيام الناقصة بصفر عشان الرسم يغطي كل الـ14 يوم حتى لو ما فيه مبيعات ببعضها
      const trendByDay = new Map(trendRaw.map((r) => [r.dim, r]));
      const trend = [];
      for (let dayAgo = 13; dayAgo >= 0; dayAgo--) {
        const day = new Date(Date.now() - dayAgo * 86400000).toISOString().slice(0, 10);
        trend.push(trendByDay.get(day) || { dim: day, total_sales: 0 });
      }
      const byCategory = await queryMeasures(hostname, ['total_sales'], 'category');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(tenantDashboardHtml(hostname, tenant, kpis, trend, byCategory));
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
      console.log(`نسق PoC v3 يعمل على http://localhost:${PORT}`);
      console.log(`جرّب: curl -H "Host: shorooq.${ROOT_DOMAIN}" http://localhost:${PORT}/`);
    });
  })
  .catch((err) => {
    console.error('فشل تجهيز قاعدة البيانات:', err);
    process.exit(1);
  });
