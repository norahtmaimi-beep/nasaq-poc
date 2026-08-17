const http = require('http');
const { URL } = require('url');

const PORT = process.env.PORT || 4000;
const ROOT_DOMAIN = 'nasaq-platform.com';

const tenants = new Map([
  ['shorooq.' + ROOT_DOMAIN, { name: 'شركة شروق التجارية', primary: '#286140', accent: '#B58500', createdAt: '2026-08-01' }],
  ['nova.' + ROOT_DOMAIN,    { name: 'Nova Logistics',      primary: '#B58500', accent: '#1B365D', createdAt: '2026-08-05' }],
  ['amal.' + ROOT_DOMAIN,    { name: 'جمعية أمل الخيرية',    primary: '#1B365D', accent: '#6BCABA', createdAt: '2026-08-10' }],
]);

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' }[c]));
}

function normalizeHost(rawHost) {
  return String(rawHost || '').split(':')[0].trim().toLowerCase();
}

function tenantDashboardHtml(hostname, tenant) {
  const name = escapeHtml(tenant.name);
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<title>${name} · نسق</title>
<style>
  body{font-family:Segoe UI, Tahoma, sans-serif; background:#f9f9f7; margin:0; color:#0b0b0b;}
  .bar{background:${tenant.primary}; color:#fff; padding:16px 24px; display:flex; justify-content:space-between; align-items:center;}
  .bar .host{font-family:Consolas, monospace; font-size:12px; opacity:.85; direction:ltr;}
  .wrap{max-width:720px; margin:32px auto; padding:0 20px;}
  .card{background:#fff; border:1px solid rgba(11,11,11,.08); border-radius:14px; padding:22px; box-shadow:0 8px 24px rgba(20,20,15,.06);}
  .badge{display:inline-block; background:${tenant.accent}22; color:${tenant.accent}; border:1px solid ${tenant.accent}55; padding:4px 10px; border-radius:999px; font-size:12px; font-weight:700; margin-bottom:14px;}
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
      <div class="badge">✓ تمّ التعرّف على المستأجر تلقائياً من اسم النطاق</div>
      <h1>لوحة ${name}</h1>
      <div class="meta">مُنشأ الحساب: ${escapeHtml(tenant.createdAt)} · مساحة عمل معزولة بالكامل عن بقية المشتركين</div>
      <div class="kpi-row">
        <div class="kpi"><b>—</b>إجمالي المبيعات</div>
        <div class="kpi"><b>—</b>عملاء نشطون</div>
        <div class="kpi"><b>—</b>معدل التحويل</div>
      </div>
    </div>
  </div>
  <footer>هذه بيانات إثبات تقني (PoC) — لا اتصال ببيانات فعلية بعد. الهوية (${tenant.primary} / ${tenant.accent}) قُرئت من سجل المستأجر المرتبط بـ ${escapeHtml(hostname)} فقط.</footer>
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
  <p style="color:#666;font-size:14px">لو هذا نطاقك، تأكد إن سجل CNAME يشير لبيئة نسق، وإن المستأجر مُسجَّل عبر <code>POST /api/tenants</code>.</p>
</div></body></html>`;
}

function rootHtml() {
  const rows = [...tenants.entries()].map(([host, t]) =>
    `<li><code>${escapeHtml(host)}</code> — ${escapeHtml(t.name)}</li>`).join('');
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>نسق — بيئة الإثبات التقني</title>
<style>body{font-family:Segoe UI,Tahoma,sans-serif;background:#0d0d0d;color:#eee;padding:40px;line-height:1.8}
code{direction:ltr;display:inline-block;background:#1a1a19;padding:2px 8px;border-radius:6px;color:#8fd6b8}
a{color:#8fd6b8}</style></head>
<body>
  <h1>🟢 بيئة نسق للإثبات التقني — تعمل</h1>
  <p>هذا هو النطاق الجذر (<code>${ROOT_DOMAIN}</code>). المستأجرون الحاليون:</p>
  <ul>${rows}</ul>
  <p>جرّبي طلب أي نطاق فرعي أعلاه بترويسة <code>Host</code> لتري تحليل المستأجر يعمل تلقائياً.</p>
  <p>تسجيل مستأجر جديد فورياً: <code>POST /api/tenants</code> بجسم JSON: <code>{"subdomain":"demo","name":"..","primary":"#286140","accent":"#B58500"}</code></p>
</body></html>`;
}

const server = http.createServer((req, res) => {
  const hostname = normalizeHost(req.headers.host);
  const url = new URL(req.url, 'http://placeholder');

  if (url.pathname === '/api/tenants' && req.method === 'POST') {
    let body = '';
    req.on('data', (chunk) => { body += chunk; if (body.length > 10_000) req.destroy(); });
    req.on('end', () => {
      try {
        const data = JSON.parse(body || '{}');
        const sub = String(data.subdomain || '').trim().toLowerCase().replace(/[^a-z0-9-]/g, '');
        if (!sub) { res.writeHead(400, {'Content-Type':'application/json; charset=utf-8'}); return res.end(JSON.stringify({error:'subdomain مطلوب'})); }
        const fullHost = `${sub}.${ROOT_DOMAIN}`;
        const tenant = {
          name: String(data.name || sub).slice(0, 80),
          primary: /^#[0-9a-fA-F]{6}$/.test(data.primary) ? data.primary : '#286140',
          accent: /^#[0-9a-fA-F]{6}$/.test(data.accent) ? data.accent : '#B58500',
          createdAt: new Date().toISOString().slice(0,10),
        };
        tenants.set(fullHost, tenant);
        res.writeHead(201, {'Content-Type':'application/json; charset=utf-8'});
        res.end(JSON.stringify({ ok:true, liveUrl: `https://${fullHost}`, note: 'مُسجَّل في بيئة الإثبات فقط — يحتاج سجل DNS فعلي ليصبح حياً على الإنترنت.' }, null, 2));
      } catch (e) {
        res.writeHead(400, {'Content-Type':'application/json; charset=utf-8'});
        res.end(JSON.stringify({ error: 'JSON غير صالح' }));
      }
    });
    return;
  }

  if (url.pathname === '/api/tenants' && req.method === 'GET') {
    res.writeHead(200, {'Content-Type':'application/json; charset=utf-8'});
    return res.end(JSON.stringify(Object.fromEntries(tenants), null, 2));
  }

  if (hostname === ROOT_DOMAIN || hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '') {
    res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
    return res.end(rootHtml());
  }

  const tenant = tenants.get(hostname);
  if (tenant) {
    res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
    return res.end(tenantDashboardHtml(hostname, tenant));
  }

  res.writeHead(404, {'Content-Type':'text/html; charset=utf-8'});
  return res.end(notProvisionedHtml(hostname));
});

server.listen(PORT, () => {
  console.log(`نسق PoC server يعمل على http://localhost:${PORT}`);
});
