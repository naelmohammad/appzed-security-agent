/**
 * AppZed Security Agent (sample). Cloudflare live collection + multi-vendor
 * findings ingestion (aws/gcp/azure/oracle/digitalocean/onprem) with a
 * dashboard: findings, monitoring, configuration, administration.
 * Bindings: AI, DB (d1). Vars: CF_ACCOUNT_ID. Secrets: CF_API_TOKEN.
 */
const API = "https://api.cloudflare.com/client/v4";
const PROVIDERS = ["cloudflare", "aws", "gcp", "azure", "oracle", "digitalocean", "onprem"];
const SEVERITIES = ["info", "low", "medium", "high", "critical"];
const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, provider TEXT NOT NULL, category TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL, detail TEXT DEFAULT '', ref TEXT DEFAULT '', created_at TEXT DEFAULT (datetime('now')))",
  "CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, status TEXT NOT NULL, detail TEXT DEFAULT '', created_at TEXT DEFAULT (datetime('now')))",
].join(";");

async function init(env) {
  for (const stmt of SCHEMA.split(";")) {
    const s = stmt.trim();
    if (s) await env.DB.exec(s);
  }
}

async function cf(env, path) {
  const res = await fetch(API + path, { headers: { authorization: "Bearer " + env.CF_API_TOKEN } });
  const json = await res.json().catch(() => null);
  if (!res.ok || !json || json.success !== true) throw new Error("CF API " + path + ": HTTP " + res.status);
  return json.result;
}

async function collect(env) {
  const acct = env.CF_ACCOUNT_ID;
  const [tagged, workers, queues, d1, kv, r2] = await Promise.all([
    cf(env, "/accounts/" + acct + "/tags/resources?per_page=100").catch(() => []),
    cf(env, "/accounts/" + acct + "/workers/scripts?per_page=100").catch(() => []),
    cf(env, "/accounts/" + acct + "/queues?per_page=100").catch(() => []),
    cf(env, "/accounts/" + acct + "/d1/database?per_page=100").catch(() => []),
    cf(env, "/accounts/" + acct + "/storage/kv/namespaces?per_page=100").catch(() => []),
    cf(env, "/accounts/" + acct + "/r2/buckets?per_page=100").catch(() => []),
  ]);
  const tagById = {};
  for (const t of (Array.isArray(tagged) ? tagged : [])) tagById[t.id] = t.tags || {};
  const req = ["appzed:solution", "appzed:env", "appzed:customer", "appzed:managed"];
  const rows = [];
  const push = (list, idFn, type) => {
    for (const r of (Array.isArray(list) ? list : [])) {
      const name = r.name || r.title || r.queue_name || "?";
      rows.push({ type, id: idFn(r), name, tags: tagById[idFn(r)] || {} });
    }
  };
  push(workers, (r) => r.id || r.name, "worker");
  push(queues, (r) => r.queue_id || r.queue_name, "queue");
  push(d1, (r) => r.uuid || r.name, "d1");
  push(kv, (r) => r.id || r.title, "kv");
  push(r2, (r) => r.name, "r2");
  const out = [["inventory", "info", "Security inventory: " + rows.length + " resources scanned"]];
  const managed = rows.filter((r) => r.name.startsWith("appzed-"));
  const bad = managed.filter((r) => req.some((k) => !(k in r.tags)));
  for (const v of bad.slice(0, 25)) {
    out.push(["tag-policy", "high", v.type + " " + v.name + " missing tags: " + req.filter((k) => !(k in v.tags)).join(",")]);
  }
  out.push(["tag-policy", bad.length ? "medium" : "info",
    bad.length + " of " + managed.length + " managed resources violate tag policy"]);
  return out;
}

async function storeFindings(env, rows, provider) {
  for (const [category, severity, title] of rows) {
    await env.DB.prepare(
      "INSERT INTO findings (id, provider, category, severity, title) VALUES (?, ?, ?, ?, ?)"
    ).bind(crypto.randomUUID(), provider, category, severity, title).run();
  }
}
const DASH = (name) => `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${name} — AppZed agent</title>
<style>body{background:#0A0A0B;color:#e2e8f0;font:14px/1.5 system-ui,sans-serif;margin:0;padding:24px;max-width:960px}
h1{font-size:22px;margin:0 0 4px}h1 span{color:#60a5fa}.sub{color:#94a3b8;font-size:13px;margin:0 0 16px}
.tabs{display:flex;gap:8px;margin:16px 0}.tabs button{background:#fff1;border:1px solid #ffffff22;color:#cbd5e1;border-radius:10px;padding:8px 14px;cursor:pointer}
.tabs button.on{background:#2563eb;border-color:#2563eb;color:#fff}
table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #ffffff14}
th{color:#94a3b8;font-weight:600}.pill{display:inline-block;border-radius:999px;padding:1px 10px;font-size:12px;background:#ffffff14}
.sev-critical{background:#7f1d1d}.sev-high{background:#9a3412}.sev-medium{background:#854d0e}.sev-low{background:#1e40af}.sev-info{background:#334155}
input,select{background:#ffffff0d;border:1px solid #ffffff26;color:#fff;border-radius:10px;padding:8px 10px;margin:4px 4px 4px 0}
button.act{background:#2563eb;border:0;color:#fff;border-radius:10px;padding:8px 14px;cursor:pointer}
pre{background:#0D0D10;border:1px solid #ffffff14;border-radius:12px;padding:12px;overflow:auto;font-size:12px}
.tab{display:none}.tab.on{display:block}</style></head><body>
<h1><span>AppZed</span> ${name}</h1><p class="sub">Findings · Monitoring · Configuration · Administration</p>
<div class="tabs"><button data-t="findings" class="on">Findings</button><button data-t="monitor">Monitoring</button><button data-t="config">Configuration</button><button data-t="admin">Administration</button></div>
<div id="findings" class="tab on"><div><select id="fprov"><option value="">all providers</option></select>
<select id="fsev"><option value="">all severities</option></select> <button class="act" onclick="loadF()">Refresh</button></div>
<table><thead><tr><th>Provider</th><th>Severity</th><th>Title</th><th>Time</th></tr></thead><tbody id="fb"></tbody></table></div>
<div id="monitor" class="tab"><button class="act" onclick="runCollect()">Run collection now</button>
<button class="act" onclick="aiSummary()">AI summary</button><pre id="mon">—</pre></div>
<div id="config" class="tab"><pre id="cfg">—</pre><div><input id="ck" placeholder="key"><input id="cv" placeholder="value">
<button class="act" onclick="setCfg()">Set</button></div></div>
<div id="admin" class="tab"><div id="adm">—</div><div style="margin-top:12px">
<button class="act" onclick="admin('purge')">Purge findings older than 30d</button></div></div>
<script>
const PROVIDERS=${JSON.stringify(["cloudflare","aws","gcp","azure","oracle","digitalocean","onprem"])};
const SEVS=["info","low","medium","high","critical"];
document.querySelectorAll(".tabs button").forEach(b=>b.onclick=()=>{document.querySelectorAll(".tabs button").forEach(x=>x.classList.remove("on"));document.querySelectorAll(".tab").forEach(x=>x.classList.remove("on"));b.classList.add("on");document.getElementById(b.dataset.t).classList.add("on");});
PROVIDERS.forEach(p=>{const o=document.createElement("option");o.value=o.textContent=p;fprov.appendChild(o);});
SEVS.forEach(s=>{const o=document.createElement("option");o.value=o.textContent=s;fsev.appendChild(o);});
async function loadF(){const r=await fetch("/api/findings?provider="+fprov.value+"&severity="+fsev.value).then(r=>r.json());
fb.innerHTML=r.findings.map(f=>"<tr><td>"+f.provider+"</td><td><span class='pill sev-"+f.severity+"'>"+f.severity+"</span></td><td>"+esc(f.title)+"</td><td>"+f.created_at.slice(0,16).replace("T"," ")+"</td></tr>").join("")||"<tr><td colspan=4>No findings yet.</td></tr>";}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));}
async function runCollect(){mon.textContent="collecting…";const r=await fetch("/api/collect",{method:"POST"}).then(r=>r.json());mon.textContent=JSON.stringify(r,null,2);loadF();}
async function aiSummary(){mon.textContent="summarizing…";const r=await fetch("/api/summary").then(r=>r.json());mon.textContent=r.summary||JSON.stringify(r);}
async function loadCfg(){const r=await fetch("/api/config").then(r=>r.json());cfg.textContent=JSON.stringify(r,null,2);}
async function setCfg(){await fetch("/api/config",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({key:ck.value,value:cv.value})});ck.value="";cv.value="";loadCfg();}
async function admin(op){const r=await fetch("/api/admin/"+op,{method:"POST"}).then(r=>r.json());adm.innerHTML="<pre>"+esc(JSON.stringify(r,null,2))+"</pre>";loadF();}
async function loadAdm(){const r=await fetch("/api/status").then(r=>r.json());adm.innerHTML="<pre>"+esc(JSON.stringify(r,null,2))+"</pre>";}
loadF();loadCfg();loadAdm();
</script></body></html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    await init(env).catch(() => null);
    try {
      if (url.pathname === "/") return new Response(DASH("Security Agent"), { headers: { "content-type": "text/html" } });
      if (url.pathname === "/health") return Response.json({ ok: true, solution: "security-agent" });
      if (url.pathname === "/api/status") {
        const n = await env.DB.prepare("SELECT COUNT(*) c FROM findings").first();
        const last = await env.DB.prepare("SELECT kind,status,created_at FROM runs ORDER BY created_at DESC LIMIT 1").first();
        return Response.json({ findings: (n && n.c) || 0, last_run: last || null, token: env.CF_API_TOKEN ? "set" : "missing" });
      }
      if (url.pathname === "/api/findings" && request.method === "GET") {
        const p = url.searchParams.get("provider") || "";
        const s = url.searchParams.get("severity") || "";
        let q = "SELECT provider,category,severity,title,created_at FROM findings WHERE 1=1";
        const args = [];
        if (p) { q += " AND provider=?"; args.push(p); }
        if (s) { q += " AND severity=?"; args.push(s); }
        q += " ORDER BY created_at DESC LIMIT 200";
        const rows = await env.DB.prepare(q).bind(...args).all();
        return Response.json({ findings: rows.results || [] });
      }
      if (url.pathname === "/api/findings" && request.method === "POST") {
        const b = await request.json().catch(() => ({}));
        if (!PROVIDERS.includes(b.provider)) return Response.json({ error: "provider must be one of " + PROVIDERS.join(",") }, { status: 400 });
        if (!SEVERITIES.includes(b.severity)) return Response.json({ error: "severity must be one of " + SEVERITIES.join(",") }, { status: 400 });
        if (!b.title || typeof b.title !== "string") return Response.json({ error: "title is required." }, { status: 400 });
        await env.DB.prepare(
          "INSERT INTO findings (id, provider, category, severity, title, detail, ref) VALUES (?, ?, ?, ?, ?, ?, ?)"
        ).bind(crypto.randomUUID(), b.provider, String(b.category || "external").slice(0, 40), b.severity, b.title.slice(0, 500), String(b.detail || "").slice(0, 2000), String(b.ref || "").slice(0, 300)).run();
        return Response.json({ ok: true }, { status: 201 });
      }
      if (url.pathname === "/api/collect" && request.method === "POST") {
        if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return Response.json({ error: "Missing CF_API_TOKEN/CF_ACCOUNT_ID." }, { status: 500 });
        const rows = await collect(env);
        await storeFindings(env, rows, "cloudflare");
        await env.DB.prepare("INSERT INTO runs (id, kind, status, detail) VALUES (?, 'collect', 'ok', ?)").bind(crypto.randomUUID(), rows.length + " findings").run();
        return Response.json({ ok: true, stored: rows.length });
      }
      if (url.pathname === "/api/summary") {
        const rows = await env.DB.prepare("SELECT provider,severity,title FROM findings ORDER BY created_at DESC LIMIT 50").all();
        const out = await env.AI.run("@cf/meta/llama-3.1-8b-instruct-fp8", {
          messages: [
            { role: "system", content: "Summarize these security findings in 5 bullets ordered by severity. Be specific about remediation." },
            { role: "user", content: JSON.stringify((rows.results || [])).slice(0, 6000) },
          ],
          max_tokens: 400,
        });
        return Response.json({ summary: out.response || "" });
      }
      if (url.pathname === "/api/config" && request.method === "GET") {
        const rows = await env.DB.prepare("SELECT key, value FROM config").all();
        const cfg = {};
        for (const r of (rows.results || [])) cfg[r.key] = r.value;
        return Response.json({ config: cfg, providers: PROVIDERS });
      }
      if (url.pathname === "/api/config" && request.method === "POST") {
        const b = await request.json().catch(() => ({}));
        if (!b.key || typeof b.key !== "string") return Response.json({ error: "key is required." }, { status: 400 });
        await env.DB.prepare("INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(b.key.slice(0, 80), String(b.value ?? "").slice(0, 2000)).run();
        return Response.json({ ok: true });
      }
      if (url.pathname === "/api/admin/purge" && request.method === "POST") {
        await env.DB.prepare("DELETE FROM findings WHERE created_at < datetime('now','-30 days')").run();
        return Response.json({ ok: true });
      }
      return new Response("Not found", { status: 404 });
    } catch (err) {
      return Response.json({ error: String((err && err.message) || err) }, { status: 502 });
    }
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      try {
        await init(env);
        const rows = await collect(env);
        await storeFindings(env, rows, "cloudflare");
        await env.DB.prepare("INSERT INTO runs (id, kind, status, detail) VALUES (?, 'scheduled', 'ok', ?)").bind(crypto.randomUUID(), rows.length + " findings").run();
      } catch { /* next run */ }
    })());
  },
};
