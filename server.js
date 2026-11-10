import http from "node:http";
import fs from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { WebSocketServer, WebSocket } from "ws";

/*
 * ATARENVER GATE — RENDER ENTRY + VLESS GENERATOR
 * ------------------------------------------------
 * Public client endpoint: this Render service.
 * Fixed upstream: https://atavpnvercel.vercel.app
 * VLESS authentication/path must match the ServerVPN deployment.
 * WebSocket frames are bridged transparently to the single Vercel upstream.
 */

const PORT = Number(process.env.PORT || 10000);
const DATA_DIR = process.env.DATA_DIR || "/app/data";
const CONFIG_FILE = process.env.CONFIG_FILE || path.join(DATA_DIR, "config.json");

// One fixed ServerVPN backend. Public clients connect to this Gate on Render;
// the Gate forwards their WebSocket stream to the ServerVPN deployment on Vercel.
const SERVERVPN_ORIGIN = new URL(process.env.SERVERVPN_ORIGIN || "https://atavpnvercel.vercel.app");
if (SERVERVPN_ORIGIN.protocol !== "https:") {
  throw new Error("SERVERVPN_ORIGIN harus menggunakan https://");
}
const SERVERVPN_HOST = SERVERVPN_ORIGIN.hostname;

// Must match UUID and WSPATH used by ServerVPN/index.js.
const VPN_UUID = String(process.env.VPN_UUID || "d1cf4b9c-3e57-085d-b34a-797fcf601381").trim();
const VPN_WS_PATH = (() => {
  const value = String(process.env.VPN_WS_PATH || "/d1cf4b9c").trim();
  const normalized = "/" + value.replace(/^\/+|\/+$/g, "");
  if (!/^\/[A-Za-z0-9._~-]{1,100}$/.test(normalized)) {
    throw new Error("VPN_WS_PATH tidak valid; gunakan contoh /d1cf4b9c");
  }
  return normalized;
})();
if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(VPN_UUID)) {
  throw new Error("VPN_UUID harus berupa UUID valid");
}

const DEFAULT_ADMIN_PASSWORD =
  process.env.DEFAULT_ADMIN_PASSWORD || "admin123";

const CONFIG_CACHE_TTL_MS = 30_000;
const BACKEND_DEAD_TTL_MS = 60_000;
const BACKEND_FAILURE_THRESHOLD = 2;
const REQUEST_TIMEOUT_MS = 10_000;
const HEALTH_TIMEOUT_MS = 5_000;

const LOGIN_MAX_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60_000;
const LOGIN_BLOCK_MS = 15 * 60_000;
const SESSION_TTL_SEC = 8 * 60 * 60;

let configMemory = { value: null, ts: 0 };
let configLoaded = false;

const backendState = new Map();
const loginAttempts = new Map();

function normalizeHost(value) {
  let s = String(value || "").trim().toLowerCase();
  s = s.replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  return /^[a-z0-9.-]+$/.test(s) ? s : "";
}



function escapeHTML(v) {
  return String(v ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}


function minifyHTML(s) {
  return s.replace(/<!--[\s\S]*?-->/g, "").replace(/>\s+</g, "><").trim();
}


function getBackendInfo(host) {
  let s = backendState.get(host);
  if (!s) {
    s = { failures: 0, deadUntil: 0, lastOk: 0, lastFail: 0, latency: null };
    backendState.set(host, s);
  }
  return s;
}

function isBackendDead(host) {
  const s = getBackendInfo(host);
  if (s.deadUntil && Date.now() >= s.deadUntil) {
    s.deadUntil = 0;
    s.failures = 0;
  }
  return s.deadUntil > Date.now();
}

function markBackendFailure(host) {
  const s = getBackendInfo(host);
  s.failures++;
  s.lastFail = Date.now();
  if (s.failures >= BACKEND_FAILURE_THRESHOLD) {
    s.deadUntil = Date.now() + BACKEND_DEAD_TTL_MS;
  }
}

function markBackendOK(host, latency = null) {
  const s = getBackendInfo(host);
  s.failures = 0;
  s.deadUntil = 0;
  s.lastOk = Date.now();
  if (Number.isFinite(latency)) s.latency = latency;
}

function backendStats(host) {
  const s = getBackendInfo(host);
  return {
    host,
    alive: !isBackendDead(host),
    failures: s.failures,
    deadUntil: s.deadUntil || 0,
    lastOk: s.lastOk || 0,
    lastFail: s.lastFail || 0,
    latency: s.latency
  };
}

async function sha256(text) {
  return crypto.createHash("sha256").update(String(text)).digest("hex");
}

function constantTimeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

function b64urlEncode(s) {
  return Buffer.from(String(s)).toString("base64url");
}

function b64urlDecode(s) {
  try { return Buffer.from(String(s), "base64url").toString(); }
  catch { return ""; }
}

function hmacSHA256(secret, text) {
  return crypto.createHmac("sha256", String(secret)).update(String(text)).digest("hex");
}

function getClientIP(req) {
  return String(
    req.headers["x-real-ip"] ||
    String(req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

async function ensureDataDir() {
  try {
    await fs.mkdir(DATA_DIR, { recursive: true });
  } catch (err) {
    console.error(`[Atarenver Gate] Tidak dapat membuat DATA_DIR=${DATA_DIR}:`, err);
    throw new Error(`DATA_DIR tidak dapat ditulis: ${DATA_DIR} (${err.code || err.message})`);
  }
}

async function readConfig(force = false) {
  const now = Date.now();
  if (!force && configMemory.value && now - configMemory.ts < CONFIG_CACHE_TTL_MS) {
    return configMemory.value;
  }

  if (!configLoaded) {
    try {
      const raw = await fs.readFile(CONFIG_FILE, "utf8");
      const cfg = JSON.parse(raw);
      configMemory = { value: cfg && typeof cfg === "object" ? cfg : {}, ts: now };
    } catch {
      configMemory = { value: {}, ts: now };
    }
    configLoaded = true;
  } else if (force) {
    try {
      const raw = await fs.readFile(CONFIG_FILE, "utf8");
      const cfg = JSON.parse(raw);
      configMemory = { value: cfg && typeof cfg === "object" ? cfg : {}, ts: now };
    } catch {}
  }

  return configMemory.value || {};
}

async function writeConfig(patch) {
  await ensureDataDir();
  const current = await readConfig(true);
  const merged = { ...current, ...patch };
  const tmp = `${CONFIG_FILE}.tmp`;
  await fs.writeFile(tmp, JSON.stringify(merged, null, 2), "utf8");
  await fs.rename(tmp, CONFIG_FILE);
  configMemory = { value: merged, ts: Date.now() };
  return merged;
}

async function getBackends() {
  return [SERVERVPN_HOST];
}

async function getAdminPasswordHash() {
  const cfg = await readConfig();
  if (cfg.passwordHash) return String(cfg.passwordHash);
  return sha256(DEFAULT_ADMIN_PASSWORD);
}

function loginCheck(ip) {
  const now = Date.now();
  const r = loginAttempts.get(ip);
  if (!r) return { ok: true };
  if (r.blockedUntil > now) {
    return { ok: false, retryAfter: Math.ceil((r.blockedUntil - now) / 1000) };
  }
  if (now - r.first > LOGIN_WINDOW_MS) loginAttempts.delete(ip);
  return { ok: true };
}

function loginFail(ip) {
  const now = Date.now();
  let r = loginAttempts.get(ip);
  if (!r || now - r.first > LOGIN_WINDOW_MS) {
    r = { count: 0, first: now, blockedUntil: 0 };
  }
  r.count++;
  if (r.count >= LOGIN_MAX_ATTEMPTS) {
    r.blockedUntil = now + LOGIN_BLOCK_MS;
    r.count = 0;
    r.first = now;
  }
  loginAttempts.set(ip, r);
}

function loginSuccess(ip) {
  loginAttempts.delete(ip);
}

function createSession(ip) {
  const secret = String(
    process.env.SESSION_SECRET ||
    process.env.ADMIN_SESSION_SECRET ||
    process.env.ADMIN_SECRET ||
    DEFAULT_ADMIN_PASSWORD
  );
  const payload = `${Date.now() + SESSION_TTL_SEC * 1000}.${ip}`;
  const sig = hmacSHA256(secret, payload);
  return `${b64urlEncode(payload)}.${sig}`;
}

function verifySession(req) {
  const cookie = parseCookies(req).atarenver_admin;
  if (!cookie) return false;
  const dot = cookie.lastIndexOf(".");
  if (dot < 1) return false;

  const payload = b64urlDecode(cookie.slice(0, dot));
  const sig = cookie.slice(dot + 1);
  const [exp, ip] = payload.split(".");
  if (!exp || !ip || Number(exp) < Date.now()) return false;
  if (ip !== getClientIP(req)) return false;

  const secret = String(
    process.env.SESSION_SECRET ||
    process.env.ADMIN_SESSION_SECRET ||
    process.env.ADMIN_SECRET ||
    DEFAULT_ADMIN_PASSWORD
  );
  const expected = hmacSHA256(secret, payload);
  return constantTimeEqual(sig, expected);
}

async function fetchWithTimeout(url, init = {}, timeoutMs = 10_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

function buildVlessConfig(publicHost) {
  const host = normalizeHost(publicHost);
  if (!host) throw new Error("Hostname Gate tidak valid");

  // The account must use the same UUID/path the Vercel ServerVPN validates.
  const query = [
    `path=${encodeURIComponent(VPN_WS_PATH)}`,
    "security=tls",
    "encryption=none",
    "insecure=0",
    `host=${encodeURIComponent(host)}`,
    "fp=chrome",
    "type=ws",
    "allowInsecure=0",
    `sni=${encodeURIComponent(host)}`
  ].join("&");

  return `vless://${VPN_UUID}@${host}:443?${query}#ver`;
}

function buildSubscriptionPage(publicHost) {
  const config = buildVlessConfig(publicHost);
  const escaped = escapeHTML(config);
  const host = normalizeHost(publicHost);

  return minifyHTML(`<!doctype html><html lang="id"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Atarenver VPN Generator</title>
<style>
:root{--bg:#090a0f;--panel:#17131f;--text:#f1eff6;--muted:#9b96a8;--line:rgba(220,214,235,.14);--cyan:#00f0ff;--green:#45f5a1}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at top,#12212b 0,#090a0f 48%);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,sans-serif}
.wrap{width:min(760px,calc(100% - 28px));margin:0 auto;padding:28px 0 56px}.top,.card{background:rgba(23,19,31,.9);border:1px solid var(--line);border-radius:12px;box-shadow:0 18px 50px rgba(0,0,0,.22)}
.top{padding:20px;display:flex;justify-content:space-between;align-items:center;gap:14px}.brand{display:flex;align-items:center;gap:12px}.mark{width:42px;height:42px;display:grid;place-items:center;border:1px solid rgba(0,240,255,.35);border-radius:9px;color:var(--cyan);font-weight:800}.brand h1{font-size:16px;margin:0}.brand p{font-size:10px;color:var(--muted);margin:5px 0 0;letter-spacing:.12em}.status{font-size:10px;color:var(--green);border:1px solid rgba(69,245,161,.25);padding:7px 9px;border-radius:6px}
.intro{padding:28px 4px 18px}.intro small{color:var(--cyan);letter-spacing:.16em;font-size:10px}.intro h2{font-size:27px;margin:8px 0}.intro p{color:var(--muted);font-size:13px;margin:0;line-height:1.6}.card{padding:20px}.label{display:flex;justify-content:space-between;gap:12px;color:var(--muted);font-size:10px;letter-spacing:.1em;margin-bottom:10px}.config{padding:14px;background:#090a0f;border:1px solid var(--line);border-radius:8px;overflow-wrap:anywhere;word-break:break-word;font:12px/1.7 ui-monospace,SFMono-Regular,Menlo,monospace;color:#b9faff;user-select:text}
button{width:100%;margin-top:13px;padding:13px;border:1px solid rgba(0,240,255,.4);border-radius:7px;background:rgba(0,240,255,.1);color:#a5faff;font-weight:700;cursor:pointer}button:hover{background:rgba(0,240,255,.18)}.meta{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:14px}.meta div{padding:12px;border:1px solid var(--line);border-radius:7px}.meta small{display:block;color:var(--muted);font-size:9px;margin-bottom:6px}.meta strong{font-size:11px;overflow-wrap:anywhere}.foot{text-align:center;color:#706b7a;font-size:10px;margin-top:18px}
@media(max-width:520px){.top{align-items:flex-start}.intro h2{font-size:23px}.meta{grid-template-columns:1fr}.card{padding:15px}}
</style></head><body><main class="wrap">
<section class="top"><div class="brand"><div class="mark">AV</div><div><h1>ATA VPN <span style="color:var(--cyan)">GATE</span></h1><p>VLESS ACCOUNT GENERATOR</p></div></div><span class="status">● READY</span></section>
<section class="intro"><small>PERSONAL CONFIGURATION</small><h2>VLESS WebSocket TLS</h2><p>Konfigurasi dibuat otomatis berdasarkan domain Gate Render. Gunakan tombol salin untuk memasukkan akun ke aplikasi VPN yang mendukung VLESS.</p></section>
<section class="card"><div class="label"><span>VLESS CONFIG</span><span>PORT 443</span></div><div class="config" id="config">${escaped}</div><button id="copy">SALIN KONFIGURASI</button>
<div class="meta"><div><small>SERVER / SNI</small><strong>${escapeHTML(host)}</strong></div><div><small>WEBSOCKET PATH</small><strong>${escapeHTML(VPN_WS_PATH)}</strong></div></div></section>
<p class="foot">Atarenver Gate · ServerVPN upstream: ${escapeHTML(SERVERVPN_HOST)}</p>
</main><script>
const btn=document.getElementById('copy');btn.addEventListener('click',async()=>{const value=document.getElementById('config').textContent;try{await navigator.clipboard.writeText(value);btn.textContent='TERSALIN ✓';}catch{const t=document.createElement('textarea');t.value=value;document.body.appendChild(t);t.select();document.execCommand('copy');t.remove();btn.textContent='TERSALIN ✓';}setTimeout(()=>btn.textContent='SALIN KONFIGURASI',1800)});
</script></body></html>`);
}

function sanitizeForwardHeaders(headers) {
  const skip = new Set([
    "host","connection","upgrade","content-length",
    "cf-connecting-ip","cf-ray","cf-visitor","cf-worker",
    "x-forwarded-host","x-forwarded-proto"
  ]);
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (!skip.has(k.toLowerCase())) out[k] = v;
  }
  return out;
}

async function readRequestBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

async function forwardHTTP(req, res) {
  const backends = await getBackends();
  if (!backends.length) return sendText(res, 503, "No backend configured");

  const candidates = backends.filter(h => !isBackendDead(h));
  const usable = candidates.length ? candidates : backends;

  const incoming = new URL(req.url, `https://${req.headers.host || "localhost"}`);
  const body = req.method === "GET" || req.method === "HEAD" ? undefined : await readRequestBody(req);
  let lastError = null;

  for (const host of usable) {
    try {
      const target = new URL(`${incoming.pathname}${incoming.search}`, SERVERVPN_ORIGIN);
      target.protocol = "https:";
      target.hostname = host;
      const headers = sanitizeForwardHeaders(req.headers);
      headers["x-forwarded-host"] = req.headers.host || "";
      headers["x-atarenver-gate"] = "1";

      const started = Date.now();
      const upstream = await fetchWithTimeout(target.toString(), {
        method: req.method,
        headers,
        body,
        redirect: "manual"
      }, REQUEST_TIMEOUT_MS);

      const latency = Date.now() - started;
      if (upstream.status >= 500 || upstream.status === 429) {
        markBackendFailure(host);
        lastError = new Error(`${host}: HTTP ${upstream.status}`);
        continue;
      }

      markBackendOK(host, latency);
      const buf = Buffer.from(await upstream.arrayBuffer());
      const outHeaders = {};
      for (const [k,v] of upstream.headers) {
        if (!["connection","transfer-encoding"].includes(k.toLowerCase())) outHeaders[k] = v;
      }
      outHeaders["x-atarenver-upstream"] = host;
      outHeaders["x-atarenver-latency"] = String(latency);
      res.writeHead(upstream.status, outHeaders);
      return res.end(buf);
    } catch (e) {
      markBackendFailure(host);
      lastError = e;
    }
  }

  console.error("ServerVPN upstream HTTP gagal:", lastError?.message || lastError);
  return sendJSON(res, 503, { ok:false, error:"ServerVPN upstream unavailable", backends:usable.length });
}

function websocketHeaders(req, host) {
  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) {
    const key = k.toLowerCase();
    if (["host","connection","upgrade","sec-websocket-key","sec-websocket-version","sec-websocket-extensions","content-length"].includes(key)) continue;
    headers[k] = v;
  }
  headers["x-forwarded-host"] = req.headers.host || "";
  headers["x-atarenver-gate"] = "1";
  return headers;
}

async function proxyWebSocket(req, clientSocket, head) {
  const requestURL = new URL(req.url, `https://${req.headers.host || "localhost"}`);
  if (requestURL.pathname !== VPN_WS_PATH) {
    try { clientSocket.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 9\r\n\r\nNot Found"); } catch {}
    return clientSocket.destroy();
  }

  const backends = await getBackends();
  if (!backends.length) return clientSocket.destroy();

  const candidates = backends.filter(h => !isBackendDead(h));
  const usable = candidates.length ? candidates : backends;

  const incoming = requestURL;

  for (const host of usable) {
    const target = new URL(`${incoming.pathname}${incoming.search}`, SERVERVPN_ORIGIN);
    target.protocol = "wss:";
    target.hostname = host;

    const protocols = req.headers["sec-websocket-protocol"];
    const opts = {
      headers: websocketHeaders(req, host),
      perMessageDeflate: false,
      handshakeTimeout: REQUEST_TIMEOUT_MS
    };
    if (protocols) {
      opts.protocol = String(protocols).split(",")[0].trim();
    }

    const started = Date.now();
    const backend = new WebSocket(target.toString(), opts);

    let settled = false;
    const fail = () => {
      if (settled) return;
      settled = true;
      try { backend.terminate(); } catch {}
      markBackendFailure(host);
    };

    await new Promise(resolve => {
      const timer = setTimeout(() => { fail(); resolve(); }, REQUEST_TIMEOUT_MS);

      backend.once("open", () => {
        clearTimeout(timer);
        settled = true;
        markBackendOK(host, Date.now() - started);

        const wss = new WebSocketServer({ noServer: true });
        wss.handleUpgrade(req, clientSocket, head, client => {
          backend.on("message", (data, isBinary) => {
            if (client.readyState === WebSocket.OPEN) client.send(data, { binary: isBinary });
          });

          backend.on("close", (code, reason) => {
            if (client.readyState === WebSocket.OPEN) {
              // 1006 may be emitted by ws for an abnormal close, but it
              // MUST NOT be sent in a WebSocket close frame.
              const n = Number(code);
              const validCloseCode =
                Number.isInteger(n) &&
                ((n >= 1000 && n <= 1003) || (n >= 1007 && n <= 1014) || (n >= 3000 && n <= 4999));
              try {
                if (validCloseCode) client.close(n, reason);
                else client.terminate();
              } catch {
                try { client.terminate(); } catch {}
              }
            }
            try { wss.close(); } catch {}
          });

          backend.on("error", () => {
            if (client.readyState === WebSocket.OPEN) client.close(1011, "backend error");
          });

          client.on("message", (data, isBinary) => {
            if (backend.readyState === WebSocket.OPEN) backend.send(data, { binary: isBinary });
          });

          client.on("close", () => {
            try {
              if (backend.readyState === WebSocket.OPEN) backend.close(1000, "client closed");
              else if (backend.readyState === WebSocket.CONNECTING) backend.terminate();
            } catch {
              try { backend.terminate(); } catch {}
            }
            try { wss.close(); } catch {}
          });

          client.on("error", () => {
            try {
              if (backend.readyState === WebSocket.OPEN) backend.close(1011, "client error");
              else backend.terminate();
            } catch {
              try { backend.terminate(); } catch {}
            }
            try { wss.close(); } catch {}
          });
        });
        resolve(true);
      });

      backend.once("error", () => { clearTimeout(timer); fail(); resolve(false); });
    });

    if (settled && backend.readyState === WebSocket.OPEN) return;
  }

  try {
    clientSocket.write("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 19\r\n\r\nAll backends failed");
  } catch {}
  clientSocket.destroy();
}

async function checkBackend(host) {
  const started = Date.now();
  try {
    const r = await fetchWithTimeout(new URL("/", SERVERVPN_ORIGIN).toString(), {
      headers: { "user-agent": "AtarenverGate-Health/1.0" }
    }, HEALTH_TIMEOUT_MS);
    const latency = Date.now() - started;
    if (r.status >= 500) {
      markBackendFailure(host);
      return { ...backendStats(host), ok:false, status:r.status, latency };
    }
    markBackendOK(host, latency);
    return { ...backendStats(host), ok:true, status:r.status, latency };
  } catch (e) {
    markBackendFailure(host);
    return { ...backendStats(host), ok:false, status:0, latency:Date.now()-started, error:e.message };
  }
}

function sendJSON(res, status, data, extra = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...extra
  });
  res.end(body);
}

function sendText(res, status, text) {
  res.writeHead(status, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" });
  res.end(text);
}

function adminPage() {
  return `<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Atarenver Gate Admin</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#090a0f;color:#eee;font-family:system-ui,sans-serif}
main{max-width:900px;margin:30px auto;padding:16px}.card{padding:20px;margin-bottom:14px;border:1px solid #292633;border-radius:10px;background:#121019}
h1{margin-top:0;color:#00f0ff}input,button{width:100%;padding:11px;border-radius:6px;border:1px solid #332f3d;background:#0b0b10;color:#eee;margin:5px 0 10px}
.btn{cursor:pointer;background:#071d20;border-color:#00f0ff;color:#8deaf0}.backend{padding:9px;border-bottom:1px solid #24212b;font:12px monospace;display:flex;justify-content:space-between;gap:10px;overflow-wrap:anywhere}.ok{color:#45f5a1}.bad{color:#ff5678}.muted{color:#9b96a8;font-size:12px}
</style></head><body><main>
<div class="card" id="login"><h1>Atarenver Gate</h1><p>Admin panel</p>
<input id="password" type="password" placeholder="Password"><button class="btn" id="loginBtn">LOGIN</button>
<p class="muted">Password awal: admin123. Segera ganti setelah login pertama.</p></div>
<div id="panel" style="display:none">
<div class="card"><h1>ServerVPN Upstream</h1><p id="backend" class="muted">${escapeHTML(SERVERVPN_ORIGIN.origin)}</p><p class="muted">WebSocket path: ${escapeHTML(VPN_WS_PATH)} · Backend dikunci ke satu domain Vercel.</p></div>
<div class="card"><h2>Ganti Password Admin</h2>
<input id="newpass" type="password" placeholder="Password baru (min. 10 karakter)">
<button class="btn" id="changePass">CHANGE PASSWORD</button></div>
<div class="card"><h2>Backend Health</h2><button class="btn" id="health">CHECK SERVERVPN</button><div id="results"></div></div>
<div class="card"><button class="btn" id="logout">LOGOUT</button></div>
</div>
<script>
const $=id=>document.getElementById(id);
async function api(url,opt){const r=await fetch(url,opt);let d={};try{d=await r.json()}catch{}if(!r.ok)throw new Error(d.error||'Request failed');return d}
async function load(){await api('/admin/api/config');$('login').style.display='none';$('panel').style.display='block'}
$('loginBtn').onclick=async()=>{try{await api('/admin/api/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:$('password').value})});await load()}catch(e){alert(e.message)}};
$('changePass').onclick=async()=>{try{await api('/admin/api/password',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({password:$('newpass').value})});$('newpass').value='';alert('Password changed')}catch(e){alert(e.message)}};
$('health').onclick=async()=>{try{const d=await api('/admin/api/health');$('results').innerHTML=d.results.map(x=>'<div class="backend"><span>'+x.host+'</span><span class="'+(x.ok?'ok':'bad')+'">'+(x.ok?'OK '+x.status+' '+x.latency+'ms':'FAIL '+(x.error||x.status))+'</span></div>').join('')}catch(e){alert(e.message)}};
$('logout').onclick=async()=>{await fetch('/admin/api/logout',{method:'POST'});location.reload()};
load().catch(()=>{});
</script></main></body></html>`;
}

async function handleAdmin(req, res, url) {
  if (url.pathname === "/admin/api/login" && req.method === "POST") {
    const ip = getClientIP(req);
    const lim = loginCheck(ip);
    if (!lim.ok) return sendJSON(res, 429, { error:"Too many attempts", retryAfter:lim.retryAfter });

    let body = {};
    try { body = JSON.parse((await readRequestBody(req)).toString() || "{}"); } catch {}
    const expected = await getAdminPasswordHash();
    const suppliedHash = await sha256(String(body.password || ""));

    if (!constantTimeEqual(suppliedHash, expected)) {
      loginFail(ip);
      return sendJSON(res, 401, { error:"Invalid password" });
    }

    loginSuccess(ip);
    const token = createSession(ip);
    return sendJSON(res, 200, { ok:true }, {
      "set-cookie": `atarenver_admin=${token}; Max-Age=${SESSION_TTL_SEC}; Path=/admin; HttpOnly; Secure; SameSite=Strict`
    });
  }

  if (url.pathname === "/admin/api/logout" && req.method === "POST") {
    return sendJSON(res, 200, { ok:true }, {
      "set-cookie": "atarenver_admin=; Max-Age=0; Path=/admin; HttpOnly; Secure; SameSite=Strict"
    });
  }

  if (!verifySession(req)) return sendJSON(res, 401, { error:"Unauthorized" });

  if (url.pathname === "/admin/api/config" && req.method === "GET") {
    return sendJSON(res, 200, {
      serverVpn: SERVERVPN_ORIGIN.origin,
      backend: SERVERVPN_HOST,
      uuid: VPN_UUID,
      websocketPath: VPN_WS_PATH
    });
  }


  if (url.pathname === "/admin/api/password" && req.method === "POST") {
    let body = {};
    try { body = JSON.parse((await readRequestBody(req)).toString() || "{}"); } catch {}
    const password = String(body.password || "");
    if (password.length < 10 || password.length > 200) {
      return sendJSON(res, 400, { error:"Password harus 10-200 karakter." });
    }
    const hash = await sha256(password);
    await writeConfig({ passwordHash:hash });
    const token = createSession(getClientIP(req));
    return sendJSON(res, 200, { ok:true }, {
      "set-cookie": `atarenver_admin=${token}; Max-Age=${SESSION_TTL_SEC}; Path=/admin; HttpOnly; Secure; SameSite=Strict`
    });
  }

  if (url.pathname === "/admin/api/health" && req.method === "GET") {
    const hosts = await getBackends();
    return sendJSON(res, 200, { results: await Promise.all(hosts.map(checkBackend)) });
  }

  return sendJSON(res, 404, { error:"Not found" });
}

async function handleHTTP(req, res) {
  const started = Date.now();
  const url = new URL(req.url, `https://${req.headers.host || "localhost"}`);

  res.once("finish", () => {
    const ms = Date.now() - started;
    if (req.method !== "GET" || url.pathname === "/" || url.pathname.startsWith("/sub")) {
      console.log(`[HTTP] ${req.method} ${url.pathname} -> ${res.statusCode} ${ms}ms`);
    }
  });

  if (url.pathname === "/health") {
    const backends = await getBackends();
    return sendJSON(res, 200, {
      ok:true,
      service:"Atarenver Gate",
      runtime:"Render / Node.js",
      serverVpn:SERVERVPN_HOST,
      websocketPath:VPN_WS_PATH,
      backends:backends.length,
      alive:backends.filter(h => !isBackendDead(h)).length,
      time:new Date().toISOString()
    });
  }

  // Fast client connectivity probes.
  // Client HEAD/OPTIONS probes are answered locally; they do not need to
  // traverse the ServerVPN upstream.
  if (req.method === "HEAD" || req.method === "OPTIONS") {
    res.writeHead(204, {
      "cache-control": "no-store",
      "content-length": "0",
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,HEAD,OPTIONS",
      "access-control-allow-headers": "*"
    });
    return res.end();
  }

  if (url.pathname.startsWith("/admin/api/")) return handleAdmin(req, res, url);
  if (url.pathname === "/admin" || url.pathname === "/admin/") {
    return res.end(adminPage());
  }

  if (url.pathname === "/sub.txt") {
    const host = normalizeHost(req.headers.host);
    if (!host) return sendText(res, 400, "Invalid Gate hostname");
    res.writeHead(200, {
      "content-type":"text/plain; charset=utf-8",
      "cache-control":"no-store"
    });
    return res.end(buildVlessConfig(host) + "\n");
  }

  if (url.pathname === "/sub" || url.pathname.startsWith("/sub/")) {
    const host = normalizeHost(req.headers.host);
    if (!host) return sendText(res, 400, "Invalid Gate hostname");
    const result = buildSubscriptionPage(host);
    res.writeHead(200, {
      "content-type":"text/html; charset=utf-8",
      "cache-control":"no-store"
    });
    return res.end(result);
  }

  if (url.pathname === "/") {
    return res.end(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Atarenver Gate</title><body style="background:#090a0f;color:#eee;font:16px system-ui;padding:40px"><h1 style="color:#00f0ff">Atarenver Gate</h1><p>Gate is online and configured to forward tunnel traffic to ServerVPN.</p><p><a href="/sub" style="color:#8deaf0">VPN Generator</a> · <a href="/admin" style="color:#8deaf0">/admin</a> · <a href="/health" style="color:#8deaf0">/health</a></p></body>`);
  }

  return forwardHTTP(req, res);
}

await ensureDataDir();
await readConfig();

const server = http.createServer((req, res) => {
  handleHTTP(req, res).catch(e => {
    console.error("HTTP:", e);
    if (!res.headersSent) sendJSON(res, 500, { ok:false, error:"Internal server error" });
    else res.destroy();
  });
});

server.on("upgrade", (req, socket, head) => {
  proxyWebSocket(req, socket, head).catch(e => {
    console.error("WebSocket:", e);
    try { socket.destroy(); } catch {}
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`[Atarenver Gate] listening on 0.0.0.0:${PORT}`);
  console.log(`[Atarenver Gate] backend: ${SERVERVPN_HOST}`);
});
