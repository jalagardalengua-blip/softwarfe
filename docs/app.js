/*
 * app.js — Bóveda cifrada con DESBLOQUEO POR PATRÓN (PWA).
 *
 *   - El patrón (secuencia de puntos) actúa como "contraseña".
 *   - Clave derivada con PBKDF2-SHA256 (600k iteraciones).
 *   - Datos cifrados con AES-256-GCM (WebCrypto, nativo).
 *   - La clave NUNCA se guarda: se deriva del patrón al vuelo.
 *   - Tras N fallos -> crypto-erase: se borra salt + ciphertext (irreversible).
 *   - Todo en el dispositivo. Nada se envía a ningún servidor.
 */

const STORE_KEY = "boveda.state.v2";
const PBKDF2_ITERS = 600000;
const enc = new TextEncoder();
const dec = new TextDecoder();

const b64 = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  dec: (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0)),
};

// ---------- persistencia ----------
const loadState = () => { try { return JSON.parse(localStorage.getItem(STORE_KEY)); } catch { return null; } };
const saveState = (s) => localStorage.setItem(STORE_KEY, JSON.stringify(s));
const clearState = () => localStorage.removeItem(STORE_KEY);

// ---------- criptografía ----------
async function deriveKey(secret, saltBytes) {
  const base = await crypto.subtle.importKey("raw", enc.encode("PATTERN:" + secret), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
async function encryptData(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64.enc(iv), ct: b64.enc(ct) };
}
async function decryptData(key, blob) {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64.dec(blob.iv) }, key, b64.dec(blob.ct));
  return JSON.parse(dec.decode(pt));
}

// ---------- modelo ----------
let sessionKey = null, sessionData = null;

async function createVault(pattern, maxAttempts) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(pattern, salt);
  const data = { entries: [] };
  saveState({ version: 2, salt: b64.enc(salt), iters: PBKDF2_ITERS, failed: 0, maxAttempts, destroyed: false, blob: await encryptData(key, data) });
  sessionKey = key; sessionData = data;
}
async function unlockVault(pattern) {
  const s = loadState();
  if (!s || s.destroyed) throw new Error("DESTROYED");
  const key = await deriveKey(pattern, b64.dec(s.salt));
  try {
    const data = await decryptData(key, s.blob);
    s.failed = 0; saveState(s);
    sessionKey = key; sessionData = data; return data;
  } catch {
    s.failed = (s.failed || 0) + 1;
    const left = s.maxAttempts - s.failed;
    if (left <= 0) { selfDestruct(); throw new Error("JUST_DESTROYED"); }
    saveState(s);
    const e = new Error("WRONG"); e.left = left; throw e;
  }
}
function selfDestruct() {
  saveState({ version: 2, destroyed: true, failed: 0, maxAttempts: 0 });
  sessionKey = null; sessionData = null;
}
async function persistSession() {
  const s = loadState();
  s.blob = await encryptData(sessionKey, sessionData);
  saveState(s);
}

// ================= Pattern pad =================
const CENTERS = [];
for (let r = 0; r < 3; r++) for (let c = 0; c < 3; c++) CENTERS.push({ x: 43.33 + c * 86.67, y: 43.33 + r * 86.67 });

function buildPad(padId, lineId, onComplete) {
  const pad = document.getElementById(padId);
  const grid = pad.querySelector(".grid");
  const line = document.getElementById(lineId);
  const dots = [];
  for (let i = 0; i < 9; i++) {
    const cell = document.createElement("div"); cell.className = "cell";
    const dot = document.createElement("div"); dot.className = "dot"; dot.dataset.i = i;
    cell.appendChild(dot); grid.appendChild(cell); dots.push(dot);
  }
  let drawing = false, seq = [], errTimer = null;

  const reset = () => { if (errTimer) { clearTimeout(errTimer); errTimer = null; } seq = []; dots.forEach((d) => d.classList.remove("on")); pad.classList.remove("err"); line.setAttribute("points", ""); };

  function render(liveVb) {
    const pts = seq.map((i) => `${CENTERS[i].x},${CENTERS[i].y}`);
    if (liveVb) pts.push(`${liveVb.x},${liveVb.y}`);
    line.setAttribute("points", pts.join(" "));
  }
  function hit(px, py) {
    const rect = pad.getBoundingClientRect();
    for (const d of dots) {
      const i = +d.dataset.i;
      if (seq.includes(i)) continue;
      const dr = d.getBoundingClientRect();
      const cx = dr.left + dr.width / 2 - rect.left, cy = dr.top + dr.height / 2 - rect.top;
      if (Math.hypot(px - cx, py - cy) < dr.width * 0.95) { seq.push(i); d.classList.add("on"); }
    }
  }
  function toVb(px, py) { const rect = pad.getBoundingClientRect(); return { x: (px / rect.width) * 260, y: (py / rect.height) * 260 }; }
  function pos(e) { const rect = pad.getBoundingClientRect(); return { x: e.clientX - rect.left, y: e.clientY - rect.top }; }

  pad.addEventListener("pointerdown", (e) => { e.preventDefault(); drawing = true; reset(); const p = pos(e); hit(p.x, p.y); render(toVb(p.x, p.y)); });
  pad.addEventListener("pointermove", (e) => { if (!drawing) return; const p = pos(e); hit(p.x, p.y); render(toVb(p.x, p.y)); });
  const end = () => {
    if (!drawing) return; drawing = false; render(null);
    if (seq.length < 4) { pad.classList.add("err"); errTimer = setTimeout(reset, 450); return; }
    onComplete(seq.join("-"));
  };
  window.addEventListener("pointerup", end);
  window.addEventListener("pointercancel", end);
  return { reset, flashError: () => { pad.classList.add("err"); errTimer = setTimeout(reset, 450); } };
}

// ================= UI =================
const $ = (id) => document.getElementById(id);
const screens = ["create", "unlock", "vault", "destroyed"];
const show = (name) => screens.forEach((s) => $("screen-" + s).classList.toggle("hidden", s !== name));
function msg(id, text, kind) { const el = $(id); el.textContent = text || ""; el.className = text ? "msg show " + (kind || "") : "msg"; }

// --- flujo CREAR (dibujar + confirmar) ---
let firstPattern = null;
let padCreate, padUnlock;

function startCreate() {
  firstPattern = null;
  $("create-prompt").textContent = "Dibuja tu patrón (mínimo 4 puntos)";
  msg("create-msg", "");
  padCreate.reset();
}
function onCreateDraw(pattern) {
  if (!firstPattern) {
    firstPattern = pattern;
    $("create-prompt").textContent = "Confírmalo: dibújalo otra vez";
    msg("create-msg", "Bien. Repite el mismo patrón para confirmar.", "ok");
    padCreate.reset();
  } else if (pattern === firstPattern) {
    const max = Math.max(3, Math.min(20, parseInt($("create-max").value) || 5));
    msg("create-msg", "Cifrando…", "");
    createVault(firstPattern, max).then(() => { renderEntries(); show("vault"); msg("vault-msg", "Bóveda creada y cifrada ✅", "ok"); });
  } else {
    firstPattern = null;
    $("create-prompt").textContent = "Dibuja tu patrón (mínimo 4 puntos)";
    msg("create-msg", "No coincidía. Empieza de nuevo.", "err");
    padCreate.flashError();
  }
}

function onUnlockDraw(pattern) {
  msg("unlock-msg", "Descifrando…", "");
  unlockVault(pattern).then(() => {
    $("unlock-attempts").textContent = ""; msg("unlock-msg", ""); renderEntries(); show("vault");
  }).catch((e) => {
    if (e.message === "WRONG") { $("unlock-attempts").textContent = `Intentos restantes: ${e.left}`; msg("unlock-msg", "Patrón incorrecto.", "err"); padUnlock.flashError(); }
    else { show("destroyed"); }
  });
}

function renderEntries() {
  const box = $("entries"); box.innerHTML = "";
  if (!sessionData.entries.length) { box.innerHTML = '<p class="hint">Aún no hay secretos. Añade el primero abajo.</p>'; }
  sessionData.entries.forEach((e, i) => {
    const div = document.createElement("div"); div.className = "entry";
    const info = document.createElement("div"); info.innerHTML = '<div class="k"></div><div class="v"></div>';
    info.querySelector(".k").textContent = e.key; info.querySelector(".v").textContent = e.val;
    const del = document.createElement("button"); del.textContent = "Borrar";
    del.onclick = async () => { sessionData.entries.splice(i, 1); await persistSession(); renderEntries(); };
    div.append(info, del); box.append(div);
  });
}

function routeStart() {
  const s = loadState();
  if (!s) { startCreate(); return show("create"); }
  if (s.destroyed) return show("destroyed");
  padUnlock.reset();
  const left = s.maxAttempts - (s.failed || 0);
  $("unlock-attempts").textContent = s.failed > 0 ? `Intentos restantes: ${left}` : "";
  show("unlock");
}

// --- eventos estáticos ---
$("btn-create-reset").onclick = startCreate;
$("btn-add").onclick = async () => {
  const k = $("entry-key").value.trim(), v = $("entry-val").value.trim();
  if (!k || !v) return msg("vault-msg", "Pon nombre y valor.", "warn");
  sessionData.entries.push({ key: k, val: v }); await persistSession();
  $("entry-key").value = $("entry-val").value = ""; renderEntries(); msg("vault-msg", "Guardado y cifrado ✅", "ok");
};
$("btn-lock").onclick = () => { sessionKey = null; sessionData = null; routeStart(); };
$("btn-wipe").onclick = () => { if (confirm("¿Seguro? Destruye la clave y TODOS los datos para siempre.")) { selfDestruct(); show("destroyed"); } };
$("btn-reset").onclick = () => { clearState(); startCreate(); show("create"); };

// --- arranque ---
padCreate = buildPad("pad-create", "line-create", onCreateDraw);
padUnlock = buildPad("pad-unlock", "line-unlock", onUnlockDraw);
routeStart();
if ("serviceWorker" in navigator) navigator.serviceWorker.register("sw.js").catch(() => {});
