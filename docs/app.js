/*
 * app.js — Lógica de la bóveda cifrada (PWA).
 *
 * Modelo de seguridad (equivalente al motor Python del repo):
 *   - Clave derivada de la contraseña con PBKDF2-SHA256 (600k iteraciones).
 *   - Datos cifrados con AES-256-GCM vía WebCrypto (nativo del navegador).
 *   - La clave NUNCA se guarda: se deriva al vuelo en cada apertura.
 *   - Tras N intentos fallidos -> crypto-erase: se borra salt + ciphertext.
 *   - Todo vive en localStorage del dispositivo. Nada se envía a ningún servidor.
 */

const STORE_KEY = "boveda.state.v1";
const PBKDF2_ITERS = 600000;
const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------- utilidades base64 <-> bytes ----------
const b64 = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  dec: (str) => Uint8Array.from(atob(str), (c) => c.charCodeAt(0)),
};

// ---------- persistencia ----------
function loadState() {
  try { return JSON.parse(localStorage.getItem(STORE_KEY)); }
  catch { return null; }
}
function saveState(s) { localStorage.setItem(STORE_KEY, JSON.stringify(s)); }
function clearState() { localStorage.removeItem(STORE_KEY); }

// ---------- criptografía ----------
async function deriveKey(password, saltBytes) {
  const base = await crypto.subtle.importKey(
    "raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: saltBytes, iterations: PBKDF2_ITERS, hash: "SHA-256" },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptData(key, dataObj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const pt = enc.encode(JSON.stringify(dataObj));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt);
  return { iv: b64.enc(iv), ct: b64.enc(ct) };
}

async function decryptData(key, blob) {
  const iv = b64.dec(blob.iv);
  const ct = b64.dec(blob.ct);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return JSON.parse(dec.decode(pt));
}

// ---------- modelo de bóveda ----------
let sessionKey = null;   // clave en memoria mientras la bóveda está abierta
let sessionData = null;  // datos descifrados en memoria

async function createVault(password, maxAttempts) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(password, salt);
  const data = { entries: [] };
  const blob = await encryptData(key, data);
  saveState({
    version: 1,
    salt: b64.enc(salt),
    iters: PBKDF2_ITERS,
    failed: 0,
    maxAttempts,
    destroyed: false,
    blob,
  });
  sessionKey = key; sessionData = data;
}

async function unlockVault(password) {
  const s = loadState();
  if (!s || s.destroyed) throw new Error("DESTROYED");
  const key = await deriveKey(password, b64.dec(s.salt));
  try {
    const data = await decryptData(key, s.blob);
    s.failed = 0; saveState(s);          // éxito -> reset contador
    sessionKey = key; sessionData = data;
    return data;
  } catch (e) {
    // Fallo de autenticación GCM => contraseña incorrecta
    s.failed = (s.failed || 0) + 1;
    const left = s.maxAttempts - s.failed;
    if (left <= 0) { selfDestruct(); throw new Error("JUST_DESTROYED"); }
    saveState(s);
    const err = new Error("WRONG"); err.left = left; throw err;
  }
}

function selfDestruct() {
  // crypto-erase: sin salt ni ciphertext, los datos son ruido irreversible.
  saveState({ version: 1, destroyed: true, failed: 0, maxAttempts: 0 });
  sessionKey = null; sessionData = null;
}

async function persistSession() {
  const s = loadState();
  s.blob = await encryptData(sessionKey, sessionData);
  saveState(s);
}

// ================= UI =================
const $ = (id) => document.getElementById(id);
const screens = ["create", "unlock", "vault", "destroyed"];
function show(name) {
  screens.forEach((s) => $("screen-" + s).classList.toggle("hidden", s !== name));
}
function msg(id, text, kind) {
  const el = $(id);
  el.textContent = text;
  el.className = "msg show " + (kind || "");
  if (!text) el.className = "msg";
}

function routeStart() {
  const s = loadState();
  if (!s) return show("create");
  if (s.destroyed) return show("destroyed");
  show("unlock");
  const left = s.maxAttempts - (s.failed || 0);
  if (s.failed > 0) $("unlock-attempts").textContent = `Intentos restantes: ${left}`;
}

function renderEntries() {
  const box = $("entries");
  box.innerHTML = "";
  if (!sessionData.entries.length) {
    box.innerHTML = '<p class="hint">Aún no hay secretos. Añade el primero abajo.</p>';
  }
  sessionData.entries.forEach((e, i) => {
    const div = document.createElement("div");
    div.className = "entry";
    const info = document.createElement("div");
    info.innerHTML = `<div class="k"></div><div class="v"></div>`;
    info.querySelector(".k").textContent = e.key;
    info.querySelector(".v").textContent = e.val;
    const del = document.createElement("button");
    del.textContent = "Borrar";
    del.onclick = async () => {
      sessionData.entries.splice(i, 1);
      await persistSession();
      renderEntries();
    };
    div.append(info, del);
    box.append(div);
  });
}

// ---- eventos ----
$("btn-create").onclick = async () => {
  const p1 = $("create-pass").value, p2 = $("create-pass2").value;
  const max = Math.max(3, Math.min(20, parseInt($("create-max").value) || 5));
  if (p1.length < 8) return msg("create-msg", "La contraseña debe tener al menos 8 caracteres.", "err");
  if (p1 !== p2) return msg("create-msg", "Las contraseñas no coinciden.", "err");
  msg("create-msg", "Cifrando…", "");
  await createVault(p1, max);
  $("create-pass").value = $("create-pass2").value = "";
  renderEntries(); show("vault");
  msg("vault-msg", "Bóveda creada y cifrada ✅", "ok");
};

$("btn-unlock").onclick = async () => {
  const p = $("unlock-pass").value;
  if (!p) return;
  msg("unlock-msg", "Descifrando…", "");
  try {
    await unlockVault(p);
    $("unlock-pass").value = "";
    $("unlock-attempts").textContent = "";
    msg("unlock-msg", "", "");
    renderEntries(); show("vault");
  } catch (e) {
    if (e.message === "WRONG") {
      $("unlock-attempts").textContent = `Intentos restantes: ${e.left}`;
      msg("unlock-msg", "Contraseña incorrecta.", "err");
    } else if (e.message === "JUST_DESTROYED") {
      show("destroyed");
    } else {
      show("destroyed");
    }
  }
};

$("btn-add").onclick = async () => {
  const k = $("entry-key").value.trim();
  const v = $("entry-val").value.trim();
  if (!k || !v) return msg("vault-msg", "Pon nombre y valor.", "warn");
  sessionData.entries.push({ key: k, val: v });
  await persistSession();
  $("entry-key").value = $("entry-val").value = "";
  renderEntries();
  msg("vault-msg", "Guardado y cifrado ✅", "ok");
};

$("btn-lock").onclick = () => {
  sessionKey = null; sessionData = null;
  routeStart();
};

$("btn-wipe").onclick = () => {
  if (confirm("¿Seguro? Esto destruye la clave y TODOS los datos para siempre. No hay vuelta atrás.")) {
    selfDestruct();
    show("destroyed");
  }
};

$("btn-reset").onclick = () => { clearState(); show("create"); };

// ---- arranque + service worker ----
routeStart();
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("sw.js").catch(() => {});
}
