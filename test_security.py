"""
test_security.py — Batería de pruebas adversariales sobre el motor de bóveda.

No comprueba solo que "funcione": intenta ROMPERLO de varias formas y verifica
que el modelo de seguridad aguanta. Ejecutar con:  python3 test_security.py
"""

import os
import sys
import time

from vault import Vault, WrongPassword, VaultDestroyed, _derive_key, SALT_LEN
import secrets

TMP = "/home/user/vault-core/_test_vault.json"
PASS = "ContraseñaCorrecta#2026"
DATA = {"secreto": "lanzamiento el viernes", "pin": "7731"}

_passed = 0
_failed = 0

def fresh():
    for p in (TMP, TMP + ".tmp"):
        if os.path.exists(p):
            os.remove(p)

def check(nombre, condicion):
    global _passed, _failed
    if condicion:
        _passed += 1
        print(f"  ✅ {nombre}")
    else:
        _failed += 1
        print(f"  ❌ FALLO: {nombre}")

print("\n" + "=" * 64)
print("  BATERÍA DE PRUEBAS DE SEGURIDAD")
print("=" * 64)

# --- 1. Confidencialidad: el texto plano NO aparece en el fichero ------------
print("\n[1] Confidencialidad — el secreto no está en claro en disco")
fresh()
Vault.create(TMP, PASS, DATA)
raw = open(TMP, "rb").read()
check("el secreto 'viernes' no aparece en el fichero cifrado",
      b"viernes" not in raw)
check("el PIN '7731' no aparece en el fichero cifrado",
      b"7731" not in raw)

# --- 2. Apertura legítima ----------------------------------------------------
print("\n[2] Apertura legítima — la contraseña correcta devuelve los datos")
check("los datos descifrados coinciden con los originales",
      Vault(TMP).open(PASS) == DATA)

# --- 3. Integridad GCM: manipular el cifrado se detecta ----------------------
print("[3] Integridad — manipular el ciphertext es detectado (AES-GCM)")
fresh()
Vault.create(TMP, PASS, DATA)
import json
st = json.load(open(TMP))
ct = bytearray(bytes.fromhex(st["ciphertext"]))
ct[20] ^= 0x01  # cambiamos 1 bit
st["ciphertext"] = ct.hex()
json.dump(st, open(TMP, "w"))
detectado = False
try:
    Vault(TMP).open(PASS)
except (WrongPassword, VaultDestroyed):
    detectado = True
check("un solo bit alterado invalida el descifrado", detectado)

# --- 4. Nonce único por cifrado (no reutilización) ---------------------------
print("[4] Nonces — cada cifrado usa un nonce distinto (nunca se reutiliza)")
nonces = set()
for _ in range(1000):
    blob = Vault._encrypt(secrets.token_bytes(32), {"x": 1})
    nonces.add(blob[:24])  # 12 bytes de nonce = 24 hex
check("1000 cifrados -> 1000 nonces distintos", len(nonces) == 1000)

# --- 5. Mismo dato, distinto cifrado (no revela repeticiones) ----------------
print("[5] Semántica — cifrar el mismo dato dos veces da cifrados distintos")
key = secrets.token_bytes(32)
check("dos cifrados del mismo dato son diferentes",
      Vault._encrypt(key, DATA) != Vault._encrypt(key, DATA))

# --- 6. Contraseñas distintas -> claves distintas ----------------------------
print("[6] KDF — contraseñas distintas producen claves distintas")
salt = secrets.token_bytes(SALT_LEN)
check("claves derivadas distintas para contraseñas distintas",
      _derive_key("password-A", salt) != _derive_key("password-B", salt))
check("misma contraseña + mismo salt -> misma clave (determinista)",
      _derive_key(PASS, salt) == _derive_key(PASS, salt))

# --- 7. Autodestrucción irreversible -----------------------------------------
print("[7] Autodestrucción — tras N fallos, ni la clave correcta abre")
fresh()
Vault.create(TMP, PASS, DATA)
for _ in range(5):
    try:
        Vault(TMP).open("mala")
    except (WrongPassword, VaultDestroyed):
        pass
irrecuperable = False
try:
    Vault(TMP).open(PASS)
except VaultDestroyed:
    irrecuperable = True
check("tras la autodestrucción, la contraseña correcta ya no funciona",
      irrecuperable)
st = json.load(open(TMP))
check("el ciphertext fue eliminado del disco (crypto-erase)",
      st.get("ciphertext") is None and st.get("destroyed") is True)

# --- 8. Coste de fuerza bruta (el KDF debe ser lento a propósito) ------------
print("[8] Anti-fuerza-bruta — el KDF es costoso (lento) a propósito")
salt = secrets.token_bytes(SALT_LEN)
t0 = time.perf_counter()
_derive_key("x", salt)
dt = time.perf_counter() - t0
print(f"      tiempo por derivación: {dt*1000:.1f} ms")
check("cada intento cuesta >20 ms (frena el brute-force)", dt > 0.02)
# A ese ritmo, probar un diccionario de 10M contraseñas tardaría:
horas = (10_000_000 * dt) / 3600
print(f"      -> 10 millones de intentos costarían ~{horas:,.0f} horas de CPU")

fresh()
print("\n" + "=" * 64)
print(f"  RESULTADO: {_passed} pruebas superadas, {_failed} fallos")
print("=" * 64 + "\n")
sys.exit(1 if _failed else 0)
