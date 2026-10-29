"""
panel_core.py — Núcleo criptográfico del panel de Windows.

COMPATIBLE BIT A BIT con la app del iPhone (PWA):
  - Clave: PBKDF2-HMAC-SHA256, 600.000 iteraciones, sobre "PATTERN:" + patrón.
  - Cifrado: AES-256-GCM, iv y ciphertext en base64.
  - Mismo formato de estado JSON (boveda.state.v2).

Separado de la interfaz (Tkinter) para poder probarlo sin pantalla.
"""

import base64
import json
import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PBKDF2_ITERS = 600000


class WrongPattern(Exception):
    def __init__(self, left):
        self.left = left
        super().__init__(f"Patrón incorrecto. Intentos restantes: {left}")


class VaultDestroyed(Exception):
    pass


def _derive(pattern: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERS)
    return kdf.derive(("PATTERN:" + pattern).encode("utf-8"))


def decrypt_vault(state: dict, pattern: str) -> dict:
    """Devuelve los datos descifrados. Lanza WrongPattern/VaultDestroyed."""
    if not state or state.get("destroyed"):
        raise VaultDestroyed("La bóveda está destruida.")
    salt = base64.b64decode(state["salt"])
    key = _derive(pattern, salt)
    blob = state["blob"]
    iv = base64.b64decode(blob["iv"])
    ct = base64.b64decode(blob["ct"])
    try:
        pt = AESGCM(key).decrypt(iv, ct, None)
    except Exception:
        # Fallo de autenticación GCM => patrón incorrecto. Actualiza contador.
        state["failed"] = state.get("failed", 0) + 1
        left = state.get("maxAttempts", 5) - state["failed"]
        if left <= 0:
            raise VaultDestroyed("Límite de intentos superado.")
        raise WrongPattern(left)
    state["failed"] = 0
    return json.loads(pt.decode("utf-8"))


def encrypt_vault(state: dict, pattern: str, data: dict) -> dict:
    """Re-cifra `data` dentro de `state` con el patrón dado (mismo salt)."""
    salt = base64.b64decode(state["salt"])
    key = _derive(pattern, salt)
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps(data).encode("utf-8"), None)
    state["blob"] = {
        "iv": base64.b64encode(iv).decode(),
        "ct": base64.b64encode(ct).decode(),
    }
    return state


def new_vault(pattern: str, data: dict, max_attempts: int = 5) -> dict:
    salt = os.urandom(16)
    state = {
        "version": 2,
        "salt": base64.b64encode(salt).decode(),
        "iters": PBKDF2_ITERS,
        "failed": 0,
        "maxAttempts": max_attempts,
        "destroyed": False,
    }
    return encrypt_vault(state, pattern, data)


def load_file(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_file(path: str, state: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)
