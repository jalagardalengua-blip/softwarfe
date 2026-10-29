"""
vault.py — Motor de bóveda cifrada con autodestrucción (crypto-erase).

Modelo de seguridad (idéntico al que irá en la app de iPhone):
  - Clave de datos derivada de la contraseña con Scrypt (KDF memory-hard).
  - Datos cifrados con AES-256-GCM (confidencialidad + integridad/autenticidad).
  - La clave NUNCA se guarda: se reconstruye al vuelo desde la contraseña.
  - Tras N intentos fallidos -> crypto-erase: se destruye el salt/estado
    y los datos quedan como ruido irrecuperable para siempre.

Este fichero es independiente del iPhone. La misma lógica se traduce luego
a Swift/Keychain/Secure Enclave. Aquí la validamos de verdad.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# --- Parámetros de seguridad --------------------------------------------------
# Scrypt: n=2^15 es un buen punto para móvil (coste memoria/CPU alto para
# frenar fuerza bruta, pero usable). En producción se calibra por dispositivo.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32          # 256 bits -> AES-256
SALT_LEN = 16
NONCE_LEN = 12        # 96 bits, estándar recomendado para GCM
MAX_ATTEMPTS = 5      # intentos fallidos antes de la autodestrucción


class VaultDestroyed(Exception):
    """La bóveda fue destruida (crypto-erase). No hay recuperación posible."""


class WrongPassword(Exception):
    """Contraseña incorrecta. Incluye los intentos que quedan."""
    def __init__(self, attempts_left: int):
        self.attempts_left = attempts_left
        super().__init__(f"Contraseña incorrecta. Intentos restantes: {attempts_left}")


def _derive_key(password: str, salt: bytes) -> bytes:
    """Deriva la clave AES-256 desde la contraseña. Memory-hard => anti-fuerza-bruta."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


@dataclass
class Vault:
    """Una bóveda persistida en un fichero JSON. El contenido va cifrado."""
    path: str

    # ---------- Creación ----------
    @classmethod
    def create(cls, path: str, password: str, data: dict) -> "Vault":
        if os.path.exists(path):
            raise FileExistsError(f"Ya existe una bóveda en {path}")
        salt = secrets.token_bytes(SALT_LEN)
        key = _derive_key(password, salt)
        blob = cls._encrypt(key, data)
        state = {
            "version": 1,
            "salt": salt.hex(),
            "failed_attempts": 0,
            "max_attempts": MAX_ATTEMPTS,
            "destroyed": False,
            "ciphertext": blob,
        }
        cls._write(path, state)
        return cls(path)

    # ---------- Apertura (con lógica de autodestrucción) ----------
    def open(self, password: str) -> dict:
        state = self._read()
        if state["destroyed"] or "salt" not in state:
            raise VaultDestroyed("La bóveda fue autodestruida. Datos irrecuperables.")

        salt = bytes.fromhex(state["salt"])
        key = _derive_key(password, salt)
        try:
            data = self._decrypt(key, state["ciphertext"])
        except Exception:
            # Fallo de autenticación GCM => contraseña incorrecta.
            state["failed_attempts"] += 1
            left = state["max_attempts"] - state["failed_attempts"]
            if left <= 0:
                self._self_destruct(state)
                raise VaultDestroyed(
                    "Límite de intentos superado. Bóveda autodestruida (crypto-erase)."
                )
            self._write(self.path, state)
            raise WrongPassword(left)

        # Éxito: reseteamos el contador de fallos.
        state["failed_attempts"] = 0
        self._write(self.path, state)
        return data

    # ---------- Autodestrucción (crypto-erase) ----------
    def _self_destruct(self, state: dict) -> None:
        """Destruye el salt y el ciphertext. Sin salt la clave no se puede
        rederivar; el AES-GCM queda como ruido matemáticamente irreversible."""
        # Sobrescribimos con basura antes de borrar (defensa en profundidad).
        state["salt"] = secrets.token_bytes(SALT_LEN).hex()  # salt falso inútil
        state["ciphertext"] = secrets.token_bytes(64).hex()
        state.pop("salt", None)
        state["destroyed"] = True
        state["ciphertext"] = None
        self._write(self.path, state)

    # ---------- Primitivas AES-256-GCM ----------
    @staticmethod
    def _encrypt(key: bytes, data: dict) -> str:
        nonce = secrets.token_bytes(NONCE_LEN)
        plaintext = json.dumps(data).encode("utf-8")
        ct = AESGCM(key).encrypt(nonce, plaintext, None)
        return (nonce + ct).hex()

    @staticmethod
    def _decrypt(key: bytes, blob_hex: str) -> dict:
        blob = bytes.fromhex(blob_hex)
        nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
        plaintext = AESGCM(key).decrypt(nonce, ct, None)
        return json.loads(plaintext.decode("utf-8"))

    # ---------- Persistencia ----------
    def _read(self) -> dict:
        with open(self.path, "r") as f:
            return json.load(f)

    @staticmethod
    def _write(path: str, state: dict) -> None:
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, path)  # escritura atómica
