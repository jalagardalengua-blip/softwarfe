"""Demo automática del motor de bóveda. Prueba el modelo de seguridad completo."""

import os
from vault import Vault, WrongPassword, VaultDestroyed

PATH = "/home/user/vault-core/demo_vault.json"

def line(t): print("\n" + "=" * 60 + f"\n  {t}\n" + "=" * 60)

# Empezar limpio
if os.path.exists(PATH):
    os.remove(PATH)

secreto = {"nota": "Coordenadas del tesoro: 40.4168N, 3.7038W", "pin_banco": "4921"}

line("1) CREAR la bóveda con contraseña 'ClaveFuerte#2026'")
Vault.create(PATH, "ClaveFuerte#2026", secreto)
print("   Bóveda creada y cifrada en disco (AES-256-GCM).")
print("   Contenido crudo del fichero (lo que vería un ladrón):")
with open(PATH) as f:
    print("   " + f.read().replace("\n", "\n   ")[:300] + " ...")

line("2) ABRIR con la contraseña CORRECTA")
print("   Datos descifrados:", Vault(PATH).open("ClaveFuerte#2026"))

line("3) FALLAR la contraseña varias veces (ver cuenta atrás)")
for intento in range(1, 10):
    try:
        Vault(PATH).open("contraseña-mala")
        print(f"   intento {intento}: ABIERTA (no debería pasar)")
    except WrongPassword as e:
        print(f"   intento {intento}: {e}")
    except VaultDestroyed as e:
        print(f"   intento {intento}: 💥 {e}")
        break

line("4) Intentar abrir DESPUÉS de la autodestrucción (con la clave BUENA)")
try:
    Vault(PATH).open("ClaveFuerte#2026")
    print("   ABIERTA (FALLO DE SEGURIDAD)")
except VaultDestroyed as e:
    print(f"   🔒 {e}")
    print("   -> Ni con la contraseña correcta hay vuelta atrás. Crypto-erase OK.")

print("\n   Estado final del fichero en disco:")
with open(PATH) as f:
    print("   " + f.read().replace("\n", "\n   "))
