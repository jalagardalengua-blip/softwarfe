# 🖥️ Panel de control (Windows)

Abre, descifra y edita las copias de tu bóveda desde el PC, y las sincroniza
con la app del iPhone. Usa **el mismo cifrado** que la app (AES-256-GCM +
PBKDF2 600k), así que son 100% compatibles.

## Instalar (una sola vez)

1. Instala **Python 3** desde [python.org](https://www.python.org/downloads/)
   (marca la casilla **"Add Python to PATH"**).
2. Abre **PowerShell** y ejecuta:
   ```
   pip install cryptography
   ```

## Ejecutar

Doble clic en `panel.py`, o desde PowerShell en esta carpeta:
```
python panel.py
```

## Cómo sincronizar (iPhone ⇄ PC)

**Del iPhone al PC:**
1. En la app (iPhone) → **Exportar copia cifrada (.vault)**.
2. Pasa el archivo al PC (AirDrop, correo, cable, lo que quieras — va cifrado).
3. En el panel → **Abrir copia** → dibuja tu patrón → **Desbloquear**.

**Del PC al iPhone:**
1. En el panel, edita y pulsa **Guardar copia** (te pedirá tu patrón).
2. Pasa el `.vault` al iPhone.
3. En la app → **Importar copia del PC** → desbloquea con tu patrón.

## Seguridad

- El archivo `.vault` **siempre está cifrado**. Sin tu patrón no se puede leer,
  ni siquiera abriéndolo con un editor de texto.
- El patrón **nunca se guarda**. Si lo olvidas, no hay recuperación.
- El panel aplica la **misma autodestrucción**: si fallas el patrón demasiadas
  veces al abrir una copia, esa copia se destruye (crypto-erase).

## Ficheros

- `panel.py` — la interfaz (ventana de Windows).
- `panel_core.py` — el motor de cifrado (compatible con la app).
