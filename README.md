# 🔐 Vault Core — Motor de bóveda cifrada con autodestrucción

Núcleo criptográfico para una app de protección de datos (destino: iOS/iPhone).
Diseñado con **defensa en profundidad**: varias capas que, juntas, hacen
inviable acceder a los datos sin la contraseña correcta.

## Modelo de seguridad

| Capa | Técnica | Para qué |
|------|---------|----------|
| Cifrado de datos | **AES-256-GCM** | Confidencialidad + detección de manipulación |
| Derivación de clave | **Scrypt** (memory-hard) | Frena la fuerza bruta |
| Clave | Nunca se guarda; se deriva al vuelo | Sin contraseña no hay clave que robar |
| Autodestrucción | **Crypto-erase** tras N intentos | Destruye la clave → datos irrecuperables |

## Uso

```bash
python3 demo.py   # ejecuta la demostración completa del ciclo de seguridad
```

## Ficheros

- `vault.py` — el motor (cifrado + derivación + autodestrucción).
- `demo.py` — demostración automática: crear, abrir, fallar, autodestruir.

## Aviso

Ningún software es "infalible". Este diseño hace que vulnerar la bóveda sin la
contraseña sea, en la práctica, inviable — que es la meta real en seguridad.
Úsalo solo en dispositivos y datos propios o con autorización.

## Hoja de ruta

- [ ] Batería de tests de seguridad (intentos de manipulación)
- [ ] Endurecimiento anti-fuerza-bruta (retardo creciente)
- [ ] Interfaz de línea de comandos
- [ ] Puente a iOS: Swift + Keychain + Secure Enclave
