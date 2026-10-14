# arpa-auth

Contraseñas, tokens JWT y tokens opacos, resueltos una sola vez para todos los servicios.
Sin estado, sin leer variables de entorno ni ficheros, sin dependencia de ningún framework:
la aplicación construye los objetos al arrancar con su propia configuración.

```bash
uv add "arpa-auth @ git+https://github.com/fabianvaccaro/arpa-libs@arpa-auth/v0.1.0#subdirectory=packages/arpa-auth"
```

## Contraseñas

```python
from arpa_auth import PasswordHasher

ph = PasswordHasher()                      # Argon2id, 64 MiB, t=3, p=4
stored = ph.hash("contraseña")

ok, needs_rehash = ph.verify(password, user.password_hash)
if ok and needs_rehash:                    # hash antiguo o parámetros más débiles
    user.password_hash = ph.hash(password)
```

`verify` acepta también los formatos PBKDF2-SHA256 que ya existen, así que se puede migrar sin
resetear contraseñas: el hash se actualiza solo en el siguiente login.

- `pbkdf2_sha256$<iteraciones>$<sal hex>$<hash hex>`
- `{"iterations": ..., "salt": "<hex>", "hash": "<hex>"}` (registro en una base documental)

Nunca lanza excepción por una contraseña o un hash erróneos: devuelve `(False, False)`.

`password_problems(pw, min_length=12, min_classes=3, identity=("usuario",))` devuelve códigos
(`too_short`, `too_simple`, `too_long`, `contains_identity`), y cada servicio los traduce.

## Tokens JWT

```python
from datetime import timedelta
from arpa_auth import Keyring, SigningKey, TokenIssuer, InvalidToken, REFRESH

keys = Keyring(SigningKey.hmac(settings.jwt_secret, kid="2026-10"))
tokens = TokenIssuer(keys, issuer="mi-servicio", audience="mi-api",
                     access_ttl=timedelta(minutes=15), refresh_ttl=timedelta(days=14))

access = tokens.issue_access(user.id, {"tid": tenant_id, "roles": roles})
refresh = tokens.issue_refresh(user.id)            # nueva familia en el login

try:
    claims = tokens.decode(bearer)                 # solo tokens de acceso
except InvalidToken as e:
    log.info("token rechazado: %s", e.reason)      # seguro de loguear, no incluye el token
```

- **Algoritmo fijado por clave.** `alg: none` o un algoritmo distinto al de la clave se rechazan
  antes de comprobar la firma. HS256/384/512, ES256/384, RS256/384/512, PS256, EdDSA.
- **Rotación.** `keys.rotated(SigningKey.hmac(nuevo, kid="2026-11"))` firma con la nueva y sigue
  aceptando la anterior hasta que caduquen sus tokens.
- **Asimétrico.** `SigningKey("k1", "ES256", signing=pem_privada, verifying=pem_publica)`. Un
  servicio que solo verifica usa `SigningKey("k1", "ES256", verifying=pem_publica)`.
- **Claims fijos:** `iss`, `aud`, `sub`, `iat`, `nbf`, `exp`, `jti`, `typ` (`access`/`refresh`).
  Un token de refresco nunca se acepta como acceso.
- **Familias de refresco.** En cada uso: `decode(t, REFRESH)`, emitir `issue_refresh(sub,
  family=claims["fid"])`, guardar el nuevo `jti` como único vivo de la familia. Si vuelve un
  `jti` que no es el vivo, revocar la familia entera (el token fue robado y reutilizado).
- Tolerancia de reloj de 60 s por defecto (`leeway`).

## Tokens opacos

```python
from arpa_auth import new_token, digest, matches, OneTimeCode

session = new_token()                 # al cliente
store(digest(session))                # en la base, nunca el token

code = OneTimeCode.issue(ttl=timedelta(seconds=120))   # enlace de login, código de lanzamiento
save(code.digest, code.expires_at); send(code.code)
OneTimeCode.redeem(received, row.digest, row.expires_at)  # y borrar la fila en la misma transacción
```

## Garantías

- Dependencias solo con licencias permisivas: `argon2-cffi` (MIT), `PyJWT` (MIT), `cryptography`
  (Apache-2.0/BSD). Ninguna copyleft.
- Ni las contraseñas ni los tokens aparecen en `repr`, en los mensajes de excepción ni en logs.
- Python 3.11+, tipado (`py.typed`), cobertura mínima del 90 %.

Licencia MIT, © Fabián Vaccaro.
