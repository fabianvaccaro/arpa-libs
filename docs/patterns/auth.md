# Autenticación

**Estado:** paquete `arpa-auth`. No copies este código: instala el paquete.

**Problema:** cada servicio resolvía a su manera contraseñas, JWT y tokens de sesión.

**Dónde estaba (2026-10):** cuatro servicios con cuatro implementaciones distintas: PBKDF2 con cookies
firmadas con itsdangerous, Argon2id con python-jose, Argon2id con PyJWT ES256 y familias de
refresco, y Argon2id con tokens opacos y política de contraseñas.

**Por qué así:**

- Argon2id es la recomendación actual de OWASP. Se verifica PBKDF2 para poder migrar sin resetear
  contraseñas.
- python-jose está prácticamente abandonado y arrastra dependencias con avisos de seguridad. Por
  eso se usa PyJWT, que además es MIT.
- itsdangerous no permite rotar claves ni revocar. Sirve un token opaco con digest en la base, o
  un JWT de corta vida.

**Migración de un servicio:**

1. Añadir `arpa-auth`.
2. Sustituir `hash_password` y `verify_password` por `PasswordHasher`, y rehashear al hacer login
   cuando `needs_rehash` sea verdadero.
3. Sustituir la emisión y validación de JWT por `TokenIssuer`, manteniendo `issuer`, `audience` y
   el algoritmo actuales para que los tokens vivos sigan valiendo.
4. Borrar el módulo propio.
