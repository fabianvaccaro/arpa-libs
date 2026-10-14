# arpa-libs

Librerías propias, probadas y versionadas, para no reescribir lo mismo en cada proyecto.
Cada pieza vive en `packages/<nombre>/`, con sus tests y su versión. Se instala como cualquier
dependencia y se actualiza cuando conviene, no por copia y pega.

| Paquete | Estado | Qué resuelve |
|---|---|---|
| [`arpa-auth`](packages/arpa-auth) | experimental (0.x) | Contraseñas (Argon2id y verificación de PBKDF2 antiguo), JWT de acceso y refresco con rotación de claves, tokens opacos y códigos de un solo uso |

El catálogo completo, legible por máquina, está en [`catalog.yaml`](catalog.yaml).

## Instalar

Cada versión es una etiqueta `<paquete>/v<versión>` y una release de GitHub con el wheel y el sdist
adjuntos. Se instala directamente desde la etiqueta:

```bash
uv add "arpa-auth @ git+https://github.com/fabianvaccaro/arpa-libs@arpa-auth/v0.1.0#subdirectory=packages/arpa-auth"
```

o desde el wheel de la release:

```bash
uv add "arpa-auth @ https://github.com/fabianvaccaro/arpa-libs/releases/download/arpa-auth/v0.1.0/arpa_auth-0.1.0-py3-none-any.whl"
```

Actualizar es cambiar la etiqueta. No hace falta ninguna credencial: el repositorio es público.

## Reglas

1. **Antes de escribir algo, busca aquí.** Si existe, úsalo. Si casi existe, amplía el paquete en
   lugar de copiarlo.
2. **Una pieza entra cuando se repite.** Lo que aparece en dos proyectos es candidato y en tres
   es obligatorio. Hasta entonces se documenta como patrón en [`docs/patterns/`](docs/patterns).
3. **Versionado semántico.** `0.x` es experimental y puede romper la API en un cambio menor.
   Desde `1.0`, romper la API exige una versión mayor. Las versiones publicadas son inmutables:
   una etiqueta publicada no se mueve ni se borra.
4. **Etiquetas por paquete:** `arpa-auth/v0.1.0`. Al empujar la etiqueta, CI prueba, construye y
   crea la release de GitHub con los ficheros.
5. **Licencias.** Todo lo de este repositorio es MIT, © Fabián Vaccaro. Las dependencias solo
   pueden ser MIT, BSD, Apache-2.0 o ISC, sin copyleft (GPL, LGPL, AGPL, SSPL, EUPL). Así
   cualquier cliente puede consumirlas. CI lo comprueba.
6. **Calidad.** Ruff, tests con cobertura mínima del 90 %, tipado (`py.typed`), código y
   comentarios en inglés, README en español. Sin estado global, sin leer el entorno al importar
   y sin dependencia de un framework en el núcleo (las integraciones van como extras).
7. **Seguridad.** Ningún secreto en logs, `repr` ni mensajes de excepción.
