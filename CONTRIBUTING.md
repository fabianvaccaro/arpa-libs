# Añadir o cambiar un paquete

1. Busca en `catalog.yaml` y en `docs/patterns/`. Si ya existe, amplíalo.
2. Paquete nuevo: copia la estructura de `packages/arpa-auth` (`pyproject.toml`, `src/<modulo>/`,
   `py.typed`, `tests/`, `README.md` y `LICENSE`) y añade su entrada en `catalog.yaml` y en la
   tabla del README.
3. `uv run ruff check . && uv run ruff format . && uv run pytest` dentro del paquete.
4. Sube la versión en `pyproject.toml` y en `__version__`, y apunta el cambio en el `CHANGELOG.md`
   del paquete.
5. Tras el merge a `main`: `git tag <paquete>/v<versión> && git push --tags`. CI crea la release de GitHub.

Commits: Conventional Commits (`feat(arpa-auth): ...`, `fix(arpa-auth): ...`).
