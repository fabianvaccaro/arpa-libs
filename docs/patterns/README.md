# Patrones y prácticas

Lo que todavía no es un paquete: decisiones de diseño, snippets y prácticas probadas que se
repiten entre proyectos. Un patrón que aparece en tres proyectos pasa a ser un paquete en
`packages/`, y aquí queda solo el enlace.

Cada patrón ocupa un fichero `<tema>.md` con estas secciones:

- **Problema**: qué resuelve, en una frase.
- **Solución**: el snippet mínimo, completo y que funcione.
- **Dónde se usa**: proyectos y rutas, para que se pueda comparar.
- **Por qué así**: la alternativa descartada y su motivo.
- **Estado**: `patrón` (se copia y adapta) o `paquete: arpa-xxx` (ya no se copia).

| Patrón | Estado |
|---|---|
| [Autenticación](auth.md) | paquete: `arpa-auth` |
