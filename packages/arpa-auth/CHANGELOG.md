# Changelog

## 0.1.0 (2026-10-14)

- `PasswordHasher`: Argon2id. Verifies legacy PBKDF2-SHA256 hashes (string and mapping forms)
  and returns `needs_rehash`.
- `TokenIssuer` / `Keyring` / `SigningKey`: JWT access and refresh tokens. Algorithms pinned per
  key, `kid` rotation, refresh families, fixed claims, an injectable clock.
- `new_token` / `digest` / `matches` / `OneTimeCode`: opaque tokens and single-use codes.
- `password_problems`: strength policy that returns problem codes.
