# Health Metrics Vault

Secure storage for patients' medical records. Patients keep encrypted records and decide which doctors may read them.

## Structure

```
backend/    Go (Gin) REST API + PostgreSQL (GORM)
frontend/   React + TypeScript + Vite
docker-compose.yml
.github/workflows/   CI: tests, SAST, SCA, secrets scanning
```

## Security highlights

- **Identity management:** registration/login, JWT (HS256, short TTL, issuer check), RBAC (`patient` / `doctor`), per-object authorization (no IDOR), doctor access only with explicit patient consent.
- **Cryptography:** bcrypt (cost 12) for passwords, AES-256-GCM for medical records at rest, keys only from environment variables.
- **Hardening:** secure HTTP headers, strict CORS allow-list, body size limit, server timeouts, distroless non-root container with read-only FS.

## Run with Docker

```bash
cp .env.example .env
# fill in secrets:
#   JWT_SECRET          -> openssl rand -base64 48
#   AES_ENCRYPTION_KEY  -> openssl rand -hex 32
#   POSTGRES_PASSWORD   -> any strong password
docker compose up --build
```

- API: http://localhost:8080
- Frontend: http://localhost:5173

## Local development

```bash
# backend (needs a running PostgreSQL and .env in the repo root)
cd backend && go run .

# frontend
cd frontend && npm ci && npm run dev
```

## Contributing

- `main` is protected: changes go only through Pull Requests with 1 approval.
- Branch naming: `feature/<name>`, `fix/<name>`, `docs/<name>`.
- All CI checks must pass before merge.
- Never commit secrets: `.env` is git-ignored, only `.env.example` is tracked.
