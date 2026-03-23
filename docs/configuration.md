## Configuration and Environment

Settings source: `app/core/config.py` (`Settings` from pydantic-settings)

Important environment variables (see `backend/env.example`):
- `GROQ_API_KEY`, `GROQ_MODEL`
- `DATABASE_URL`, `REDIS_URL`
- `JWT_SECRET` (must be 32+ chars), `JWT_ALGORITHM`, `JWT_EXPIRATION_MINUTES`, `REFRESH_TOKEN_EXPIRATION_DAYS`
- `APP_NAME`, `APP_VERSION`, `DEBUG`, `ENVIRONMENT` (development|staging|production)
- `RATE_LIMIT_*`, `SECURE_HEADERS`, `CORS_ORIGINS`
- SMTP: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`, `SMTP_USE_TLS`
- Logging/Audit: `LOG_LEVEL`, `LOG_FORMAT`, `AUDIT_LOG_DIR`, `AUDIT_LOG_RETENTION_DAYS`

Frontend
- `NEXT_PUBLIC_API_URL` used by `login.tsx` and `chat.tsx`

Profiles
- CSP profiles: `loose` (dev) vs `strict` (prod). Dev mode enables permissive CSP for Next.js HMR and assets.


