## Backend Deep Dive

Entrypoint: `backend/main.py`
- App creation with `FastAPI(lifespan=lifespan)` and logging
- Middleware:
  - `TimeoutMiddleware` (504 on long requests)
  - `PerIpRateLimitMiddleware` (in-memory fallback)
  - Security headers/CSP (dev vs strict profiles)
  - CORS and optional `TrustedHostMiddleware`
- Global exception handler logs security events
- Health endpoints: `/health`, `/metrics`, `/security/status`, `/`
- Routers mounted under `/api/v1/` for chat, users, security, admin

Core config: `app/core/config.py`
- `Settings` (pydantic-settings) reads `.env`
- Important fields: JWT, CSP profile, rate limits, SMTP, audit log settings
- Validators: enforce JWT length, non-empty CORS, valid environment
- `SECURITY_CONSTANTS`: patterns and disclaimers used by security layer

Authentication/RBAC: `app/core/auth.py`
- `UserRole`, `Permission`, `ROLE_PERMISSIONS`
- `AuthManager`: password hash/verify (bcrypt), JWT create/verify, dependencies for role/permission requirements
- Common dependencies exported (e.g., `require_manage_users`)

Security engine: `app/core/security.py`
- `SecurityManager` with:
  - Threat pattern loading (`prompt_injection`, `sensitive_data`, `malicious_code`)
  - `sanitize_input` → length limits, injection/PII/malicious checks, HTML/SQL detection
  - `validate_output` → length, PII masking, disclaimer injection, HTML sanitization
  - `check_rate_limit` → role-aware sliding window; logs exceeded events
  - Audit logging with redaction and retention window
  - Report generation for dashboards

LLM service: `app/services/llm_service.py`
- Role-based system prompts; secure prompt construction with limited history
- `generate_response` pipeline orchestrates input security, rate limiting, Groq API call, output validation, event logging
- HTTP via `httpx.AsyncClient`, endpoint: `https://api.groq.com/openai/v1/chat/completions`

Email/OTP services:
- `email_service.py`: SMTP-based `send_otp`
- `otp_service.py`: Redis-backed OTP with in-memory fallback, 6-digit TTL codes

API routers:
- `app/api/v1/chat.py`: send message, list sessions, get session, delete session, test-security
- `app/api/v1/users.py`: register, login (step 1 OTP), verify OTP (step 2), me, CRUD operations
- `app/api/v1/security.py`: security events, metrics, test, OWASP coverage, threat landscape, configure
- `app/api/v1/admin.py`: system status/metrics/health, dashboard, audit log, config update

Notable considerations/bugs to address:
- `users.py` constructs `auth_manager.User(...)` instead of `User(...)` from `app.core.auth` → will raise attribute error
- `auth.py` role check uses string comparison `user.role.value < required_role.value` → not a reliable ordering for RBAC
- `llm_service.validate_medical_accuracy` references `settings.SECURITY_CONSTANTS` (does not exist); should import and use `SECURITY_CONSTANTS`
- `chat.py` references `security_manager.SECURITY_CONSTANTS` (not an attribute); should import `SECURITY_CONSTANTS`
- JWT library mismatch: code uses `import jwt` (PyJWT exceptions) while requirements include `python-jose`; align imports/libs


