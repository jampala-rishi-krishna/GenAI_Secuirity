## Architecture Overview

High-level flow:

1) Frontend (Next.js) → 2) Backend (FastAPI) → 3) Security Layer → 4) LLM Service (Groq) → 5) Response validation → Frontend

Key components:
- Frontend: Next.js pages in `frontend/pages/` (`index.tsx`, `login.tsx`, `chat.tsx`)
- Backend App: FastAPI app in `backend/main.py`
- Core: `app/core/` for `config.py`, `auth.py`, `security.py`
- Services: `app/services/` for `llm_service.py`, `otp_service.py`, `email_service.py`
- API Routers: `app/api/v1/` (`chat.py`, `users.py`, `security.py`, `admin.py`)

Request lifecycle:
- Next.js makes a request to backend API (e.g., POST `/api/v1/chat/send`)
- `main.py` middleware applies timeouts, rate limiting (per-IP), and security headers/CSP
- FastAPI routes handle the request and may use dependencies from `auth_manager` (RBAC)
- Inputs are sanitized/detected for threats via `security_manager.sanitize_input`
- LLM call is made via `llm_service._call_groq_api` if allowed
- Outputs validated via `security_manager.validate_output` and security events logged

Security layers (where enforced):
- Input layer: `SecurityManager.sanitize_input` (prompt injection, PII, SQL/HTML)
- Rate limiting: `SecurityManager.check_rate_limit` and `PerIpRateLimitMiddleware`
- Output layer: `SecurityManager.validate_output` (masking, disclaimers)
- Headers: CSP/HSTS/X-Frame/etc. set in `main.py` middleware
- RBAC: token/permission checks via `AuthManager` in `auth.py`

Environments:
- Settings via `app/core/config.py` (`Settings`, `SECURITY_CONSTANTS`) with `.env` loading
- CSP profile differs between development (permissive) and production (strict)


