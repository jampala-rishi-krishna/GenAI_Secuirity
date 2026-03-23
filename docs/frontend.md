## Frontend Deep Dive (Next.js)

Global app: `frontend/pages/_app.tsx`
- Imports Tailwind globals and renders pages

Home page: `frontend/pages/index.tsx`
- Marketing-style overview with links to Chat and Login
- Highlights security features and OWASP coverage

Login page: `frontend/pages/login.tsx`
- 2-step flow (credentials → OTP)
- Start login: POST `/api/v1/users/login` with `{ email, password }`
- Verify OTP: POST `/api/v1/users/login/verify` with `{ email, otp }`
- On success: stores tokens in `localStorage` and shows links to secure areas

Chat page: `frontend/pages/chat.tsx`
- Renders chat UI with security status side panel
- Health check against backend `/health`
- Send message: POST `/api/v1/chat/send` with `{ message, session_id?, user_role }`
- Displays `security_report` indicators for input/output/overall security
- Quick test buttons set inputs for security scenarios (prompt injection, PII, XSS, SQLi)

Environment:
- Backend base URL via `NEXT_PUBLIC_API_URL` (e.g., `http://localhost:8000`)


