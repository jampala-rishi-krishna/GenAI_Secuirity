## API Endpoints

General
- GET `/health` → app status
- GET `/metrics` → basic JSON metrics
- GET `/security/status` → security report and OWASP coverage summary

Chat (`/api/v1/chat`)
- POST `/send` → body: `{ message, session_id?, user_role? }` → returns `{ response, session_id, timestamp, security_level, security_report, medical_disclaimer, confidence_score }`
- GET `/sessions` → list sessions for current user (requires `CHAT_HISTORY`)
- GET `/sessions/{session_id}` → details (requires `CHAT_HISTORY`)
- DELETE `/sessions/{session_id}` → delete (requires `CHAT_HISTORY`)
- POST `/test-security` → query `type` and `input` to demo security pipeline

Users (`/api/v1/users`)
- POST `/register` → email/username/password/role → returns created user
- POST `/login` → step 1, sends OTP
- POST `/login/verify` → step 2, returns tokens and user
- GET `/me` → current user info
- GET `/` → list users (requires `VIEW_USERS`)
- GET `/{user_id}` → get user (requires `VIEW_USERS`)
- PUT `/{user_id}` → update (requires `MANAGE_USERS`)
- DELETE `/{user_id}` → deactivate (requires `MANAGE_USERS`)

Security (`/api/v1/security`)
- GET `/events` → query: `hours`, `threat_type`, `security_level`
- GET `/metrics` → security metrics
- POST `/test` → body: `{ test_type, test_input }` → returns sanitized input + report
- GET `/owasp-coverage` → OWASP mapping
- GET `/threat-landscape` → recent threats and risk
- POST `/configure` → update settings (mock)

Admin (`/api/v1/admin`)
- GET `/system/status` → status and enabled security features
- GET `/system/metrics` → simulated performance metrics
- GET `/security/dashboard` → threat landscape, recent events, recommendations
- GET `/security/audit-log` → filterable audit log
- POST `/system/configure` → configuration update (mock)
- GET `/system/health-check` → runs health checks across subsystems
- GET `/system/backup-status` → simulated backup status

Auth model (JWT)
- Access token carries: `user_id`, `email`, `role`, `permissions`, `exp`
- Permissions derived from `ROLE_PERMISSIONS` in `app/core/auth.py`


