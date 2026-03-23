## Showcase and Demos

Chat security demos (in `frontend/pages/chat.tsx`):
- Prompt Injection: sets input to classic bypass phrase
- Sensitive Data: includes SSN and phone to trigger PII detection
- Malicious Code: includes `<script>` to trigger XSS filters
- SQL Injection: sends typical SQLi string

Admin/Security views:
- Security metrics: GET `/api/v1/security/metrics`
- OWASP coverage: GET `/api/v1/security/owasp-coverage`
- Threat landscape: GET `/api/v1/security/threat-landscape`
- Audit log: GET `/api/v1/admin/security/audit-log`

Health checks:
- System health: GET `/api/v1/admin/system/health-check`
- Backend liveness: GET `/health`


