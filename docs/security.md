## Security Mapping (OWASP LLM Top 10)

LLM01: Prompt Injection
- Detect: `SecurityManager.detect_prompt_injection`
- Enforce: `sanitize_input` blocks or flags high/critical
- Log: `log_security_event`

LLM02: Sensitive Information Disclosure
- Detect: `detect_sensitive_data` via regex patterns and medical indicators
- Enforce: `validate_output` masks and appends disclaimers

LLM03: Supply Chain
- Groq API usage via `httpx` with controlled headers; pinned deps in `requirements.txt`

LLM05: Improper Output Handling
- `validate_output` removes HTML, masks PII, clamps length, appends disclaimer

LLM06: Excessive Agency
- RBAC with roles/permissions in `auth.py`; route dependencies enforce permissions

LLM07: System Prompt Leakage
- `LLMService._build_secure_prompt` isolates system prompt and limits history

LLM08: Vector/Embedding Weaknesses
- Not using vectors here; placeholders in coverage and secure context limits

LLM09: Misinformation
- `validate_medical_accuracy` heuristic; disclaimer always present in outputs

LLM10: Unbounded Consumption
- `SecurityManager.check_rate_limit` role-aware limits; per-IP middleware fallback

Headers and Transport
- CSP/HSTS/X-Content-Type/X-Frame/XSS headers in `main.py` middleware

Audit and Monitoring
- `log_security_event` persists to `logs/security_events.log` with PII redaction
- Retention enforced via `audit_log_retention_days`

Known gaps to fix
- Align JWT library imports with `requirements.txt`
- Correct references to `SECURITY_CONSTANTS` and role comparisons


