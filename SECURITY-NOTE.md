# NoteShare Secure Auth Lab: Security Architecture & Design Note

## 1. What Was Built

The **NoteShare Secure Auth Lab** is a hardened, production-aligned authentication microservice built using Node.js, Express, and SQLite (`better-sqlite3`). It implements the core identity lifecycle for NoteShare:
* **Student Registration (`POST /register`)**: Validates input syntax, rejects weak/compromised passphrases, normalizes emails, and stores salted password hashes using bcrypt.
* **Authentication (`POST /login`)**: Authenticates users with constant-time hash comparisons, equalized response timing to resist account enumeration, and regenerates session IDs upon login.
* **Session Lifecycle (`GET /me`, `POST /logout`)**: Issues strictly isolated, HttpOnly cookies with idle and absolute expiration policies, and destroys server-side sessions cleanly on logout.
* **Security Middleware Pipeline**: Integrates Helmet HTTP security headers, disabled framework fingerprints, JSON payload caps, CSRF header enforcement, and adaptive compound rate limiting.
* **Forensic Audit Logging**: Records an append-only JSON event trail with timestamps, event types, client IP addresses, and non-reversible hashed identifiers while strictly omitting credentials, tokens, and PII.

---

## 2. Threat Mitigation & Verification Matrix

The table below maps each implemented security control directly to the corresponding threat from the NoteShare threat model and the automated test that proves its effectiveness.

| Threat ID | Threat Description | Security Control Implemented | Proving Test in `test/auth.test.js` |
| :---: | :--- | :--- | :--- |
| **T2** | Credential stuffing and weak passwords | Password hashing using `bcrypt` (cost factor 12) with per-user salt; server-side length validation (12–128 chars); 20+ common password blocklist. | `Test 1` (password stored hashed, never plaintext)<br/>`Test 2` (weak, short, common, and non-string passwords rejected with 400). |
| **T2** | User account enumeration | Generic error messages (`401 Invalid email or password`) for both non-existent users and incorrect passwords; dummy hash execution to equalize response latency; generic registration response on duplicate email. | `Test 4` (duplicate registration generic response)<br/>`Test 6` (wrong password and unknown email give identical status and body). |
| **T3** | SQL injection in queries | 100% parameterized queries using `better-sqlite3` prepared statements (`?` placeholders) for all database operations. | `Test 12` (SQL injection payloads `' OR '1'='1` in email do not bypass login and do not crash). |
| **T7** | Insecure password reset tokens | *Explicitly out of scope for this authentication lab.* Documented under Next Steps for future sprint implementation. | Documented limitation / future milestone. |
| **T11** | CSRF attacks on state-changing endpoints | Custom header verification (`X-Requested-With: XMLHttpRequest`) required on all `POST` routes (`/register`, `/login`, `/logout`). | `Test 15` (CSRF defense: POST endpoints require custom `X-Requested-With` header, returning 403 when absent). |
| **T11** | Session hijacking, cookie theft & fixation | Session cookie named `sid`; flags `HttpOnly`, `SameSite=Strict`, `Secure` (in production); `req.session.regenerate()` on login; 15-min idle timeout; 8-hr absolute cap; server-side session destruction. | `Test 5` (cookie flags HttpOnly, SameSite, custom name)<br/>`Test 8` (session ID changes after login)<br/>`Test 9` (`/me` requires active session)<br/>`Test 10` (logout invalidates session)<br/>`Test 11` (session expires after idle timeout). |
| **T12** | Missing audit trail & repudiation | Append-only structured JSON log (`logs/audit.log`) tracking `REGISTER`, `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`, and `RATE_LIMIT_HIT` with truncated SHA-256 identifiers; zero secrets logged. | `Test 16` (audit log records events with timestamps, truncated hashes, and no plaintext secrets). |
| **T13** | Login endpoint flooding & resource exhaustion | Compound IP + email rate limiting via `express-rate-limit` (5 requests / 15 minutes for `/login`), sending `429 Too Many Requests` with `Retry-After` header; 10kb JSON body size limit. | `Test 7` (the 6th rapid failed login returns 429 with `Retry-After` header). |
| **T14** | Verbose error stack traces and technology disclosures | Centralized Express error handler returning generic `500 Internal server error` responses; server-side error logging; `app.disable('x-powered-by')`; Helmet security headers. | `Test 13` (error responses contain no stack trace and disclose no internal paths)<br/>`Test 14` (response headers include Helmet defaults and no `X-Powered-By`). |

---

## 3. Design Choices & Rationales

* **Password Hashing (`bcrypt`, Cost Factor 12)**:
  * *Choice*: `bcrypt` with work factor 12 was chosen over lower cost factors.
  * *Rationale*: Cost factor 12 requires ~250–350 ms per hash calculation on standard server hardware. This computational cost severely handicaps offline dictionary attacks and GPU cracking rigs without degrading legitimate user login experience.
* **Timing Discrepancy Equalization**:
  * *Choice*: A precomputed dummy bcrypt hash (`$2b$12$e8uq5X...`) is evaluated whenever a login query specifies an unregistered email address.
  * *Rationale*: Without this dummy hash calculation, requests for non-existent users would return in < 5 ms, whereas requests for valid users with incorrect passwords would take ~300 ms. Attackers could exploit this side-channel timing delta to enumerate valid registered student emails.
* **Session Cookie Architecture (`sid`, `HttpOnly`, `SameSite=Strict`, `rolling`)**:
  * *Choice*: Cookie name is set to generic `sid` (obscuring Express / `connect.sid`). Flags include `HttpOnly` (blocks XSS token theft via JavaScript), `SameSite=Strict` (blocks cross-site cookie transmission), and `rolling: true` (refreshes the 15-minute idle window on user interaction).
  * *Choice*: `Secure` flag is enabled automatically when `NODE_ENV=production` or `COOKIE_SECURE=true`, while remaining configurable to facilitate local HTTP test execution.
* **Session Lifespan Policies**:
  * *Idle Timeout (15 minutes)*: Minimizes the window of opportunity if a student leaves a shared university workstation unlocked.
  * *Absolute Timeout (8 hours)*: Enforces re-authentication after a full study session, regardless of continuous activity, neutralizing indefinitely persistent hijacked sessions.
* **Rate Limiting (Compound Key)**:
  * *Choice*: Keyed on `${req.ip}_${normalizedEmail}`.
  * *Rationale*: Purely IP-based rate limiting can inadvertently block multiple students sharing a university campus Wi-Fi proxy. Purely email-based limiting allows an attacker to lock out legitimate students deliberately. A compound key balances brute-force protection with shared network resilience.
* **CSRF Mitigation (Custom Header)**:
  * *Choice*: Requiring `X-Requested-With: XMLHttpRequest` on state-changing POST requests.
  * *Rationale*: Cross-origin HTML forms and scripts cannot attach custom headers without triggering a CORS preflight (`OPTIONS`) check. This provides lightweight, stateless protection against Cross-Site Request Forgery for JSON APIs without requiring complex anti-CSRF token synchronization across server restarts.

---

## 4. Known Limitations

This service is a focused educational authentication lab and exhibits the following documented limitations:
1. **Memory Session Store**: The default Express memory session store is used for simplicity. Sessions are stored in process RAM and do not persist across server restarts, nor do they scale across multi-instance clusters. A production deployment requires Redis or an isolated session database.
2. **Absence of Multi-Factor Authentication (MFA)**: Administrative and privileged accounts rely solely on single-factor passwords. TOTP/WebAuthn is not yet implemented.
3. **No Email Verification**: Accounts activate immediately upon registration without verifying that the student actually controls the submitted `@school.edu` email address.
4. **No Password Reset Flow**: The password reset mechanism (threat model item T7) is omitted in this lab to maintain a tight scope.
5. **Proxy Header IP Spoofing**: In the absence of an upstream trusted proxy configuration (`app.set('trust proxy', ...)`), client IP identification relies on direct socket connection IP, which can be manipulated if placed behind untrusted intermediaries.
6. **No Account Lockout Notifications**: Users are not notified via email when repeated failed logins trigger rate-limit throttling on their account identifier.

---

## 5. Next Steps

To transition this lab authentication component into NoteShare's production infrastructure:
1. **Persistent Session Storage**: Migrate session persistence to an encrypted Redis cache or dedicated PostgreSQL session table.
2. **Secure Password Reset Engine (T7)**: Implement single-use, 15-minute cryptographically random reset tokens transmitted via NoteShare's outbound SMTP service.
3. **Email Verification**: Send cryptographic verification tokens upon registration before granting full note-upload permissions.
4. **MFA for Moderation Roles**: Enforce RFC 6238 TOTP two-factor authentication for accounts assigned `/admin` roles.
5. **Log Forwarding**: Ship `logs/audit.log` over mutual TLS to a centralized append-only log aggregator (e.g., Elasticsearch, OpenSearch, or CloudWatch) to prevent local log tampering.
