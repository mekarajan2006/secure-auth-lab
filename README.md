# NoteShare: Secure Authentication Lab

A lightweight, hardened authentication microservice developed as the login component of **NoteShare** (a student notes-sharing platform). Built with Node.js, Express, and SQLite (`better-sqlite3`), this service addresses core authentication and session threats identified in the NoteShare threat model.

> **Authorized Educational Exercise**: This is a local, hypothetical security implementation. Do not scan or attack live systems, and never commit production credentials.

---

## 1. Security Features

* **Password Hashing (T2)**: Passwords hashed with `bcrypt` (cost factor 12) with unique per-user salts. Plaintext passwords and hashes are never returned or logged.
* **Input Validation (T2)**: Validates email format and RFC 5321 length (max 254 chars); enforces 12–128 character passwords; checks against a 20+ common weak password blocklist; trims and normalizes emails.
* **Anti-Enumeration & Constant-Time Responses (T2)**: Login returns identical HTTP 401 status and error messages (`"Invalid email or password"`) for both unknown emails and incorrect passwords, equalized with dummy bcrypt hash computations to eliminate timing side-channels.
* **Parameterized Database Queries (T3)**: 100% prepared SQL statements with `better-sqlite3` (`?` placeholders) preventing SQL injection attacks.
* **Hardened Session Management (T11)**: Cookie named `sid` with `HttpOnly`, `SameSite=Strict`, configurable `Secure` flags; new session ID generated on login (`req.session.regenerate()`) to prevent session fixation; 15-minute idle expiration; 8-hour absolute maximum lifespan.
* **CSRF Mitigation (T11)**: Requires custom `X-Requested-With: XMLHttpRequest` header on all state-changing `POST` endpoints.
* **Forensic Audit Logging (T12)**: Append-only JSON log file (`logs/audit.log`) tracking logins, logouts, registrations, and rate-limiting events with timestamps, IP addresses, and truncated SHA-256 identifier hashes. No credentials or plain emails are ever logged.
* **Endpoint Rate Limiting (T13)**: Compound IP + email throttling (5 failed attempts per 15 minutes) returning HTTP 429 with `Retry-After` header.
* **Technology Obscuration & Generic Errors (T14)**: Uses Helmet HTTP headers, disables `X-Powered-By`, restricts JSON payload to 10kb, and suppresses stack traces in all responses.

---

## 2. Prerequisites

* **Node.js**: `v18.0.0` or higher (tested on Node v22.14.0)
* **npm**: `v9.0.0` or higher (tested on npm 10.9.2)

---

## 3. Setup & Installation

1. **Clone or navigate into the repository**:
   ```bash
   cd secure-auth-lab
   ```

2. **Configure environment variables**:
   ```bash
   cp .env.example .env
   ```
   *(Review `.env` to verify `PORT=3000` and `SESSION_SECRET`)*

3. **Install dependencies**:
   ```bash
   npm install
   ```

---

## 4. Running the Service & Automated Tests

### Start the Server
```bash
npm start
```
*The server will start at `http://localhost:3000`.*

### Run Automated Tests
```bash
npm test
```
*Executes all 16 automated tests using Node's built-in `node:test` runner and `supertest`.*

### Run and Save Test Report
```bash
npm run test:report
```
*Runs the test suite and captures the complete TAP report to `evidence/test-output.txt`.*

---

## 5. Walkthrough: `curl` Commands

All `POST` endpoints require the `X-Requested-With: XMLHttpRequest` header for CSRF defense.

### Step 1: Register a New Student Account
```bash
curl -i -X POST http://localhost:3000/register \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d '{"email":"student@school.edu","password":"MySecurePassphrase2026!"}'
```
**Expected Response**:
```http
HTTP/1.1 201 Created
Content-Type: application/json; charset=utf-8

{"message":"Registration successful"}
```

---

### Step 2: Log In & Store Session Cookie
```bash
curl -i -c cookies.txt -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -H "X-Requested-With: XMLHttpRequest" \
  -d '{"email":"student@school.edu","password":"MySecurePassphrase2026!"}'
```
**Expected Response**:
```http
HTTP/1.1 200 OK
Set-Cookie: sid=s%3A...; Path=/; Expires=...; HttpOnly; SameSite=Strict
Content-Type: application/json; charset=utf-8

{"message":"Login successful"}
```

---

### Step 3: Access Protected Route (`GET /me`)
```bash
curl -i -b cookies.txt http://localhost:3000/me
```
**Expected Response**:
```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8

{"email":"student@school.edu"}
```

---

### Step 4: Log Out & Invalidate Session
```bash
curl -i -b cookies.txt -X POST http://localhost:3000/logout \
  -H "X-Requested-With: XMLHttpRequest"
```
**Expected Response**:
```http
HTTP/1.1 200 OK
Set-Cookie: sid=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT

{"message":"Logged out successfully"}
```

*Verifying subsequent access to `GET /me` with the previous cookie now returns `HTTP 401 Unauthorized`.*

---

## 6. Project Structure

```
secure-auth-lab/
├── .env.example              # Template configuration and secret placeholders
├── .gitignore                # Ignores .env, *.db, *.db-wal, logs/, and node_modules/
├── .npmrc                    # Local npm environment settings
├── package.json              # Project scripts and pinned dependencies
├── README.md                 # Setup, run guide, and curl examples
├── SECURITY-NOTE.md          # Comprehensive threat matrix, design choices, limitations
├── evidence/
│   └── test-output.txt       # Real, complete output of "npm test"
├── logs/                     # Audit trail directory (ignored by git)
│   └── audit.log             # Structured append-only security logs
├── src/
│   ├── app.js                # Express app, middleware, routes, error handling
│   ├── audit.js              # Append-only structured audit logger
│   ├── db.js                 # SQLite connection and parameterized SQL operations
│   ├── server.js             # HTTP server bootstrap and production secret validation
│   └── validators.js         # Input validation, normalization, and weak password blocklist
└── test/
    └── auth.test.js          # 16 automated tests covering all security requirements
```
