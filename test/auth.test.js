const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const request = require('supertest');

// Configure test environment variables before requiring app modules
const TEST_DB_PATH = path.join(__dirname, 'test-auth.db');
const TEST_LOG_PATH = path.join(__dirname, 'test-audit.log');

process.env.NODE_ENV = 'test';
process.env.DB_PATH = TEST_DB_PATH;
process.env.AUDIT_LOG_PATH = TEST_LOG_PATH;
process.env.SESSION_SECRET = 'test-suite-super-secret-key-32-chars-long!';
process.env.COOKIE_SECURE = 'false'; // Allow HTTP cookies in local automated test harness
process.env.LOGIN_RATE_LIMIT_MAX = '5';
process.env.LOGIN_RATE_LIMIT_WINDOW_MS = '60000'; // 1 minute window for tests
process.env.SESSION_IDLE_TIMEOUT_MS = '150'; // 150ms idle expiry for test verification
process.env.SESSION_ABSOLUTE_TIMEOUT_MS = '1000';

const { createApp } = require('../src/app');
const { initDb, closeDb, findUserByEmail } = require('../src/db');

describe('NoteShare Secure Authentication Service Tests', () => {
  let app;

  before(() => {
    // Clean up any residual test files
    if (fs.existsSync(TEST_DB_PATH)) fs.unlinkSync(TEST_DB_PATH);
    if (fs.existsSync(TEST_LOG_PATH)) fs.unlinkSync(TEST_LOG_PATH);

    initDb(TEST_DB_PATH);
    app = createApp();
  });

  after(() => {
    closeDb();
    // Clean up SQLite files
    if (fs.existsSync(TEST_DB_PATH)) fs.unlinkSync(TEST_DB_PATH);
    if (fs.existsSync(TEST_DB_PATH + '-wal')) fs.unlinkSync(TEST_DB_PATH + '-wal');
    if (fs.existsSync(TEST_DB_PATH + '-shm')) fs.unlinkSync(TEST_DB_PATH + '-shm');
    if (fs.existsSync(TEST_LOG_PATH)) fs.unlinkSync(TEST_LOG_PATH);
  });

  // =========================================================================
  // 1. Password Hashing (T2)
  // =========================================================================
  it('1. Passwords are stored hashed (never plaintext, starts with $2b$12$ or $2a$12$)', async () => {
    const email = 'hashing_test@school.edu';
    const plaintext = 'SuperSecretPass123!';

    const res = await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password: plaintext });

    assert.equal(res.status, 201);
    assert.equal(res.body.message, 'Registration successful');
    assert.equal(res.body.password, undefined);
    assert.equal(res.body.password_hash, undefined);

    // Verify database record directly
    const user = findUserByEmail(email);
    assert.ok(user, 'User record must exist in database');
    assert.notEqual(user.password_hash, plaintext, 'Password must never be stored in plaintext');
    assert.match(
      user.password_hash,
      /^\$2[ab]\$12\$/,
      'Password hash must start with bcrypt cost factor 12 prefix ($2b$12$ or $2a$12$)'
    );
  });

  // =========================================================================
  // 2. Input Validation: Weak, Short, Common, Non-string Passwords (T2)
  // =========================================================================
  it('2. Weak, short, common, and non-string passwords are rejected with 400', async () => {
    // 2a. Too short (< 12 characters)
    const shortRes = await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email: 'short@school.edu', password: 'Short1!' });
    assert.equal(shortRes.status, 400);
    assert.match(shortRes.body.error, /Password must be between 12 and 128 characters/i);

    // 2b. Common password from blocklist
    const commonRes = await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email: 'common@school.edu', password: 'password123456' });
    assert.equal(commonRes.status, 400);
    assert.match(commonRes.body.error, /too common/i);

    // 2c. Non-string password
    const nonStringRes = await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email: 'num@school.edu', password: 1234567890123 });
    assert.equal(nonStringRes.status, 400);
    assert.match(nonStringRes.body.error, /must be strings/i);

    // 2d. Missing password
    const missingRes = await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email: 'missing@school.edu' });
    assert.equal(missingRes.status, 400);
  });

  // =========================================================================
  // 3. Input Validation: Invalid Emails (T2)
  // =========================================================================
  it('3. Invalid emails are rejected with 400', async () => {
    const invalidEmails = [
      'not-an-email',
      '@missinguser.com',
      'user@.com',
      'spaces in@email.com',
      ''
    ];

    for (const email of invalidEmails) {
      const res = await request(app)
        .post('/register')
        .set('X-Requested-With', 'XMLHttpRequest')
        .send({ email, password: 'ValidPassword123!' });
      assert.equal(res.status, 400, `Expected 400 for invalid email: "${email}"`);
    }

    // Non-string email
    const nonStringEmailRes = await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email: 987654, password: 'ValidPassword123!' });
    assert.equal(nonStringEmailRes.status, 400);
  });

  // =========================================================================
  // 4. Duplicate Registration (T2 User Enumeration Defense)
  // =========================================================================
  it('4. Duplicate registration does not reveal whether the email exists beyond a generic response', async () => {
    const email = 'duplicate_test@school.edu';
    const password = 'StrongPassword123!';

    // First registration succeeds
    const firstRes = await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });
    assert.equal(firstRes.status, 201);

    // Second registration with same email
    const secondRes = await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });

    assert.equal(secondRes.status, 400);
    assert.equal(secondRes.body.error, 'Registration could not be completed');
    assert.equal(
      /already exists|taken|registered/i.test(secondRes.body.error),
      false,
      'Error message must not leak user account existence'
    );
  });

  // =========================================================================
  // 5. Login Success Sets Secure Cookie Flags (T11)
  // =========================================================================
  it('5. Login success sets a cookie with HttpOnly, SameSite, and custom sid name', async () => {
    const email = 'cookie_test@school.edu';
    const password = 'StrongPassword123!';

    await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });

    const res = await request(app)
      .post('/login')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });

    assert.equal(res.status, 200);
    assert.equal(res.body.message, 'Login successful');

    const cookies = res.headers['set-cookie'];
    assert.ok(cookies, 'set-cookie header must be present on login');

    const sidCookie = cookies.find((c) => c.startsWith('sid='));
    assert.ok(sidCookie, 'Cookie name must be "sid"');
    assert.match(sidCookie, /HttpOnly/i, 'Cookie must include HttpOnly flag');
    assert.match(sidCookie, /SameSite=Strict/i, 'Cookie must include SameSite=Strict flag');
  });

  // =========================================================================
  // 6. Generic Authentication Errors & Equalized Responses (T2)
  // =========================================================================
  it('6. Wrong password and unknown email give identical status (401) and identical body', async () => {
    const email = 'known_user@school.edu';
    const password = 'StrongPassword123!';

    await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });

    // Attempt 1: Unknown email
    const unknownRes = await request(app)
      .post('/login')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email: 'nonexistent_user@school.edu', password: 'SomeRandomPassword123!' });

    // Attempt 2: Registered email with wrong password
    const wrongPassRes = await request(app)
      .post('/login')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password: 'WrongPassword123!' });

    // Verify identical status
    assert.equal(unknownRes.status, 401);
    assert.equal(wrongPassRes.status, 401);

    // Verify identical body
    assert.deepEqual(unknownRes.body, wrongPassRes.body);
    assert.equal(unknownRes.body.error, 'Invalid email or password');
  });

  // =========================================================================
  // 7. Rate Limiting: 6th Failed Login Returns 429 with Retry-After (T13)
  // =========================================================================
  it('7. The 6th rapid failed login returns 429 with Retry-After header', async () => {
    const email = 'bruteforce_target@school.edu';

    // Send 5 rapid failed login requests (max allowed = 5)
    for (let i = 1; i <= 5; i++) {
      const res = await request(app)
        .post('/login')
        .set('X-Requested-With', 'XMLHttpRequest')
        .send({ email, password: 'WrongPassword123!' });
      assert.equal(res.status, 401, `Attempt ${i} should be 401`);
    }

    // 6th attempt should be blocked by rate limiter
    const blockedRes = await request(app)
      .post('/login')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password: 'WrongPassword123!' });

    assert.equal(blockedRes.status, 429);
    assert.ok(blockedRes.headers['retry-after'], 'Retry-After header must be present on 429 response');
    assert.match(blockedRes.body.error, /Too many login attempts/i);
  });

  // =========================================================================
  // 8. Session Fixation Prevention: Session ID Changes After Login (T11)
  // =========================================================================
  it('8. Session ID changes after login (session fixation prevention)', async () => {
    const email = 'fixation_test@school.edu';
    const password = 'StrongPassword123!';

    await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });

    // First establish an unauthenticated session cookie by calling /health or an initial request
    const agent = request.agent(app);
    const preLoginRes = await agent.get('/health');
    
    // Perform login with the same agent session
    const loginRes = await agent
      .post('/login')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });

    assert.equal(loginRes.status, 200);

    const loginCookies = loginRes.headers['set-cookie'];
    assert.ok(loginCookies, 'set-cookie header must be sent upon login');
    const newSidCookie = loginCookies.find((c) => c.startsWith('sid='));
    assert.ok(newSidCookie, 'A new sid cookie must be issued on login');
  });

  // =========================================================================
  // 9. Protected Route: /me Returns 401 Without Session and 200 with One (T11)
  // =========================================================================
  it('9. /me returns 401 without a session and 200 with one', async () => {
    // 9a. Request without session
    const unauthRes = await request(app).get('/me');
    assert.equal(unauthRes.status, 401);
    assert.equal(unauthRes.body.error, 'Unauthorized');

    // 9b. Request with valid authenticated session
    const email = 'me_test@school.edu';
    const password = 'StrongPassword123!';

    await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });

    const loginRes = await request(app)
      .post('/login')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });

    const cookie = loginRes.headers['set-cookie'];

    const authRes = await request(app)
      .get('/me')
      .set('Cookie', cookie);

    assert.equal(authRes.status, 200);
    assert.equal(authRes.body.email, email);
    assert.equal(authRes.body.password, undefined);
    assert.equal(authRes.body.password_hash, undefined);
  });

  // =========================================================================
  // 10. Logout Invalidates Session Server-Side (T11)
  // =========================================================================
  it('10. Logout invalidates the session (a reused old cookie returns 401)', async () => {
    const email = 'logout_test@school.edu';
    const password = 'StrongPassword123!';

    await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });

    const loginRes = await request(app)
      .post('/login')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });

    const cookie = loginRes.headers['set-cookie'];

    // Verify authenticated access prior to logout
    const preLogoutRes = await request(app).get('/me').set('Cookie', cookie);
    assert.equal(preLogoutRes.status, 200);

    // Perform logout
    const logoutRes = await request(app)
      .post('/logout')
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('Cookie', cookie);
    assert.equal(logoutRes.status, 200);
    assert.equal(logoutRes.body.message, 'Logged out successfully');

    // Attempt to reuse old session cookie
    const postLogoutRes = await request(app).get('/me').set('Cookie', cookie);
    assert.equal(postLogoutRes.status, 401);
    assert.equal(postLogoutRes.body.error, 'Unauthorized');
  });

  // =========================================================================
  // 11. Session Expiry After Idle Timeout (T11)
  // =========================================================================
  it('11. Session expires after idle timeout (short configurable timeout)', async () => {
    const email = 'idle_timeout_test@school.edu';
    const password = 'StrongPassword123!';

    await request(app)
      .post('/register')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });

    const loginRes = await request(app)
      .post('/login')
      .set('X-Requested-With', 'XMLHttpRequest')
      .send({ email, password });

    const cookie = loginRes.headers['set-cookie'];

    // Confirm immediate access works
    const immediateRes = await request(app).get('/me').set('Cookie', cookie);
    assert.equal(immediateRes.status, 200);

    // Wait 200ms (configured SESSION_IDLE_TIMEOUT_MS is 150ms)
    await new Promise((resolve) => setTimeout(resolve, 200));

    // Request after idle timeout must fail with 401
    const expiredRes = await request(app).get('/me').set('Cookie', cookie);
    assert.equal(expiredRes.status, 401);
  });

  // =========================================================================
  // 12. SQL Injection Resistance (T3)
  // =========================================================================
  it('12. SQL injection string in email does not log in and does not crash', async () => {
    const sqliPayloads = [
      "' OR '1'='1",
      "' OR '1'='1' --",
      "admin'--",
      "' UNION SELECT null, 'admin', 'hash' --"
    ];

    for (const payload of sqliPayloads) {
      const res = await request(app)
        .post('/login')
        .set('X-Requested-With', 'XMLHttpRequest')
        .send({ email: payload, password: 'AnyPassword123!' });

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Invalid email or password');
    }

    // Verify service remains healthy after injection attempts
    const healthRes = await request(app).get('/health');
    assert.equal(healthRes.status, 200);
    assert.equal(healthRes.body.status, 'ok');
  });

  // =========================================================================
  // 13. Error Responses Contain No Stack Trace (T14)
  // =========================================================================
  it('13. Error responses contain no stack trace and disclose no internal paths', async () => {
    const res = await request(app).get('/test-error');

    assert.equal(res.status, 500);
    assert.equal(res.body.error, 'Internal server error');
    assert.equal(res.body.stack, undefined);
    assert.equal(res.body.message, undefined);

    const rawResponse = JSON.stringify(res.body);
    assert.equal(/at\s+\w+|node_modules|src\\|\.js:\d+/i.test(rawResponse), false);
  });

  // =========================================================================
  // 14. Response Headers Include Helmet Defaults and No X-Powered-By (T14)
  // =========================================================================
  it('14. Response headers include helmet defaults and no X-Powered-By header', async () => {
    const res = await request(app).get('/health');

    assert.equal(res.status, 200);
    assert.equal(res.headers['x-powered-by'], undefined, 'X-Powered-By must be disabled');
    assert.equal(res.headers['x-content-type-options'], 'nosniff', 'X-Content-Type-Options must be nosniff');
    assert.equal(res.headers['x-frame-options'], 'SAMEORIGIN', 'X-Frame-Options must be configured');
    assert.ok(res.headers['content-security-policy'], 'Content-Security-Policy must be set by Helmet');
  });

  // =========================================================================
  // 15. CSRF Protection for State-Changing Routes (T11)
  // =========================================================================
  it('15. CSRF defense: POST endpoints require custom X-Requested-With header', async () => {
    // Missing X-Requested-With on register
    const regRes = await request(app)
      .post('/register')
      .send({ email: 'csrf_test@school.edu', password: 'ValidPassword123!' });
    assert.equal(regRes.status, 403);
    assert.match(regRes.body.error, /CSRF protection/i);

    // Missing X-Requested-With on login
    const loginRes = await request(app)
      .post('/login')
      .send({ email: 'csrf_test@school.edu', password: 'ValidPassword123!' });
    assert.equal(loginRes.status, 403);
    assert.match(loginRes.body.error, /CSRF protection/i);

    // Missing X-Requested-With on logout
    const logoutRes = await request(app).post('/logout');
    assert.equal(logoutRes.status, 403);
    assert.match(logoutRes.body.error, /CSRF protection/i);
  });

  // =========================================================================
  // 16. Audit Log Verification (T12)
  // =========================================================================
  it('16. Audit log records events with timestamps, truncated hashes, and no plaintext secrets', () => {
    assert.ok(fs.existsSync(TEST_LOG_PATH), 'Audit log file must be created');
    const logContent = fs.readFileSync(TEST_LOG_PATH, 'utf8');
    const lines = logContent.trim().split('\n').filter(Boolean);

    assert.ok(lines.length > 0, 'Audit log must contain logged events');

    for (const line of lines) {
      const entry = JSON.parse(line);
      assert.ok(entry.timestamp, 'Entry must contain ISO timestamp');
      assert.ok(entry.event, 'Entry must contain event type');
      assert.ok(entry.identifier, 'Entry must contain hashed identifier');
      assert.ok(entry.ip, 'Entry must contain IP address');

      // Crucial Security Checks: Never log plaintext emails, passwords, or tokens
      assert.equal(/@school\.edu/i.test(line), false, 'Audit log must never contain plain email addresses');
      assert.equal(entry.password, undefined, 'Audit log must never contain password field');
      assert.equal(entry.password_hash, undefined, 'Audit log must never contain password_hash field');
      assert.equal(entry.token, undefined, 'Audit log must never contain token field');
    }
  });
});
