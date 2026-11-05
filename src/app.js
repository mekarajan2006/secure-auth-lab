const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const { createUser, findUserByEmail } = require('./db');
const { validateRegistrationInput, validateLoginInput } = require('./validators');
const { logAuditEvent } = require('./audit');

// Precomputed bcrypt hash (cost factor 12) for timing equalization on unknown emails
const DUMMY_HASH = '$2b$12$e8uq5X1Q77XjQcQ2i80lcePZZWvj2.gEaQdE3hR9aX6.sV3gD2gOm';

function createApp() {
  const app = express();

  // Security Control (T11, T14): Helmet sets HTTP headers restricting framing, sniffing and XSS
  app.use(helmet());

  // Security Control (T14): Disable X-Powered-By header to obscure technology stack
  app.disable('x-powered-by');

  // Security Control (T13): Limit JSON payload size to 10kb to prevent memory exhaustion
  app.use(express.json({ limit: '10kb' }));

  // Security Control (T11): Configure hardened session cookies
  const isSecure = process.env.COOKIE_SECURE === 'true' || process.env.NODE_ENV === 'production';
  const idleTimeout = Number(process.env.SESSION_IDLE_TIMEOUT_MS) || 15 * 60 * 1000;
  const absoluteTimeout = Number(process.env.SESSION_ABSOLUTE_TIMEOUT_MS) || 8 * 60 * 60 * 1000;

  app.use(session({
    name: 'sid', // Security Control: Use generic cookie name to obscure underlying framework
    secret: process.env.SESSION_SECRET || 'dev-secret-key-change-in-production-12345',
    resave: false,
    saveUninitialized: false,
    rolling: true, // Security Control: Reset idle expiration timer on every active response
    cookie: {
      httpOnly: true, // Security Control (T5, T11): Prevent client-side script access to cookie
      sameSite: 'strict', // Security Control (T11): Strictly isolate cookies to first-party context
      secure: isSecure, // Security Control (T11): Enforce HTTPS transmission in production
      maxAge: idleTimeout // Security Control (T11): Idle timeout of 15 minutes
    }
  }));

  // Security Control (T11): Absolute session lifetime enforcement (8 hours maximum)
  app.use((req, res, next) => {
    if (req.session && req.session.userId) {
      const now = Date.now();
      if (req.session.createdAt && (now - req.session.createdAt > absoluteTimeout)) {
        logAuditEvent({ event: 'SESSION_EXPIRED', identifier: req.session.email, ip: req.ip, status: 'EXPIRED' });
        return req.session.destroy(() => {
          res.clearCookie('sid');
          return res.status(401).json({ error: 'Session expired. Please log in again.' });
        });
      }
    }
    next();
  });

  // Security Control (T11): CSRF defense requiring custom header for state-changing routes
  const requireCsrfHeader = (req, res, next) => {
    const customHeader = req.headers['x-requested-with'];
    if (!customHeader || typeof customHeader !== 'string' || customHeader.toLowerCase() !== 'xmlhttprequest') {
      logAuditEvent({ event: 'CSRF_BLOCKED', ip: req.ip, status: 'BLOCKED' });
      return res.status(403).json({ error: 'CSRF protection: missing or invalid X-Requested-With header' });
    }
    next();
  };

  // Security Control (T13): Rate limiting on login attempts to resist credential stuffing
  const loginLimiter = rateLimit({
    windowMs: Number(process.env.LOGIN_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max: Number(process.env.LOGIN_RATE_LIMIT_MAX) || 5,
    standardHeaders: true,
    legacyHeaders: false,
    // Security Control (T13): Limit by compound IP and email to isolate targeted attacks
    keyGenerator: (req) => `${req.ip}_${(req.body && req.body.email ? String(req.body.email).toLowerCase().trim() : 'anonymous')}`,
    handler: (req, res, next, options) => {
      logAuditEvent({ event: 'RATE_LIMIT_HIT', identifier: req.body && req.body.email, ip: req.ip, status: 'BLOCKED' });
      res.setHeader('Retry-After', Math.ceil(options.windowMs / 1000));
      return res.status(429).json({ error: 'Too many login attempts. Please try again later.' });
    }
  });

  // Security Control (T13): Rate limiting on account registration
  const registerLimiter = rateLimit({
    windowMs: Number(process.env.REGISTER_RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    max: Number(process.env.REGISTER_RATE_LIMIT_MAX) || 20,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res, next, options) => {
      logAuditEvent({ event: 'RATE_LIMIT_HIT', identifier: req.body && req.body.email, ip: req.ip, status: 'BLOCKED' });
      res.setHeader('Retry-After', Math.ceil(options.windowMs / 1000));
      return res.status(429).json({ error: 'Too many registration attempts. Please try again later.' });
    }
  });

  // Health check endpoint
  app.get('/health', (req, res) => {
    res.status(200).json({ status: 'ok' });
  });

  // POST /register - Student account registration
  app.post('/register', requireCsrfHeader, registerLimiter, async (req, res, next) => {
    try {
      // Security Control (T2): Server-side input validation and normalization
      const validation = validateRegistrationInput(req.body);
      if (!validation.valid) {
        logAuditEvent({ event: 'REGISTER_FAILURE', identifier: req.body && req.body.email, ip: req.ip, status: 'BAD_INPUT' });
        return res.status(400).json({ error: validation.error });
      }

      const { email, password } = validation;

      // Security Control (T3): Parameterized query checks if user already exists
      const existingUser = findUserByEmail(email);
      if (existingUser) {
        logAuditEvent({ event: 'REGISTER_DUPLICATE', identifier: email, ip: req.ip, status: 'DUPLICATE' });
        // Security Control (T2): Generic error avoids revealing account existence
        return res.status(400).json({ error: 'Registration could not be completed' });
      }

      // Security Control (T2): Hash password with bcrypt cost factor 12 and per-user salt
      const saltRounds = 12;
      const passwordHash = await bcrypt.hash(password, saltRounds);

      // Security Control (T3): Store user using parameterized query; never store plaintext
      createUser(email, passwordHash);

      logAuditEvent({ event: 'REGISTER_SUCCESS', identifier: email, ip: req.ip, status: 'SUCCESS' });
      return res.status(201).json({ message: 'Registration successful' });
    } catch (err) {
      next(err);
    }
  });

  // POST /login - Student authentication
  app.post('/login', requireCsrfHeader, loginLimiter, async (req, res, next) => {
    try {
      // Security Control (T2): Validate presence and types of login payload
      const validation = validateLoginInput(req.body);
      if (!validation.valid) {
        // Run dummy hash comparison to prevent timing discrepancy on invalid formats
        await bcrypt.compare('dummy-password', DUMMY_HASH);
        logAuditEvent({ event: 'LOGIN_FAILURE', identifier: req.body && req.body.email, ip: req.ip, status: 'BAD_INPUT' });
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      const { email, password } = validation;

      // Security Control (T3): Query database using parameterized query
      const user = findUserByEmail(email);

      // Security Control (T2): Equalize timing by executing dummy hash compare if user does not exist
      if (!user) {
        await bcrypt.compare(password, DUMMY_HASH);
        logAuditEvent({ event: 'LOGIN_FAILURE', identifier: email, ip: req.ip, status: 'USER_NOT_FOUND' });
        // Security Control (T2): Generic error message identical to wrong password
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Security Control (T2): Verify password using constant-time hash comparison
      const passwordMatch = await bcrypt.compare(password, user.password_hash);
      if (!passwordMatch) {
        logAuditEvent({ event: 'LOGIN_FAILURE', identifier: email, ip: req.ip, status: 'WRONG_PASSWORD' });
        // Security Control (T2): Generic error message identical to unknown user
        return res.status(401).json({ error: 'Invalid email or password' });
      }

      // Security Control (T11): Regenerate session ID upon login to prevent session fixation attacks
      req.session.regenerate((err) => {
        if (err) {
          return next(err);
        }
        req.session.userId = user.id;
        req.session.email = user.email;
        req.session.createdAt = Date.now();

        logAuditEvent({ event: 'LOGIN_SUCCESS', identifier: email, ip: req.ip, status: 'SUCCESS' });
        return res.status(200).json({ message: 'Login successful' });
      });
    } catch (err) {
      next(err);
    }
  });

  // POST /logout - Terminate session
  app.post('/logout', requireCsrfHeader, (req, res, next) => {
    if (!req.session || !req.session.userId) {
      res.clearCookie('sid');
      return res.status(200).json({ message: 'Logged out successfully' });
    }

    const email = req.session.email;
    logAuditEvent({ event: 'LOGOUT', identifier: email, ip: req.ip, status: 'SUCCESS' });

    // Security Control (T11): Invalidate session server-side and clear client cookie
    req.session.destroy((err) => {
      if (err) {
        return next(err);
      }
      res.clearCookie('sid');
      return res.status(200).json({ message: 'Logged out successfully' });
    });
  });

  // GET /me - Protected route returning authenticated user's email only
  app.get('/me', (req, res) => {
    // Security Control (T11): Enforce session authentication check on protected route
    if (!req.session || !req.session.userId) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    // Security Control: Return minimal required profile data only; never return IDs or hashes
    return res.status(200).json({ email: req.session.email });
  });

  // Test-only endpoint to trigger an error and verify central error handler
  if (process.env.NODE_ENV === 'test') {
    app.get('/test-error', (req, res, next) => {
      next(new Error('Simulated database or server failure'));
    });
  }

  // Security Control (T14): Centralized error handler suppressing stack traces and technical paths
  app.use((err, req, res, next) => {
    if (res.headersSent) {
      return next(err);
    }
    // Log complete stack trace internally to stderr without exposing to client
    console.error('[Internal Error Logged]:', err.message);
    const statusCode = err.status && typeof err.status === 'number' ? err.status : 500;
    return res.status(statusCode).json({
      error: 'Internal server error'
    });
  });

  return app;
}

module.exports = { createApp };
