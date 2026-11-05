const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Security Control (T12): Hash and truncate identifier so full emails are never logged
function hashIdentifier(identifier) {
  if (!identifier || typeof identifier !== 'string') {
    return 'anonymous';
  }
  // Produce a 12-character truncated SHA-256 hash for correlation without leaking PII
  return crypto.createHash('sha256').update(identifier.trim().toLowerCase()).digest('hex').slice(0, 12);
}

// Security Control (T12): Write append-only structured audit logs without sensitive secrets
function logAuditEvent({ event, identifier, ip, status = 'INFO', details = {} }) {
  const logPath = process.env.AUDIT_LOG_PATH || path.join(__dirname, '..', 'logs', 'audit.log');
  const logDir = path.dirname(logPath);

  try {
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }

    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      identifier: hashIdentifier(identifier),
      ip: ip || 'unknown',
      status,
      // Ensure details never contains password, hash, or token properties
      details: sanitizeDetails(details)
    };

    // Security Control (T12): Append-only write ensures audit log records cannot be overwritten
    fs.appendFileSync(logPath, JSON.stringify(logEntry) + '\n', 'utf8');
  } catch (err) {
    // Fail safe to stderr without breaking application request flow
    console.error('Audit logging failure:', err.message);
  }
}

// Security Control: Strip passwords, hashes, tokens or session secrets from log details
function sanitizeDetails(details) {
  if (!details || typeof details !== 'object') {
    return {};
  }
  const clean = { ...details };
  delete clean.password;
  delete clean.password_hash;
  delete clean.token;
  delete clean.sid;
  delete clean.secret;
  return clean;
}

module.exports = {
  logAuditEvent,
  hashIdentifier
};
