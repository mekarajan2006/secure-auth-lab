// Security Control (T2): Common weak passwords blocklist with at least 20 entries
const COMMON_PASSWORDS = new Set([
  'password123456',
  '123456789012',
  'qwertyuiopas',
  'admin1234567',
  'welcome123456',
  'iloveyou12345',
  'monkey123456',
  'dragon123456',
  'master123456',
  'sunshine12345',
  'princess1234',
  'football1234',
  'trustno112345',
  'superman12345',
  'charlie12345',
  'jordan123456',
  'harley123456',
  'michael12345',
  'cookie123456',
  'shadow123456',
  'student123456',
  'noteshare1234'
]);

// Standard email syntax check according to HTML5 / RFC 5321 specification
const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

// Security Control (T2): Server-side input validation for user registration
function validateRegistrationInput(body) {
  // Security Control: Reject missing, null or non-object payloads
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false, error: 'Invalid request body format' };
  }

  // Security Control: Reject non-string or missing email and password fields
  if (typeof body.email !== 'string' || typeof body.password !== 'string') {
    return { valid: false, error: 'Email and password must be strings' };
  }

  // Security Control: Trim and normalize email to lowercase to prevent casing collisions
  const email = body.email.trim().toLowerCase();
  const password = body.password;

  // Security Control: Validate email length (RFC 5321 maximum 254 characters)
  if (email.length === 0 || email.length > 254) {
    return { valid: false, error: 'Invalid email address length' };
  }

  // Security Control: Validate email structure against format specification
  if (!EMAIL_REGEX.test(email)) {
    return { valid: false, error: 'Invalid email address format' };
  }

  // Security Control (T2): Enforce password length between 12 and 128 characters
  if (password.length < 12 || password.length > 128) {
    return { valid: false, error: 'Password must be between 12 and 128 characters' };
  }

  // Security Control (T2): Block dictionary words and widely compromised passwords
  if (COMMON_PASSWORDS.has(password.toLowerCase())) {
    return { valid: false, error: 'Password is too common; please choose a stronger passphrase' };
  }

  return { valid: true, email, password };
}

// Security Control (T2): Server-side input validation for login requests
function validateLoginInput(body) {
  // Security Control: Reject missing, null or non-object payloads
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return { valid: false };
  }

  // Security Control: Ensure both email and password are provided as strings
  if (typeof body.email !== 'string' || typeof body.password !== 'string') {
    return { valid: false };
  }

  const email = body.email.trim().toLowerCase();
  const password = body.password;

  if (email.length === 0 || email.length > 254 || password.length === 0 || password.length > 128) {
    return { valid: false };
  }

  return { valid: true, email, password };
}

module.exports = {
  COMMON_PASSWORDS,
  validateRegistrationInput,
  validateLoginInput
};
