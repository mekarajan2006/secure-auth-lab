const Database = require('better-sqlite3');
const path = require('path');

let dbInstance = null;

// Initialize SQLite database connection and run schema migrations
function initDb(customPath) {
  const dbPath = customPath || process.env.DB_PATH || path.join(__dirname, '..', 'auth.db');
  dbInstance = new Database(dbPath);

  // Enable Write-Ahead Logging (WAL) mode for concurrency and performance
  dbInstance.pragma('journal_mode = WAL');

  // Security Control (T3): Create users table with unique email constraint
  dbInstance.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL COLLATE NOCASE,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  return dbInstance;
}

// Get the active database instance, initializing if needed
function getDb() {
  if (!dbInstance) {
    return initDb();
  }
  return dbInstance;
}

// Security Control (T3): Parameterized query prevents SQL injection when inserting users
function createUser(email, passwordHash) {
  const db = getDb();
  const stmt = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)');
  const info = stmt.run(email, passwordHash);
  return { id: info.lastInsertRowid, email };
}

// Security Control (T3): Parameterized query prevents SQL injection when looking up users by email
function findUserByEmail(email) {
  const db = getDb();
  const stmt = db.prepare('SELECT id, email, password_hash, created_at FROM users WHERE email = ?');
  return stmt.get(email);
}

// Close database connection cleanly
function closeDb() {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
}

module.exports = {
  initDb,
  getDb,
  createUser,
  findUserByEmail,
  closeDb
};
