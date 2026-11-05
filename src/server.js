require('dotenv').config();
const { createApp } = require('./app');
const { initDb, closeDb } = require('./db');

// Security Control (T8): Fail to start in production if SESSION_SECRET is missing or default
if (process.env.NODE_ENV === 'production') {
  if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'dev-secret-key-change-in-production-12345') {
    console.error('FATAL: SESSION_SECRET must be configured with a strong secret in production environment.');
    process.exit(1);
  }
}

// Initialize database
initDb();

const app = createApp();
const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, () => {
  console.log(`NoteShare Secure Auth Lab running on http://localhost:${PORT} [${process.env.NODE_ENV || 'development'}]`);
});

// Graceful shutdown handling
function gracefulShutdown(signal) {
  console.log(`\nReceived ${signal}. Shutting down gracefully...`);
  server.close(() => {
    closeDb();
    console.log('Database connection closed and HTTP server stopped.');
    process.exit(0);
  });
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));
