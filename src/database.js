const fs = require('node:fs');
const path = require('node:path');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

function createDatabase(filename, adminCredentials) {
  if (Boolean(adminCredentials?.username) !== Boolean(adminCredentials?.password)) {
    throw new Error('Both admin username and password must be configured together.');
  }

  if (filename !== ':memory:') {
    fs.mkdirSync(path.dirname(filename), { recursive: true });
  }

  const db = new Database(filename);
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS feedback (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
  `);

  if (adminCredentials?.username && adminCredentials?.password) {
    const username = adminCredentials.username.trim();
    if (username.length < 3 || username.length > 32 || adminCredentials.password.length < 12) {
      db.close();
      throw new Error('Admin username must be 3-32 characters and password at least 12 characters.');
    }

    const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
    if (!existing) {
      const passwordHash = bcrypt.hashSync(adminCredentials.password, 12);
      db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
        .run(username, passwordHash, 'admin');
    }
  }

  return db;
}

module.exports = { createDatabase };
