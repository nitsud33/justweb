const Database = require('better-sqlite3');
const path = require('path');

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'babysitter.db');
const db = new Database(dbPath);

// Initialize database schema
db.exec(`
  -- Users table
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    name TEXT NOT NULL,
    is_babysitter INTEGER DEFAULT 0,
    google_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  
  -- Add google_id column if it doesn't exist (migration for existing DBs)
  -- SQLite doesn't support IF NOT EXISTS for columns, so we handle it in code

  -- Babysitter profiles
  CREATE TABLE IF NOT EXISTS babysitter_profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER UNIQUE NOT NULL,
    bio TEXT,
    experience TEXT,
    certifications TEXT,
    hourly_rate REAL,
    age_range TEXT,
    availability TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  -- Connections (bidirectional friendships)
  CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id INTEGER NOT NULL,
    user2_id INTEGER NOT NULL,
    relationship_type TEXT DEFAULT 'friend',
    status TEXT DEFAULT 'pending',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user1_id) REFERENCES users(id),
    FOREIGN KEY (user2_id) REFERENCES users(id),
    UNIQUE(user1_id, user2_id)
  );

  -- Vouches for babysitters
  CREATE TABLE IF NOT EXISTS vouches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    voucher_id INTEGER NOT NULL,
    babysitter_id INTEGER NOT NULL,
    relationship TEXT,
    times_used INTEGER DEFAULT 1,
    recommendation TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (voucher_id) REFERENCES users(id),
    FOREIGN KEY (babysitter_id) REFERENCES users(id),
    UNIQUE(voucher_id, babysitter_id)
  );
`);

// Migration: Add google_id column if it doesn't exist
try {
  const columns = db.prepare("PRAGMA table_info(users)").all();
  if (!columns.find(c => c.name === 'google_id')) {
    db.exec("ALTER TABLE users ADD COLUMN google_id TEXT");
    console.log('Migration: Added google_id column to users table');
  }
} catch (err) {
  console.error('Migration error:', err.message);
}

// Also ensure password is nullable (for OAuth-only users)
try {
  const columns = db.prepare("PRAGMA table_info(users)").all();
  const passwordCol = columns.find(c => c.name === 'password');
  if (passwordCol && passwordCol.notnull === 1) {
    console.log('Note: password column allows NULL for OAuth users');
  }
} catch (err) {
  // Ignore
}

module.exports = db;
