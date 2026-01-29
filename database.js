const Database = require('better-sqlite3');
const path = require('path');

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'pokemon.db');
const db = new Database(dbPath);

// Initialize database schema
db.exec(`
  -- Users table
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    name TEXT NOT NULL,
    google_id TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- User's card collection
  CREATE TABLE IF NOT EXISTS collection (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    card_id TEXT NOT NULL,
    card_name TEXT NOT NULL,
    card_image TEXT,
    set_id TEXT,
    set_name TEXT,
    rarity TEXT,
    quantity INTEGER DEFAULT 1,
    condition TEXT DEFAULT 'Near Mint',
    purchase_price REAL,
    market_price REAL,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(user_id, card_id, condition)
  );

  -- User's want list
  CREATE TABLE IF NOT EXISTS want_list (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    card_id TEXT NOT NULL,
    card_name TEXT NOT NULL,
    card_image TEXT,
    set_id TEXT,
    set_name TEXT,
    rarity TEXT,
    max_price REAL,
    priority INTEGER DEFAULT 1,
    notes TEXT,
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(user_id, card_id)
  );

  -- Price history cache
  CREATE TABLE IF NOT EXISTS price_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id TEXT NOT NULL,
    price REAL NOT NULL,
    source TEXT DEFAULT 'tcgplayer',
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Card cache (to reduce API calls)
  CREATE TABLE IF NOT EXISTS card_cache (
    card_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Set cache
  CREATE TABLE IF NOT EXISTS set_cache (
    set_id TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    cached_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

module.exports = db;
