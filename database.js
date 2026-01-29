const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

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
    share_token TEXT UNIQUE,
    profile_public INTEGER DEFAULT 0,
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

  -- Price history for tracking trends
  CREATE TABLE IF NOT EXISTS price_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id TEXT NOT NULL,
    price REAL NOT NULL,
    source TEXT DEFAULT 'tcgplayer',
    recorded_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Daily portfolio snapshots for value tracking
  CREATE TABLE IF NOT EXISTS portfolio_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    total_value REAL NOT NULL,
    total_cards INTEGER NOT NULL,
    snapshot_date DATE NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(user_id, snapshot_date)
  );

  -- Price alerts for want list items
  CREATE TABLE IF NOT EXISTS price_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    card_id TEXT NOT NULL,
    target_price REAL NOT NULL,
    alert_type TEXT DEFAULT 'below',
    active INTEGER DEFAULT 1,
    triggered_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
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

  -- Create indexes for performance
  CREATE INDEX IF NOT EXISTS idx_price_history_card ON price_history(card_id);
  CREATE INDEX IF NOT EXISTS idx_price_history_date ON price_history(recorded_at);
  CREATE INDEX IF NOT EXISTS idx_collection_user ON collection(user_id);
  CREATE INDEX IF NOT EXISTS idx_collection_set ON collection(set_id);
  CREATE INDEX IF NOT EXISTS idx_portfolio_user_date ON portfolio_snapshots(user_id, snapshot_date);
`);

// Migrations
try {
  const columns = db.prepare("PRAGMA table_info(users)").all();
  const columnNames = columns.map(c => c.name);
  
  if (!columnNames.includes('google_id')) {
    db.exec("ALTER TABLE users ADD COLUMN google_id TEXT");
    console.log('Migration: Added google_id column to users table');
  }
  
  if (!columnNames.includes('share_token')) {
    db.exec("ALTER TABLE users ADD COLUMN share_token TEXT");
    console.log('Migration: Added share_token column to users table');
  }
  
  if (!columnNames.includes('profile_public')) {
    db.exec("ALTER TABLE users ADD COLUMN profile_public INTEGER DEFAULT 0");
    console.log('Migration: Added profile_public column to users table');
  }
  
  // Generate share tokens for existing users
  const usersWithoutToken = db.prepare("SELECT id FROM users WHERE share_token IS NULL").all();
  for (const user of usersWithoutToken) {
    const token = crypto.randomBytes(8).toString('hex');
    db.prepare("UPDATE users SET share_token = ? WHERE id = ?").run(token, user.id);
  }
  if (usersWithoutToken.length > 0) {
    console.log(`Migration: Generated share tokens for ${usersWithoutToken.length} users`);
  }
} catch (err) {
  console.error('Migration error:', err.message);
}

// Helper function to generate share token
db.generateShareToken = () => crypto.randomBytes(8).toString('hex');

module.exports = db;
