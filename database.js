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

  -- Categories for multi-collectible support
  CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    icon TEXT,
    api_source TEXT,
    color TEXT DEFAULT '#ff6b35',
    active INTEGER DEFAULT 1
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
    category TEXT DEFAULT 'pokemon',
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(user_id, card_id, condition, category)
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
    category TEXT DEFAULT 'pokemon',
    added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(user_id, card_id, category)
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

  -- Trade proposals between users
  CREATE TABLE IF NOT EXISTS trades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    proposer_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    status TEXT DEFAULT 'pending',
    message TEXT,
    proposer_value REAL DEFAULT 0,
    recipient_value REAL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (proposer_id) REFERENCES users(id),
    FOREIGN KEY (recipient_id) REFERENCES users(id)
  );

  -- Cards offered/requested in trades
  CREATE TABLE IF NOT EXISTS trade_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    trade_id INTEGER NOT NULL,
    card_id TEXT NOT NULL,
    card_name TEXT NOT NULL,
    card_image TEXT,
    set_name TEXT,
    rarity TEXT,
    market_price REAL,
    quantity INTEGER DEFAULT 1,
    direction TEXT NOT NULL,
    FOREIGN KEY (trade_id) REFERENCES trades(id) ON DELETE CASCADE
  );

  -- Match scores between users (cached)
  CREATE TABLE IF NOT EXISTS match_scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user1_id INTEGER NOT NULL,
    user2_id INTEGER NOT NULL,
    score REAL NOT NULL,
    direct_matches INTEGER DEFAULT 0,
    last_calculated DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user1_id) REFERENCES users(id),
    FOREIGN KEY (user2_id) REFERENCES users(id),
    UNIQUE(user1_id, user2_id)
  );

  -- Create indexes for performance
  CREATE INDEX IF NOT EXISTS idx_price_history_card ON price_history(card_id);
  CREATE INDEX IF NOT EXISTS idx_price_history_date ON price_history(recorded_at);
  CREATE INDEX IF NOT EXISTS idx_collection_user ON collection(user_id);
  CREATE INDEX IF NOT EXISTS idx_collection_set ON collection(set_id);
  CREATE INDEX IF NOT EXISTS idx_portfolio_user_date ON portfolio_snapshots(user_id, snapshot_date);
  CREATE INDEX IF NOT EXISTS idx_trades_proposer ON trades(proposer_id);
  CREATE INDEX IF NOT EXISTS idx_trades_recipient ON trades(recipient_id);
  CREATE INDEX IF NOT EXISTS idx_trades_status ON trades(status);
  CREATE INDEX IF NOT EXISTS idx_trade_items_trade ON trade_items(trade_id);
  CREATE INDEX IF NOT EXISTS idx_match_scores_user ON match_scores(user1_id);
  CREATE INDEX IF NOT EXISTS idx_want_list_card ON want_list(card_id);
  CREATE INDEX IF NOT EXISTS idx_collection_card ON collection(card_id);

  -- Sports card specific tables
  CREATE TABLE IF NOT EXISTS sports_cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    player_name TEXT NOT NULL,
    team TEXT,
    year INTEGER NOT NULL,
    set_name TEXT NOT NULL,
    set_id TEXT,
    card_number TEXT,
    sport TEXT NOT NULL,
    rarity TEXT,
    image_url TEXT,
    -- Raw/ungraded pricing
    price_raw REAL,
    -- PSA graded prices
    price_psa_1 REAL,
    price_psa_2 REAL,
    price_psa_3 REAL,
    price_psa_4 REAL,
    price_psa_5 REAL,
    price_psa_6 REAL,
    price_psa_7 REAL,
    price_psa_8 REAL,
    price_psa_9 REAL,
    price_psa_10 REAL,
    -- BGS graded prices
    price_bgs_8 REAL,
    price_bgs_8_5 REAL,
    price_bgs_9 REAL,
    price_bgs_9_5 REAL,
    price_bgs_10 REAL,
    price_bgs_pristine REAL,
    -- SGC graded prices
    price_sgc_9 REAL,
    price_sgc_10 REAL,
    -- Metadata
    rookie_card INTEGER DEFAULT 0,
    parallel TEXT,
    notes TEXT,
    last_price_update DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Population reports for graded cards
  CREATE TABLE IF NOT EXISTS population_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    card_id TEXT NOT NULL,
    grader TEXT NOT NULL,
    grade TEXT NOT NULL,
    population INTEGER DEFAULT 0,
    plus_population INTEGER DEFAULT 0,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(card_id, grader, grade)
  );

  -- Sports card sets/years
  CREATE TABLE IF NOT EXISTS sports_sets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    set_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    year INTEGER NOT NULL,
    sport TEXT NOT NULL,
    manufacturer TEXT,
    total_cards INTEGER,
    description TEXT,
    image_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  -- Index for sports cards
  CREATE INDEX IF NOT EXISTS idx_sports_cards_player ON sports_cards(player_name);
  CREATE INDEX IF NOT EXISTS idx_sports_cards_year ON sports_cards(year);
  CREATE INDEX IF NOT EXISTS idx_sports_cards_sport ON sports_cards(sport);
  CREATE INDEX IF NOT EXISTS idx_sports_cards_set ON sports_cards(set_name);
  CREATE INDEX IF NOT EXISTS idx_population_card ON population_reports(card_id);
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
  
  // Add category column to collection if missing
  const collectionCols = db.prepare("PRAGMA table_info(collection)").all();
  const collectionColNames = collectionCols.map(c => c.name);
  if (!collectionColNames.includes('category')) {
    db.exec("ALTER TABLE collection ADD COLUMN category TEXT DEFAULT 'pokemon'");
    console.log('Migration: Added category column to collection table');
  }
  
  // Add category column to want_list if missing
  const wantListCols = db.prepare("PRAGMA table_info(want_list)").all();
  const wantListColNames = wantListCols.map(c => c.name);
  if (!wantListColNames.includes('category')) {
    db.exec("ALTER TABLE want_list ADD COLUMN category TEXT DEFAULT 'pokemon'");
    console.log('Migration: Added category column to want_list table');
  }
  
  // Seed default categories (including sports)
  const existingCategories = db.prepare("SELECT COUNT(*) as count FROM categories").get();
  if (existingCategories.count === 0) {
    db.prepare(`
      INSERT INTO categories (slug, name, description, icon, api_source, color) VALUES
      ('pokemon', 'Pokémon TCG', 'Pokémon Trading Card Game', '⚡', 'tcgdex', '#ffcb05'),
      ('mtg', 'Magic: The Gathering', 'The original trading card game', '🔮', 'scryfall', '#9b59b6'),
      ('yugioh', 'Yu-Gi-Oh!', 'Yu-Gi-Oh! Trading Card Game', '🎴', 'ygoprodeck', '#e74c3c'),
      ('baseball', 'Baseball Cards', 'Vintage & Modern Baseball Cards', '⚾', 'sports_internal', '#c41e3a'),
      ('basketball', 'Basketball Cards', 'NBA & Basketball Cards', '🏀', 'sports_internal', '#fd5a1e'),
      ('football', 'Football Cards', 'NFL & Football Cards', '🏈', 'sports_internal', '#013369')
    `).run();
    console.log('Migration: Seeded default categories (including sports)');
  }
  
  // Add sports categories if they don't exist
  const sportsCategories = [
    { slug: 'baseball', name: 'Baseball Cards', desc: 'Vintage & Modern Baseball Cards', icon: '⚾', color: '#c41e3a' },
    { slug: 'basketball', name: 'Basketball Cards', desc: 'NBA & Basketball Cards', icon: '🏀', color: '#fd5a1e' },
    { slug: 'football', name: 'Football Cards', desc: 'NFL & Football Cards', icon: '🏈', color: '#013369' }
  ];
  
  for (const cat of sportsCategories) {
    const exists = db.prepare("SELECT id FROM categories WHERE slug = ?").get(cat.slug);
    if (!exists) {
      db.prepare(`
        INSERT INTO categories (slug, name, description, icon, api_source, color)
        VALUES (?, ?, ?, ?, 'sports_internal', ?)
      `).run(cat.slug, cat.name, cat.desc, cat.icon, cat.color);
      console.log(`Migration: Added ${cat.name} category`);
    }
  }
  
  // Add grading fields to collection if missing
  const collectionColsCheck = db.prepare("PRAGMA table_info(collection)").all();
  const collectionColNamesCheck = collectionColsCheck.map(c => c.name);
  
  if (!collectionColNamesCheck.includes('grade')) {
    db.exec("ALTER TABLE collection ADD COLUMN grade TEXT");
    console.log('Migration: Added grade column to collection table');
  }
  
  if (!collectionColNamesCheck.includes('grader')) {
    db.exec("ALTER TABLE collection ADD COLUMN grader TEXT");
    console.log('Migration: Added grader column to collection table');
  }
  
  if (!collectionColNamesCheck.includes('cert_number')) {
    db.exec("ALTER TABLE collection ADD COLUMN cert_number TEXT");
    console.log('Migration: Added cert_number column to collection table');
  }
  
  if (!collectionColNamesCheck.includes('player_name')) {
    db.exec("ALTER TABLE collection ADD COLUMN player_name TEXT");
    console.log('Migration: Added player_name column to collection table');
  }
  
  if (!collectionColNamesCheck.includes('year')) {
    db.exec("ALTER TABLE collection ADD COLUMN year INTEGER");
    console.log('Migration: Added year column to collection table');
  }
} catch (err) {
  console.error('Migration error:', err.message);
}

// Helper function to generate share token
db.generateShareToken = () => crypto.randomBytes(8).toString('hex');

module.exports = db;
