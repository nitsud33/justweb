const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Pokemon TCG API base
const POKEMON_API = 'https://api.pokemontcg.io/v2';

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'pokemon-card-finder-secret-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: false,
    maxAge: 7 * 24 * 60 * 60 * 1000 // 1 week
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(id);
  done(null, user);
});

// Google OAuth Strategy
if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  const callbackURL = process.env.GOOGLE_CALLBACK_URL || 
    (process.env.RAILWAY_PUBLIC_DOMAIN 
      ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}/auth/google/callback`
      : 'http://localhost:3000/auth/google/callback');
  
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: callbackURL
  }, (accessToken, refreshToken, profile, done) => {
    try {
      const email = profile.emails[0].value.toLowerCase();
      const name = profile.displayName;
      const googleId = profile.id;
      
      let user = db.prepare('SELECT * FROM users WHERE google_id = ? OR email = ?').get(googleId, email);
      
      if (user) {
        if (!user.google_id) {
          db.prepare('UPDATE users SET google_id = ? WHERE id = ?').run(googleId, user.id);
        }
      } else {
        const result = db.prepare('INSERT INTO users (email, password, name, google_id) VALUES (?, ?, ?, ?)')
          .run(email, '', name, googleId);
        user = db.prepare('SELECT * FROM users WHERE id = ?').get(result.lastInsertRowid);
      }
      
      done(null, user);
    } catch (err) {
      done(err, null);
    }
  }));
  
  console.log('✅ Google OAuth configured');
  console.log('   Callback URL:', callbackURL);
} else {
  console.log('⚠️  Google OAuth not configured - set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET');
}

// Auth middleware
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
};

// Helper: Fetch from Pokemon TCG API with caching
async function fetchPokemonAPI(endpoint, cacheKey, cacheDuration = 3600000) {
  // Check cache first
  if (cacheKey) {
    const cached = db.prepare('SELECT data, cached_at FROM card_cache WHERE card_id = ?').get(cacheKey);
    if (cached) {
      const age = Date.now() - new Date(cached.cached_at).getTime();
      if (age < cacheDuration) {
        return JSON.parse(cached.data);
      }
    }
  }
  
  const response = await fetch(`${POKEMON_API}${endpoint}`, {
    headers: {
      'X-Api-Key': process.env.POKEMON_TCG_API_KEY || ''
    }
  });
  
  if (!response.ok) {
    throw new Error(`Pokemon API error: ${response.status}`);
  }
  
  const data = await response.json();
  
  // Cache the result
  if (cacheKey) {
    db.prepare('INSERT OR REPLACE INTO card_cache (card_id, data, cached_at) VALUES (?, ?, CURRENT_TIMESTAMP)')
      .run(cacheKey, JSON.stringify(data));
  }
  
  return data;
}

// ============ GOOGLE OAUTH ROUTES ============

app.get('/auth/google', passport.authenticate('google', { 
  scope: ['profile', 'email'] 
}));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/?error=oauth_failed' }),
  (req, res) => {
    req.session.userId = req.user.id;
    res.redirect('/');
  }
);

app.get('/api/auth/providers', (req, res) => {
  res.json({
    google: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET)
  });
});

// ============ AUTH ROUTES ============

app.post('/api/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password || !name) {
      return res.status(400).json({ error: 'All fields required' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = db.prepare('INSERT INTO users (email, password, name) VALUES (?, ?, ?)')
      .run(email.toLowerCase(), hashedPassword, name);
    
    req.session.userId = result.lastInsertRowid;
    res.json({ success: true, userId: result.lastInsertRowid });
  } catch (err) {
    if (err.message.includes('UNIQUE constraint')) {
      return res.status(400).json({ error: 'Email already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
    
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    if (!user.password) {
      return res.status(401).json({ error: 'Please sign in with Google' });
    }
    
    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    req.session.userId = user.id;
    res.json({ success: true, user: { id: user.id, name: user.name, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, email, name FROM users WHERE id = ?').get(req.session.userId);
  
  // Get collection stats
  const stats = db.prepare(`
    SELECT 
      COUNT(*) as totalCards,
      SUM(quantity) as totalQuantity,
      COALESCE(SUM(quantity * COALESCE(market_price, 0)), 0) as totalValue
    FROM collection WHERE user_id = ?
  `).get(req.session.userId);
  
  const wantListCount = db.prepare('SELECT COUNT(*) as count FROM want_list WHERE user_id = ?')
    .get(req.session.userId).count;
  
  res.json({ 
    user, 
    stats: {
      ...stats,
      wantListCount
    }
  });
});

// ============ POKEMON TCG API PROXY ============

app.get('/api/cards/search', async (req, res) => {
  try {
    const { q, page = 1, pageSize = 20 } = req.query;
    if (!q) {
      return res.status(400).json({ error: 'Query required' });
    }
    
    // Build search query - search by name
    const searchQuery = `name:"*${q}*"`;
    const endpoint = `/cards?q=${encodeURIComponent(searchQuery)}&page=${page}&pageSize=${pageSize}&orderBy=-set.releaseDate`;
    
    const data = await fetchPokemonAPI(endpoint);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cards/:id', async (req, res) => {
  try {
    const data = await fetchPokemonAPI(`/cards/${req.params.id}`, `card:${req.params.id}`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sets', async (req, res) => {
  try {
    const data = await fetchPokemonAPI('/sets?orderBy=-releaseDate', 'all_sets', 86400000); // Cache 24h
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sets/:id', async (req, res) => {
  try {
    const data = await fetchPokemonAPI(`/sets/${req.params.id}`, `set:${req.params.id}`);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sets/:id/cards', async (req, res) => {
  try {
    const { page = 1, pageSize = 50 } = req.query;
    const endpoint = `/cards?q=set.id:${req.params.id}&page=${page}&pageSize=${pageSize}&orderBy=number`;
    const data = await fetchPokemonAPI(endpoint);
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ COLLECTION ROUTES ============

app.get('/api/collection', requireAuth, (req, res) => {
  const collection = db.prepare(`
    SELECT * FROM collection 
    WHERE user_id = ? 
    ORDER BY added_at DESC
  `).all(req.session.userId);
  
  res.json(collection);
});

app.post('/api/collection', requireAuth, (req, res) => {
  try {
    const { cardId, cardName, cardImage, setId, setName, rarity, quantity = 1, condition = 'Near Mint', purchasePrice, marketPrice } = req.body;
    
    if (!cardId || !cardName) {
      return res.status(400).json({ error: 'Card ID and name required' });
    }
    
    // Check if card already exists in collection with same condition
    const existing = db.prepare('SELECT * FROM collection WHERE user_id = ? AND card_id = ? AND condition = ?')
      .get(req.session.userId, cardId, condition);
    
    if (existing) {
      // Update quantity
      db.prepare('UPDATE collection SET quantity = quantity + ? WHERE id = ?')
        .run(quantity, existing.id);
      const updated = db.prepare('SELECT * FROM collection WHERE id = ?').get(existing.id);
      return res.json({ success: true, card: updated, action: 'updated' });
    }
    
    const result = db.prepare(`
      INSERT INTO collection (user_id, card_id, card_name, card_image, set_id, set_name, rarity, quantity, condition, purchase_price, market_price)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.session.userId, cardId, cardName, cardImage, setId, setName, rarity, quantity, condition, purchasePrice, marketPrice);
    
    const card = db.prepare('SELECT * FROM collection WHERE id = ?').get(result.lastInsertRowid);
    res.json({ success: true, card, action: 'added' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/collection/:id', requireAuth, (req, res) => {
  try {
    const { quantity, condition, purchasePrice } = req.body;
    
    const existing = db.prepare('SELECT * FROM collection WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.session.userId);
    
    if (!existing) {
      return res.status(404).json({ error: 'Card not found in collection' });
    }
    
    db.prepare(`
      UPDATE collection SET quantity = ?, condition = ?, purchase_price = ?
      WHERE id = ?
    `).run(quantity || existing.quantity, condition || existing.condition, purchasePrice, req.params.id);
    
    const updated = db.prepare('SELECT * FROM collection WHERE id = ?').get(req.params.id);
    res.json({ success: true, card: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/collection/:id', requireAuth, (req, res) => {
  try {
    const result = db.prepare('DELETE FROM collection WHERE id = ? AND user_id = ?')
      .run(req.params.id, req.session.userId);
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Card not found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Collection by set (for completion tracking)
app.get('/api/collection/by-set', requireAuth, (req, res) => {
  const bySet = db.prepare(`
    SELECT set_id, set_name, 
           COUNT(DISTINCT card_id) as unique_cards,
           SUM(quantity) as total_cards,
           SUM(quantity * COALESCE(market_price, 0)) as set_value
    FROM collection 
    WHERE user_id = ? AND set_id IS NOT NULL
    GROUP BY set_id
    ORDER BY set_name
  `).all(req.session.userId);
  
  res.json(bySet);
});

// ============ WANT LIST ROUTES ============

app.get('/api/want-list', requireAuth, (req, res) => {
  const wantList = db.prepare(`
    SELECT * FROM want_list 
    WHERE user_id = ? 
    ORDER BY priority DESC, added_at DESC
  `).all(req.session.userId);
  
  res.json(wantList);
});

app.post('/api/want-list', requireAuth, (req, res) => {
  try {
    const { cardId, cardName, cardImage, setId, setName, rarity, maxPrice, priority = 1, notes } = req.body;
    
    if (!cardId || !cardName) {
      return res.status(400).json({ error: 'Card ID and name required' });
    }
    
    // Check if already on want list
    const existing = db.prepare('SELECT * FROM want_list WHERE user_id = ? AND card_id = ?')
      .get(req.session.userId, cardId);
    
    if (existing) {
      return res.status(400).json({ error: 'Card already on want list' });
    }
    
    // Check if already in collection
    const inCollection = db.prepare('SELECT * FROM collection WHERE user_id = ? AND card_id = ?')
      .get(req.session.userId, cardId);
    
    if (inCollection) {
      return res.status(400).json({ error: 'Card already in your collection' });
    }
    
    const result = db.prepare(`
      INSERT INTO want_list (user_id, card_id, card_name, card_image, set_id, set_name, rarity, max_price, priority, notes)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.session.userId, cardId, cardName, cardImage, setId, setName, rarity, maxPrice, priority, notes);
    
    const card = db.prepare('SELECT * FROM want_list WHERE id = ?').get(result.lastInsertRowid);
    res.json({ success: true, card });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/want-list/:id', requireAuth, (req, res) => {
  try {
    const { maxPrice, priority, notes } = req.body;
    
    const existing = db.prepare('SELECT * FROM want_list WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.session.userId);
    
    if (!existing) {
      return res.status(404).json({ error: 'Card not found on want list' });
    }
    
    db.prepare(`
      UPDATE want_list SET max_price = ?, priority = ?, notes = ?
      WHERE id = ?
    `).run(maxPrice, priority || existing.priority, notes, req.params.id);
    
    const updated = db.prepare('SELECT * FROM want_list WHERE id = ?').get(req.params.id);
    res.json({ success: true, card: updated });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/want-list/:id', requireAuth, (req, res) => {
  try {
    const result = db.prepare('DELETE FROM want_list WHERE id = ? AND user_id = ?')
      .run(req.params.id, req.session.userId);
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Card not found' });
    }
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Move from want list to collection
app.post('/api/want-list/:id/acquired', requireAuth, (req, res) => {
  try {
    const { purchasePrice, condition = 'Near Mint' } = req.body;
    
    const wantItem = db.prepare('SELECT * FROM want_list WHERE id = ? AND user_id = ?')
      .get(req.params.id, req.session.userId);
    
    if (!wantItem) {
      return res.status(404).json({ error: 'Card not found on want list' });
    }
    
    // Add to collection
    db.prepare(`
      INSERT INTO collection (user_id, card_id, card_name, card_image, set_id, set_name, rarity, quantity, condition, purchase_price)
      VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    `).run(req.session.userId, wantItem.card_id, wantItem.card_name, wantItem.card_image, 
           wantItem.set_id, wantItem.set_name, wantItem.rarity, condition, purchasePrice);
    
    // Remove from want list
    db.prepare('DELETE FROM want_list WHERE id = ?').run(req.params.id);
    
    res.json({ success: true, message: 'Card moved to collection!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ SEED DATA ENDPOINT ============

app.post('/api/seed', async (req, res) => {
  const { secret, force } = req.body;
  
  if (secret !== (process.env.SEED_SECRET || 'demo-seed-secret')) {
    return res.status(401).json({ error: 'Invalid seed secret' });
  }
  
  try {
    const existingUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();
    if (existingUsers.count > 0 && !force) {
      return res.json({ 
        success: false, 
        message: 'Database already has users (use force:true to reseed)',
        userCount: existingUsers.count
      });
    }
    
    if (force && existingUsers.count > 0) {
      db.prepare('DELETE FROM want_list').run();
      db.prepare('DELETE FROM collection').run();
      db.prepare('DELETE FROM users').run();
    }
    
    const hashedPassword = await bcrypt.hash('password123', 10);
    
    // Create demo user
    const result = db.prepare('INSERT INTO users (email, password, name) VALUES (?, ?, ?)')
      .run('trainer@pokemon.com', hashedPassword, 'Ash Ketchum');
    const userId = result.lastInsertRowid;
    
    // Add some sample collection cards (using real Pokemon TCG API card IDs)
    const sampleCollection = [
      { cardId: 'base1-4', cardName: 'Charizard', cardImage: 'https://images.pokemontcg.io/base1/4_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', quantity: 1, condition: 'Near Mint', marketPrice: 420.00 },
      { cardId: 'base1-2', cardName: 'Blastoise', cardImage: 'https://images.pokemontcg.io/base1/2_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', quantity: 1, condition: 'Near Mint', marketPrice: 85.00 },
      { cardId: 'base1-15', cardName: 'Venusaur', cardImage: 'https://images.pokemontcg.io/base1/15_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', quantity: 1, condition: 'Lightly Played', marketPrice: 65.00 },
      { cardId: 'base1-58', cardName: 'Pikachu', cardImage: 'https://images.pokemontcg.io/base1/58_hires.png', setId: 'base1', setName: 'Base', rarity: 'Common', quantity: 4, condition: 'Near Mint', marketPrice: 15.00 },
      { cardId: 'swsh9-166', cardName: 'Charizard VSTAR', cardImage: 'https://images.pokemontcg.io/swsh9/166_hires.png', setId: 'swsh9', setName: 'Brilliant Stars', rarity: 'Rare Holo VSTAR', quantity: 2, condition: 'Near Mint', marketPrice: 35.00 },
      { cardId: 'sv3pt5-197', cardName: 'Umbreon ex', cardImage: 'https://images.pokemontcg.io/sv3pt5/197_hires.png', setId: 'sv3pt5', setName: '151', rarity: 'Special Art Rare', quantity: 1, condition: 'Near Mint', marketPrice: 145.00 },
    ];
    
    for (const card of sampleCollection) {
      db.prepare(`
        INSERT INTO collection (user_id, card_id, card_name, card_image, set_id, set_name, rarity, quantity, condition, market_price)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(userId, card.cardId, card.cardName, card.cardImage, card.setId, card.setName, card.rarity, card.quantity, card.condition, card.marketPrice);
    }
    
    // Add some want list items
    const sampleWantList = [
      { cardId: 'base1-1', cardName: 'Alakazam', cardImage: 'https://images.pokemontcg.io/base1/1_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', maxPrice: 50.00, priority: 2 },
      { cardId: 'base1-3', cardName: 'Chansey', cardImage: 'https://images.pokemontcg.io/base1/3_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', maxPrice: 30.00, priority: 1 },
      { cardId: 'sv3pt5-199', cardName: 'Mew ex', cardImage: 'https://images.pokemontcg.io/sv3pt5/199_hires.png', setId: 'sv3pt5', setName: '151', rarity: 'Special Art Rare', maxPrice: 200.00, priority: 3 },
    ];
    
    for (const card of sampleWantList) {
      db.prepare(`
        INSERT INTO want_list (user_id, card_id, card_name, card_image, set_id, set_name, rarity, max_price, priority)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(userId, card.cardId, card.cardName, card.cardImage, card.setId, card.setName, card.rarity, card.maxPrice, card.priority);
    }
    
    res.json({ 
      success: true, 
      message: 'Database seeded successfully',
      created: {
        users: 1,
        collectionCards: sampleCollection.length,
        wantListCards: sampleWantList.length
      },
      demoLogin: {
        email: 'trainer@pokemon.com',
        password: 'password123'
      }
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Fallback to index.html for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`⚡ Pokemon Card Finder running on port ${PORT}`);
});
