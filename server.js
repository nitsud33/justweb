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

// ============ SET COMPLETION TRACKER ============

// Get detailed set completion with missing cards
app.get('/api/sets/:id/completion', requireAuth, async (req, res) => {
  try {
    const setId = req.params.id;
    
    // Fetch all cards in set from API
    const endpoint = `/cards?q=set.id:${setId}&pageSize=250&orderBy=number`;
    const data = await fetchPokemonAPI(endpoint, `set_cards:${setId}`, 86400000);
    const allCards = data.data || [];
    
    // Get user's owned cards in this set
    const owned = db.prepare(`
      SELECT card_id, card_name, quantity, condition, market_price 
      FROM collection 
      WHERE user_id = ? AND set_id = ?
    `).all(req.session.userId, setId);
    
    const ownedIds = new Set(owned.map(c => c.card_id));
    
    // Calculate completion
    const ownedCards = allCards.filter(c => ownedIds.has(c.id));
    const missingCards = allCards.filter(c => !ownedIds.has(c.id));
    
    // Calculate cost to complete
    const completionCost = missingCards.reduce((sum, card) => {
      const price = card.tcgplayer?.prices?.holofoil?.market ||
                   card.tcgplayer?.prices?.normal?.market ||
                   card.tcgplayer?.prices?.reverseHolofoil?.market || 0;
      return sum + price;
    }, 0);
    
    // Current owned value
    const ownedValue = ownedCards.reduce((sum, card) => {
      const price = card.tcgplayer?.prices?.holofoil?.market ||
                   card.tcgplayer?.prices?.normal?.market ||
                   card.tcgplayer?.prices?.reverseHolofoil?.market || 0;
      return sum + price;
    }, 0);
    
    res.json({
      setId,
      totalCards: allCards.length,
      ownedCount: ownedCards.length,
      missingCount: missingCards.length,
      completionPercent: Math.round((ownedCards.length / allCards.length) * 100),
      ownedValue: Math.round(ownedValue * 100) / 100,
      completionCost: Math.round(completionCost * 100) / 100,
      missingCards: missingCards.map(card => ({
        id: card.id,
        name: card.name,
        number: card.number,
        rarity: card.rarity,
        image: card.images?.small,
        price: card.tcgplayer?.prices?.holofoil?.market ||
               card.tcgplayer?.prices?.normal?.market ||
               card.tcgplayer?.prices?.reverseHolofoil?.market || null
      })).sort((a, b) => (a.price || 0) - (b.price || 0)), // cheapest first
      ownedCards: ownedCards.map(card => ({
        id: card.id,
        name: card.name,
        number: card.number,
        rarity: card.rarity,
        image: card.images?.small
      }))
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ PORTFOLIO DASHBOARD ============

// Get portfolio stats with daily tracking
app.get('/api/portfolio/stats', requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;
    
    // Current totals
    const current = db.prepare(`
      SELECT 
        COUNT(DISTINCT card_id) as uniqueCards,
        COALESCE(SUM(quantity), 0) as totalCards,
        COALESCE(SUM(quantity * COALESCE(market_price, 0)), 0) as totalValue,
        COALESCE(SUM(quantity * COALESCE(purchase_price, 0)), 0) as totalCost
      FROM collection WHERE user_id = ?
    `).get(userId);
    
    // Top 5 most valuable cards
    const topCards = db.prepare(`
      SELECT card_id, card_name, card_image, set_name, rarity, quantity, market_price,
             (quantity * COALESCE(market_price, 0)) as total_value
      FROM collection 
      WHERE user_id = ? AND market_price IS NOT NULL
      ORDER BY total_value DESC
      LIMIT 5
    `).all(userId);
    
    // Value by set
    const bySet = db.prepare(`
      SELECT set_id, set_name,
             COUNT(DISTINCT card_id) as cards,
             SUM(quantity * COALESCE(market_price, 0)) as value
      FROM collection 
      WHERE user_id = ? AND set_id IS NOT NULL
      GROUP BY set_id
      ORDER BY value DESC
      LIMIT 10
    `).all(userId);
    
    // Get yesterday's snapshot for daily change
    const yesterday = new Date();
    yesterday.setDate(yesterday.getDate() - 1);
    const yesterdayStr = yesterday.toISOString().split('T')[0];
    
    const prevSnapshot = db.prepare(`
      SELECT total_value FROM portfolio_snapshots 
      WHERE user_id = ? AND snapshot_date <= ?
      ORDER BY snapshot_date DESC LIMIT 1
    `).get(userId, yesterdayStr);
    
    // Calculate daily change
    const dailyChange = prevSnapshot 
      ? current.totalValue - prevSnapshot.total_value 
      : 0;
    const dailyChangePercent = prevSnapshot && prevSnapshot.total_value > 0
      ? ((current.totalValue - prevSnapshot.total_value) / prevSnapshot.total_value) * 100
      : 0;
    
    // Save today's snapshot
    const todayStr = new Date().toISOString().split('T')[0];
    db.prepare(`
      INSERT OR REPLACE INTO portfolio_snapshots (user_id, total_value, total_cards, snapshot_date)
      VALUES (?, ?, ?, ?)
    `).run(userId, current.totalValue, current.totalCards, todayStr);
    
    // ROI calculation
    const roi = current.totalCost > 0 
      ? ((current.totalValue - current.totalCost) / current.totalCost) * 100 
      : 0;
    
    res.json({
      uniqueCards: current.uniqueCards,
      totalCards: current.totalCards,
      totalValue: Math.round(current.totalValue * 100) / 100,
      totalCost: Math.round(current.totalCost * 100) / 100,
      profit: Math.round((current.totalValue - current.totalCost) * 100) / 100,
      roi: Math.round(roi * 10) / 10,
      dailyChange: Math.round(dailyChange * 100) / 100,
      dailyChangePercent: Math.round(dailyChangePercent * 10) / 10,
      topCards,
      bySet
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Portfolio value history (for charts)
app.get('/api/portfolio/history', requireAuth, (req, res) => {
  const days = parseInt(req.query.days) || 30;
  const history = db.prepare(`
    SELECT snapshot_date, total_value, total_cards
    FROM portfolio_snapshots
    WHERE user_id = ?
    ORDER BY snapshot_date DESC
    LIMIT ?
  `).all(req.session.userId, days);
  
  res.json(history.reverse());
});

// ============ DUPLICATES TRACKER ============

app.get('/api/collection/duplicates', requireAuth, (req, res) => {
  const duplicates = db.prepare(`
    SELECT card_id, card_name, card_image, set_name, rarity, 
           SUM(quantity) as total_quantity, market_price,
           (SUM(quantity) - 1) as trade_quantity,
           ((SUM(quantity) - 1) * COALESCE(market_price, 0)) as trade_value
    FROM collection 
    WHERE user_id = ?
    GROUP BY card_id
    HAVING total_quantity > 1
    ORDER BY trade_value DESC
  `).all(req.session.userId);
  
  const totalTradeValue = duplicates.reduce((sum, d) => sum + (d.trade_value || 0), 0);
  
  res.json({
    duplicates,
    totalTradeValue: Math.round(totalTradeValue * 100) / 100,
    totalTradeCards: duplicates.reduce((sum, d) => sum + d.trade_quantity, 0)
  });
});

// ============ SHAREABLE COLLECTION ============

// Get current user's share settings
app.get('/api/share/settings', requireAuth, (req, res) => {
  const user = db.prepare(`
    SELECT share_token, profile_public FROM users WHERE id = ?
  `).get(req.session.userId);
  
  res.json({
    shareToken: user.share_token,
    isPublic: user.profile_public === 1,
    shareUrl: user.share_token ? `/c/${user.share_token}` : null
  });
});

// Toggle public profile
app.post('/api/share/toggle', requireAuth, (req, res) => {
  const user = db.prepare('SELECT profile_public, share_token FROM users WHERE id = ?')
    .get(req.session.userId);
  
  const newStatus = user.profile_public === 1 ? 0 : 1;
  
  // Generate share token if doesn't exist
  let shareToken = user.share_token;
  if (!shareToken && newStatus === 1) {
    shareToken = db.generateShareToken ? db.generateShareToken() : 
                 require('crypto').randomBytes(8).toString('hex');
    db.prepare('UPDATE users SET share_token = ? WHERE id = ?')
      .run(shareToken, req.session.userId);
  }
  
  db.prepare('UPDATE users SET profile_public = ? WHERE id = ?')
    .run(newStatus, req.session.userId);
  
  res.json({ 
    isPublic: newStatus === 1, 
    shareToken,
    shareUrl: `/c/${shareToken}`
  });
});

// Public collection view (no auth required)
app.get('/api/public/collection/:token', (req, res) => {
  const user = db.prepare(`
    SELECT id, name, share_token, profile_public, created_at FROM users 
    WHERE share_token = ? AND profile_public = 1
  `).get(req.params.token);
  
  if (!user) {
    return res.status(404).json({ error: 'Collection not found or private' });
  }
  
  const collection = db.prepare(`
    SELECT card_id, card_name, card_image, set_id, set_name, rarity, quantity, market_price
    FROM collection WHERE user_id = ?
    ORDER BY market_price DESC NULLS LAST
  `).all(user.id);
  
  const stats = db.prepare(`
    SELECT 
      COUNT(DISTINCT card_id) as uniqueCards,
      COALESCE(SUM(quantity), 0) as totalCards,
      COALESCE(SUM(quantity * COALESCE(market_price, 0)), 0) as totalValue
    FROM collection WHERE user_id = ?
  `).get(user.id);
  
  const bySet = db.prepare(`
    SELECT set_name, COUNT(DISTINCT card_id) as cards
    FROM collection WHERE user_id = ? AND set_name IS NOT NULL
    GROUP BY set_name ORDER BY cards DESC LIMIT 5
  `).all(user.id);
  
  res.json({
    collector: {
      name: user.name,
      memberSince: user.created_at
    },
    stats,
    topSets: bySet,
    collection
  });
});

// ============ PRICE HISTORY ============

// Record price when viewing card (background task)
async function recordPrice(cardId, price) {
  if (!price || price <= 0) return;
  
  // Only record once per day per card
  const today = new Date().toISOString().split('T')[0];
  const existing = db.prepare(`
    SELECT id FROM price_history 
    WHERE card_id = ? AND DATE(recorded_at) = ?
  `).get(cardId, today);
  
  if (!existing) {
    db.prepare(`
      INSERT INTO price_history (card_id, price, recorded_at) VALUES (?, ?, CURRENT_TIMESTAMP)
    `).run(cardId, price);
  }
}

// Get price history for a card
app.get('/api/cards/:id/price-history', async (req, res) => {
  try {
    const cardId = req.params.id;
    const days = parseInt(req.query.days) || 90;
    
    // Get from our DB
    const history = db.prepare(`
      SELECT price, DATE(recorded_at) as date
      FROM price_history 
      WHERE card_id = ?
      ORDER BY recorded_at DESC
      LIMIT ?
    `).all(cardId, days);
    
    // If we don't have much history, fetch current price and record it
    if (history.length < 2) {
      try {
        const cardData = await fetchPokemonAPI(`/cards/${cardId}`, `card:${cardId}`);
        const card = cardData.data;
        const price = card?.tcgplayer?.prices?.holofoil?.market ||
                     card?.tcgplayer?.prices?.normal?.market ||
                     card?.tcgplayer?.prices?.reverseHolofoil?.market;
        if (price) {
          recordPrice(cardId, price);
        }
      } catch (e) {}
    }
    
    res.json({
      cardId,
      history: history.reverse(),
      dataPoints: history.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ PRICE ALERTS ============

app.get('/api/alerts', requireAuth, (req, res) => {
  const alerts = db.prepare(`
    SELECT a.*, w.card_name, w.card_image 
    FROM price_alerts a
    LEFT JOIN want_list w ON a.card_id = w.card_id AND a.user_id = w.user_id
    WHERE a.user_id = ? AND a.active = 1
    ORDER BY a.created_at DESC
  `).all(req.session.userId);
  
  res.json(alerts);
});

app.post('/api/alerts', requireAuth, (req, res) => {
  const { cardId, targetPrice, alertType = 'below' } = req.body;
  
  if (!cardId || !targetPrice) {
    return res.status(400).json({ error: 'Card ID and target price required' });
  }
  
  const result = db.prepare(`
    INSERT INTO price_alerts (user_id, card_id, target_price, alert_type)
    VALUES (?, ?, ?, ?)
  `).run(req.session.userId, cardId, targetPrice, alertType);
  
  res.json({ success: true, alertId: result.lastInsertRowid });
});

app.delete('/api/alerts/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM price_alerts WHERE id = ? AND user_id = ?')
    .run(req.params.id, req.session.userId);
  res.json({ success: true });
});

// ============ EXPORT COLLECTION ============

app.get('/api/collection/export', requireAuth, (req, res) => {
  const collection = db.prepare(`
    SELECT card_id, card_name, set_name, rarity, quantity, condition, purchase_price, market_price, added_at
    FROM collection WHERE user_id = ?
    ORDER BY set_name, card_name
  `).all(req.session.userId);
  
  // CSV format
  const headers = ['Card ID', 'Card Name', 'Set', 'Rarity', 'Quantity', 'Condition', 'Purchase Price', 'Market Price', 'Added'];
  const rows = collection.map(c => [
    c.card_id, c.card_name, c.set_name || '', c.rarity || '', 
    c.quantity, c.condition, c.purchase_price || '', c.market_price || '', c.added_at
  ]);
  
  const csv = [headers.join(','), ...rows.map(r => r.map(v => `"${v}"`).join(','))].join('\n');
  
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename=pokemon-collection.csv');
  res.send(csv);
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

// ============ TRADE MATCHING SYSTEM ============

// Find trade matches for the current user
app.get('/api/matches', requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;
    const limit = parseInt(req.query.limit) || 20;
    
    // Get user's want list
    const myWants = db.prepare(`
      SELECT card_id, card_name, card_image, set_name, rarity, max_price 
      FROM want_list WHERE user_id = ?
    `).all(userId);
    
    // Get user's collection (tradeable duplicates)
    const myHaves = db.prepare(`
      SELECT card_id, card_name, card_image, set_name, rarity, market_price,
             (quantity - 1) as tradeable_qty
      FROM collection 
      WHERE user_id = ? AND quantity > 1
    `).all(userId);
    
    if (myWants.length === 0 && myHaves.length === 0) {
      return res.json({
        matches: [],
        message: 'Add cards to your want list or have duplicates to find trades'
      });
    }
    
    const myWantIds = new Set(myWants.map(c => c.card_id));
    const myHaveIds = new Set(myHaves.map(c => c.card_id));
    
    // Find other users who have what I want
    const usersWithMyWants = db.prepare(`
      SELECT DISTINCT c.user_id, u.name, u.share_token,
             GROUP_CONCAT(c.card_id) as has_cards
      FROM collection c
      JOIN users u ON c.user_id = u.id
      WHERE c.card_id IN (${myWants.map(() => '?').join(',')})
        AND c.user_id != ?
        AND c.quantity > 1
      GROUP BY c.user_id
    `).all(...myWants.map(w => w.card_id), userId);
    
    // Find other users who want what I have
    const usersWantingMyHaves = db.prepare(`
      SELECT DISTINCT w.user_id, u.name, u.share_token,
             GROUP_CONCAT(w.card_id) as wants_cards
      FROM want_list w
      JOIN users u ON w.user_id = u.id
      WHERE w.card_id IN (${myHaves.map(() => '?').join(',')})
        AND w.user_id != ?
      GROUP BY w.user_id
    `).all(...myHaves.map(h => h.card_id), userId);
    
    // Build user maps
    const userHasMap = new Map();
    for (const u of usersWithMyWants) {
      userHasMap.set(u.user_id, {
        ...u,
        hasCards: u.has_cards.split(',')
      });
    }
    
    const userWantsMap = new Map();
    for (const u of usersWantingMyHaves) {
      userWantsMap.set(u.user_id, {
        ...u,
        wantsCards: u.wants_cards.split(',')
      });
    }
    
    // Find bidirectional matches (best matches - they have what I want AND want what I have)
    const matches = [];
    const seenUsers = new Set();
    
    for (const [otherUserId, hasInfo] of userHasMap) {
      const wantsInfo = userWantsMap.get(otherUserId);
      
      if (wantsInfo) {
        // Bidirectional match!
        const theyHave = hasInfo.hasCards.filter(id => myWantIds.has(id));
        const theyWant = wantsInfo.wantsCards.filter(id => myHaveIds.has(id));
        
        // Get full card details
        const theyHaveCards = myWants.filter(w => theyHave.includes(w.card_id));
        const theyWantCards = myHaves.filter(h => theyWant.includes(h.card_id));
        
        // Calculate values
        const theyOfferValue = theyHaveCards.reduce((sum, c) => sum + (c.max_price || 0), 0);
        const iOfferValue = theyWantCards.reduce((sum, c) => sum + (c.market_price || 0), 0);
        
        // Score based on match quality
        const matchScore = (theyHaveCards.length + theyWantCards.length) * 100 +
                          Math.min(theyOfferValue, iOfferValue) -
                          Math.abs(theyOfferValue - iOfferValue) * 0.5;
        
        matches.push({
          userId: otherUserId,
          userName: hasInfo.name,
          shareToken: hasInfo.share_token,
          matchType: 'bidirectional',
          score: matchScore,
          theyHave: theyHaveCards,
          theyWant: theyWantCards,
          theyOfferValue: Math.round(theyOfferValue * 100) / 100,
          iOfferValue: Math.round(iOfferValue * 100) / 100,
          fairness: calculateFairness(theyOfferValue, iOfferValue)
        });
        
        seenUsers.add(otherUserId);
      }
    }
    
    // Add one-way matches (they have what I want but don't necessarily want what I have)
    for (const [otherUserId, hasInfo] of userHasMap) {
      if (seenUsers.has(otherUserId)) continue;
      
      const theyHave = hasInfo.hasCards.filter(id => myWantIds.has(id));
      const theyHaveCards = myWants.filter(w => theyHave.includes(w.card_id));
      const theyOfferValue = theyHaveCards.reduce((sum, c) => sum + (c.max_price || 0), 0);
      
      matches.push({
        userId: otherUserId,
        userName: hasInfo.name,
        shareToken: hasInfo.share_token,
        matchType: 'they_have',
        score: theyHaveCards.length * 50 + theyOfferValue * 0.1,
        theyHave: theyHaveCards,
        theyWant: [],
        theyOfferValue: Math.round(theyOfferValue * 100) / 100,
        iOfferValue: 0,
        fairness: null
      });
      
      seenUsers.add(otherUserId);
    }
    
    // Add one-way matches (they want what I have)
    for (const [otherUserId, wantsInfo] of userWantsMap) {
      if (seenUsers.has(otherUserId)) continue;
      
      const theyWant = wantsInfo.wantsCards.filter(id => myHaveIds.has(id));
      const theyWantCards = myHaves.filter(h => theyWant.includes(h.card_id));
      const iOfferValue = theyWantCards.reduce((sum, c) => sum + (c.market_price || 0), 0);
      
      matches.push({
        userId: otherUserId,
        userName: wantsInfo.name,
        shareToken: wantsInfo.share_token,
        matchType: 'they_want',
        score: theyWantCards.length * 30 + iOfferValue * 0.05,
        theyHave: [],
        theyWant: theyWantCards,
        theyOfferValue: 0,
        iOfferValue: Math.round(iOfferValue * 100) / 100,
        fairness: null
      });
    }
    
    // Sort by score (best matches first)
    matches.sort((a, b) => b.score - a.score);
    
    // Cache match scores for future use
    for (const match of matches.slice(0, 50)) {
      db.prepare(`
        INSERT OR REPLACE INTO match_scores (user1_id, user2_id, score, direct_matches, last_calculated)
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
      `).run(
        userId, 
        match.userId, 
        match.score, 
        match.theyHave.length + match.theyWant.length
      );
    }
    
    res.json({
      matches: matches.slice(0, limit),
      totalMatches: matches.length,
      myWantCount: myWants.length,
      myTradeableCount: myHaves.length
    });
  } catch (err) {
    console.error('Match error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Helper: Calculate trade fairness (0-100)
function calculateFairness(value1, value2) {
  if (value1 === 0 && value2 === 0) return 100;
  if (value1 === 0 || value2 === 0) return 0;
  const ratio = Math.min(value1, value2) / Math.max(value1, value2);
  return Math.round(ratio * 100);
}

// Propose a trade
app.post('/api/trades', requireAuth, (req, res) => {
  try {
    const { recipientId, offeredCards, requestedCards, message } = req.body;
    const proposerId = req.session.userId;
    
    if (proposerId === recipientId) {
      return res.status(400).json({ error: 'Cannot trade with yourself' });
    }
    
    if (!offeredCards?.length && !requestedCards?.length) {
      return res.status(400).json({ error: 'Must offer or request at least one card' });
    }
    
    // Validate I own the offered cards
    for (const card of offeredCards || []) {
      const owned = db.prepare(`
        SELECT quantity FROM collection 
        WHERE user_id = ? AND card_id = ?
      `).get(proposerId, card.cardId);
      
      if (!owned || owned.quantity < (card.quantity || 1)) {
        return res.status(400).json({ error: `You don't have enough of ${card.cardName}` });
      }
    }
    
    // Calculate values
    const proposerValue = (offeredCards || []).reduce((sum, c) => sum + (c.marketPrice || 0) * (c.quantity || 1), 0);
    const recipientValue = (requestedCards || []).reduce((sum, c) => sum + (c.marketPrice || 0) * (c.quantity || 1), 0);
    
    // Create trade
    const result = db.prepare(`
      INSERT INTO trades (proposer_id, recipient_id, status, message, proposer_value, recipient_value)
      VALUES (?, ?, 'pending', ?, ?, ?)
    `).run(proposerId, recipientId, message || null, proposerValue, recipientValue);
    
    const tradeId = result.lastInsertRowid;
    
    // Add offered cards (direction: 'offer' = proposer gives to recipient)
    for (const card of offeredCards || []) {
      db.prepare(`
        INSERT INTO trade_items (trade_id, card_id, card_name, card_image, set_name, rarity, market_price, quantity, direction)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'offer')
      `).run(tradeId, card.cardId, card.cardName, card.cardImage, card.setName, card.rarity, card.marketPrice, card.quantity || 1);
    }
    
    // Add requested cards (direction: 'request' = proposer wants from recipient)
    for (const card of requestedCards || []) {
      db.prepare(`
        INSERT INTO trade_items (trade_id, card_id, card_name, card_image, set_name, rarity, market_price, quantity, direction)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'request')
      `).run(tradeId, card.cardId, card.cardName, card.cardImage, card.setName, card.rarity, card.marketPrice, card.quantity || 1);
    }
    
    res.json({ 
      success: true, 
      tradeId,
      message: 'Trade proposal sent!'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get my trades (sent and received)
app.get('/api/trades', requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;
    const status = req.query.status || 'all';
    
    let whereClause = '(t.proposer_id = ? OR t.recipient_id = ?)';
    const params = [userId, userId];
    
    if (status !== 'all') {
      whereClause += ' AND t.status = ?';
      params.push(status);
    }
    
    const trades = db.prepare(`
      SELECT t.*,
             proposer.name as proposer_name,
             recipient.name as recipient_name,
             CASE WHEN t.proposer_id = ? THEN 'sent' ELSE 'received' END as direction
      FROM trades t
      JOIN users proposer ON t.proposer_id = proposer.id
      JOIN users recipient ON t.recipient_id = recipient.id
      WHERE ${whereClause}
      ORDER BY t.created_at DESC
    `).all(userId, ...params);
    
    // Get items for each trade
    for (const trade of trades) {
      trade.offeredCards = db.prepare(`
        SELECT * FROM trade_items WHERE trade_id = ? AND direction = 'offer'
      `).all(trade.id);
      
      trade.requestedCards = db.prepare(`
        SELECT * FROM trade_items WHERE trade_id = ? AND direction = 'request'
      `).all(trade.id);
    }
    
    res.json(trades);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get single trade
app.get('/api/trades/:id', requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;
    
    const trade = db.prepare(`
      SELECT t.*,
             proposer.name as proposer_name,
             recipient.name as recipient_name,
             CASE WHEN t.proposer_id = ? THEN 'sent' ELSE 'received' END as direction
      FROM trades t
      JOIN users proposer ON t.proposer_id = proposer.id
      JOIN users recipient ON t.recipient_id = recipient.id
      WHERE t.id = ? AND (t.proposer_id = ? OR t.recipient_id = ?)
    `).get(userId, req.params.id, userId, userId);
    
    if (!trade) {
      return res.status(404).json({ error: 'Trade not found' });
    }
    
    trade.offeredCards = db.prepare(`
      SELECT * FROM trade_items WHERE trade_id = ? AND direction = 'offer'
    `).all(trade.id);
    
    trade.requestedCards = db.prepare(`
      SELECT * FROM trade_items WHERE trade_id = ? AND direction = 'request'
    `).all(trade.id);
    
    res.json(trade);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Update trade (accept/reject/cancel)
app.put('/api/trades/:id', requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;
    const { action } = req.body;
    
    const trade = db.prepare(`
      SELECT * FROM trades WHERE id = ?
    `).get(req.params.id);
    
    if (!trade) {
      return res.status(404).json({ error: 'Trade not found' });
    }
    
    if (trade.status !== 'pending') {
      return res.status(400).json({ error: 'Trade is no longer pending' });
    }
    
    // Validate permissions
    if (action === 'cancel' && trade.proposer_id !== userId) {
      return res.status(403).json({ error: 'Only the proposer can cancel' });
    }
    
    if ((action === 'accept' || action === 'reject') && trade.recipient_id !== userId) {
      return res.status(403).json({ error: 'Only the recipient can accept or reject' });
    }
    
    if (action === 'accept') {
      // Execute the trade - swap cards between users
      const offeredCards = db.prepare(`
        SELECT * FROM trade_items WHERE trade_id = ? AND direction = 'offer'
      `).all(trade.id);
      
      const requestedCards = db.prepare(`
        SELECT * FROM trade_items WHERE trade_id = ? AND direction = 'request'
      `).all(trade.id);
      
      // Validate both parties still have the cards
      for (const card of offeredCards) {
        const owned = db.prepare(`
          SELECT quantity FROM collection WHERE user_id = ? AND card_id = ?
        `).get(trade.proposer_id, card.card_id);
        
        if (!owned || owned.quantity < card.quantity) {
          db.prepare('UPDATE trades SET status = ? WHERE id = ?').run('failed', trade.id);
          return res.status(400).json({ error: `Proposer no longer has ${card.card_name}` });
        }
      }
      
      for (const card of requestedCards) {
        const owned = db.prepare(`
          SELECT quantity FROM collection WHERE user_id = ? AND card_id = ?
        `).get(trade.recipient_id, card.card_id);
        
        if (!owned || owned.quantity < card.quantity) {
          db.prepare('UPDATE trades SET status = ? WHERE id = ?').run('failed', trade.id);
          return res.status(400).json({ error: `Recipient no longer has ${card.card_name}` });
        }
      }
      
      // Execute transfer: proposer's cards go to recipient
      for (const card of offeredCards) {
        // Reduce from proposer
        db.prepare(`
          UPDATE collection SET quantity = quantity - ? 
          WHERE user_id = ? AND card_id = ?
        `).run(card.quantity, trade.proposer_id, card.card_id);
        
        // Add to recipient (or update if exists)
        const existing = db.prepare(`
          SELECT id FROM collection WHERE user_id = ? AND card_id = ?
        `).get(trade.recipient_id, card.card_id);
        
        if (existing) {
          db.prepare('UPDATE collection SET quantity = quantity + ? WHERE id = ?')
            .run(card.quantity, existing.id);
        } else {
          db.prepare(`
            INSERT INTO collection (user_id, card_id, card_name, card_image, set_name, rarity, quantity, market_price)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `).run(trade.recipient_id, card.card_id, card.card_name, card.card_image, 
                 card.set_name, card.rarity, card.quantity, card.market_price);
        }
        
        // Remove from recipient's want list if present
        db.prepare('DELETE FROM want_list WHERE user_id = ? AND card_id = ?')
          .run(trade.recipient_id, card.card_id);
      }
      
      // Execute transfer: recipient's cards go to proposer
      for (const card of requestedCards) {
        // Reduce from recipient
        db.prepare(`
          UPDATE collection SET quantity = quantity - ? 
          WHERE user_id = ? AND card_id = ?
        `).run(card.quantity, trade.recipient_id, card.card_id);
        
        // Add to proposer
        const existing = db.prepare(`
          SELECT id FROM collection WHERE user_id = ? AND card_id = ?
        `).get(trade.proposer_id, card.card_id);
        
        if (existing) {
          db.prepare('UPDATE collection SET quantity = quantity + ? WHERE id = ?')
            .run(card.quantity, existing.id);
        } else {
          db.prepare(`
            INSERT INTO collection (user_id, card_id, card_name, card_image, set_name, rarity, quantity, market_price)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
          `).run(trade.proposer_id, card.card_id, card.card_name, card.card_image,
                 card.set_name, card.rarity, card.quantity, card.market_price);
        }
        
        // Remove from proposer's want list if present
        db.prepare('DELETE FROM want_list WHERE user_id = ? AND card_id = ?')
          .run(trade.proposer_id, card.card_id);
      }
      
      // Clean up zero-quantity entries
      db.prepare('DELETE FROM collection WHERE quantity <= 0').run();
    }
    
    // Update trade status
    const newStatus = action === 'accept' ? 'completed' : 
                      action === 'reject' ? 'rejected' : 'cancelled';
    
    db.prepare(`
      UPDATE trades SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
    `).run(newStatus, trade.id);
    
    res.json({ 
      success: true, 
      status: newStatus,
      message: action === 'accept' ? 'Trade completed! Cards have been exchanged.' :
               action === 'reject' ? 'Trade rejected' : 'Trade cancelled'
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Quick match suggestion endpoint (for a specific user)
app.get('/api/matches/:userId/suggest', requireAuth, (req, res) => {
  try {
    const myId = req.session.userId;
    const theirId = parseInt(req.params.userId);
    
    if (myId === theirId) {
      return res.status(400).json({ error: 'Cannot match with yourself' });
    }
    
    // Get their want list
    const theirWants = db.prepare('SELECT card_id FROM want_list WHERE user_id = ?')
      .all(theirId).map(r => r.card_id);
    
    // Get my tradeable cards that they want
    const canOffer = db.prepare(`
      SELECT card_id, card_name, card_image, set_name, rarity, market_price, (quantity - 1) as tradeable
      FROM collection 
      WHERE user_id = ? AND quantity > 1 AND card_id IN (${theirWants.map(() => '?').join(',') || "''"})
    `).all(myId, ...theirWants);
    
    // Get my want list
    const myWants = db.prepare('SELECT card_id FROM want_list WHERE user_id = ?')
      .all(myId).map(r => r.card_id);
    
    // Get their tradeable cards that I want
    const canRequest = db.prepare(`
      SELECT card_id, card_name, card_image, set_name, rarity, market_price, (quantity - 1) as tradeable
      FROM collection 
      WHERE user_id = ? AND quantity > 1 AND card_id IN (${myWants.map(() => '?').join(',') || "''"})
    `).all(theirId, ...myWants);
    
    res.json({
      canOffer,
      canRequest,
      offerValue: canOffer.reduce((s, c) => s + (c.market_price || 0), 0),
      requestValue: canRequest.reduce((s, c) => s + (c.market_price || 0), 0)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get trade stats
app.get('/api/trades/stats', requireAuth, (req, res) => {
  try {
    const userId = req.session.userId;
    
    const stats = db.prepare(`
      SELECT 
        COUNT(*) FILTER (WHERE status = 'completed' AND proposer_id = ?) as completed_proposed,
        COUNT(*) FILTER (WHERE status = 'completed' AND recipient_id = ?) as completed_received,
        COUNT(*) FILTER (WHERE status = 'pending' AND proposer_id = ?) as pending_sent,
        COUNT(*) FILTER (WHERE status = 'pending' AND recipient_id = ?) as pending_received,
        COALESCE(SUM(CASE WHEN status = 'completed' AND proposer_id = ? THEN proposer_value ELSE 0 END), 0) as value_traded_out,
        COALESCE(SUM(CASE WHEN status = 'completed' AND proposer_id = ? THEN recipient_value ELSE 0 END), 0) as value_traded_in
      FROM trades
      WHERE proposer_id = ? OR recipient_id = ?
    `).get(userId, userId, userId, userId, userId, userId, userId, userId);
    
    res.json({
      completedTrades: (stats.completed_proposed || 0) + (stats.completed_received || 0),
      pendingSent: stats.pending_sent || 0,
      pendingReceived: stats.pending_received || 0,
      valueTradedOut: Math.round((stats.value_traded_out || 0) * 100) / 100,
      valueTradedIn: Math.round((stats.value_traded_in || 0) * 100) / 100
    });
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
    
    // Create additional demo users for trade matching
    const demoUsers = [
      { email: 'misty@pokemon.com', name: 'Misty', 
        collection: [
          { cardId: 'base1-1', cardName: 'Alakazam', cardImage: 'https://images.pokemontcg.io/base1/1_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', quantity: 2, marketPrice: 45.00 },
          { cardId: 'base1-3', cardName: 'Chansey', cardImage: 'https://images.pokemontcg.io/base1/3_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', quantity: 3, marketPrice: 28.00 },
          { cardId: 'base1-6', cardName: 'Gyarados', cardImage: 'https://images.pokemontcg.io/base1/6_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', quantity: 2, marketPrice: 55.00 },
        ],
        wants: [
          { cardId: 'base1-58', cardName: 'Pikachu', cardImage: 'https://images.pokemontcg.io/base1/58_hires.png', setId: 'base1', setName: 'Base', rarity: 'Common', maxPrice: 20.00 },
          { cardId: 'base1-4', cardName: 'Charizard', cardImage: 'https://images.pokemontcg.io/base1/4_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', maxPrice: 500.00 },
        ]
      },
      { email: 'brock@pokemon.com', name: 'Brock',
        collection: [
          { cardId: 'base1-58', cardName: 'Pikachu', cardImage: 'https://images.pokemontcg.io/base1/58_hires.png', setId: 'base1', setName: 'Base', rarity: 'Common', quantity: 5, marketPrice: 15.00 },
          { cardId: 'sv3pt5-199', cardName: 'Mew ex', cardImage: 'https://images.pokemontcg.io/sv3pt5/199_hires.png', setId: 'sv3pt5', setName: '151', rarity: 'Special Art Rare', quantity: 2, marketPrice: 180.00 },
        ],
        wants: [
          { cardId: 'base1-2', cardName: 'Blastoise', cardImage: 'https://images.pokemontcg.io/base1/2_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', maxPrice: 100.00 },
          { cardId: 'sv3pt5-197', cardName: 'Umbreon ex', cardImage: 'https://images.pokemontcg.io/sv3pt5/197_hires.png', setId: 'sv3pt5', setName: '151', rarity: 'Special Art Rare', maxPrice: 160.00 },
        ]
      },
      { email: 'gary@pokemon.com', name: 'Gary Oak',
        collection: [
          { cardId: 'base1-2', cardName: 'Blastoise', cardImage: 'https://images.pokemontcg.io/base1/2_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', quantity: 3, marketPrice: 85.00 },
          { cardId: 'base1-15', cardName: 'Venusaur', cardImage: 'https://images.pokemontcg.io/base1/15_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', quantity: 2, marketPrice: 65.00 },
        ],
        wants: [
          { cardId: 'base1-4', cardName: 'Charizard', cardImage: 'https://images.pokemontcg.io/base1/4_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', maxPrice: 500.00 },
          { cardId: 'swsh9-166', cardName: 'Charizard VSTAR', cardImage: 'https://images.pokemontcg.io/swsh9/166_hires.png', setId: 'swsh9', setName: 'Brilliant Stars', rarity: 'Rare Holo VSTAR', maxPrice: 40.00 },
        ]
      }
    ];
    
    let additionalUsers = 0;
    let additionalCards = 0;
    let additionalWants = 0;
    
    for (const demoUser of demoUsers) {
      const userResult = db.prepare('INSERT INTO users (email, password, name) VALUES (?, ?, ?)')
        .run(demoUser.email, hashedPassword, demoUser.name);
      const demoUserId = userResult.lastInsertRowid;
      additionalUsers++;
      
      for (const card of demoUser.collection) {
        db.prepare(`
          INSERT INTO collection (user_id, card_id, card_name, card_image, set_id, set_name, rarity, quantity, market_price)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).run(demoUserId, card.cardId, card.cardName, card.cardImage, card.setId, card.setName, card.rarity, card.quantity, card.marketPrice);
        additionalCards++;
      }
      
      for (const want of demoUser.wants) {
        db.prepare(`
          INSERT INTO want_list (user_id, card_id, card_name, card_image, set_id, set_name, rarity, max_price, priority)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
        `).run(demoUserId, want.cardId, want.cardName, want.cardImage, want.setId, want.setName, want.rarity, want.maxPrice);
        additionalWants++;
      }
    }
    
    res.json({ 
      success: true, 
      message: 'Database seeded successfully with trade demo data',
      created: {
        users: 1 + additionalUsers,
        collectionCards: sampleCollection.length + additionalCards,
        wantListCards: sampleWantList.length + additionalWants
      },
      demoLogins: [
        { email: 'trainer@pokemon.com', password: 'password123', description: 'Main user (Ash)' },
        { email: 'misty@pokemon.com', password: 'password123', description: 'Has Alakazam, Chansey (Ash wants these)' },
        { email: 'brock@pokemon.com', password: 'password123', description: 'Has Mew ex (Ash wants), wants Umbreon ex' },
        { email: 'gary@pokemon.com', password: 'password123', description: 'Wants Charizard VSTAR (Ash has dupes)' }
      ]
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
