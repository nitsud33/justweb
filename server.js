const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// API endpoints for each card game
const APIS = {
  pokemon: 'https://api.tcgdex.net/v2/en',
  mtg: 'https://api.scryfall.com',
  yugioh: 'https://db.ygoprodeck.com/api/v7'
};

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

// Helper: Fetch from any API with caching
async function fetchAPI(url, cacheKey, cacheDuration = 3600000) {
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
  
  const response = await fetch(url, {
    headers: { 'Accept': 'application/json' }
  });
  
  if (!response.ok) {
    throw new Error(`API error: ${response.status}`);
  }
  
  const data = await response.json();
  
  // Cache the result
  if (cacheKey) {
    db.prepare('INSERT OR REPLACE INTO card_cache (card_id, data, cached_at) VALUES (?, ?, CURRENT_TIMESTAMP)')
      .run(cacheKey, JSON.stringify(data));
  }
  
  return data;
}

// Helper: Fetch from Pokemon TCG API with caching (backwards compat)
async function fetchPokemonAPI(endpoint, cacheKey, cacheDuration = 3600000) {
  return fetchAPI(`${APIS.pokemon}${endpoint}`, cacheKey, cacheDuration);
}

// ============ MTG (SCRYFALL) API HELPERS ============

async function searchMTGCards(query) {
  const data = await fetchAPI(
    `${APIS.mtg}/cards/search?q=${encodeURIComponent(query)}`,
    null, // Don't cache searches
    0
  );
  return data;
}

async function getMTGCard(id) {
  return fetchAPI(`${APIS.mtg}/cards/${id}`, `mtg:${id}`, 3600000);
}

async function getMTGSets() {
  return fetchAPI(`${APIS.mtg}/sets`, 'mtg:all_sets', 86400000);
}

function normalizeMTGCard(card) {
  const prices = card.prices || {};
  const price = parseFloat(prices.usd) || parseFloat(prices.usd_foil) || null;
  
  return {
    id: card.id,
    name: card.name,
    images: {
      small: card.image_uris?.small || card.card_faces?.[0]?.image_uris?.small,
      large: card.image_uris?.normal || card.card_faces?.[0]?.image_uris?.normal
    },
    set: { id: card.set, name: card.set_name },
    rarity: card.rarity,
    number: card.collector_number,
    artist: card.artist,
    prices: {
      usd: prices.usd,
      usd_foil: prices.usd_foil,
      market: price
    },
    tcgplayer: card.purchase_uris?.tcgplayer ? { url: card.purchase_uris.tcgplayer } : null,
    // MTG-specific fields
    mana_cost: card.mana_cost,
    type_line: card.type_line,
    oracle_text: card.oracle_text,
    power: card.power,
    toughness: card.toughness,
    colors: card.colors,
    category: 'mtg'
  };
}

// ============ YU-GI-OH (YGOPRODECK) API HELPERS ============

async function searchYugiohCards(query) {
  try {
    const data = await fetchAPI(
      `${APIS.yugioh}/cardinfo.php?fname=${encodeURIComponent(query)}`,
      null,
      0
    );
    return data;
  } catch (e) {
    // YGOPRODeck returns error for no results
    return { data: [] };
  }
}

async function getYugiohCard(id) {
  const data = await fetchAPI(`${APIS.yugioh}/cardinfo.php?id=${id}`, `yugioh:${id}`, 3600000);
  return data.data?.[0] || null;
}

async function getYugiohSets() {
  return fetchAPI(`${APIS.yugioh}/cardsets.php`, 'yugioh:all_sets', 86400000);
}

function normalizeYugiohCard(card) {
  const prices = card.card_prices?.[0] || {};
  const price = parseFloat(prices.tcgplayer_price) || parseFloat(prices.cardmarket_price) || null;
  
  // Get the first card image
  const image = card.card_images?.[0];
  
  return {
    id: card.id.toString(),
    name: card.name,
    images: {
      small: image?.image_url_small || image?.image_url,
      large: image?.image_url
    },
    set: card.card_sets?.[0] ? { 
      id: card.card_sets[0].set_code, 
      name: card.card_sets[0].set_name 
    } : { id: '', name: '' },
    rarity: card.card_sets?.[0]?.set_rarity || card.race,
    number: card.card_sets?.[0]?.set_code || '',
    prices: {
      tcgplayer: prices.tcgplayer_price,
      cardmarket: prices.cardmarket_price,
      market: price
    },
    tcgplayer: prices.tcgplayer_price ? { 
      url: `https://www.tcgplayer.com/search/yugioh?q=${encodeURIComponent(card.name)}` 
    } : null,
    // Yu-Gi-Oh-specific fields
    type: card.type,
    desc: card.desc,
    atk: card.atk,
    def: card.def,
    level: card.level,
    race: card.race,
    attribute: card.attribute,
    category: 'yugioh'
  };
}

// ============ SPORTS CARDS API ============

// Get all sports cards with optional filters
app.get('/api/sports/cards', async (req, res) => {
  try {
    const { sport, player, year, set, minPrice, maxPrice, rookie, graded, page = 1, pageSize = 20 } = req.query;
    
    let where = ['1=1'];
    const params = [];
    
    if (sport) {
      where.push('sport = ?');
      params.push(sport);
    }
    
    if (player) {
      where.push('player_name LIKE ?');
      params.push(`%${player}%`);
    }
    
    if (year) {
      where.push('year = ?');
      params.push(parseInt(year));
    }
    
    if (set) {
      where.push('(set_name LIKE ? OR set_id = ?)');
      params.push(`%${set}%`, set);
    }
    
    if (rookie === 'true') {
      where.push('rookie_card = 1');
    }
    
    if (minPrice) {
      where.push('COALESCE(price_raw, 0) >= ?');
      params.push(parseFloat(minPrice));
    }
    
    if (maxPrice) {
      where.push('COALESCE(price_raw, 0) <= ?');
      params.push(parseFloat(maxPrice));
    }
    
    const offset = (parseInt(page) - 1) * parseInt(pageSize);
    
    const countQuery = `SELECT COUNT(*) as total FROM sports_cards WHERE ${where.join(' AND ')}`;
    const total = db.prepare(countQuery).get(...params).total;
    
    const query = `
      SELECT * FROM sports_cards 
      WHERE ${where.join(' AND ')}
      ORDER BY year DESC, player_name ASC
      LIMIT ? OFFSET ?
    `;
    
    const cards = db.prepare(query).all(...params, parseInt(pageSize), offset);
    
    // Transform to match common card format
    const transformedCards = cards.map(normalizeSportsCard);
    
    res.json({
      data: transformedCards,
      totalCount: total,
      page: parseInt(page),
      pageSize: parseInt(pageSize)
    });
  } catch (err) {
    console.error('Sports cards search error:', err);
    res.status(500).json({ error: err.message });
  }
});

// Get single sports card by ID
app.get('/api/sports/cards/:id', async (req, res) => {
  try {
    const card = db.prepare('SELECT * FROM sports_cards WHERE card_id = ?').get(req.params.id);
    
    if (!card) {
      return res.status(404).json({ error: 'Card not found' });
    }
    
    // Get population reports for this card
    const popReports = db.prepare(`
      SELECT grader, grade, population, plus_population, last_updated
      FROM population_reports WHERE card_id = ?
      ORDER BY grader, 
        CASE grade 
          WHEN '10' THEN 10 WHEN '9.5' THEN 9.5 WHEN '9' THEN 9 
          WHEN '8.5' THEN 8.5 WHEN '8' THEN 8 WHEN '7' THEN 7 
          ELSE CAST(grade AS REAL) 
        END DESC
    `).all(req.params.id);
    
    const normalized = normalizeSportsCard(card);
    normalized.populationReports = popReports;
    
    res.json({ data: normalized });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Search sports cards by player name
app.get('/api/sports/players/:name/cards', async (req, res) => {
  try {
    const { name } = req.params;
    const { sport, page = 1, pageSize = 50 } = req.query;
    
    let where = 'player_name LIKE ?';
    const params = [`%${name}%`];
    
    if (sport) {
      where += ' AND sport = ?';
      params.push(sport);
    }
    
    const offset = (parseInt(page) - 1) * parseInt(pageSize);
    
    const cards = db.prepare(`
      SELECT * FROM sports_cards 
      WHERE ${where}
      ORDER BY year ASC, set_name ASC
      LIMIT ? OFFSET ?
    `).all(...params, parseInt(pageSize), offset);
    
    const total = db.prepare(`SELECT COUNT(*) as c FROM sports_cards WHERE ${where}`).get(...params).c;
    
    res.json({
      player: name,
      data: cards.map(normalizeSportsCard),
      totalCount: total,
      page: parseInt(page),
      pageSize: parseInt(pageSize)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get all players for a sport (for autocomplete)
app.get('/api/sports/players', async (req, res) => {
  try {
    const { sport, q } = req.query;
    
    let where = '1=1';
    const params = [];
    
    if (sport) {
      where += ' AND sport = ?';
      params.push(sport);
    }
    
    if (q) {
      where += ' AND player_name LIKE ?';
      params.push(`%${q}%`);
    }
    
    const players = db.prepare(`
      SELECT DISTINCT player_name, sport, COUNT(*) as card_count,
             MIN(year) as first_year, MAX(year) as last_year
      FROM sports_cards 
      WHERE ${where}
      GROUP BY player_name, sport
      ORDER BY card_count DESC
      LIMIT 50
    `).all(...params);
    
    res.json(players);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get sports card sets
app.get('/api/sports/sets', async (req, res) => {
  try {
    const { sport, year } = req.query;
    
    let where = '1=1';
    const params = [];
    
    if (sport) {
      where += ' AND sport = ?';
      params.push(sport);
    }
    
    if (year) {
      where += ' AND year = ?';
      params.push(parseInt(year));
    }
    
    const sets = db.prepare(`
      SELECT * FROM sports_sets 
      WHERE ${where}
      ORDER BY year DESC, name ASC
    `).all(...params);
    
    res.json({ data: sets });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get years available for a sport
app.get('/api/sports/years', async (req, res) => {
  try {
    const { sport } = req.query;
    
    let where = '1=1';
    const params = [];
    
    if (sport) {
      where += ' AND sport = ?';
      params.push(sport);
    }
    
    const years = db.prepare(`
      SELECT DISTINCT year, COUNT(*) as card_count
      FROM sports_cards 
      WHERE ${where}
      GROUP BY year
      ORDER BY year DESC
    `).all(...params);
    
    res.json(years);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get population report for a card
app.get('/api/sports/cards/:id/population', async (req, res) => {
  try {
    const popReports = db.prepare(`
      SELECT grader, grade, population, plus_population, last_updated
      FROM population_reports WHERE card_id = ?
      ORDER BY grader, 
        CASE grade 
          WHEN '10' THEN 10 WHEN '9.5' THEN 9.5 WHEN '9' THEN 9 
          WHEN '8.5' THEN 8.5 WHEN '8' THEN 8 WHEN '7' THEN 7 
          ELSE CAST(grade AS REAL) 
        END DESC
    `).all(req.params.id);
    
    // Group by grader
    const byGrader = {};
    for (const report of popReports) {
      if (!byGrader[report.grader]) {
        byGrader[report.grader] = [];
      }
      byGrader[report.grader].push(report);
    }
    
    // Calculate totals
    const totalGraded = popReports.reduce((sum, r) => sum + (r.population || 0), 0);
    
    res.json({
      cardId: req.params.id,
      byGrader,
      totalGraded,
      reports: popReports
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Helper: Normalize sports card to common format
function normalizeSportsCard(card) {
  // Build graded prices object
  const gradedPrices = {
    raw: card.price_raw,
    psa: {
      1: card.price_psa_1,
      2: card.price_psa_2,
      3: card.price_psa_3,
      4: card.price_psa_4,
      5: card.price_psa_5,
      6: card.price_psa_6,
      7: card.price_psa_7,
      8: card.price_psa_8,
      9: card.price_psa_9,
      10: card.price_psa_10
    },
    bgs: {
      8: card.price_bgs_8,
      8.5: card.price_bgs_8_5,
      9: card.price_bgs_9,
      9.5: card.price_bgs_9_5,
      10: card.price_bgs_10,
      pristine: card.price_bgs_pristine
    },
    sgc: {
      9: card.price_sgc_9,
      10: card.price_sgc_10
    }
  };
  
  return {
    id: card.card_id,
    name: card.name,
    playerName: card.player_name,
    team: card.team,
    year: card.year,
    images: {
      small: card.image_url,
      large: card.image_url
    },
    set: { 
      id: card.set_id || card.set_name.toLowerCase().replace(/\s+/g, '-'), 
      name: card.set_name 
    },
    rarity: card.rarity,
    number: card.card_number,
    sport: card.sport,
    category: card.sport,
    rookieCard: card.rookie_card === 1,
    parallel: card.parallel,
    prices: {
      market: card.price_raw,
      graded: gradedPrices
    },
    gradedPrices,
    lastPriceUpdate: card.last_price_update
  };
}

// ============ SPORTS CARDS CATEGORY ENDPOINTS (unified with TCG) ============

// Add sports to the category search endpoint
async function searchSportsCards(query, sport, page, pageSize) {
  const offset = (parseInt(page) - 1) * parseInt(pageSize);
  
  const cards = db.prepare(`
    SELECT * FROM sports_cards 
    WHERE sport = ? AND (
      player_name LIKE ? OR 
      name LIKE ? OR 
      set_name LIKE ? OR
      team LIKE ?
    )
    ORDER BY year DESC, player_name ASC
    LIMIT ? OFFSET ?
  `).all(sport, `%${query}%`, `%${query}%`, `%${query}%`, `%${query}%`, parseInt(pageSize), offset);
  
  const total = db.prepare(`
    SELECT COUNT(*) as c FROM sports_cards 
    WHERE sport = ? AND (
      player_name LIKE ? OR 
      name LIKE ? OR 
      set_name LIKE ? OR
      team LIKE ?
    )
  `).get(sport, `%${query}%`, `%${query}%`, `%${query}%`, `%${query}%`).c;
  
  return {
    data: cards.map(normalizeSportsCard),
    totalCount: total,
    page: parseInt(page),
    pageSize: parseInt(pageSize)
  };
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

// ============ CATEGORIES API ============

app.get('/api/categories', (req, res) => {
  const categories = db.prepare('SELECT * FROM categories WHERE active = 1 ORDER BY id').all();
  res.json(categories);
});

// ============ MULTI-GAME CARD API ============

// Universal search endpoint - routes to appropriate API based on category
app.get('/api/:category/cards/search', async (req, res) => {
  try {
    const { category } = req.params;
    const { q, page = 1, pageSize = 20 } = req.query;
    
    if (!q) {
      return res.status(400).json({ error: 'Query required' });
    }
    
    let result;
    
    switch (category) {
      case 'pokemon':
        result = await searchPokemonCards(q, page, pageSize);
        break;
      case 'mtg':
        result = await searchMTGCardsHandler(q, page, pageSize);
        break;
      case 'yugioh':
        result = await searchYugiohCardsHandler(q, page, pageSize);
        break;
      // Sports categories
      case 'baseball':
      case 'basketball':
      case 'football':
        result = await searchSportsCards(q, category, page, pageSize);
        break;
      default:
        return res.status(400).json({ error: 'Invalid category' });
    }
    
    res.json(result);
  } catch (err) {
    console.error(`Search error (${req.params.category}):`, err.message);
    res.status(500).json({ error: err.message });
  }
});

// Pokemon search handler
async function searchPokemonCards(query, page, pageSize) {
  const endpoint = `/cards?name=${encodeURIComponent(query)}`;
  const cards = await fetchPokemonAPI(endpoint);
  
  const startIdx = (page - 1) * pageSize;
  const paginatedCards = cards.slice(startIdx, startIdx + parseInt(pageSize));
  
  const transformedCards = paginatedCards.map(card => ({
    id: card.id,
    name: card.name,
    images: { 
      small: card.image ? `${card.image}/low.webp` : null,
      large: card.image ? `${card.image}/high.webp` : null
    },
    set: card.set || { id: card.id.split('-')[0], name: 'Unknown Set' },
    rarity: card.rarity || 'Unknown',
    tcgplayer: card.pricing?.tcgplayer || null,
    cardmarket: card.pricing?.cardmarket || null,
    category: 'pokemon'
  }));
  
  return { 
    data: transformedCards,
    totalCount: cards.length,
    page: parseInt(page),
    pageSize: parseInt(pageSize)
  };
}

// MTG search handler
async function searchMTGCardsHandler(query, page, pageSize) {
  try {
    const data = await searchMTGCards(query);
    const cards = data.data || [];
    
    const startIdx = (page - 1) * pageSize;
    const paginatedCards = cards.slice(startIdx, startIdx + parseInt(pageSize));
    
    return {
      data: paginatedCards.map(normalizeMTGCard),
      totalCount: data.total_cards || cards.length,
      page: parseInt(page),
      pageSize: parseInt(pageSize)
    };
  } catch (err) {
    // Scryfall returns 404 for no results
    if (err.message.includes('404')) {
      return { data: [], totalCount: 0, page: parseInt(page), pageSize: parseInt(pageSize) };
    }
    throw err;
  }
}

// Yu-Gi-Oh search handler  
async function searchYugiohCardsHandler(query, page, pageSize) {
  const data = await searchYugiohCards(query);
  const cards = data.data || [];
  
  const startIdx = (page - 1) * pageSize;
  const paginatedCards = cards.slice(startIdx, startIdx + parseInt(pageSize));
  
  return {
    data: paginatedCards.map(normalizeYugiohCard),
    totalCount: cards.length,
    page: parseInt(page),
    pageSize: parseInt(pageSize)
  };
}

// Get single card by category
app.get('/api/:category/cards/:id', async (req, res) => {
  try {
    const { category, id } = req.params;
    let card;
    
    switch (category) {
      case 'pokemon':
        const pokemonData = await fetchPokemonAPI(`/cards/${id}`, `card:${id}`);
        card = {
          id: pokemonData.id,
          name: pokemonData.name,
          images: { 
            small: pokemonData.image ? `${pokemonData.image}/low.webp` : null,
            large: pokemonData.image ? `${pokemonData.image}/high.webp` : null
          },
          set: pokemonData.set || { id: pokemonData.id.split('-')[0], name: 'Unknown Set' },
          rarity: pokemonData.rarity || 'Unknown',
          hp: pokemonData.hp,
          types: pokemonData.types,
          attacks: pokemonData.attacks,
          weaknesses: pokemonData.weaknesses,
          resistances: pokemonData.resistances,
          retreatCost: pokemonData.retreat,
          tcgplayer: pokemonData.pricing?.tcgplayer || null,
          cardmarket: pokemonData.pricing?.cardmarket || null,
          category: 'pokemon'
        };
        break;
        
      case 'mtg':
        const mtgData = await getMTGCard(id);
        card = normalizeMTGCard(mtgData);
        break;
        
      case 'yugioh':
        const yugiohData = await getYugiohCard(id);
        if (!yugiohData) {
          return res.status(404).json({ error: 'Card not found' });
        }
        card = normalizeYugiohCard(yugiohData);
        break;
      
      // Sports categories
      case 'baseball':
      case 'basketball':
      case 'football':
        const sportsCard = db.prepare('SELECT * FROM sports_cards WHERE card_id = ? AND sport = ?').get(id, category);
        if (!sportsCard) {
          return res.status(404).json({ error: 'Card not found' });
        }
        // Get population reports
        const popReports = db.prepare(`
          SELECT grader, grade, population, plus_population
          FROM population_reports WHERE card_id = ?
        `).all(id);
        
        card = normalizeSportsCard(sportsCard);
        card.populationReports = popReports;
        break;
        
      default:
        return res.status(400).json({ error: 'Invalid category' });
    }
    
    res.json({ data: card });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get sets by category
app.get('/api/:category/sets', async (req, res) => {
  try {
    const { category } = req.params;
    let sets;
    
    switch (category) {
      case 'pokemon':
        const pokemonSets = await fetchPokemonAPI('/sets', 'all_sets', 86400000);
        sets = pokemonSets.map(set => ({
          id: set.id,
          name: set.name,
          images: { logo: set.logo, symbol: set.symbol },
          total: set.cardCount?.total || 0,
          category: 'pokemon'
        })).reverse();
        break;
        
      case 'mtg':
        const mtgData = await getMTGSets();
        sets = (mtgData.data || [])
          .filter(set => set.set_type === 'expansion' || set.set_type === 'core' || set.set_type === 'masters')
          .slice(0, 100)
          .map(set => ({
            id: set.code,
            name: set.name,
            images: { logo: set.icon_svg_uri, symbol: set.icon_svg_uri },
            total: set.card_count || 0,
            released: set.released_at,
            category: 'mtg'
          }));
        break;
        
      case 'yugioh':
        const yugiohSets = await getYugiohSets();
        sets = (yugiohSets || []).slice(0, 100).map(set => ({
          id: set.set_code,
          name: set.set_name,
          images: { logo: null, symbol: null },
          total: set.num_of_cards || 0,
          released: set.tcg_date,
          category: 'yugioh'
        }));
        break;
        
      // Sports categories
      case 'baseball':
      case 'basketball':
      case 'football':
        const sportsSets = db.prepare(`
          SELECT * FROM sports_sets WHERE sport = ? ORDER BY year DESC, name ASC
        `).all(category);
        
        sets = sportsSets.map(set => ({
          id: set.set_id,
          name: set.name,
          year: set.year,
          images: { logo: set.image_url, symbol: null },
          total: set.total_cards || 0,
          manufacturer: set.manufacturer,
          category: category
        }));
        break;
        
      default:
        return res.status(400).json({ error: 'Invalid category' });
    }
    
    res.json({ data: sets });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ POKEMON TCG API PROXY (Legacy endpoints for backwards compatibility) ============

app.get('/api/cards/search', async (req, res) => {
  try {
    const { q, page = 1, pageSize = 20 } = req.query;
    if (!q) {
      return res.status(400).json({ error: 'Query required' });
    }
    
    // TCGdex search by name
    const endpoint = `/cards?name=${encodeURIComponent(q)}`;
    const cards = await fetchPokemonAPI(endpoint);
    
    // Transform to match expected format and paginate
    const startIdx = (page - 1) * pageSize;
    const paginatedCards = cards.slice(startIdx, startIdx + parseInt(pageSize));
    
    // Transform TCGdex format to match our frontend expectations
    const transformedCards = paginatedCards.map(card => ({
      id: card.id,
      name: card.name,
      images: { 
        small: card.image ? `${card.image}/low.webp` : null,
        large: card.image ? `${card.image}/high.webp` : null
      },
      set: card.set || { id: card.id.split('-')[0], name: 'Unknown Set' },
      rarity: card.rarity || 'Unknown',
      tcgplayer: card.pricing?.tcgplayer || null,
      cardmarket: card.pricing?.cardmarket || null
    }));
    
    res.json({ 
      data: transformedCards,
      totalCount: cards.length,
      page: parseInt(page),
      pageSize: parseInt(pageSize)
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/cards/:id', async (req, res) => {
  try {
    const card = await fetchPokemonAPI(`/cards/${req.params.id}`, `card:${req.params.id}`);
    
    // Transform TCGdex format to match frontend expectations
    const transformed = {
      data: {
        id: card.id,
        name: card.name,
        images: { 
          small: card.image ? `${card.image}/low.webp` : null,
          large: card.image ? `${card.image}/high.webp` : null
        },
        set: card.set || { id: card.id.split('-')[0], name: 'Unknown Set' },
        rarity: card.rarity || 'Unknown',
        hp: card.hp,
        types: card.types,
        attacks: card.attacks,
        weaknesses: card.weaknesses,
        resistances: card.resistances,
        retreatCost: card.retreat,
        // Pricing from TCGdex!
        tcgplayer: card.pricing?.tcgplayer || null,
        cardmarket: card.pricing?.cardmarket || null
      }
    };
    res.json(transformed);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sets', async (req, res) => {
  try {
    const sets = await fetchPokemonAPI('/sets', 'all_sets', 86400000); // Cache 24h
    
    // Transform to match frontend expectations
    const transformed = sets.map(set => ({
      id: set.id,
      name: set.name,
      images: {
        logo: set.logo || null,
        symbol: set.symbol || null
      },
      total: set.cardCount?.total || 0
    }));
    
    // Sort by most recent first (reverse order since TCGdex returns chronological)
    res.json({ data: transformed.reverse() });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sets/:id', async (req, res) => {
  try {
    const set = await fetchPokemonAPI(`/sets/${req.params.id}`, `set:${req.params.id}`);
    
    const transformed = {
      data: {
        id: set.id,
        name: set.name,
        images: {
          logo: set.logo || null,
          symbol: set.symbol || null
        },
        total: set.cardCount?.total || 0,
        cards: set.cards || []
      }
    };
    res.json(transformed);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/sets/:id/cards', async (req, res) => {
  try {
    const { page = 1, pageSize = 50 } = req.query;
    // Get full set info which includes cards list
    const set = await fetchPokemonAPI(`/sets/${req.params.id}`, `set:${req.params.id}`);
    
    const cards = set.cards || [];
    const startIdx = (page - 1) * pageSize;
    const paginatedCards = cards.slice(startIdx, startIdx + parseInt(pageSize));
    
    // Transform cards
    const transformedCards = paginatedCards.map(card => ({
      id: card.id,
      name: card.name,
      images: { 
        small: card.image ? `${card.image}/low.webp` : null,
        large: card.image ? `${card.image}/high.webp` : null
      },
      localId: card.localId
    }));
    
    res.json({ 
      data: transformedCards,
      totalCount: cards.length,
      page: parseInt(page),
      pageSize: parseInt(pageSize)
    });
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
    const { cardId, cardName, cardImage, setId, setName, rarity, quantity = 1, condition = 'Near Mint', purchasePrice, marketPrice, category = 'pokemon' } = req.body;
    
    if (!cardId || !cardName) {
      return res.status(400).json({ error: 'Card ID and name required' });
    }
    
    // Check if card already exists in collection with same condition and category
    const existing = db.prepare('SELECT * FROM collection WHERE user_id = ? AND card_id = ? AND condition = ? AND category = ?')
      .get(req.session.userId, cardId, condition, category);
    
    if (existing) {
      // Update quantity
      db.prepare('UPDATE collection SET quantity = quantity + ? WHERE id = ?')
        .run(quantity, existing.id);
      const updated = db.prepare('SELECT * FROM collection WHERE id = ?').get(existing.id);
      return res.json({ success: true, card: updated, action: 'updated' });
    }
    
    const result = db.prepare(`
      INSERT INTO collection (user_id, card_id, card_name, card_image, set_id, set_name, rarity, quantity, condition, purchase_price, market_price, category)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.session.userId, cardId, cardName, cardImage, setId, setName, rarity, quantity, condition, purchasePrice, marketPrice, category);
    
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
    const { cardId, cardName, cardImage, setId, setName, rarity, maxPrice, priority = 1, notes, category = 'pokemon' } = req.body;
    
    if (!cardId || !cardName) {
      return res.status(400).json({ error: 'Card ID and name required' });
    }
    
    // Check if already on want list (same category)
    const existing = db.prepare('SELECT * FROM want_list WHERE user_id = ? AND card_id = ? AND category = ?')
      .get(req.session.userId, cardId, category);
    
    if (existing) {
      return res.status(400).json({ error: 'Card already on want list' });
    }
    
    // Check if already in collection (same category)
    const inCollection = db.prepare('SELECT * FROM collection WHERE user_id = ? AND card_id = ? AND category = ?')
      .get(req.session.userId, cardId, category);
    
    if (inCollection) {
      return res.status(400).json({ error: 'Card already in your collection' });
    }
    
    const result = db.prepare(`
      INSERT INTO want_list (user_id, card_id, card_name, card_image, set_id, set_name, rarity, max_price, priority, notes, category)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(req.session.userId, cardId, cardName, cardImage, setId, setName, rarity, maxPrice, priority, notes, category);
    
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

// ============ SPORTS CARD SEEDING ============

async function seedSportsCards() {
  console.log('Seeding sports cards...');
  
  // Clear existing sports data
  db.prepare('DELETE FROM sports_cards').run();
  db.prepare('DELETE FROM sports_sets').run();
  db.prepare('DELETE FROM population_reports').run();
  
  // ========== BASEBALL SETS ==========
  const baseballSets = [
    { set_id: '1952-topps', name: '1952 Topps', year: 1952, sport: 'baseball', manufacturer: 'Topps', total_cards: 407 },
    { set_id: '1954-topps', name: '1954 Topps', year: 1954, sport: 'baseball', manufacturer: 'Topps', total_cards: 250 },
    { set_id: '1955-topps', name: '1955 Topps', year: 1955, sport: 'baseball', manufacturer: 'Topps', total_cards: 206 },
    { set_id: '1956-topps', name: '1956 Topps', year: 1956, sport: 'baseball', manufacturer: 'Topps', total_cards: 340 },
    { set_id: '1963-topps', name: '1963 Topps', year: 1963, sport: 'baseball', manufacturer: 'Topps', total_cards: 576 },
    { set_id: '1965-topps', name: '1965 Topps', year: 1965, sport: 'baseball', manufacturer: 'Topps', total_cards: 598 },
    { set_id: '1968-topps', name: '1968 Topps', year: 1968, sport: 'baseball', manufacturer: 'Topps', total_cards: 598 },
    { set_id: '1969-topps', name: '1969 Topps', year: 1969, sport: 'baseball', manufacturer: 'Topps', total_cards: 664 },
    { set_id: '1975-topps', name: '1975 Topps', year: 1975, sport: 'baseball', manufacturer: 'Topps', total_cards: 660 },
    { set_id: '1989-upper-deck', name: '1989 Upper Deck', year: 1989, sport: 'baseball', manufacturer: 'Upper Deck', total_cards: 800 },
    { set_id: '1993-sp', name: '1993 SP', year: 1993, sport: 'baseball', manufacturer: 'Upper Deck', total_cards: 290 },
    { set_id: '2011-topps-update', name: '2011 Topps Update', year: 2011, sport: 'baseball', manufacturer: 'Topps', total_cards: 330 },
  ];
  
  // ========== BASKETBALL SETS ==========
  const basketballSets = [
    { set_id: '1986-fleer', name: '1986-87 Fleer', year: 1986, sport: 'basketball', manufacturer: 'Fleer', total_cards: 132 },
    { set_id: '1996-topps-chrome', name: '1996-97 Topps Chrome', year: 1996, sport: 'basketball', manufacturer: 'Topps', total_cards: 220 },
    { set_id: '1997-metal-universe', name: '1997-98 Metal Universe', year: 1997, sport: 'basketball', manufacturer: 'Fleer', total_cards: 150 },
    { set_id: '2003-topps-chrome', name: '2003-04 Topps Chrome', year: 2003, sport: 'basketball', manufacturer: 'Topps', total_cards: 165 },
    { set_id: '2009-panini-national-treasures', name: '2009-10 National Treasures', year: 2009, sport: 'basketball', manufacturer: 'Panini', total_cards: 99 },
    { set_id: '2018-prizm', name: '2018-19 Prizm', year: 2018, sport: 'basketball', manufacturer: 'Panini', total_cards: 300 },
    { set_id: '2019-prizm', name: '2019-20 Prizm', year: 2019, sport: 'basketball', manufacturer: 'Panini', total_cards: 300 },
    { set_id: '2020-prizm', name: '2020-21 Prizm', year: 2020, sport: 'basketball', manufacturer: 'Panini', total_cards: 300 },
  ];
  
  // ========== FOOTBALL SETS ==========
  const footballSets = [
    { set_id: '1958-topps', name: '1958 Topps', year: 1958, sport: 'football', manufacturer: 'Topps', total_cards: 132 },
    { set_id: '1965-topps', name: '1965 Topps', year: 1965, sport: 'football', manufacturer: 'Topps', total_cards: 176 },
    { set_id: '1976-topps', name: '1976 Topps', year: 1976, sport: 'football', manufacturer: 'Topps', total_cards: 528 },
    { set_id: '1998-playoff-contenders', name: '1998 Playoff Contenders', year: 1998, sport: 'football', manufacturer: 'Playoff', total_cards: 100 },
    { set_id: '2000-playoff-contenders', name: '2000 Playoff Contenders', year: 2000, sport: 'football', manufacturer: 'Playoff', total_cards: 196 },
    { set_id: '2017-panini-prizm', name: '2017 Panini Prizm', year: 2017, sport: 'football', manufacturer: 'Panini', total_cards: 300 },
    { set_id: '2020-panini-prizm', name: '2020 Panini Prizm', year: 2020, sport: 'football', manufacturer: 'Panini', total_cards: 400 },
  ];
  
  // Insert all sets
  const allSets = [...baseballSets, ...basketballSets, ...footballSets];
  for (const set of allSets) {
    db.prepare(`
      INSERT OR REPLACE INTO sports_sets (set_id, name, year, sport, manufacturer, total_cards)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(set.set_id, set.name, set.year, set.sport, set.manufacturer, set.total_cards);
  }
  
  // ========== BASEBALL CARDS ==========
  const baseballCards = [
    // 1952 Topps - The Holy Grails
    { card_id: '1952-topps-311', name: '1952 Topps #311 Mickey Mantle RC', player_name: 'Mickey Mantle', team: 'New York Yankees', year: 1952, set_name: '1952 Topps', set_id: '1952-topps', card_number: '311', sport: 'baseball', rarity: 'Ultra Rare', rookie_card: 1, price_raw: 85000, price_psa_1: 35000, price_psa_3: 95000, price_psa_5: 200000, price_psa_6: 350000, price_psa_7: 650000, price_psa_8: 2200000, price_psa_9: 5200000, price_psa_10: 12600000, image_url: 'https://www.psacard.com/cardfacts/baseball-cards/1952-topps/mickey-mantle-311/24342' },
    { card_id: '1952-topps-1', name: '1952 Topps #1 Andy Pafko', player_name: 'Andy Pafko', team: 'Brooklyn Dodgers', year: 1952, set_name: '1952 Topps', set_id: '1952-topps', card_number: '1', sport: 'baseball', rarity: 'Rare', rookie_card: 0, price_raw: 1500, price_psa_5: 3500, price_psa_7: 8000, price_psa_8: 18000, price_psa_9: 75000, image_url: null },
    { card_id: '1952-topps-261', name: '1952 Topps #261 Willie Mays', player_name: 'Willie Mays', team: 'New York Giants', year: 1952, set_name: '1952 Topps', set_id: '1952-topps', card_number: '261', sport: 'baseball', rarity: 'Ultra Rare', rookie_card: 0, price_raw: 15000, price_psa_5: 35000, price_psa_7: 85000, price_psa_8: 180000, price_psa_9: 550000, price_psa_10: 1800000, image_url: null },
    
    // 1954 Topps
    { card_id: '1954-topps-128', name: '1954 Topps #128 Hank Aaron RC', player_name: 'Hank Aaron', team: 'Milwaukee Braves', year: 1954, set_name: '1954 Topps', set_id: '1954-topps', card_number: '128', sport: 'baseball', rarity: 'Ultra Rare', rookie_card: 1, price_raw: 8500, price_psa_5: 22000, price_psa_7: 45000, price_psa_8: 95000, price_psa_9: 400000, price_psa_10: 2500000, image_url: null },
    { card_id: '1954-topps-94', name: '1954 Topps #94 Ernie Banks RC', player_name: 'Ernie Banks', team: 'Chicago Cubs', year: 1954, set_name: '1954 Topps', set_id: '1954-topps', card_number: '94', sport: 'baseball', rarity: 'Rare', rookie_card: 1, price_raw: 2000, price_psa_5: 5500, price_psa_7: 12000, price_psa_8: 32000, price_psa_9: 125000, image_url: null },
    
    // 1955 Topps
    { card_id: '1955-topps-164', name: '1955 Topps #164 Roberto Clemente RC', player_name: 'Roberto Clemente', team: 'Pittsburgh Pirates', year: 1955, set_name: '1955 Topps', set_id: '1955-topps', card_number: '164', sport: 'baseball', rarity: 'Ultra Rare', rookie_card: 1, price_raw: 4500, price_psa_5: 12000, price_psa_7: 28000, price_psa_8: 65000, price_psa_9: 250000, price_psa_10: 1200000, image_url: null },
    { card_id: '1955-topps-123', name: '1955 Topps #123 Sandy Koufax RC', player_name: 'Sandy Koufax', team: 'Brooklyn Dodgers', year: 1955, set_name: '1955 Topps', set_id: '1955-topps', card_number: '123', sport: 'baseball', rarity: 'Rare', rookie_card: 1, price_raw: 2800, price_psa_5: 7500, price_psa_7: 18000, price_psa_8: 45000, price_psa_9: 175000, image_url: null },
    
    // 1968-1969 Topps
    { card_id: '1968-topps-177', name: '1968 Topps #177 Nolan Ryan RC', player_name: 'Nolan Ryan', team: 'New York Mets', year: 1968, set_name: '1968 Topps', set_id: '1968-topps', card_number: '177', sport: 'baseball', rarity: 'Rare', rookie_card: 1, price_raw: 800, price_psa_5: 1800, price_psa_7: 3500, price_psa_8: 9500, price_psa_9: 55000, price_psa_10: 600000, image_url: null },
    { card_id: '1969-topps-260', name: '1969 Topps #260 Reggie Jackson RC', player_name: 'Reggie Jackson', team: 'Oakland Athletics', year: 1969, set_name: '1969 Topps', set_id: '1969-topps', card_number: '260', sport: 'baseball', rarity: 'Rare', rookie_card: 1, price_raw: 250, price_psa_5: 550, price_psa_7: 1100, price_psa_8: 2800, price_psa_9: 18000, price_psa_10: 150000, image_url: null },
    
    // 1989 Upper Deck
    { card_id: '1989-ud-1', name: '1989 Upper Deck #1 Ken Griffey Jr. RC', player_name: 'Ken Griffey Jr.', team: 'Seattle Mariners', year: 1989, set_name: '1989 Upper Deck', set_id: '1989-upper-deck', card_number: '1', sport: 'baseball', rarity: 'Rare', rookie_card: 1, price_raw: 25, price_psa_7: 50, price_psa_8: 100, price_psa_9: 250, price_psa_10: 2500, image_url: null },
    
    // 1993 SP
    { card_id: '1993-sp-279', name: '1993 SP #279 Derek Jeter RC', player_name: 'Derek Jeter', team: 'New York Yankees', year: 1993, set_name: '1993 SP', set_id: '1993-sp', card_number: '279', sport: 'baseball', rarity: 'Ultra Rare', rookie_card: 1, price_raw: 350, price_psa_7: 650, price_psa_8: 1200, price_psa_9: 3500, price_psa_10: 25000, image_url: null },
    
    // 2011 Topps Update
    { card_id: '2011-topps-us175', name: '2011 Topps Update #US175 Mike Trout RC', player_name: 'Mike Trout', team: 'Los Angeles Angels', year: 2011, set_name: '2011 Topps Update', set_id: '2011-topps-update', card_number: 'US175', sport: 'baseball', rarity: 'Rare', rookie_card: 1, price_raw: 150, price_psa_7: 250, price_psa_8: 500, price_psa_9: 1500, price_psa_10: 12000, image_url: null },
  ];
  
  // ========== BASKETBALL CARDS ==========
  const basketballCards = [
    // 1986-87 Fleer - THE basketball set
    { card_id: '1986-fleer-57', name: '1986-87 Fleer #57 Michael Jordan RC', player_name: 'Michael Jordan', team: 'Chicago Bulls', year: 1986, set_name: '1986-87 Fleer', set_id: '1986-fleer', card_number: '57', sport: 'basketball', rarity: 'Ultra Rare', rookie_card: 1, price_raw: 8000, price_psa_5: 18000, price_psa_6: 28000, price_psa_7: 45000, price_psa_8: 95000, price_psa_9: 350000, price_psa_10: 1800000, price_bgs_9: 120000, price_bgs_9_5: 450000, price_bgs_10: 3000000, image_url: 'https://www.psacard.com/cardfacts/basketball-cards/1986-fleer/michael-jordan-57/137005' },
    { card_id: '1986-fleer-68', name: '1986-87 Fleer #68 Akeem Olajuwon RC', player_name: 'Hakeem Olajuwon', team: 'Houston Rockets', year: 1986, set_name: '1986-87 Fleer', set_id: '1986-fleer', card_number: '68', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 150, price_psa_7: 350, price_psa_8: 750, price_psa_9: 3000, price_psa_10: 25000, image_url: null },
    { card_id: '1986-fleer-82', name: '1986-87 Fleer #82 Charles Barkley RC', player_name: 'Charles Barkley', team: 'Philadelphia 76ers', year: 1986, set_name: '1986-87 Fleer', set_id: '1986-fleer', card_number: '82', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 150, price_psa_7: 350, price_psa_8: 700, price_psa_9: 2500, price_psa_10: 20000, image_url: null },
    { card_id: '1986-fleer-109', name: '1986-87 Fleer #109 Patrick Ewing RC', player_name: 'Patrick Ewing', team: 'New York Knicks', year: 1986, set_name: '1986-87 Fleer', set_id: '1986-fleer', card_number: '109', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 100, price_psa_7: 250, price_psa_8: 500, price_psa_9: 1800, price_psa_10: 15000, image_url: null },
    { card_id: '1986-fleer-53', name: '1986-87 Fleer #53 Karl Malone RC', player_name: 'Karl Malone', team: 'Utah Jazz', year: 1986, set_name: '1986-87 Fleer', set_id: '1986-fleer', card_number: '53', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 80, price_psa_7: 200, price_psa_8: 450, price_psa_9: 1500, price_psa_10: 12000, image_url: null },
    
    // 1996-97 Topps Chrome
    { card_id: '1996-chrome-138', name: '1996-97 Topps Chrome #138 Kobe Bryant RC', player_name: 'Kobe Bryant', team: 'Los Angeles Lakers', year: 1996, set_name: '1996-97 Topps Chrome', set_id: '1996-topps-chrome', card_number: '138', sport: 'basketball', rarity: 'Ultra Rare', rookie_card: 1, price_raw: 2500, price_psa_7: 4500, price_psa_8: 8500, price_psa_9: 35000, price_psa_10: 300000, price_bgs_9_5: 55000, price_bgs_10: 500000, image_url: null },
    { card_id: '1996-chrome-217', name: '1996-97 Topps Chrome #217 Allen Iverson RC', player_name: 'Allen Iverson', team: 'Philadelphia 76ers', year: 1996, set_name: '1996-97 Topps Chrome', set_id: '1996-topps-chrome', card_number: '217', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 200, price_psa_7: 400, price_psa_8: 850, price_psa_9: 3500, price_psa_10: 25000, image_url: null },
    { card_id: '1996-chrome-171', name: '1996-97 Topps Chrome #171 Steve Nash RC', player_name: 'Steve Nash', team: 'Phoenix Suns', year: 1996, set_name: '1996-97 Topps Chrome', set_id: '1996-topps-chrome', card_number: '171', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 100, price_psa_7: 250, price_psa_8: 500, price_psa_9: 2000, price_psa_10: 15000, image_url: null },
    
    // 2003-04 Topps Chrome - LeBron RC year
    { card_id: '2003-chrome-111', name: '2003-04 Topps Chrome #111 LeBron James RC', player_name: 'LeBron James', team: 'Cleveland Cavaliers', year: 2003, set_name: '2003-04 Topps Chrome', set_id: '2003-topps-chrome', card_number: '111', sport: 'basketball', rarity: 'Ultra Rare', rookie_card: 1, price_raw: 4500, price_psa_7: 7500, price_psa_8: 15000, price_psa_9: 65000, price_psa_10: 650000, price_bgs_9_5: 95000, price_bgs_10: 1200000, image_url: null },
    { card_id: '2003-chrome-113', name: '2003-04 Topps Chrome #113 Dwyane Wade RC', player_name: 'Dwyane Wade', team: 'Miami Heat', year: 2003, set_name: '2003-04 Topps Chrome', set_id: '2003-topps-chrome', card_number: '113', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 350, price_psa_7: 650, price_psa_8: 1200, price_psa_9: 4500, price_psa_10: 35000, image_url: null },
    { card_id: '2003-chrome-115', name: '2003-04 Topps Chrome #115 Carmelo Anthony RC', player_name: 'Carmelo Anthony', team: 'Denver Nuggets', year: 2003, set_name: '2003-04 Topps Chrome', set_id: '2003-topps-chrome', card_number: '115', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 150, price_psa_7: 300, price_psa_8: 600, price_psa_9: 2500, price_psa_10: 18000, image_url: null },
    
    // 2018-19 Prizm - Luka RC year
    { card_id: '2018-prizm-280', name: '2018-19 Prizm #280 Luka Doncic RC', player_name: 'Luka Doncic', team: 'Dallas Mavericks', year: 2018, set_name: '2018-19 Prizm', set_id: '2018-prizm', card_number: '280', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 200, price_psa_8: 350, price_psa_9: 800, price_psa_10: 5000, image_url: null },
    { card_id: '2018-prizm-278', name: '2018-19 Prizm #278 Trae Young RC', player_name: 'Trae Young', team: 'Atlanta Hawks', year: 2018, set_name: '2018-19 Prizm', set_id: '2018-prizm', card_number: '278', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 50, price_psa_8: 100, price_psa_9: 250, price_psa_10: 1500, image_url: null },
    
    // 2019-20 Prizm - Ja/Zion RC year
    { card_id: '2019-prizm-248', name: '2019-20 Prizm #248 Zion Williamson RC', player_name: 'Zion Williamson', team: 'New Orleans Pelicans', year: 2019, set_name: '2019-20 Prizm', set_id: '2019-prizm', card_number: '248', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 75, price_psa_8: 150, price_psa_9: 350, price_psa_10: 2000, image_url: null },
    { card_id: '2019-prizm-249', name: '2019-20 Prizm #249 Ja Morant RC', player_name: 'Ja Morant', team: 'Memphis Grizzlies', year: 2019, set_name: '2019-20 Prizm', set_id: '2019-prizm', card_number: '249', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 100, price_psa_8: 200, price_psa_9: 500, price_psa_10: 3500, image_url: null },
    
    // 2020-21 Prizm - LaMelo RC year
    { card_id: '2020-prizm-278', name: '2020-21 Prizm #278 LaMelo Ball RC', player_name: 'LaMelo Ball', team: 'Charlotte Hornets', year: 2020, set_name: '2020-21 Prizm', set_id: '2020-prizm', card_number: '278', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 50, price_psa_8: 100, price_psa_9: 200, price_psa_10: 1200, image_url: null },
    { card_id: '2020-prizm-258', name: '2020-21 Prizm #258 Anthony Edwards RC', player_name: 'Anthony Edwards', team: 'Minnesota Timberwolves', year: 2020, set_name: '2020-21 Prizm', set_id: '2020-prizm', card_number: '258', sport: 'basketball', rarity: 'Rare', rookie_card: 1, price_raw: 45, price_psa_8: 90, price_psa_9: 200, price_psa_10: 1000, image_url: null },
  ];
  
  // ========== FOOTBALL CARDS ==========
  const footballCards = [
    // 1958 Topps
    { card_id: '1958-topps-62', name: '1958 Topps #62 Jim Brown RC', player_name: 'Jim Brown', team: 'Cleveland Browns', year: 1958, set_name: '1958 Topps', set_id: '1958-topps', card_number: '62', sport: 'football', rarity: 'Ultra Rare', rookie_card: 1, price_raw: 3500, price_psa_5: 8500, price_psa_7: 22000, price_psa_8: 65000, price_psa_9: 275000, price_psa_10: null, image_url: null },
    
    // 1965 Topps
    { card_id: '1965-topps-122', name: '1965 Topps #122 Joe Namath RC', player_name: 'Joe Namath', team: 'New York Jets', year: 1965, set_name: '1965 Topps', set_id: '1965-topps', card_number: '122', sport: 'football', rarity: 'Ultra Rare', rookie_card: 1, price_raw: 2500, price_psa_5: 6000, price_psa_7: 15000, price_psa_8: 45000, price_psa_9: 180000, image_url: null },
    
    // 1976 Topps
    { card_id: '1976-topps-148', name: '1976 Topps #148 Walter Payton RC', player_name: 'Walter Payton', team: 'Chicago Bears', year: 1976, set_name: '1976 Topps', set_id: '1976-topps', card_number: '148', sport: 'football', rarity: 'Rare', rookie_card: 1, price_raw: 400, price_psa_5: 850, price_psa_7: 2200, price_psa_8: 5500, price_psa_9: 35000, price_psa_10: 350000, image_url: null },
    
    // 1998 Playoff Contenders
    { card_id: '1998-contenders-87', name: '1998 Playoff Contenders #87 Peyton Manning RC Auto', player_name: 'Peyton Manning', team: 'Indianapolis Colts', year: 1998, set_name: '1998 Playoff Contenders', set_id: '1998-playoff-contenders', card_number: '87', sport: 'football', rarity: 'Ultra Rare', rookie_card: 1, price_raw: 15000, price_psa_7: 25000, price_psa_8: 45000, price_psa_9: 125000, price_psa_10: 750000, price_bgs_9_5: 175000, image_url: null },
    
    // 2000 Playoff Contenders
    { card_id: '2000-contenders-144', name: '2000 Playoff Contenders #144 Tom Brady RC Auto', player_name: 'Tom Brady', team: 'New England Patriots', year: 2000, set_name: '2000 Playoff Contenders', set_id: '2000-playoff-contenders', card_number: '144', sport: 'football', rarity: 'Ultra Rare', rookie_card: 1, price_raw: 50000, price_psa_7: 75000, price_psa_8: 150000, price_psa_9: 450000, price_psa_10: 3500000, price_bgs_9_5: 650000, price_bgs_10: 4200000, image_url: null },
    
    // 2017 Panini Prizm
    { card_id: '2017-prizm-269', name: '2017 Panini Prizm #269 Patrick Mahomes II RC', player_name: 'Patrick Mahomes', team: 'Kansas City Chiefs', year: 2017, set_name: '2017 Panini Prizm', set_id: '2017-panini-prizm', card_number: '269', sport: 'football', rarity: 'Rare', rookie_card: 1, price_raw: 400, price_psa_8: 750, price_psa_9: 2000, price_psa_10: 15000, image_url: null },
    { card_id: '2017-prizm-292', name: '2017 Panini Prizm #292 Deshaun Watson RC', player_name: 'Deshaun Watson', team: 'Houston Texans', year: 2017, set_name: '2017 Panini Prizm', set_id: '2017-panini-prizm', card_number: '292', sport: 'football', rarity: 'Rare', rookie_card: 1, price_raw: 25, price_psa_8: 50, price_psa_9: 125, price_psa_10: 800, image_url: null },
    
    // 2020 Panini Prizm
    { card_id: '2020-prizm-307', name: '2020 Panini Prizm #307 Justin Herbert RC', player_name: 'Justin Herbert', team: 'Los Angeles Chargers', year: 2020, set_name: '2020 Panini Prizm', set_id: '2020-panini-prizm', card_number: '307', sport: 'football', rarity: 'Rare', rookie_card: 1, price_raw: 75, price_psa_8: 125, price_psa_9: 300, price_psa_10: 2000, image_url: null },
    { card_id: '2020-prizm-325', name: '2020 Panini Prizm #325 Joe Burrow RC', player_name: 'Joe Burrow', team: 'Cincinnati Bengals', year: 2020, set_name: '2020 Panini Prizm', set_id: '2020-panini-prizm', card_number: '325', sport: 'football', rarity: 'Rare', rookie_card: 1, price_raw: 65, price_psa_8: 110, price_psa_9: 275, price_psa_10: 1800, image_url: null },
  ];
  
  // Insert all cards
  const allCards = [...baseballCards, ...basketballCards, ...footballCards];
  for (const card of allCards) {
    db.prepare(`
      INSERT OR REPLACE INTO sports_cards (
        card_id, name, player_name, team, year, set_name, set_id, card_number, sport, rarity, 
        rookie_card, image_url, price_raw, price_psa_1, price_psa_3, price_psa_5, price_psa_6, 
        price_psa_7, price_psa_8, price_psa_9, price_psa_10, price_bgs_9, price_bgs_9_5, price_bgs_10, price_bgs_pristine
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      card.card_id, card.name, card.player_name, card.team, card.year, card.set_name, card.set_id,
      card.card_number, card.sport, card.rarity, card.rookie_card ? 1 : 0, card.image_url,
      card.price_raw || null, card.price_psa_1 || null, card.price_psa_3 || null, card.price_psa_5 || null,
      card.price_psa_6 || null, card.price_psa_7 || null, card.price_psa_8 || null, card.price_psa_9 || null,
      card.price_psa_10 || null, card.price_bgs_9 || null, card.price_bgs_9_5 || null, 
      card.price_bgs_10 || null, card.price_bgs_pristine || null
    );
  }
  
  // ========== POPULATION REPORTS ==========
  const populationReports = [
    // 1986 Fleer Michael Jordan PSA Pop
    { card_id: '1986-fleer-57', grader: 'PSA', grade: '10', population: 316, plus_population: 0 },
    { card_id: '1986-fleer-57', grader: 'PSA', grade: '9', population: 2847, plus_population: 0 },
    { card_id: '1986-fleer-57', grader: 'PSA', grade: '8', population: 4521, plus_population: 0 },
    { card_id: '1986-fleer-57', grader: 'PSA', grade: '7', population: 3892, plus_population: 0 },
    { card_id: '1986-fleer-57', grader: 'PSA', grade: '6', population: 2156, plus_population: 0 },
    { card_id: '1986-fleer-57', grader: 'BGS', grade: '10', population: 28, plus_population: 0 },
    { card_id: '1986-fleer-57', grader: 'BGS', grade: '9.5', population: 892, plus_population: 0 },
    { card_id: '1986-fleer-57', grader: 'BGS', grade: '9', population: 1245, plus_population: 0 },
    
    // 1952 Topps Mickey Mantle PSA Pop
    { card_id: '1952-topps-311', grader: 'PSA', grade: '10', population: 3, plus_population: 0 },
    { card_id: '1952-topps-311', grader: 'PSA', grade: '9', population: 6, plus_population: 0 },
    { card_id: '1952-topps-311', grader: 'PSA', grade: '8', population: 45, plus_population: 0 },
    { card_id: '1952-topps-311', grader: 'PSA', grade: '7', population: 112, plus_population: 0 },
    { card_id: '1952-topps-311', grader: 'PSA', grade: '6', population: 198, plus_population: 0 },
    { card_id: '1952-topps-311', grader: 'PSA', grade: '5', population: 287, plus_population: 0 },
    { card_id: '1952-topps-311', grader: 'SGC', grade: '10', population: 0, plus_population: 0 },
    { card_id: '1952-topps-311', grader: 'SGC', grade: '9', population: 2, plus_population: 0 },
    
    // 2003-04 Topps Chrome LeBron James
    { card_id: '2003-chrome-111', grader: 'PSA', grade: '10', population: 1847, plus_population: 0 },
    { card_id: '2003-chrome-111', grader: 'PSA', grade: '9', population: 8932, plus_population: 0 },
    { card_id: '2003-chrome-111', grader: 'PSA', grade: '8', population: 4521, plus_population: 0 },
    { card_id: '2003-chrome-111', grader: 'BGS', grade: '10', population: 156, plus_population: 0 },
    { card_id: '2003-chrome-111', grader: 'BGS', grade: '9.5', population: 2847, plus_population: 0 },
    
    // 2000 Contenders Tom Brady
    { card_id: '2000-contenders-144', grader: 'PSA', grade: '10', population: 12, plus_population: 0 },
    { card_id: '2000-contenders-144', grader: 'PSA', grade: '9', population: 87, plus_population: 0 },
    { card_id: '2000-contenders-144', grader: 'PSA', grade: '8', population: 134, plus_population: 0 },
    { card_id: '2000-contenders-144', grader: 'BGS', grade: '10', population: 5, plus_population: 0 },
    { card_id: '2000-contenders-144', grader: 'BGS', grade: '9.5', population: 67, plus_population: 0 },
    
    // 1996-97 Topps Chrome Kobe Bryant
    { card_id: '1996-chrome-138', grader: 'PSA', grade: '10', population: 521, plus_population: 0 },
    { card_id: '1996-chrome-138', grader: 'PSA', grade: '9', population: 4892, plus_population: 0 },
    { card_id: '1996-chrome-138', grader: 'PSA', grade: '8', population: 3847, plus_population: 0 },
    { card_id: '1996-chrome-138', grader: 'BGS', grade: '10', population: 89, plus_population: 0 },
    { card_id: '1996-chrome-138', grader: 'BGS', grade: '9.5', population: 1456, plus_population: 0 },
  ];
  
  for (const pop of populationReports) {
    db.prepare(`
      INSERT OR REPLACE INTO population_reports (card_id, grader, grade, population, plus_population)
      VALUES (?, ?, ?, ?, ?)
    `).run(pop.card_id, pop.grader, pop.grade, pop.population, pop.plus_population);
  }
  
  console.log(`Seeded ${allSets.length} sports sets`);
  console.log(`Seeded ${allCards.length} sports cards`);
  console.log(`Seeded ${populationReports.length} population reports`);
  
  return { sets: allSets.length, cards: allCards.length, popReports: populationReports.length };
}

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
      db.prepare('DELETE FROM sports_cards').run();
      db.prepare('DELETE FROM sports_sets').run();
      db.prepare('DELETE FROM population_reports').run();
    }
    
    // ========== SEED SPORTS CARDS ==========
    await seedSportsCards();
    
    const hashedPassword = await bcrypt.hash('password123', 10);
    
    // Create demo user
    const result = db.prepare('INSERT INTO users (email, password, name) VALUES (?, ?, ?)')
      .run('trainer@pokemon.com', hashedPassword, 'Ash Ketchum');
    const userId = result.lastInsertRowid;
    
    // Add some sample collection cards (using real Pokemon TCG API card IDs)
    const sampleCollection = [
      // Pokemon cards
      { cardId: 'base1-4', cardName: 'Charizard', cardImage: 'https://images.pokemontcg.io/base1/4_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', quantity: 1, condition: 'Near Mint', marketPrice: 420.00, category: 'pokemon' },
      { cardId: 'base1-2', cardName: 'Blastoise', cardImage: 'https://images.pokemontcg.io/base1/2_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', quantity: 1, condition: 'Near Mint', marketPrice: 85.00, category: 'pokemon' },
      { cardId: 'base1-15', cardName: 'Venusaur', cardImage: 'https://images.pokemontcg.io/base1/15_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', quantity: 1, condition: 'Lightly Played', marketPrice: 65.00, category: 'pokemon' },
      { cardId: 'base1-58', cardName: 'Pikachu', cardImage: 'https://images.pokemontcg.io/base1/58_hires.png', setId: 'base1', setName: 'Base', rarity: 'Common', quantity: 4, condition: 'Near Mint', marketPrice: 15.00, category: 'pokemon' },
      { cardId: 'swsh9-166', cardName: 'Charizard VSTAR', cardImage: 'https://images.pokemontcg.io/swsh9/166_hires.png', setId: 'swsh9', setName: 'Brilliant Stars', rarity: 'Rare Holo VSTAR', quantity: 2, condition: 'Near Mint', marketPrice: 35.00, category: 'pokemon' },
      { cardId: 'sv3pt5-197', cardName: 'Umbreon ex', cardImage: 'https://images.pokemontcg.io/sv3pt5/197_hires.png', setId: 'sv3pt5', setName: '151', rarity: 'Special Art Rare', quantity: 1, condition: 'Near Mint', marketPrice: 145.00, category: 'pokemon' },
      // MTG cards (Scryfall IDs)
      { cardId: 'f8f3fdc5-f4cc-40f8-af5c-d4c757e54c27', cardName: 'Black Lotus', cardImage: 'https://cards.scryfall.io/normal/front/b/d/bd8fa327-dd41-4737-8f19-2cf5eb1f7c20.jpg', setId: 'lea', setName: 'Alpha', rarity: 'rare', quantity: 1, condition: 'Near Mint', marketPrice: 50000.00, category: 'mtg' },
      { cardId: '0c4b64a7-4f88-4c58-91e6-6ce3a95a026c', cardName: 'Lightning Bolt', cardImage: 'https://cards.scryfall.io/normal/front/f/2/f29ba16f-c8fb-42fe-aabf-87089cb214a7.jpg', setId: 'lea', setName: 'Alpha', rarity: 'common', quantity: 4, condition: 'Near Mint', marketPrice: 800.00, category: 'mtg' },
      { cardId: 'ce4c6535-afea-4704-b35c-badeb04c4f4c', cardName: 'Counterspell', cardImage: 'https://cards.scryfall.io/normal/front/1/9/1920dae4-fb92-4f19-ae4b-eb3276b8dac7.jpg', setId: 'lea', setName: 'Alpha', rarity: 'uncommon', quantity: 2, condition: 'Near Mint', marketPrice: 350.00, category: 'mtg' },
      // Yu-Gi-Oh cards
      { cardId: '46986414', cardName: 'Dark Magician', cardImage: 'https://images.ygoprodeck.com/images/cards/46986414.jpg', setId: 'LOB', setName: 'Legend of Blue Eyes', rarity: 'Ultra Rare', quantity: 1, condition: 'Near Mint', marketPrice: 45.00, category: 'yugioh' },
      { cardId: '89631139', cardName: 'Blue-Eyes White Dragon', cardImage: 'https://images.ygoprodeck.com/images/cards/89631139.jpg', setId: 'LOB', setName: 'Legend of Blue Eyes', rarity: 'Ultra Rare', quantity: 2, condition: 'Near Mint', marketPrice: 120.00, category: 'yugioh' },
      { cardId: '74677422', cardName: 'Red-Eyes Black Dragon', cardImage: 'https://images.ygoprodeck.com/images/cards/74677422.jpg', setId: 'LOB', setName: 'Legend of Blue Eyes', rarity: 'Ultra Rare', quantity: 1, condition: 'Near Mint', marketPrice: 55.00, category: 'yugioh' },
      // Sports cards - Baseball
      { cardId: '1989-ud-1', cardName: '1989 Upper Deck #1 Ken Griffey Jr. RC', cardImage: null, setId: '1989-upper-deck', setName: '1989 Upper Deck', rarity: 'Rare', quantity: 2, condition: 'Near Mint', marketPrice: 25.00, category: 'baseball', playerName: 'Ken Griffey Jr.', year: 1989, grade: 'PSA 9', grader: 'PSA' },
      { cardId: '1993-sp-279', cardName: '1993 SP #279 Derek Jeter RC', cardImage: null, setId: '1993-sp', setName: '1993 SP', rarity: 'Ultra Rare', quantity: 1, condition: 'Near Mint', marketPrice: 3500.00, category: 'baseball', playerName: 'Derek Jeter', year: 1993, grade: 'PSA 9', grader: 'PSA' },
      // Sports cards - Basketball
      { cardId: '1986-fleer-57', cardName: '1986-87 Fleer #57 Michael Jordan RC', cardImage: null, setId: '1986-fleer', setName: '1986-87 Fleer', rarity: 'Ultra Rare', quantity: 1, condition: 'Near Mint', marketPrice: 95000.00, category: 'basketball', playerName: 'Michael Jordan', year: 1986, grade: 'PSA 8', grader: 'PSA' },
      { cardId: '2018-prizm-280', cardName: '2018-19 Prizm #280 Luka Doncic RC', cardImage: null, setId: '2018-prizm', setName: '2018-19 Prizm', rarity: 'Rare', quantity: 2, condition: 'Near Mint', marketPrice: 800.00, category: 'basketball', playerName: 'Luka Doncic', year: 2018, grade: 'PSA 9', grader: 'PSA' },
      // Sports cards - Football
      { cardId: '2017-prizm-269', cardName: '2017 Panini Prizm #269 Patrick Mahomes II RC', cardImage: null, setId: '2017-panini-prizm', setName: '2017 Panini Prizm', rarity: 'Rare', quantity: 1, condition: 'Near Mint', marketPrice: 2000.00, category: 'football', playerName: 'Patrick Mahomes', year: 2017, grade: 'PSA 9', grader: 'PSA' },
    ];
    
    for (const card of sampleCollection) {
      db.prepare(`
        INSERT INTO collection (user_id, card_id, card_name, card_image, set_id, set_name, rarity, quantity, condition, market_price, category, player_name, year, grade, grader)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(userId, card.cardId, card.cardName, card.cardImage, card.setId, card.setName, card.rarity, card.quantity, card.condition, card.marketPrice, card.category, card.playerName || null, card.year || null, card.grade || null, card.grader || null);
    }
    
    // Add some want list items (including MTG, Yu-Gi-Oh, and Sports)
    const sampleWantList = [
      // Pokemon
      { cardId: 'base1-1', cardName: 'Alakazam', cardImage: 'https://images.pokemontcg.io/base1/1_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', maxPrice: 50.00, priority: 2, category: 'pokemon' },
      { cardId: 'base1-3', cardName: 'Chansey', cardImage: 'https://images.pokemontcg.io/base1/3_hires.png', setId: 'base1', setName: 'Base', rarity: 'Rare Holo', maxPrice: 30.00, priority: 1, category: 'pokemon' },
      { cardId: 'sv3pt5-199', cardName: 'Mew ex', cardImage: 'https://images.pokemontcg.io/sv3pt5/199_hires.png', setId: 'sv3pt5', setName: '151', rarity: 'Special Art Rare', maxPrice: 200.00, priority: 3, category: 'pokemon' },
      // MTG
      { cardId: 'c44c098e-b44f-4b35-b0a2-e43a9e3e0e3c', cardName: 'Mox Pearl', cardImage: 'https://cards.scryfall.io/normal/front/e/d/ed0ba7c9-dc6b-4e01-b65e-c7e61a2ab91c.jpg', setId: 'lea', setName: 'Alpha', rarity: 'rare', maxPrice: 10000.00, priority: 3, category: 'mtg' },
      // Yu-Gi-Oh
      { cardId: '70781052', cardName: 'Exodia the Forbidden One', cardImage: 'https://images.ygoprodeck.com/images/cards/70781052.jpg', setId: 'LOB', setName: 'Legend of Blue Eyes', rarity: 'Ultra Rare', maxPrice: 150.00, priority: 2, category: 'yugioh' },
      // Sports - Baseball
      { cardId: '1952-topps-311', cardName: '1952 Topps #311 Mickey Mantle RC', cardImage: null, setId: '1952-topps', setName: '1952 Topps', rarity: 'Ultra Rare', maxPrice: 100000.00, priority: 3, category: 'baseball' },
      { cardId: '2011-topps-us175', cardName: '2011 Topps Update #US175 Mike Trout RC', cardImage: null, setId: '2011-topps-update', setName: '2011 Topps Update', rarity: 'Rare', maxPrice: 1500.00, priority: 2, category: 'baseball' },
      // Sports - Basketball
      { cardId: '2003-chrome-111', cardName: '2003-04 Topps Chrome #111 LeBron James RC', cardImage: null, setId: '2003-topps-chrome', setName: '2003-04 Topps Chrome', rarity: 'Ultra Rare', maxPrice: 70000.00, priority: 3, category: 'basketball' },
      { cardId: '1996-chrome-138', cardName: '1996-97 Topps Chrome #138 Kobe Bryant RC', cardImage: null, setId: '1996-topps-chrome', setName: '1996-97 Topps Chrome', rarity: 'Ultra Rare', maxPrice: 40000.00, priority: 2, category: 'basketball' },
      // Sports - Football  
      { cardId: '2000-contenders-144', cardName: '2000 Playoff Contenders #144 Tom Brady RC Auto', cardImage: null, setId: '2000-playoff-contenders', setName: '2000 Playoff Contenders', rarity: 'Ultra Rare', maxPrice: 200000.00, priority: 3, category: 'football' },
    ];
    
    for (const card of sampleWantList) {
      db.prepare(`
        INSERT INTO want_list (user_id, card_id, card_name, card_image, set_id, set_name, rarity, max_price, priority, category)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(userId, card.cardId, card.cardName, card.cardImage, card.setId, card.setName, card.rarity, card.maxPrice, card.priority, card.category);
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
    
    // Get sports card counts
    const sportsCardCount = db.prepare('SELECT COUNT(*) as c FROM sports_cards').get().c;
    const sportsSetCount = db.prepare('SELECT COUNT(*) as c FROM sports_sets').get().c;
    const popReportCount = db.prepare('SELECT COUNT(*) as c FROM population_reports').get().c;
    
    res.json({ 
      success: true, 
      message: 'Database seeded successfully with trade demo data + sports cards',
      created: {
        users: 1 + additionalUsers,
        collectionCards: sampleCollection.length + additionalCards,
        wantListCards: sampleWantList.length + additionalWants,
        sportsCards: sportsCardCount,
        sportsSets: sportsSetCount,
        populationReports: popReportCount
      },
      sportsCategories: ['baseball', 'basketball', 'football'],
      demoLogins: [
        { email: 'trainer@pokemon.com', password: 'password123', description: 'Main user (Ash) - has Pokemon, MTG, Yu-Gi-Oh, and Sports cards' },
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
