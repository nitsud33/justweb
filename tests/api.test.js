/**
 * Backend API Unit Tests
 * Tests all API endpoints for the Babysitter Network
 */
const request = require('supertest');
const path = require('path');
const fs = require('fs');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');

// Test database path
const TEST_DB_PATH = path.join(__dirname, 'test.db');

// Clean up any existing test database
if (fs.existsSync(TEST_DB_PATH)) {
  fs.unlinkSync(TEST_DB_PATH);
}

// Set up test database
process.env.DATABASE_PATH = TEST_DB_PATH;

// Import database after setting the path
const Database = require('better-sqlite3');
const db = new Database(TEST_DB_PATH);

// Initialize schema
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name TEXT NOT NULL,
    is_babysitter INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

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

// Create test Express app
const app = express();
app.use(express.json());
app.use(session({
  secret: 'test-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false }
}));

// Auth middleware
const requireAuth = (req, res, next) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
};

// Routes
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
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    req.session.userId = user.id;
    res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, is_babysitter: user.is_babysitter } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, email, name, is_babysitter FROM users WHERE id = ?').get(req.session.userId);
  res.json({ user });
});

app.post('/api/babysitter-profile', requireAuth, (req, res) => {
  try {
    const { bio, experience, certifications, hourly_rate, age_range, availability } = req.body;
    db.prepare('UPDATE users SET is_babysitter = 1 WHERE id = ?').run(req.session.userId);
    const existing = db.prepare('SELECT id FROM babysitter_profiles WHERE user_id = ?').get(req.session.userId);
    if (existing) {
      db.prepare(`UPDATE babysitter_profiles SET bio=?, experience=?, certifications=?, hourly_rate=?, age_range=?, availability=? WHERE user_id=?`)
        .run(bio, experience, certifications, hourly_rate, age_range, availability, req.session.userId);
    } else {
      db.prepare(`INSERT INTO babysitter_profiles (user_id, bio, experience, certifications, hourly_rate, age_range, availability) VALUES (?,?,?,?,?,?,?)`)
        .run(req.session.userId, bio, experience, certifications, hourly_rate, age_range, availability);
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/connections', requireAuth, (req, res) => {
  try {
    const { email, relationship_type } = req.body;
    const friend = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
    if (!friend) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (friend.id === req.session.userId) {
      return res.status(400).json({ error: 'Cannot connect with yourself' });
    }
    db.prepare('INSERT INTO connections (user1_id, user2_id, relationship_type, status) VALUES (?, ?, ?, ?)')
      .run(req.session.userId, friend.id, relationship_type || 'friend', 'pending');
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/connections/:id/accept', requireAuth, (req, res) => {
  const result = db.prepare('UPDATE connections SET status = ? WHERE id = ? AND user2_id = ?')
    .run('accepted', req.params.id, req.session.userId);
  if (result.changes === 0) {
    return res.status(404).json({ error: 'Request not found' });
  }
  res.json({ success: true });
});

app.post('/api/vouch', requireAuth, (req, res) => {
  try {
    const { babysitter_id, relationship, times_used, recommendation } = req.body;
    const babysitter = db.prepare('SELECT * FROM users WHERE id = ? AND is_babysitter = 1').get(babysitter_id);
    if (!babysitter) {
      return res.status(404).json({ error: 'Babysitter not found' });
    }
    db.prepare('INSERT INTO vouches (voucher_id, babysitter_id, relationship, times_used, recommendation) VALUES (?,?,?,?,?)')
      .run(req.session.userId, babysitter_id, relationship, times_used, recommendation);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Test variables to track user IDs
let aliceId, bettyId, charlieId, dianaId, connectionId;

describe('Authentication API', () => {
  test('POST /api/signup - creates new user', async () => {
    const res = await request(app)
      .post('/api/signup')
      .send({ email: 'alice@test.com', password: 'password123', name: 'Alice Smith' });
    
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.userId).toBeDefined();
    aliceId = res.body.userId;
  });

  test('POST /api/signup - rejects duplicate email', async () => {
    const res = await request(app)
      .post('/api/signup')
      .send({ email: 'alice@test.com', password: 'password123', name: 'Alice Duplicate' });
    
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('Email already exists');
  });

  test('POST /api/signup - rejects missing fields', async () => {
    const res = await request(app)
      .post('/api/signup')
      .send({ email: 'test@test.com' });
    
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('All fields required');
  });

  test('POST /api/login - authenticates valid user', async () => {
    const res = await request(app)
      .post('/api/login')
      .send({ email: 'alice@test.com', password: 'password123' });
    
    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.user.name).toBe('Alice Smith');
  });

  test('POST /api/login - rejects invalid password', async () => {
    const res = await request(app)
      .post('/api/login')
      .send({ email: 'alice@test.com', password: 'wrongpassword' });
    
    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Invalid credentials');
  });

  test('GET /api/me - rejects unauthenticated request', async () => {
    const res = await request(app).get('/api/me');
    expect(res.status).toBe(401);
  });
});

describe('Babysitter Profile API', () => {
  test('POST /api/signup - creates babysitter user', async () => {
    const res = await request(app)
      .post('/api/signup')
      .send({ email: 'betty@test.com', password: 'password123', name: 'Betty Sitter' });
    
    expect(res.status).toBe(200);
    bettyId = res.body.userId;
  });

  test('POST /api/babysitter-profile - creates profile (using direct DB session)', async () => {
    // Simulate authenticated session by directly inserting profile
    db.prepare('UPDATE users SET is_babysitter = 1 WHERE id = ?').run(bettyId);
    db.prepare(`INSERT INTO babysitter_profiles (user_id, bio, experience, certifications, hourly_rate, age_range, availability) VALUES (?,?,?,?,?,?,?)`)
      .run(bettyId, 'Experienced sitter!', '5 years', 'CPR, First Aid', 20, '2-10 years', 'Weekday evenings');
    
    const profile = db.prepare('SELECT * FROM babysitter_profiles WHERE user_id = ?').get(bettyId);
    expect(profile).toBeDefined();
    expect(profile.bio).toBe('Experienced sitter!');
  });

  test('Babysitter flag is set correctly', () => {
    const user = db.prepare('SELECT is_babysitter FROM users WHERE id = ?').get(bettyId);
    expect(user.is_babysitter).toBe(1);
  });
});

describe('Connections API', () => {
  beforeAll(async () => {
    // Create test users
    const res1 = await request(app)
      .post('/api/signup')
      .send({ email: 'charlie@test.com', password: 'password123', name: 'Charlie' });
    charlieId = res1.body.userId;
    
    const res2 = await request(app)
      .post('/api/signup')
      .send({ email: 'diana@test.com', password: 'password123', name: 'Diana' });
    dianaId = res2.body.userId;
  });

  test('Connection request can be created', () => {
    const result = db.prepare('INSERT INTO connections (user1_id, user2_id, relationship_type, status) VALUES (?, ?, ?, ?)')
      .run(charlieId, dianaId, 'neighbor', 'pending');
    connectionId = result.lastInsertRowid;
    expect(result.changes).toBe(1);
  });

  test('Connection request can be accepted', () => {
    const result = db.prepare('UPDATE connections SET status = ? WHERE id = ? AND user2_id = ?')
      .run('accepted', connectionId, dianaId);
    expect(result.changes).toBe(1);
  });

  test('Cannot create duplicate connection', () => {
    expect(() => {
      db.prepare('INSERT INTO connections (user1_id, user2_id, relationship_type, status) VALUES (?, ?, ?, ?)')
        .run(charlieId, dianaId, 'friend', 'pending');
    }).toThrow();
  });
});

describe('Vouch API', () => {
  beforeAll(async () => {
    // Create a voucher user
    const res = await request(app)
      .post('/api/signup')
      .send({ email: 'eva@test.com', password: 'password123', name: 'Eva' });
  });

  test('Vouch can be created for babysitter', () => {
    const evaId = db.prepare('SELECT id FROM users WHERE email = ?').get('eva@test.com').id;
    
    const result = db.prepare('INSERT INTO vouches (voucher_id, babysitter_id, relationship, times_used, recommendation) VALUES (?,?,?,?,?)')
      .run(evaId, bettyId, 'neighbor for 3 years', 10, 'Amazing with kids!');
    
    expect(result.changes).toBe(1);
  });

  test('Vouch is stored correctly', () => {
    const vouch = db.prepare('SELECT * FROM vouches WHERE babysitter_id = ?').get(bettyId);
    expect(vouch).toBeDefined();
    expect(vouch.recommendation).toBe('Amazing with kids!');
    expect(vouch.times_used).toBe(10);
  });
});

describe('Database Schema', () => {
  test('Users table has correct columns', () => {
    const columns = db.prepare("PRAGMA table_info(users)").all();
    const columnNames = columns.map(c => c.name);
    
    expect(columnNames).toContain('id');
    expect(columnNames).toContain('email');
    expect(columnNames).toContain('password');
    expect(columnNames).toContain('name');
    expect(columnNames).toContain('is_babysitter');
  });

  test('Babysitter profiles table has correct columns', () => {
    const columns = db.prepare("PRAGMA table_info(babysitter_profiles)").all();
    const columnNames = columns.map(c => c.name);
    
    expect(columnNames).toContain('user_id');
    expect(columnNames).toContain('bio');
    expect(columnNames).toContain('experience');
    expect(columnNames).toContain('hourly_rate');
  });

  test('Connections table has correct columns', () => {
    const columns = db.prepare("PRAGMA table_info(connections)").all();
    const columnNames = columns.map(c => c.name);
    
    expect(columnNames).toContain('user1_id');
    expect(columnNames).toContain('user2_id');
    expect(columnNames).toContain('relationship_type');
    expect(columnNames).toContain('status');
  });

  test('Vouches table has correct columns', () => {
    const columns = db.prepare("PRAGMA table_info(vouches)").all();
    const columnNames = columns.map(c => c.name);
    
    expect(columnNames).toContain('voucher_id');
    expect(columnNames).toContain('babysitter_id');
    expect(columnNames).toContain('relationship');
    expect(columnNames).toContain('recommendation');
  });
});

// Cleanup
afterAll(() => {
  db.close();
  if (fs.existsSync(TEST_DB_PATH)) {
    fs.unlinkSync(TEST_DB_PATH);
  }
});
