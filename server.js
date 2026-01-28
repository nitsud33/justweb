const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const path = require('path');
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'babysitter-network-secret-key-change-in-prod',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production' && process.env.RAILWAY_ENVIRONMENT ? false : false,
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
  const user = db.prepare('SELECT id, email, name, is_babysitter FROM users WHERE id = ?').get(id);
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
      
      // Check if user exists by google_id or email
      let user = db.prepare('SELECT * FROM users WHERE google_id = ? OR email = ?').get(googleId, email);
      
      if (user) {
        // Update google_id if user exists but signed up differently
        if (!user.google_id) {
          db.prepare('UPDATE users SET google_id = ? WHERE id = ?').run(googleId, user.id);
        }
      } else {
        // Create new user (no password for OAuth users)
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

// ============ GOOGLE OAUTH ROUTES ============

app.get('/auth/google', passport.authenticate('google', { 
  scope: ['profile', 'email'] 
}));

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/?error=oauth_failed' }),
  (req, res) => {
    // Set session userId for consistency with regular auth
    req.session.userId = req.user.id;
    res.redirect('/');
  }
);

// Check if Google OAuth is available
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
    
    // Check if user only has OAuth (no password)
    if (!user.password) {
      return res.status(401).json({ error: 'Please sign in with Google' });
    }
    
    if (!(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    req.session.userId = user.id;
    res.json({ success: true, user: { id: user.id, name: user.name, email: user.email, is_babysitter: user.is_babysitter } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

app.get('/api/me', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id, email, name, is_babysitter FROM users WHERE id = ?').get(req.session.userId);
  const profile = db.prepare('SELECT * FROM babysitter_profiles WHERE user_id = ?').get(req.session.userId);
  res.json({ user, profile });
});

// ============ BABYSITTER PROFILE ROUTES ============

app.post('/api/babysitter-profile', requireAuth, (req, res) => {
  try {
    const { bio, experience, certifications, hourly_rate, age_range, availability } = req.body;
    
    // Update user to be a babysitter
    db.prepare('UPDATE users SET is_babysitter = 1 WHERE id = ?').run(req.session.userId);
    
    // Upsert profile
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

// ============ CONNECTION ROUTES ============

app.get('/api/connections', requireAuth, (req, res) => {
  const connections = db.prepare(`
    SELECT c.*, 
           u1.name as user1_name, u1.email as user1_email,
           u2.name as user2_name, u2.email as user2_email
    FROM connections c
    JOIN users u1 ON c.user1_id = u1.id
    JOIN users u2 ON c.user2_id = u2.id
    WHERE (c.user1_id = ? OR c.user2_id = ?) AND c.status = 'accepted'
  `).all(req.session.userId, req.session.userId);
  
  // Transform to show the "other" person
  const result = connections.map(c => ({
    id: c.id,
    friend: c.user1_id === req.session.userId 
      ? { id: c.user2_id, name: c.user2_name, email: c.user2_email }
      : { id: c.user1_id, name: c.user1_name, email: c.user1_email },
    relationship_type: c.relationship_type
  }));
  
  res.json(result);
});

app.get('/api/connection-requests', requireAuth, (req, res) => {
  const requests = db.prepare(`
    SELECT c.*, u.name, u.email
    FROM connections c
    JOIN users u ON c.user1_id = u.id
    WHERE c.user2_id = ? AND c.status = 'pending'
  `).all(req.session.userId);
  res.json(requests);
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
    
    // Check if connection exists
    const existing = db.prepare(`
      SELECT * FROM connections 
      WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
    `).get(req.session.userId, friend.id, friend.id, req.session.userId);
    
    if (existing) {
      return res.status(400).json({ error: 'Connection already exists' });
    }
    
    db.prepare('INSERT INTO connections (user1_id, user2_id, relationship_type, status) VALUES (?, ?, ?, ?)')
      .run(req.session.userId, friend.id, relationship_type || 'friend', 'pending');
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/connections/:id/accept', requireAuth, (req, res) => {
  try {
    const result = db.prepare('UPDATE connections SET status = ? WHERE id = ? AND user2_id = ?')
      .run('accepted', req.params.id, req.session.userId);
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'Request not found' });
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ VOUCH ROUTES ============

app.post('/api/vouch', requireAuth, (req, res) => {
  try {
    const { babysitter_id, relationship, times_used, recommendation } = req.body;
    
    // Verify babysitter exists and is a babysitter
    const babysitter = db.prepare('SELECT * FROM users WHERE id = ? AND is_babysitter = 1').get(babysitter_id);
    if (!babysitter) {
      return res.status(404).json({ error: 'Babysitter not found' });
    }
    
    // Upsert vouch
    const existing = db.prepare('SELECT id FROM vouches WHERE voucher_id = ? AND babysitter_id = ?')
      .get(req.session.userId, babysitter_id);
    
    if (existing) {
      db.prepare('UPDATE vouches SET relationship=?, times_used=?, recommendation=? WHERE id=?')
        .run(relationship, times_used, recommendation, existing.id);
    } else {
      db.prepare('INSERT INTO vouches (voucher_id, babysitter_id, relationship, times_used, recommendation) VALUES (?,?,?,?,?)')
        .run(req.session.userId, babysitter_id, relationship, times_used, recommendation);
    }
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ BROWSE BABYSITTERS ============

app.get('/api/babysitters', requireAuth, (req, res) => {
  const userId = req.session.userId;
  
  // Get 1st degree connections
  const firstDegree = db.prepare(`
    SELECT CASE WHEN user1_id = ? THEN user2_id ELSE user1_id END as friend_id
    FROM connections
    WHERE (user1_id = ? OR user2_id = ?) AND status = 'accepted'
  `).all(userId, userId, userId).map(r => r.friend_id);
  
  if (firstDegree.length === 0) {
    return res.json([]);
  }
  
  // Get 2nd degree connections (friends of friends)
  const secondDegree = new Set();
  for (const friendId of firstDegree) {
    const fof = db.prepare(`
      SELECT CASE WHEN user1_id = ? THEN user2_id ELSE user1_id END as friend_id
      FROM connections
      WHERE (user1_id = ? OR user2_id = ?) AND status = 'accepted'
    `).all(friendId, friendId, friendId);
    fof.forEach(r => {
      if (r.friend_id !== userId && !firstDegree.includes(r.friend_id)) {
        secondDegree.add(r.friend_id);
      }
    });
  }
  
  const networkIds = [...firstDegree, ...secondDegree];
  
  // Get babysitters vouched for by people in network
  const babysitters = db.prepare(`
    SELECT DISTINCT 
      u.id, u.name, u.email,
      bp.bio, bp.experience, bp.certifications, bp.hourly_rate, bp.age_range, bp.availability
    FROM users u
    JOIN babysitter_profiles bp ON u.id = bp.user_id
    JOIN vouches v ON u.id = v.babysitter_id
    WHERE v.voucher_id IN (${networkIds.map(() => '?').join(',')})
  `).all(...networkIds);
  
  // Add trust chain info for each babysitter
  const result = babysitters.map(sitter => {
    // Get all vouches for this sitter from people in your network
    const vouches = db.prepare(`
      SELECT v.*, u.name as voucher_name
      FROM vouches v
      JOIN users u ON v.voucher_id = u.id
      WHERE v.babysitter_id = ?
    `).all(sitter.id);
    
    // Build trust chains
    const trustChains = vouches.map(vouch => {
      if (firstDegree.includes(vouch.voucher_id)) {
        return {
          degree: 1,
          path: `Your ${vouch.relationship || 'friend'} ${vouch.voucher_name} vouched for them`,
          vouch
        };
      } else {
        // Find the friend who knows the voucher
        for (const friendId of firstDegree) {
          const isFriend = db.prepare(`
            SELECT 1 FROM connections 
            WHERE ((user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?))
            AND status = 'accepted'
          `).get(friendId, vouch.voucher_id, vouch.voucher_id, friendId);
          
          if (isFriend) {
            const friendName = db.prepare('SELECT name FROM users WHERE id = ?').get(friendId).name;
            return {
              degree: 2,
              path: `Your friend ${friendName} knows ${vouch.voucher_name} who vouched for them`,
              vouch
            };
          }
        }
        return null;
      }
    }).filter(Boolean);
    
    return {
      ...sitter,
      trustChains,
      vouchCount: vouches.length,
      closestConnection: trustChains.length > 0 ? Math.min(...trustChains.map(t => t.degree)) : null
    };
  });
  
  // Sort by closest connection
  result.sort((a, b) => (a.closestConnection || 99) - (b.closestConnection || 99));
  
  res.json(result);
});

app.get('/api/babysitters/:id', requireAuth, (req, res) => {
  const sitter = db.prepare(`
    SELECT u.id, u.name, u.email,
           bp.bio, bp.experience, bp.certifications, bp.hourly_rate, bp.age_range, bp.availability
    FROM users u
    JOIN babysitter_profiles bp ON u.id = bp.user_id
    WHERE u.id = ?
  `).get(req.params.id);
  
  if (!sitter) {
    return res.status(404).json({ error: 'Babysitter not found' });
  }
  
  const vouches = db.prepare(`
    SELECT v.*, u.name as voucher_name, u.email as voucher_email
    FROM vouches v
    JOIN users u ON v.voucher_id = u.id
    WHERE v.babysitter_id = ?
  `).all(req.params.id);
  
  res.json({ ...sitter, vouches });
});

// Get all users (for finding people to connect with)
app.get('/api/users/search', requireAuth, (req, res) => {
  const { q } = req.query;
  if (!q || q.length < 2) {
    return res.json([]);
  }
  
  const users = db.prepare(`
    SELECT id, name, email, is_babysitter FROM users 
    WHERE (name LIKE ? OR email LIKE ?) AND id != ?
    LIMIT 10
  `).all(`%${q}%`, `%${q}%`, req.session.userId);
  
  res.json(users);
});

// ============ SEED DATA ENDPOINT ============

app.post('/api/seed', async (req, res) => {
  const { secret } = req.body;
  
  // Require a secret to prevent accidental seeding
  if (secret !== (process.env.SEED_SECRET || 'demo-seed-secret')) {
    return res.status(401).json({ error: 'Invalid seed secret' });
  }
  
  try {
    // Check if already seeded
    const existingUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();
    if (existingUsers.count > 0) {
      return res.json({ 
        success: false, 
        message: 'Database already has users',
        userCount: existingUsers.count
      });
    }
    
    // Run the seed inline
    const hashedPassword = await bcrypt.hash('password123', 10);
    
    // Parents
    const parents = [
      { email: 'sarah.mitchell@email.com', name: 'Sarah Mitchell' },
      { email: 'mike.chen@email.com', name: 'Mike Chen' },
      { email: 'jessica.rodriguez@email.com', name: 'Jessica Rodriguez' },
      { email: 'david.thompson@email.com', name: 'David Thompson' },
      { email: 'amanda.wilson@email.com', name: 'Amanda Wilson' },
      { email: 'ryan.patel@email.com', name: 'Ryan Patel' },
      { email: 'melissa.kim@email.com', name: 'Melissa Kim' },
      { email: 'chris.johnson@email.com', name: 'Chris Johnson' },
      { email: 'laura.garcia@email.com', name: 'Laura Garcia' },
      { email: 'tom.nguyen@email.com', name: 'Tom Nguyen' },
    ];
    
    const parentIds = {};
    for (const parent of parents) {
      const result = db.prepare('INSERT INTO users (email, password, name, is_babysitter) VALUES (?, ?, ?, 0)')
        .run(parent.email, hashedPassword, parent.name);
      parentIds[parent.name] = result.lastInsertRowid;
    }
    
    // Babysitters
    const babysitters = [
      { email: 'emma.davis@email.com', name: 'Emma Davis', bio: 'Hi! I\'m Emma, a junior at State University majoring in Elementary Education.', experience: '6 years babysitting', certifications: 'CPR & First Aid certified', hourly_rate: 18, age_range: 'Infants to 12 years', availability: 'Weekday evenings, weekends' },
      { email: 'jake.martinez@email.com', name: 'Jake Martinez', bio: 'High school senior and older brother to three siblings.', experience: '4 years', certifications: 'CPR certified', hourly_rate: 15, age_range: '3-14 years', availability: 'Weekends, holidays' },
      { email: 'olivia.brown@email.com', name: 'Olivia Brown', bio: 'Former preschool teacher assistant, fluent in Spanish!', experience: '5 years', certifications: 'CPR, CDA', hourly_rate: 22, age_range: 'Infants to 6 years', availability: 'Mon/Wed/Fri, Saturday' },
      { email: 'noah.taylor@email.com', name: 'Noah Taylor', bio: 'College freshman home for the summer!', experience: '3 years', certifications: 'CPR certified', hourly_rate: 16, age_range: '5-12 years', availability: 'Flexible' },
      { email: 'sophia.lee@email.com', name: 'Sophia Lee', bio: 'Music education student who loves incorporating songs!', experience: '4 years', certifications: 'CPR, Special Needs Training', hourly_rate: 20, age_range: 'All ages', availability: 'Tues/Thurs, Sundays' },
      { email: 'lily.anderson@email.com', name: 'Lily Anderson', bio: 'High school junior, big sister to twins!', experience: '3 years', certifications: 'CPR certified', hourly_rate: 14, age_range: '2-10 years', availability: 'Weekends' },
    ];
    
    const babysitterIds = {};
    for (const s of babysitters) {
      const result = db.prepare('INSERT INTO users (email, password, name, is_babysitter) VALUES (?, ?, ?, 1)')
        .run(s.email, hashedPassword, s.name);
      babysitterIds[s.name] = result.lastInsertRowid;
      db.prepare('INSERT INTO babysitter_profiles (user_id, bio, experience, certifications, hourly_rate, age_range, availability) VALUES (?,?,?,?,?,?,?)')
        .run(result.lastInsertRowid, s.bio, s.experience, s.certifications, s.hourly_rate, s.age_range, s.availability);
    }
    
    // Connections
    const connections = [
      ['Sarah Mitchell', 'Mike Chen', 'neighbor'],
      ['Sarah Mitchell', 'Jessica Rodriguez', 'friend'],
      ['Sarah Mitchell', 'Amanda Wilson', 'neighbor'],
      ['Mike Chen', 'David Thompson', 'coworker'],
      ['Mike Chen', 'Ryan Patel', 'friend'],
      ['Jessica Rodriguez', 'Melissa Kim', 'friend'],
      ['Jessica Rodriguez', 'Laura Garcia', 'neighbor'],
      ['David Thompson', 'Chris Johnson', 'neighbor'],
      ['Amanda Wilson', 'Tom Nguyen', 'neighbor'],
      ['Ryan Patel', 'Melissa Kim', 'friend'],
      ['Chris Johnson', 'Laura Garcia', 'friend'],
      ['Tom Nguyen', 'Ryan Patel', 'coworker'],
      ['Melissa Kim', 'Amanda Wilson', 'friend'],
      ['Laura Garcia', 'Tom Nguyen', 'neighbor'],
    ];
    
    for (const [n1, n2, rel] of connections) {
      db.prepare('INSERT INTO connections (user1_id, user2_id, relationship_type, status) VALUES (?,?,?,?)')
        .run(parentIds[n1], parentIds[n2], rel, 'accepted');
    }
    
    // Vouches
    const vouches = [
      { voucher: 'Sarah Mitchell', babysitter: 'Emma Davis', relationship: 'neighbor 5 years', times_used: 30, recommendation: 'Emma is absolutely wonderful!' },
      { voucher: 'Mike Chen', babysitter: 'Jake Martinez', relationship: 'son\'s teammate\'s brother', times_used: 12, recommendation: 'Great with active boys.' },
      { voucher: 'Jessica Rodriguez', babysitter: 'Olivia Brown', relationship: 'former preschool assistant', times_used: 8, recommendation: 'Amazing with toddlers!' },
      { voucher: 'Amanda Wilson', babysitter: 'Emma Davis', relationship: 'neighbor', times_used: 15, recommendation: 'My kids ask for her by name!' },
      { voucher: 'David Thompson', babysitter: 'Noah Taylor', relationship: 'neighborhood kid', times_used: 6, recommendation: 'Very responsible.' },
      { voucher: 'Ryan Patel', babysitter: 'Sophia Lee', relationship: 'friend\'s daughter', times_used: 10, recommendation: 'Fantastic with ADHD kids!' },
      { voucher: 'Melissa Kim', babysitter: 'Olivia Brown', relationship: 'via Jessica', times_used: 4, recommendation: 'Speaks Spanish with my kids!' },
      { voucher: 'Chris Johnson', babysitter: 'Jake Martinez', relationship: 'neighbor', times_used: 8, recommendation: 'Reliable and fun!' },
      { voucher: 'Laura Garcia', babysitter: 'Lily Anderson', relationship: 'school connection', times_used: 5, recommendation: 'Great with twins!' },
      { voucher: 'Tom Nguyen', babysitter: 'Noah Taylor', relationship: 'neighborhood', times_used: 4, recommendation: 'Very trustworthy!' },
    ];
    
    for (const v of vouches) {
      db.prepare('INSERT INTO vouches (voucher_id, babysitter_id, relationship, times_used, recommendation) VALUES (?,?,?,?,?)')
        .run(parentIds[v.voucher], babysitterIds[v.babysitter], v.relationship, v.times_used, v.recommendation);
    }
    
    res.json({ 
      success: true, 
      message: 'Database seeded successfully',
      created: {
        parents: parents.length,
        babysitters: babysitters.length,
        connections: connections.length,
        vouches: vouches.length
      },
      demoLogin: {
        email: 'sarah.mitchell@email.com',
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
  console.log(`🍼 Babysitter Network running on port ${PORT}`);
});
