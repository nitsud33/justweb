#!/usr/bin/env node
/**
 * Seed script for Babysitter Network
 * Creates realistic mock data to showcase the trust chain feature
 */

const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'babysitter.db');
const db = new Database(dbPath);

// Ensure schema exists
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT,
    name TEXT NOT NULL,
    is_babysitter INTEGER DEFAULT 0,
    google_id TEXT,
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

async function seed() {
  console.log('🌱 Seeding Babysitter Network database...\n');

  // Check if already seeded
  const existingUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (existingUsers.count > 0) {
    console.log('⚠️  Database already has users. Skipping seed to avoid duplicates.');
    console.log('   To reseed, delete babysitter.db first.\n');
    return;
  }

  const hashedPassword = await bcrypt.hash('password123', 10);

  // ============ CREATE PARENTS (Users in a neighborhood) ============
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

  console.log('👨‍👩‍👧 Creating parent accounts...');
  const parentIds = {};
  for (const parent of parents) {
    const result = db.prepare('INSERT INTO users (email, password, name, is_babysitter) VALUES (?, ?, ?, 0)')
      .run(parent.email, hashedPassword, parent.name);
    parentIds[parent.name] = result.lastInsertRowid;
    console.log(`   ✓ ${parent.name}`);
  }

  // ============ CREATE BABYSITTERS ============
  const babysitters = [
    {
      email: 'emma.davis@email.com',
      name: 'Emma Davis',
      profile: {
        bio: 'Hi! I\'m Emma, a junior at State University majoring in Elementary Education. I\'ve been babysitting since I was 14 and absolutely love kids! I\'m patient, creative, and always come prepared with fun activities.',
        experience: '6 years babysitting, volunteered at summer camp for 2 years',
        certifications: 'CPR & First Aid certified, Red Cross Babysitting Certificate',
        hourly_rate: 18,
        age_range: 'Infants to 12 years',
        availability: 'Weekday evenings after 5pm, weekends flexible'
      }
    },
    {
      email: 'jake.martinez@email.com',
      name: 'Jake Martinez',
      profile: {
        bio: 'I\'m Jake, a high school senior and older brother to three younger siblings. I know all the best games and can help with homework too! Great with energetic kids - I played varsity soccer for 3 years.',
        experience: '4 years with siblings, 2 years neighborhood babysitting',
        certifications: 'CPR certified',
        hourly_rate: 15,
        age_range: '3-14 years',
        availability: 'Weekends, school holidays'
      }
    },
    {
      email: 'olivia.brown@email.com',
      name: 'Olivia Brown',
      profile: {
        bio: 'Former preschool teacher assistant, now pursuing my teaching degree! I specialize in early childhood development and love creating learning opportunities through play. Fluent in Spanish!',
        experience: '3 years as preschool assistant, 5 years babysitting',
        certifications: 'CPR & First Aid, Child Development Associate (CDA)',
        hourly_rate: 22,
        age_range: 'Infants to 6 years',
        availability: 'Mon/Wed/Fri afternoons, Saturday all day'
      }
    },
    {
      email: 'noah.taylor@email.com',
      name: 'Noah Taylor',
      profile: {
        bio: 'College freshman home for the summer! I grew up in this neighborhood and love being part of the community. I\'m responsible, punctual, and great at following parents\' instructions.',
        experience: '3 years babysitting in the neighborhood',
        certifications: 'CPR certified',
        hourly_rate: 16,
        age_range: '5-12 years',
        availability: 'Summer: very flexible, School year: limited'
      }
    },
    {
      email: 'sophia.lee@email.com',
      name: 'Sophia Lee',
      profile: {
        bio: 'Music education student who loves incorporating songs and creative activities into babysitting! I can also provide basic piano lessons. Patient with kids of all ages and special needs experience.',
        experience: '4 years babysitting, 2 years working with special needs children',
        certifications: 'CPR & First Aid, Special Needs Care Training',
        hourly_rate: 20,
        age_range: 'All ages',
        availability: 'Tues/Thurs evenings, Sundays'
      }
    },
    {
      email: 'lily.anderson@email.com',
      name: 'Lily Anderson',
      profile: {
        bio: 'High school junior and proud big sister to twins! I have tons of experience with multiples and managing multiple children at once. Love arts & crafts projects.',
        experience: '3 years with twin siblings, 1 year neighborhood sitting',
        certifications: 'CPR certified, Babysitting Basics course',
        hourly_rate: 14,
        age_range: '2-10 years',
        availability: 'Weekends, some weekday evenings'
      }
    }
  ];

  console.log('\n👧 Creating babysitter accounts...');
  const babysitterIds = {};
  for (const sitter of babysitters) {
    const result = db.prepare('INSERT INTO users (email, password, name, is_babysitter) VALUES (?, ?, ?, 1)')
      .run(sitter.email, hashedPassword, sitter.name);
    babysitterIds[sitter.name] = result.lastInsertRowid;
    
    db.prepare(`INSERT INTO babysitter_profiles 
      (user_id, bio, experience, certifications, hourly_rate, age_range, availability) 
      VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(
        result.lastInsertRowid,
        sitter.profile.bio,
        sitter.profile.experience,
        sitter.profile.certifications,
        sitter.profile.hourly_rate,
        sitter.profile.age_range,
        sitter.profile.availability
      );
    console.log(`   ✓ ${sitter.name} ($${sitter.profile.hourly_rate}/hr)`);
  }

  // ============ CREATE CONNECTIONS (Neighborhood network) ============
  console.log('\n🔗 Creating neighborhood connections...');
  
  const connections = [
    // Core friend group
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

  for (const [name1, name2, relationship] of connections) {
    db.prepare('INSERT INTO connections (user1_id, user2_id, relationship_type, status) VALUES (?, ?, ?, ?)')
      .run(parentIds[name1], parentIds[name2], relationship, 'accepted');
    console.log(`   ✓ ${name1} ↔ ${name2} (${relationship})`);
  }

  // ============ CREATE VOUCHES ============
  console.log('\n⭐ Creating vouches for babysitters...');

  const vouches = [
    // Emma gets great reviews from Sarah (1st degree for many users)
    {
      voucher: 'Sarah Mitchell',
      babysitter: 'Emma Davis',
      relationship: 'neighbor for 5 years, watched her grow up',
      times_used: 30,
      recommendation: 'Emma is absolutely wonderful! She\'s been our go-to sitter since she was 16. The kids adore her and she always leaves the house cleaner than she found it. Highly recommend!'
    },
    // Mike vouches for Jake
    {
      voucher: 'Mike Chen',
      babysitter: 'Jake Martinez',
      relationship: 'son\'s soccer teammate\'s brother',
      times_used: 12,
      recommendation: 'Jake is great with active boys. He\'ll actually run around and play with them instead of just putting on a movie. Very responsible for his age.'
    },
    // Jessica vouches for Olivia
    {
      voucher: 'Jessica Rodriguez',
      babysitter: 'Olivia Brown',
      relationship: 'former preschool assistant to my daughter',
      times_used: 8,
      recommendation: 'Olivia taught my daughter at Little Stars Preschool. She\'s amazing with toddlers and knows exactly how to handle tantrums. Worth every penny!'
    },
    // Amanda vouches for Emma (another vote for Emma!)
    {
      voucher: 'Amanda Wilson',
      babysitter: 'Emma Davis',
      relationship: 'lives down the street',
      times_used: 15,
      recommendation: 'We share Emma with Sarah Mitchell! She\'s the best in the neighborhood. My kids ask for her by name now.'
    },
    // David vouches for Noah
    {
      voucher: 'David Thompson',
      babysitter: 'Noah Taylor',
      relationship: 'watched him grow up in the neighborhood',
      times_used: 6,
      recommendation: 'Noah is very responsible and mature for his age. Great for school-age kids - he helps with homework and plays board games with them.'
    },
    // Ryan vouches for Sophia
    {
      voucher: 'Ryan Patel',
      babysitter: 'Sophia Lee',
      relationship: 'friend\'s daughter, known for 3 years',
      times_used: 10,
      recommendation: 'Sophia is fantastic with my son who has ADHD. She\'s patient and knows how to redirect his energy into positive activities. Also teaches him piano!'
    },
    // Melissa vouches for Olivia
    {
      voucher: 'Melissa Kim',
      babysitter: 'Olivia Brown',
      relationship: 'recommended by Jessica',
      times_used: 4,
      recommendation: 'Jessica put us in touch with Olivia and we\'re so glad! She speaks Spanish with my kids which is great for them.'
    },
    // Chris vouches for Jake
    {
      voucher: 'Chris Johnson',
      babysitter: 'Jake Martinez',
      relationship: 'neighbor',
      times_used: 8,
      recommendation: 'Jake is reliable and the kids love him. Great for date nights when you want someone energetic with the kids.'
    },
    // Laura vouches for Lily
    {
      voucher: 'Laura Garcia',
      babysitter: 'Lily Anderson',
      relationship: 'known through the school',
      times_used: 5,
      recommendation: 'Lily is great with my twins! She has twin siblings herself so she knows how to manage two at once. Very creative with arts and crafts.'
    },
    // Tom vouches for Noah
    {
      voucher: 'Tom Nguyen',
      babysitter: 'Noah Taylor',
      relationship: 'grew up in same neighborhood',
      times_used: 4,
      recommendation: 'Known Noah since he was little. Very trustworthy kid, always on time, and keeps us updated with texts.'
    },
  ];

  for (const vouch of vouches) {
    db.prepare(`INSERT INTO vouches (voucher_id, babysitter_id, relationship, times_used, recommendation) VALUES (?, ?, ?, ?, ?)`)
      .run(
        parentIds[vouch.voucher],
        babysitterIds[vouch.babysitter],
        vouch.relationship,
        vouch.times_used,
        vouch.recommendation
      );
    console.log(`   ✓ ${vouch.voucher} vouched for ${vouch.babysitter} (used ${vouch.times_used}x)`);
  }

  console.log('\n✅ Seed complete!\n');
  console.log('📊 Summary:');
  console.log(`   • ${parents.length} parents`);
  console.log(`   • ${babysitters.length} babysitters`);
  console.log(`   • ${connections.length} connections`);
  console.log(`   • ${vouches.length} vouches\n`);
  
  console.log('🔐 Demo login credentials (all accounts):');
  console.log('   Email: sarah.mitchell@email.com');
  console.log('   Password: password123\n');
  
  console.log('🔗 Trust chain examples:');
  console.log('   • Log in as Sarah → See Emma (1st degree, she vouched)');
  console.log('   • Log in as Mike → See Emma via Sarah (2nd degree)');
  console.log('   • Log in as David → See Jake via Mike (2nd degree)\n');
}

seed()
  .then(() => process.exit(0))
  .catch(err => {
    console.error('❌ Seed failed:', err);
    process.exit(1);
  });
