# 👶 Babysitter Network

**🚀 Live Demo: https://web-production-7ed07.up.railway.app/**

A trust-based babysitter recommendation app. Find babysitters through people you actually know and trust.

## The Problem
- Parents don't know who to trust for babysitting
- Anonymous reviews on apps are unreliable
- Word-of-mouth is limited to who you happen to ask

## The Solution
You only see babysitters vouched for by people in your network:
- **1st degree**: Your direct friends vouch for them
- **2nd degree**: Friends of friends vouch for them

Every recommendation shows the trust chain: *"Your neighbor Sarah vouched for this sitter"*

## Features

✅ User accounts (parents & babysitters)  
✅ **Google OAuth login** (plus email/password fallback)  
✅ Connect with friends/neighbors  
✅ Babysitter profiles  
✅ Vouch for babysitters you've used  
✅ Browse sitters in your trust network  
✅ See trust chains for every sitter  
✅ **Demo data seeding** for showcasing

## Tech Stack

- **Backend**: Node.js + Express + Passport.js
- **Database**: SQLite (embedded, no external DB needed)
- **Frontend**: Vanilla HTML/CSS/JS
- **Auth**: Google OAuth 2.0 + bcrypt passwords
- **Deploy**: Railway

## Local Development

```bash
# Install dependencies
npm install

# Seed demo data (optional)
npm run seed

# Run locally
npm start
```

Visit http://localhost:3000

### Google OAuth (Optional)

To enable Google sign-in locally:

```bash
export GOOGLE_CLIENT_ID=your-client-id
export GOOGLE_CLIENT_SECRET=your-secret
npm start
```

See [OAUTH-SETUP.md](./OAUTH-SETUP.md) for detailed instructions.

## Demo Credentials

After running `npm run seed`:

```
Email: sarah.mitchell@email.com
Password: password123
```

Other demo accounts: mike.chen@email.com, jessica.rodriguez@email.com, etc.

## Seeding in Production

You can seed the deployed database via API:

```bash
curl -X POST https://your-app.up.railway.app/api/seed \
  -H "Content-Type: application/json" \
  -d '{"secret": "demo-seed-secret"}'
```

Set `SEED_SECRET` environment variable in Railway for security.

## Trust Chain Examples

Log in as different users to see how trust chains work:

- **Sarah Mitchell** → Sees Emma Davis (1st degree - she vouched directly)
- **Mike Chen** → Sees Emma Davis (2nd degree - via neighbor Sarah)
- **David Thompson** → Sees Jake Martinez (2nd degree - via coworker Mike)

## Deployment

Push to GitHub → Railway auto-deploys from main branch.

### Environment Variables (Railway)

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLIENT_ID` | Optional | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Optional | Google OAuth secret |
| `SESSION_SECRET` | Recommended | Session encryption key |
| `SEED_SECRET` | Optional | Secret for API seeding |

---

Built for demonstrating the trust network concept 🍼
