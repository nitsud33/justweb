# Pokemon Card Finder - Feature Research Report

**Date:** January 29, 2026  
**Purpose:** Identify high-traffic features to add to our Pokemon Card Finder web app

---

## Current App Features
Our existing app has:
- ✅ Card search (Pokemon TCG API)
- ✅ User authentication (email + Google OAuth)
- ✅ Collection tracking (quantity, condition, purchase price)
- ✅ Want list with priority levels
- ✅ Basic set browsing
- ✅ Card caching for performance

---

## Market Research Summary

### Top Competitors Analyzed
| Platform | Strengths | Weaknesses |
|----------|-----------|------------|
| **pkmn.gg** | Best-in-class UX, gamification, friend system, deck builder | Crowded space |
| **Dex (dextcg.com)** | Multi-marketplace prices, beautiful iOS app | iOS-focused |
| **TCGPlayer** | Definitive price source, marketplace | No set completion tracking |
| **Pokellector** | Simple set checklists, good mobile app | Poor price accuracy |
| **Collectr** | Portfolio-style tracking, trend charts | Weak condition tracking |
| **PriceCharting** | Historical price data, graded prices | No collection features |
| **PokeData/PokemonPriceTracker** | Investment focus, ROI calculators | Complex for casual users |

---

## Top 10 Feature Ideas (Ranked)

### 🥇 1. Set Completion Tracker with Progress Bars
**Traffic Potential:** ⭐⭐⭐⭐⭐  
**Feasibility:** ⭐⭐⭐⭐⭐  
**Competitive Advantage:** ⭐⭐⭐⭐

Collectors are OBSESSED with completing sets. Show:
- Visual progress bars per set
- "X of Y cards" collected
- Missing cards list with quick-add to want list
- Percentage completion badges
- "Cards needed to complete" cost calculator

**Why it wins:** This is the #1 requested feature in Reddit threads. Pokellector has it, but with poor pricing. Collectr has pricing but no set tracking. We can do both.

---

### 🥈 2. Price History Charts
**Traffic Potential:** ⭐⭐⭐⭐⭐  
**Feasibility:** ⭐⭐⭐⭐  
**Competitive Advantage:** ⭐⭐⭐⭐

Show historical price trends for each card:
- 7-day, 30-day, 90-day, 1-year views
- Price alerts when cards hit target price
- "Best time to buy" indicators
- Collection value over time chart

**Data source:** TCGPlayer API or scrape PriceCharting

---

### 🥉 3. Portfolio Value Dashboard
**Traffic Potential:** ⭐⭐⭐⭐⭐  
**Feasibility:** ⭐⭐⭐⭐⭐  
**Competitive Advantage:** ⭐⭐⭐⭐

Investment-focused dashboard showing:
- Total collection value (like a stock portfolio)
- Daily/weekly/monthly gains/losses
- Top gainers and losers in your collection
- "If you sold today" calculator
- ROI on purchase price vs current value

**Why it wins:** The r/PokeInvesting crowd is MASSIVE. They want stock-market-style tools for their cards.

---

### 4. Friend System & Collection Sharing
**Traffic Potential:** ⭐⭐⭐⭐  
**Feasibility:** ⭐⭐⭐⭐  
**Competitive Advantage:** ⭐⭐⭐⭐⭐

Social features drive engagement:
- Public/private collection profiles
- Shareable collection links (no login required to view)
- "Compare collections" to find trade opportunities
- Friend activity feed
- Leaderboards (most valuable collection, most complete sets)

---

### 5. Trade Matching System
**Traffic Potential:** ⭐⭐⭐⭐⭐  
**Feasibility:** ⭐⭐⭐  
**Competitive Advantage:** ⭐⭐⭐⭐⭐

**THE killer feature no one does well:**
- Match your want list with other users' collections
- Match your duplicates with others' want lists  
- "You have what they want, they have what you want" alerts
- Direct messaging or trade proposals

**Why it wins:** This is the most requested feature in Pokemon forums. PTCGP (Pokemon TCG Pocket) just added wishlist matching and users are LOVING it.

---

### 6. PSA Grading ROI Calculator
**Traffic Potential:** ⭐⭐⭐⭐  
**Feasibility:** ⭐⭐⭐⭐  
**Competitive Advantage:** ⭐⭐⭐⭐

Help users decide if grading is worth it:
- Input: card + estimated condition
- Output: Expected PSA grade, graded value, grading cost, net profit
- "Worth grading?" recommendation
- Population data (how many PSA 10s exist)

---

### 7. Deck Builder with Validation
**Traffic Potential:** ⭐⭐⭐⭐  
**Feasibility:** ⭐⭐⭐  
**Competitive Advantage:** ⭐⭐⭐

For competitive players:
- Build decks from your collection
- Format validation (Standard, Expanded, Unlimited)
- "Missing cards" to complete deck
- Share/export decks
- Test hands feature

---

### 8. Price Alerts & Notifications
**Traffic Potential:** ⭐⭐⭐⭐  
**Feasibility:** ⭐⭐⭐⭐  
**Competitive Advantage:** ⭐⭐⭐

- Alert when want list card drops below max price
- Alert when owned card spikes in value
- Restock alerts for sealed products
- Email or browser push notifications

---

### 9. Booster Box EV Calculator
**Traffic Potential:** ⭐⭐⭐⭐  
**Feasibility:** ⭐⭐⭐  
**Competitive Advantage:** ⭐⭐⭐⭐

Calculate expected value of opening vs. holding sealed:
- Pull rates × card values = Expected Value
- Compare EV to box price
- Historical EV trends
- "Best box to open right now"

---

### 10. Virtual Binder Display
**Traffic Potential:** ⭐⭐⭐  
**Feasibility:** ⭐⭐⭐⭐  
**Competitive Advantage:** ⭐⭐⭐

Visual binder pages showing your collection:
- 9-pocket page layout
- Drag-and-drop organization
- Custom binder themes
- Shareable binder links
- "Community Showcase" gallery

---

## Recommended MVP Additions (Phase 1)

These can be added quickly with high impact:

### 1. ⭐ Set Completion Tracker (2-3 days)
```
- Fetch all cards in a set from API
- Compare against user's collection
- Show progress bar and missing cards list
- Add "Complete this set" cost calculator
```

### 2. ⭐ Portfolio Value Dashboard (1-2 days)
```
- Sum collection values
- Show daily change (cache yesterday's prices)
- Top 5 most valuable cards
- Simple pie chart by set
```

### 3. ⭐ Shareable Collection Links (1 day)
```
- Generate public URL for collection
- No auth required to view
- Nice meta tags for social sharing
```

### 4. ⭐ Price Charts (2 days)
```
- Store price history in DB
- Chart.js or similar for visualization
- 7/30/90 day views
```

### 5. ⭐ Duplicate Tracker (0.5 days)
```
- Show cards where quantity > 1
- Calculate trade bait value
- Quick-export as trade list
```

---

## Phase 2 Features (Bigger Builds)

### Trade Matching System (1-2 weeks)
- Complex database queries
- User matching algorithm
- Messaging system
- This is the BIG differentiator

### PSA Grading Calculator (1 week)
- Need graded price data (scrape or API)
- Condition input form
- ROI calculations

### Deck Builder (2 weeks)
- Complex card limit rules
- Format validation
- Export to PTCGL

### Price Alerts (1 week)
- Background job system
- Email/push notification service
- User preferences

---

## Key User Pain Points (From Reddit Research)

1. **"No app does it all"** - Users juggle 2-3 apps. Be the one-stop shop.
2. **"Can't track card condition properly"** - We already handle this!
3. **"Prices are inaccurate"** - Use TCGPlayer as source of truth
4. **"No set completion tracking"** - Add this ASAP
5. **"Can't share my collection easily"** - Public profiles needed
6. **"Language support for international cards"** - Nice to have
7. **"Finding people to trade with is hard"** - Trade matching = killer feature

---

## Data Sources to Integrate

| Source | Data | Cost |
|--------|------|------|
| **Pokemon TCG API** | Card data, images | Free |
| **TCGPlayer API** | Market prices | Free tier available |
| **PriceCharting** | Historical prices, PSA data | Scraping (TOS?) |
| **eBay API** | Sold listings | Free |

---

## Quick Wins for Traffic

1. **SEO Landing Pages** - "/sets/base-set", "/cards/charizard" with proper meta tags
2. **Share to Twitter/Reddit** - Easy share buttons for rare pulls
3. **Set Release Alerts** - Email when new sets drop
4. **Reddit Bot** - Price check bot in r/PokemonTCG (drives traffic)

---

## Conclusion

**Immediate priorities:**
1. Set Completion Tracker - THE most requested feature
2. Portfolio Dashboard - Appeals to investor crowd
3. Shareable Collections - Viral potential
4. Price History - Keeps users coming back

**Long-term differentiator:**
- Trade Matching System - No one does this well. First mover advantage.

The Pokemon card market is BOOMING (2024-2025 surge noted in research). Users are frustrated with fragmented tools. A polished all-in-one web app can capture significant market share.

---

*Research compiled from: TCGPlayer, pkmn.gg, Dex, Pokellector, PriceCharting, PokeData, Reddit (r/PokemonTCG, r/pokemoncardcollectors, r/PokeInvesting), and Pokemon community forums.*
