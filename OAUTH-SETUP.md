# Google OAuth Setup Guide

This guide helps you set up Google OAuth for the Babysitter Network app.

## Prerequisites

You need a Google Cloud Console account and project.

## Step 1: Create OAuth Credentials

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select an existing one
3. Navigate to **APIs & Services** → **Credentials**
4. Click **Create Credentials** → **OAuth client ID**
5. If prompted, configure the OAuth consent screen:
   - User Type: **External**
   - App name: **Babysitter Network**
   - User support email: Your email
   - Developer contact: Your email
   - Click **Save and Continue** through all steps

## Step 2: Configure OAuth Client

1. Application type: **Web application**
2. Name: **Babysitter Network**
3. Authorized JavaScript origins:
   ```
   http://localhost:3000
   https://your-railway-domain.up.railway.app
   ```
4. Authorized redirect URIs:
   ```
   http://localhost:3000/auth/google/callback
   https://your-railway-domain.up.railway.app/auth/google/callback
   ```
5. Click **Create**
6. Copy the **Client ID** and **Client Secret**

## Step 3: Configure Environment Variables

### Local Development

Create a `.env` file (don't commit this!):

```bash
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-secret-here
```

Or export them:

```bash
export GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
export GOOGLE_CLIENT_SECRET=GOCSPX-your-secret-here
npm run dev
```

### Railway Deployment

In Railway dashboard:
1. Go to your service → **Variables**
2. Add:
   - `GOOGLE_CLIENT_ID` = your client ID
   - `GOOGLE_CLIENT_SECRET` = your secret

Railway auto-sets `RAILWAY_PUBLIC_DOMAIN`, so the callback URL is automatically configured.

## Step 4: Test

1. Start the app: `npm run dev`
2. Visit http://localhost:3000
3. You should see "Sign in with Google" button
4. Click it and complete the OAuth flow

## Troubleshooting

### "redirect_uri_mismatch" Error
Add the exact redirect URI to your OAuth app settings:
- `http://localhost:3000/auth/google/callback` (local)
- `https://your-domain.up.railway.app/auth/google/callback` (prod)

### Google button not appearing
Check server logs for "Google OAuth configured" message. If you see the warning about missing credentials, the environment variables aren't set correctly.

### "Access blocked: This app's request is invalid"
Make sure your OAuth consent screen is configured and the app is not in testing mode (or add your test email to the test users list).

## Sharing OAuth Credentials

You can use the same Google OAuth credentials for multiple apps (e.g., Prayer App and Babysitter Network) as long as you add all the redirect URIs to the same OAuth client.

Just add both redirect URIs:
```
https://prayerapp-production.up.railway.app/_oauth/google
https://babysitter-network.up.railway.app/auth/google/callback
```

Note: Different frameworks use different callback paths:
- Meteor: `/_oauth/google`
- Express/Passport: `/auth/google/callback`
