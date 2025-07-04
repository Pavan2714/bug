# Google Sign-In Setup Guide

This guide will help you set up Google Sign-In for your YOLOv11 project.

## Prerequisites

1. A Google account
2. Access to Google Cloud Console

## Step 1: Create a Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Make sure the project is selected in the top navigation

## Step 2: Enable Google+ API

1. In the Google Cloud Console, go to "APIs & Services" > "Library"
2. Search for "Google+ API" or "Google Identity"
3. Click on it and press "Enable"

## Step 3: Create OAuth 2.0 Credentials

1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth 2.0 Client IDs"
3. If prompted, configure the OAuth consent screen first:

   - Choose "External" user type
   - Fill in the required information (App name, User support email, Developer contact information)
   - Add scopes: `email`, `profile`, `openid`
   - Add test users if needed
   - Save and continue

4. Create the OAuth 2.0 Client ID:

   - Application type: "Web application"
   - Name: "YOLOv11 Web Client"
   - Authorized JavaScript origins:
     - `http://localhost:4000` (for development)
     - `https://yourdomain.com` (for production)
   - Authorized redirect URIs:
     - `http://localhost:4000/google-callback` (for development)
     - `https://yourdomain.com/google-callback` (for production)
   - Click "Create"

5. Copy the Client ID and Client Secret

## Step 4: Configure Environment Variables

1. Copy `env_example.txt` to `.env`
2. Update the following variables in your `.env` file:

```env
GOOGLE_CLIENT_ID=your-google-client-id-here
GOOGLE_CLIENT_SECRET=your-google-client-secret-here
```

## Step 5: Install Dependencies

The required packages should already be installed, but if not:

```bash
python3 -m pip install google-auth google-auth-oauthlib google-auth-httplib2 requests
```

## Step 6: Test the Integration

1. Start your Flask application:

```bash
python3 webapp.py
```

2. Navigate to `http://localhost:4000/login-new`
3. You should see a "Sign in with Google" button
4. Click it and test the authentication flow

## Troubleshooting

### Common Issues:

1. **"Invalid client" error**: Make sure your Client ID is correct and the domain is authorized
2. **"Redirect URI mismatch"**: Ensure the redirect URI in Google Console matches your application URL
3. **"API not enabled"**: Make sure Google+ API is enabled in your Google Cloud project

### Development vs Production:

- For development: Use `http://localhost:4000`
- For production: Use your actual domain with HTTPS
- Update the authorized origins and redirect URIs in Google Cloud Console accordingly

## Security Notes

1. Never commit your `.env` file to version control
2. Keep your Client Secret secure
3. Use HTTPS in production
4. Regularly rotate your credentials

## Additional Features

The Google Sign-In integration includes:

- Automatic user creation for new Google users
- Profile picture import from Google
- Seamless login/signup flow
- Session management with Flask-Login
