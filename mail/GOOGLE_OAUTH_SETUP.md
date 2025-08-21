# Google OAuth 2.0 Setup Guide

This guide will help you set up Google OAuth 2.0 credentials to enable Gmail integration in your Mail Management System.

## Prerequisites

- A Google account
- Access to Google Cloud Console
- Basic understanding of OAuth 2.0

## Step 1: Create a Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Click on the project dropdown at the top
3. Click "New Project"
4. Enter a project name (e.g., "Mail Management System")
5. Click "Create"

## Step 2: Enable Gmail API

1. In your new project, go to "APIs & Services" > "Library"
2. Search for "Gmail API"
3. Click on "Gmail API" and then "Enable"

## Step 3: Create OAuth 2.0 Credentials

1. Go to "APIs & Services" > "Credentials"
2. Click "Create Credentials" > "OAuth 2.0 Client IDs"
3. If prompted, configure the OAuth consent screen first:
   - Choose "External" user type
   - Fill in the required fields:
     - App name: "Mail Management System"
     - User support email: Your email
     - Developer contact information: Your email
   - Add scopes:
     - `https://www.googleapis.com/auth/gmail.readonly`
     - `https://www.googleapis.com/auth/userinfo.email`
     - `https://www.googleapis.com/auth/userinfo.profile`
   - Add test users (your email address)
   - Save and continue

4. Back to creating OAuth 2.0 Client ID:
   - Application type: "Web application"
   - Name: "Mail Management System Web Client"
   - Authorized redirect URIs: `http://localhost:5000/oauth2callback`
   - Click "Create"

5. Copy the Client ID and Client Secret (you'll need these)

## Step 4: Configure Your Application

1. **Option A: Environment Variables (Recommended)**
   ```bash
   # Windows
   set GOOGLE_CLIENT_ID=your-client-id-here
   set GOOGLE_CLIENT_SECRET=your-client-secret-here
   
   # macOS/Linux
   export GOOGLE_CLIENT_ID=your-client-id-here
   export GOOGLE_CLIENT_SECRET=your-client-secret-here
   ```

2. **Option B: Update config.py directly**
   ```python
   # In config.py, replace the placeholder values:
   GOOGLE_CLIENT_ID = 'your-actual-client-id'
   GOOGLE_CLIENT_SECRET = 'your-actual-client-secret'
   ```

## Step 5: Test the Integration

1. Start your application: `python app.py`
2. Register/login to your account
3. Go to "Add Email Account"
4. Click "Sign in with Google"
5. Complete the OAuth flow
6. Your Gmail account should now be connected!

## Security Best Practices

### 1. Never Commit Credentials
- Keep your `client_secret` secure
- Use environment variables in production
- Add `config.py` to `.gitignore` if storing credentials there

### 2. Restrict OAuth Scopes
- Only request the scopes you need
- `gmail.readonly` is sufficient for reading emails
- Don't request `gmail.modify` unless you need to send/delete emails

### 3. Production Considerations
- Use HTTPS in production
- Update redirect URIs for your production domain
- Implement proper error handling
- Add rate limiting

## Troubleshooting

### Common Issues

1. **"redirect_uri_mismatch" Error**
   - Ensure the redirect URI in Google Console matches exactly
   - Check for trailing slashes or protocol differences

2. **"invalid_client" Error**
   - Verify your Client ID and Client Secret
   - Check that credentials are properly set in environment/config

3. **"access_denied" Error**
   - User may have denied permission
   - Check OAuth consent screen configuration
   - Ensure test users are added if in testing mode

4. **"invalid_grant" Error**
   - Authorization code may have expired
   - Try the OAuth flow again

### Debug Mode

Enable debug logging in your Flask app:
```python
app.run(debug=True)
```

Check the console for detailed error messages during OAuth flow.

## OAuth Flow Explanation

1. **User clicks "Sign in with Google"**
   - App generates OAuth authorization URL
   - User is redirected to Google's consent screen

2. **Google consent screen**
   - Shows what permissions your app requests
   - User can allow or deny access

3. **Authorization callback**
   - Google redirects back with authorization code
   - App exchanges code for access/refresh tokens

4. **Token storage**
   - Access token (short-lived, for API calls)
   - Refresh token (long-lived, for getting new access tokens)

5. **Gmail API access**
   - App uses access token to fetch emails
   - Automatically refreshes expired tokens

## API Quotas and Limits

- Gmail API has daily quotas
- Default: 1 billion queries per day per user
- Monitor usage in Google Cloud Console
- Implement caching for better performance

## Next Steps

Once OAuth is working:
1. Add email caching to reduce API calls
2. Implement error handling for expired tokens
3. Add support for other email providers (Outlook, Yahoo)
4. Consider implementing webhook notifications for new emails

## Support

- [Google OAuth 2.0 Documentation](https://developers.google.com/identity/protocols/oauth2)
- [Gmail API Documentation](https://developers.google.com/gmail/api)
- [Google Cloud Console](https://console.cloud.google.com/)

---

**Note**: This setup is for development/testing. For production use, ensure proper security measures, HTTPS, and production-grade hosting.
