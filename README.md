# MailPilot - AI-Powered Email Management System

A comprehensive web application for managing company emails with intelligent AI-powered filtering and categorization. This system allows users to register, manage company profiles, connect Gmail accounts via OAuth 2.0, and view intelligently filtered emails based on business relevance.

## 🚀 Features

### Core Features (Implemented)
- ✅ User registration and authentication
- ✅ Company information management
- ✅ **Gmail integration via OAuth 2.0**
- ✅ **AI-powered email filtering and categorization**
- ✅ **Smart email relevance scoring**
- ✅ **Business-essential email identification**
- ✅ Inbox and spam email viewing
- ✅ Modern, responsive UI with Bootstrap
- ✅ Secure password hashing
- ✅ SQLite database for data storage
- ✅ **No password storage** - only secure OAuth tokens

### AI Email Filtering Features
- 🤖 **Google Gemini AI integration**
- 📊 **Intelligent email categorization** (Essential, Business Lead, Partnership, Invoice, Support, Marketing, Spam, Personal)
- 🎯 **Relevance scoring** based on company details
- 🧠 **AI reasoning** for categorization decisions
- ⚡ **Batch email analysis** for efficiency
- 🔄 **Fallback analysis** when API is unavailable
- 🎨 **Visual categorization** with color-coded badges
- 💰 **Free to use** with generous rate limits

### Future Enhancements (Phase 2+)
- Email composition and sending
- Advanced email filtering and search
- Bulk email operations
- Email analytics and reporting
- Multi-user collaboration features
- Support for other email providers (Outlook, Yahoo)
- Custom AI training for specific business needs

## Technology Stack

- **Backend**: Python Flask
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Email Protocol**: **Gmail API with OAuth 2.0**
- **AI Integration**: **Google Gemini AI**
- **Security**: Werkzeug password hashing, Flask sessions, OAuth 2.0 tokens

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)
- Google Cloud Console account (for OAuth 2.0 setup)
- **Google Gemini API key** (for AI filtering - free to use)
- Internet connection for Gmail API and AI API access

## Installation

1. **Clone or download the project files**
   ```bash
   # If using git
   git clone <repository-url>
   cd mail-management-system
   ```

2. **Create a virtual environment (recommended)**
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On macOS/Linux
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up Google OAuth 2.0 credentials**
   - Follow the detailed guide in `GOOGLE_OAUTH_SETUP.md`
   - Set environment variables or update `config.py`

5. **Run the application**
   ```bash
   python app.py
   ```

6. **Access the application**
   Open your web browser and navigate to: `http://localhost:5000`

## OAuth 2.0 Setup (Required)

**Important**: Before using the application, you must set up Google OAuth 2.0 credentials.

### Quick Setup Steps:
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable Gmail API
4. Create OAuth 2.0 credentials
5. Set redirect URI to `http://localhost:5000/oauth2callback`
6. Copy Client ID and Client Secret to your app

**Detailed instructions**: See `GOOGLE_OAUTH_SETUP.md`

## 🤖 AI Configuration

### Getting Gemini API Key

#### Google Gemini API Key
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Sign in with your Google account
3. Click "Create API Key"
4. Copy the generated key

**Benefits of Gemini API:**
- ✅ **Free to use** with generous rate limits
- ✅ **No credit card required** for basic usage
- ✅ **High-quality AI analysis** powered by Google's latest models
- ✅ **Fast response times** and reliable service

### Configuring AI Filtering
1. **Start the application** and register/login
2. **Complete company information** (required for AI analysis)
3. **Navigate to AI Configuration** from the dashboard
4. **Enter your Gemini API key**
5. **Save the configuration**
6. **Connect your Gmail account** to start using AI filtering

### How AI Filtering Works
- **Company Analysis**: AI analyzes your company details (name, industry, description)
- **Email Processing**: Each email is analyzed for relevance to your business
- **Categorization**: Emails are categorized into business-relevant categories
- **Scoring**: Each email gets a relevance score (0-100%)
- **Filtering**: Essential emails are separated from less relevant ones
- **Reasoning**: AI provides explanations for its categorization decisions

## Usage Guide

### 1. User Registration
- Visit the homepage and click "Register"
- Create a username and password
- You'll be automatically redirected to add company information

### 2. Company Information
- Fill in your company details (company name is required)
- Save the information to proceed to the dashboard

### 3. Connecting Gmail Account
- From the dashboard, click "Connect Gmail Account"
- Click "Sign in with Google"
- Complete Google's OAuth consent flow
- Your Gmail account is now securely connected

### 4. AI Email Filtering (Optional but Recommended)
- Configure your AI API key from the dashboard
- Complete your company information for better filtering
- AI will automatically categorize emails as Essential or Other
- View relevance scores and AI reasoning for each email

### 5. Viewing Emails
- Once Gmail accounts are connected, click "View Mail" on any account
- **With AI filtering**: View Essential and Other emails in separate sections
- **Without AI filtering**: View standard inbox and spam emails
- Use the refresh button to get the latest emails
- Click on any email to view full content

### 6. Managing Your Account
- Update company information anytime from the dashboard
- Configure or update your AI API key
- Connect multiple Gmail accounts
- Access all features through the navigation menu

## 🧪 Testing AI Functionality

### Test Script
Run the included test script to see AI filtering in action:

```bash
python test_email_filter.py
```

This script demonstrates:
- Email categorization logic
- Relevance scoring
- Fallback analysis (when no API key is provided)
- Different email types and their classifications

### Manual Testing
1. **Configure Gemini API key** in the web interface
2. **Add company information** with detailed description
3. **Connect Gmail account** and view emails
4. **Observe AI categorization** in the mail interface
5. **Check relevance scores** and reasoning for each email

## Security Features

- **OAuth 2.0 Authentication**: Secure Google-approved access
- **No Password Storage**: Only secure access tokens are stored
- **Token Refresh**: Automatic token renewal for continuous access
- **Password Hashing**: User account passwords are securely hashed
- **Session Management**: Secure user sessions with Flask
- **Access Control**: Users can only access their own data
- **API Key Encryption**: Gemini API keys are stored securely

## Database Schema

### Users Table
- `id`: Primary key
- `username`: Unique username
- `password_hash`: Hashed password

### Company Info Table
- `id`: Primary key
- `user_id`: Foreign key to users
- `company_name`: Company name
- `industry`: Industry type
- `address`: Company address
- `phone`: Contact phone
- `website`: Company website
- `description`: Company description

### Email Accounts Table (Updated for OAuth)
- `id`: Primary key
- `user_id`: Foreign key to users
- `email`: Email address
- `access_token`: OAuth access token
- `refresh_token`: OAuth refresh token
- `token_expiry`: Token expiration time
- `provider`: Email provider (gmail, outlook, etc.)

## Configuration

### Environment Variables (Recommended)
```bash
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"
export FLASK_SECRET_KEY="your-secret-key-here"
export FLASK_ENV="development"  # or "production"
export DATABASE_URL="sqlite:///mail_app.db"
```

### Direct Configuration
Update `config.py` with your Google OAuth credentials:
```python
GOOGLE_CLIENT_ID = 'your-actual-client-id'
GOOGLE_CLIENT_SECRET = 'your-actual-client-secret'
```

## Troubleshooting

### Common Issues

1. **OAuth Setup Issues**
   - Follow `GOOGLE_OAUTH_SETUP.md` step by step
   - Verify redirect URI matches exactly
   - Check Client ID and Client Secret are correct

2. **"redirect_uri_mismatch" Error**
   - Ensure redirect URI in Google Console is exactly: `http://localhost:5000/oauth2callback`
   - Check for trailing slashes or protocol differences

3. **"invalid_client" Error**
   - Verify your Client ID and Client Secret
   - Check that credentials are properly set

4. **Database Errors**
   - Ensure the application has write permissions
   - Delete `mail_app.db` and restart to recreate the database

5. **Port Already in Use**
   - Change the port in `app.py` or stop other applications using port 5000

## Development

### Project Structure
```
mail-management-system/
├── app.py                 # Main Flask application with OAuth
├── config.py             # Configuration file for OAuth credentials
├── requirements.txt      # Python dependencies (includes OAuth libraries)
├── README.md            # This file
├── GOOGLE_OAUTH_SETUP.md # Detailed OAuth setup guide
├── templates/           # HTML templates
│   ├── base.html       # Base template with navigation
│   ├── index.html      # Landing page
│   ├── register.html   # User registration
│   ├── login.html      # User login
│   ├── company_info.html # Company information form
│   ├── dashboard.html  # Main dashboard
│   ├── add_email.html  # Gmail OAuth connection
│   └── mail.html       # Email viewing interface
└── mail_app.db         # SQLite database (created automatically)
```

### Adding New Features
1. Create new routes in `app.py`
2. Add corresponding HTML templates
3. Update the navigation in `base.html`
4. Test thoroughly before deployment

## Deployment

### Production Considerations
- Use a production WSGI server (Gunicorn, uWSGI)
- Set `FLASK_ENV=production`
- Use a production database (PostgreSQL, MySQL)
- **Update OAuth redirect URIs for production domain**
- Implement proper logging and monitoring
- Use HTTPS in production (required for OAuth)
- Regular database backups

### OAuth Production Setup
1. Update redirect URIs in Google Cloud Console
2. Add your production domain to authorized origins
3. Set environment variables securely
4. Use HTTPS (OAuth requires secure connections)

## Advantages of OAuth 2.0 over IMAP

### Security
- ✅ **No password storage** - only secure tokens
- ✅ **Revocable access** - users can revoke anytime
- ✅ **Limited scope** - only requested permissions
- ✅ **Google-approved** - follows security best practices

### User Experience
- ✅ **One-click sign-in** - no manual credential entry
- ✅ **No 2FA issues** - works with all Google security features
- ✅ **Automatic token refresh** - seamless experience
- ✅ **Professional appearance** - Google-branded authentication

### Technical Benefits
- ✅ **Modern API** - Gmail API vs legacy IMAP
- ✅ **Better performance** - optimized for web applications
- ✅ **Rich metadata** - more email information available
- ✅ **Future-proof** - Google's recommended approach

## Support

For support and questions:
- Check the troubleshooting section above
- Follow `GOOGLE_OAUTH_SETUP.md` for OAuth issues
- Review the code comments for implementation details
- Check Google Cloud Console for API quotas and errors

## Changelog

### Version 2.0.0 (Current)
- **Major upgrade**: Replaced IMAP with OAuth 2.0 + Gmail API
- Enhanced security: No password storage
- Improved user experience: One-click Google sign-in
- Better performance: Modern Gmail API integration
- Professional authentication flow

### Version 1.0.0 (Previous)
- Initial release with IMAP functionality
- User registration and authentication
- Company information management
- Email account integration via IMAP
- Inbox and spam viewing

---

**Note**: This version uses OAuth 2.0 for enhanced security and user experience. Follow the OAuth setup guide before first use.
