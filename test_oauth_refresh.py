#!/usr/bin/env python3
"""
Test script to verify OAuth token refresh functionality
"""

import os
import sys
from datetime import datetime, timedelta
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import app, db, EmailAccount, _refresh_credentials_if_needed

def test_token_refresh():
    """Test the token refresh functionality"""
    with app.app_context():
        # Get the first email account from the database
        email_account = EmailAccount.query.first()
        
        if not email_account:
            print("No email accounts found in database. Please connect a Gmail account first.")
            return False
        
        print(f"Testing token refresh for: {email_account.email}")
        print(f"Current token expiry: {email_account.token_expiry}")
        
        try:
            # Test the refresh function
            credentials = _refresh_credentials_if_needed(email_account)
            print("✅ Token refresh function executed successfully")
            print(f"New token expiry: {email_account.token_expiry}")
            
            # Test if we can build a Gmail service
            from googleapiclient.discovery import build
            service = build('gmail', 'v1', credentials=credentials)
            print("✅ Gmail service built successfully")
            
            # Test a simple API call
            profile = service.users().getProfile(userId='me').execute()
            print(f"✅ Gmail API call successful. Email: {profile.get('emailAddress')}")
            
            return True
            
        except Exception as e:
            print(f"❌ Error during token refresh test: {str(e)}")
            return False

if __name__ == "__main__":
    print("Testing OAuth token refresh functionality...")
    print("=" * 50)
    
    success = test_token_refresh()
    
    print("=" * 50)
    if success:
        print("✅ All tests passed! OAuth token refresh is working correctly.")
    else:
        print("❌ Tests failed. Please check the error messages above.")
        print("\nIf you're getting 'invalid_grant' errors, try:")
        print("1. Go to your dashboard")
        print("2. Click the 'Reconnect' button next to your Gmail account")
        print("3. Complete the OAuth flow again")
