from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import base64
import json
import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from config import Config
from email_filter_service import EmailFilterService, EmailCategory

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=True)
    company_info = db.relationship('CompanyInfo', backref='user', uselist=False)
    email_accounts = db.relationship('EmailAccount', backref='user', lazy=True)

class CompanyInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    company_name = db.Column(db.String(100), nullable=False)
    industry = db.Column(db.String(100))
    address = db.Column(db.Text)
    phone = db.Column(db.String(20))
    website = db.Column(db.String(100))
    description = db.Column(db.Text)

class EmailAccount(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    access_token = db.Column(db.Text, nullable=False)
    refresh_token = db.Column(db.Text, nullable=False)
    token_expiry = db.Column(db.DateTime)
    provider = db.Column(db.String(50), default='gmail')

class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key = db.Column(db.Text, nullable=False)

def _extract_email_body(message):
    """Extract email body text from Gmail message"""
    def _decode_body(part):
        data = part.get('body', {}).get('data')
        if data:
            # Gmail uses URL-safe base64
            decoded_bytes = base64.urlsafe_b64decode(data.encode('UTF-8'))
            return decoded_bytes.decode('utf-8', errors='replace')
        return ''
    
    body_text = ''
    body_html = ''
    payload = message.get('payload', {})
    mime_type = payload.get('mimeType')
    
    if mime_type == 'text/plain':
        body_text = _decode_body(payload)
    elif mime_type == 'text/html':
        body_html = _decode_body(payload)
    else:
        for part in payload.get('parts', []) or []:
            part_mime = part.get('mimeType')
            if part_mime == 'text/html' and not body_html:
                body_html = _decode_body(part)
            elif part_mime == 'text/plain' and not body_text:
                body_text = _decode_body(part)
    
    # Prefer plain text, fallback to HTML
    if body_text:
        return body_text[:1000]  # Limit to first 1000 characters
    elif body_html:
        # Simple HTML tag removal
        import re
        clean_text = re.sub('<[^<]+?>', '', body_html)
        return clean_text[:1000]
    
    return ''

def _refresh_credentials_if_needed(email_account):
    """Refresh OAuth credentials if needed and update database"""
    credentials = Credentials(
        token=email_account.access_token, refresh_token=email_account.refresh_token,
        token_uri=app.config['GOOGLE_TOKEN_URL'], client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'], scopes=app.config['GMAIL_SCOPES']
    )
    
    # Check if token needs refresh
    if credentials.expired and credentials.refresh_token:
        try:
            credentials.refresh(Request())
            email_account.access_token = credentials.token
            email_account.token_expiry = credentials.expiry
            db.session.commit()
        except Exception as refresh_error:
            # If refresh fails, the refresh token is likely expired/revoked
            raise Exception(f'Your Gmail access has expired. Please reconnect your Gmail account. Error: {str(refresh_error)}')
    
    return credentials


@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists!')
            return render_template('register.html')
        
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()
        
        session['user_id'] = user.id
        flash('Registration successful! Please complete your company information.')
        return redirect(url_for('company_info'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash('Login successful!')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password!')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.')
    return redirect(url_for('index'))

@app.route('/company_info', methods=['GET', 'POST'])
def company_info():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        company_name = request.form['company_name']
        industry = request.form['industry']
        address = request.form['address']
        phone = request.form['phone']
        website = request.form['website']
        description = request.form['description']
        
        if user.company_info:
            user.company_info.company_name = company_name
            user.company_info.industry = industry
            user.company_info.address = address
            user.company_info.phone = phone
            user.company_info.website = website
            user.company_info.description = description
        else:
            company_info = CompanyInfo(
                user_id=user.id, company_name=company_name, industry=industry,
                address=address, phone=phone, website=website, description=description
            )
            db.session.add(company_info)
        
        db.session.commit()
        flash('Company information saved successfully!')
        return redirect(url_for('dashboard'))
    
    return render_template('company_info.html', company_info=user.company_info)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('dashboard.html', user=user)

@app.route('/add_email')
def add_email():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('add_email.html')

@app.route('/api_key', methods=['GET', 'POST'])
def api_key():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        api_key_value = request.form['api_key']
        api_provider = request.form.get('api_provider', 'gemini')
        
        # Check if user already has an API key
        existing_key = ApiKey.query.filter_by(user_id=user.id).first()
        
        if existing_key:
            existing_key.key = api_key_value
        else:
            new_key = ApiKey(user_id=user.id, key=api_key_value)
            db.session.add(new_key)
        
        db.session.commit()
        flash('API key saved successfully!')
        return redirect(url_for('dashboard'))
    
    # Get existing API key if any
    existing_key = ApiKey.query.filter_by(user_id=user.id).first()
    return render_template('api_key.html', api_key=existing_key)

@app.route('/google_login')
def google_login():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    flow = Flow.from_client_config(
        {
            "web": {
                "client_id": app.config['GOOGLE_CLIENT_ID'],
                "client_secret": app.config['GOOGLE_CLIENT_SECRET'],
                "auth_uri": app.config['GOOGLE_AUTH_URL'],
                "token_uri": app.config['GOOGLE_TOKEN_URL'],
                "redirect_uris": [app.config['GOOGLE_REDIRECT_URI']]
            }
        },
        scopes=app.config['GMAIL_SCOPES']
    )
    
    flow.redirect_uri = app.config['GOOGLE_REDIRECT_URI']
    authorization_url, state = flow.authorization_url(
        access_type='offline', include_granted_scopes='true', prompt='consent'
    )
    
    session['oauth_state'] = state
    session.modified = True
    
    return redirect(authorization_url)

@app.route('/reconnect_gmail/<int:email_id>')
def reconnect_gmail(email_id):
    """Reconnect a Gmail account when tokens are expired/revoked"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    email_account = EmailAccount.query.get_or_404(email_id)
    if email_account.user_id != session['user_id']:
        flash('Access denied!')
        return redirect(url_for('dashboard'))
    
    # Store the email account ID for reconnection
    session['reconnect_email_id'] = email_id
    session.modified = True
    
    # Redirect to Google OAuth flow
    return redirect(url_for('google_login'))

@app.route('/oauth2callback')
def oauth2callback():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    code = request.args.get('code')
    state = request.args.get('state')
    
    if state != session.get('oauth_state'):
        flash('OAuth state mismatch. Please try again.')
        return redirect(url_for('dashboard'))
    
    try:
        flow = Flow.from_client_config(
            {
                "web": {
                    "client_id": app.config['GOOGLE_CLIENT_ID'],
                    "client_secret": app.config['GOOGLE_CLIENT_SECRET'],
                    "auth_uri": app.config['GOOGLE_AUTH_URL'],
                    "token_uri": app.config['GOOGLE_TOKEN_URL'],
                    "redirect_uris": [app.config['GOOGLE_REDIRECT_URI']]
                }
            },
            scopes=app.config['GMAIL_SCOPES']
        )
        flow.redirect_uri = app.config['GOOGLE_REDIRECT_URI']
        
        flow.fetch_token(code=code)
        credentials = flow.credentials
        
        userinfo_response = requests.get(
            app.config['GOOGLE_USERINFO_URL'],
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        userinfo = userinfo_response.json()
        
        # Check if this is a reconnection
        reconnect_email_id = session.pop('reconnect_email_id', None)
        
        if reconnect_email_id:
            # Update existing account with new tokens
            existing_account = EmailAccount.query.get(reconnect_email_id)
            if existing_account and existing_account.user_id == session['user_id']:
                existing_account.access_token = credentials.token
                existing_account.refresh_token = credentials.refresh_token
                existing_account.token_expiry = credentials.expiry
                db.session.commit()
                flash(f'Gmail account {userinfo["email"]} reconnected successfully!')
            else:
                flash('Error: Could not reconnect Gmail account.')
        else:
            # Check if account already exists
            existing_account = EmailAccount.query.filter_by(
                user_id=session['user_id'], email=userinfo['email']
            ).first()
            
            if existing_account:
                existing_account.access_token = credentials.token
                existing_account.refresh_token = credentials.refresh_token
                existing_account.token_expiry = credentials.expiry
            else:
                email_account = EmailAccount(
                    user_id=session['user_id'], email=userinfo['email'],
                    access_token=credentials.token, refresh_token=credentials.refresh_token,
                    token_expiry=credentials.expiry, provider='gmail'
                )
                db.session.add(email_account)
            
            db.session.commit()
            flash(f'Gmail account {userinfo["email"]} connected successfully!')
        
    except Exception as e:
        flash(f'Failed to connect Gmail account: {str(e)}')
    
    return redirect(url_for('dashboard'))


@app.route('/mail/<int:email_id>')
def view_mail(email_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    email_account = EmailAccount.query.get_or_404(email_id)
    if email_account.user_id != session['user_id']:
        flash('Access denied!')
        return redirect(url_for('dashboard'))
    
    try:
        credentials = _refresh_credentials_if_needed(email_account)
        service = build('gmail', 'v1', credentials=credentials)
        
        # Get user's company info and API key
        user = User.query.get(session['user_id'])
        company_info = {}
        if user.company_info:
            company_info = {
                'company_name': user.company_info.company_name,
                'industry': user.company_info.industry,
                'description': user.company_info.description,
                'website': user.company_info.website
            }
        
        api_key_record = ApiKey.query.filter_by(user_id=session['user_id']).first()
        has_ai_filtering = api_key_record is not None
        
        # Get inbox emails
        inbox_response = service.users().messages().list(
            userId='me', labelIds=['INBOX'], maxResults=20
        ).execute()
        
        inbox_emails = []
        if 'messages' in inbox_response:
            for msg in inbox_response['messages']:
                message = service.users().messages().get(
                    userId='me', id=msg['id'], format='metadata',
                    metadataHeaders=['Subject', 'From', 'Date']
                ).execute()
                
                headers = message['payload']['headers']
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
                from_addr = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')
                
                email_data = {
                    'id': msg['id'], 
                    'subject': subject, 
                    'from': from_addr, 
                    'date': date,
                    'body': ''  # We'll get body content if AI filtering is enabled
                }
                
                # If AI filtering is enabled, get email body for analysis
                if has_ai_filtering and api_key_record:
                    try:
                        full_message = service.users().messages().get(
                            userId='me', id=msg['id'], format='full'
                        ).execute()
                        email_data['body'] = _extract_email_body(full_message)
                    except:
                        pass  # Continue without body if extraction fails
                
                inbox_emails.append(email_data)
        
        # Get spam emails
        spam_response = service.users().messages().list(
            userId='me', labelIds=['SPAM'], maxResults=10
        ).execute()
        
        spam_emails = []
        if 'messages' in spam_response:
            for msg in spam_response['messages']:
                message = service.users().messages().get(
                    userId='me', id=msg['id'], format='metadata',
                    metadataHeaders=['Subject', 'From', 'Date']
                ).execute()
                
                headers = message['payload']['headers']
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
                from_addr = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')
                
                spam_emails.append({'id': msg['id'], 'subject': subject, 'from': from_addr, 'date': date})
        
        # Apply AI filtering if API key is available
        filtered_emails = []
        if has_ai_filtering and api_key_record and company_info:
            try:
                filter_service = EmailFilterService(api_key_record.key)
                email_analyses = filter_service.batch_analyze_emails(inbox_emails, company_info)
                
                # Separate essential and non-essential emails
                essential_emails = []
                other_emails = []
                
                for email_data, analysis in email_analyses:
                    email_with_analysis = {
                        **email_data,
                        'analysis': analysis,
                        'category': analysis.category.value,
                        'relevance_score': analysis.relevance_score,
                        'is_essential': analysis.is_essential,
                        'confidence': analysis.confidence,
                        'reasoning': analysis.reasoning
                    }
                    
                    if analysis.is_essential and analysis.relevance_score > 0.6:
                        essential_emails.append(email_with_analysis)
                    else:
                        other_emails.append(email_with_analysis)
                
                # Sort essential emails by relevance score
                essential_emails.sort(key=lambda x: x['relevance_score'], reverse=True)
                other_emails.sort(key=lambda x: x['relevance_score'], reverse=True)
                
                filtered_emails = {
                    'essential': essential_emails,
                    'other': other_emails
                }
                
            except Exception as e:
                flash(f'AI filtering error: {str(e)}. Showing unfiltered emails.')
                filtered_emails = None
        
        return render_template('mail.html', 
                             email_account=email_account,
                             inbox_emails=inbox_emails,
                             spam_emails=spam_emails,
                             filtered_emails=filtered_emails,
                             has_ai_filtering=has_ai_filtering,
                             company_info=company_info)
    
    except Exception as e:
        flash(f'Error accessing Gmail: {str(e)}')
        return redirect(url_for('dashboard'))

@app.route('/mail/<int:email_id>/message/<message_id>')
def view_message(email_id, message_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    email_account = EmailAccount.query.get_or_404(email_id)
    if email_account.user_id != session['user_id']:
        flash('Access denied!')
        return redirect(url_for('dashboard'))
    
    try:
        credentials = _refresh_credentials_if_needed(email_account)
        service = build('gmail', 'v1', credentials=credentials)
        message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
        
        headers = message['payload'].get('headers', [])
        subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
        from_addr = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
        date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')
        to_addr = next((h['value'] for h in headers if h['name'] == 'To'), 'Unknown')
        
        def _decode_body(part):
            data = part.get('body', {}).get('data')
            if data:
                # Gmail uses URL-safe base64
                decoded_bytes = base64.urlsafe_b64decode(data.encode('UTF-8'))
                return decoded_bytes.decode('utf-8', errors='replace')
            return ''
        
        body_text = ''
        body_html = ''
        payload = message.get('payload', {})
        mime_type = payload.get('mimeType')
        
        if mime_type == 'text/plain':
            body_text = _decode_body(payload)
        elif mime_type == 'text/html':
            body_html = _decode_body(payload)
        else:
            for part in payload.get('parts', []) or []:
                part_mime = part.get('mimeType')
                if part_mime == 'text/html' and not body_html:
                    body_html = _decode_body(part)
                elif part_mime == 'text/plain' and not body_text:
                    body_text = _decode_body(part)
        
        return render_template('message.html',
                               email_account=email_account,
                               message_id=message_id,
                               subject=subject,
                               from_addr=from_addr,
                               to_addr=to_addr,
                               date=date,
                               body_html=body_html,
                               body_text=body_text)
    except Exception as e:
        flash(f'Error loading message: {str(e)}')
        return redirect(url_for('view_mail', email_id=email_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)