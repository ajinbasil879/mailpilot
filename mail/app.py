from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
import json
import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
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
    provider = db.Column(db.String(50), default='gmail')  # gmail, outlook, etc.

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
            # Update existing company info
            user.company_info.company_name = company_name
            user.company_info.industry = industry
            user.company_info.address = address
            user.company_info.phone = phone
            user.company_info.website = website
            user.company_info.description = description
        else:
            # Create new company info
            company_info = CompanyInfo(
                user_id=user.id,
                company_name=company_name,
                industry=industry,
                address=address,
                phone=phone,
                website=website,
                description=description
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
    
    # Create OAuth flow for Google
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
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Get authorization code from callback
    code = request.args.get('code')
    state = request.args.get('state')
    
    if state != session.get('oauth_state'):
        flash('OAuth state mismatch. Please try again.')
        return redirect(url_for('dashboard'))
    
    try:
        # Exchange code for tokens
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
        
        # Exchange authorization code for tokens
        flow.fetch_token(code=code)
        credentials = flow.credentials
        
        # Get user info from Google
        userinfo_response = requests.get(
            app.config['GOOGLE_USERINFO_URL'],
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        userinfo = userinfo_response.json()
        
        # Check if email account already exists
        existing_account = EmailAccount.query.filter_by(
            user_id=session['user_id'],
            email=userinfo['email']
        ).first()
        
        if existing_account:
            # Update existing account with new tokens
            existing_account.access_token = credentials.token
            existing_account.refresh_token = credentials.refresh_token
            existing_account.token_expiry = credentials.expiry
        else:
            # Create new email account
            email_account = EmailAccount(
                user_id=session['user_id'],
                email=userinfo['email'],
                access_token=credentials.token,
                refresh_token=credentials.refresh_token,
                token_expiry=credentials.expiry,
                provider='gmail'
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
        # Create credentials from stored tokens
        credentials = Credentials(
            token=email_account.access_token,
            refresh_token=email_account.refresh_token,
            token_uri=app.config['GOOGLE_TOKEN_URL'],
            client_id=app.config['GOOGLE_CLIENT_ID'],
            client_secret=app.config['GOOGLE_CLIENT_SECRET'],
            scopes=app.config['GMAIL_SCOPES']
        )
        
        # Refresh token if expired
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            email_account.access_token = credentials.token
            email_account.token_expiry = credentials.expiry
            db.session.commit()
        
        # Build Gmail service
        service = build('gmail', 'v1', credentials=credentials)
        
        # Get inbox emails
        inbox_response = service.users().messages().list(
            userId='me',
            labelIds=['INBOX'],
            maxResults=10
        ).execute()
        
        inbox_emails = []
        if 'messages' in inbox_response:
            for msg in inbox_response['messages']:
                message = service.users().messages().get(
                    userId='me',
                    id=msg['id'],
                    format='metadata',
                    metadataHeaders=['Subject', 'From', 'Date']
                ).execute()
                
                headers = message['payload']['headers']
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
                from_addr = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')
                
                inbox_emails.append({
                    'subject': subject,
                    'from': from_addr,
                    'date': date
                })
        
        # Get spam emails
        spam_response = service.users().messages().list(
            userId='me',
            labelIds=['SPAM'],
            maxResults=10
        ).execute()
        
        spam_emails = []
        if 'messages' in spam_response:
            for msg in spam_response['messages']:
                message = service.users().messages().get(
                    userId='me',
                    id=msg['id'],
                    format='metadata',
                    metadataHeaders=['Subject', 'From', 'Date']
                ).execute()
                
                headers = message['payload']['headers']
                subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '(No Subject)')
                from_addr = next((h['value'] for h in headers if h['name'] == 'From'), 'Unknown')
                date = next((h['value'] for h in headers if h['name'] == 'Date'), 'Unknown')
                
                spam_emails.append({
                    'subject': subject,
                    'from': from_addr,
                    'date': date
                })
        
        return render_template('mail.html', 
                             email_account=email_account,
                             inbox_emails=inbox_emails,
                             spam_emails=spam_emails)
    
    except Exception as e:
        flash(f'Error accessing Gmail: {str(e)}')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
