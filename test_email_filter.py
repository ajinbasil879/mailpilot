#!/usr/bin/env python3
"""
Test script for the email filtering service
This script demonstrates how the AI email filtering works
"""

from email_filter_service import EmailFilterService, EmailCategory

def test_email_filtering():
    """Test the email filtering functionality"""
    
    # Sample company information
    company_info = {
        'company_name': 'TechCorp Solutions',
        'industry': 'Software Development',
        'description': 'We develop custom software solutions for small and medium businesses, specializing in web applications and mobile apps.',
        'website': 'https://techcorp.com'
    }
    
    # Sample emails to test
    test_emails = [
        {
            'subject': 'Partnership Proposal - Joint Software Development',
            'from': 'partnerships@bigcorp.com',
            'body': 'We are interested in partnering with TechCorp Solutions for a joint software development project. We have a large client base that could benefit from your expertise in web applications.'
        },
        {
            'subject': 'Invoice #12345 - Payment Due',
            'from': 'billing@clientcompany.com',
            'body': 'Please find attached invoice #12345 for the web application development services provided last month. Payment is due within 30 days.'
        },
        {
            'subject': 'Congratulations! You won $1,000,000!',
            'from': 'winner@lottery-scam.com',
            'body': 'Congratulations! You have won $1,000,000 in our international lottery. Click here to claim your prize immediately!'
        },
        {
            'subject': 'Customer Support Request - Login Issues',
            'from': 'support@clientcompany.com',
            'body': 'We are experiencing login issues with the web application you developed for us. Users cannot access their accounts. Please help us resolve this issue.'
        },
        {
            'subject': 'Marketing Newsletter - Industry Updates',
            'from': 'newsletter@technews.com',
            'body': 'Stay updated with the latest trends in software development. This month we cover AI integration, cloud computing, and mobile app development best practices.'
        }
    ]
    
    print("🤖 AI Email Filtering Test")
    print("=" * 50)
    print(f"Company: {company_info['company_name']}")
    print(f"Industry: {company_info['industry']}")
    print(f"Description: {company_info['description']}")
    print("=" * 50)
    
    # Note: This test uses fallback analysis since no API key is provided
    print("\n📧 Testing Email Analysis (Fallback Mode)")
    print("-" * 50)
    
    filter_service = EmailFilterService("dummy_key", "gemini")
    
    for i, email in enumerate(test_emails, 1):
        print(f"\n{i}. Subject: {email['subject']}")
        print(f"   From: {email['from']}")
        
        try:
            analysis = filter_service.analyze_email(email, company_info)
            
            print(f"   Category: {analysis.category.value}")
            print(f"   Essential: {'✅ Yes' if analysis.is_essential else '❌ No'}")
            print(f"   Relevance: {analysis.relevance_score:.1%}")
            print(f"   Confidence: {analysis.confidence:.1%}")
            print(f"   Reasoning: {analysis.reasoning}")
            
            if analysis.suggested_actions:
                print(f"   Actions: {', '.join(analysis.suggested_actions)}")
                
        except Exception as e:
            print(f"   Error: {str(e)}")
    
    print("\n" + "=" * 50)
    print("✅ Test completed! This demonstrates the fallback analysis.")
    print("💡 To use AI-powered analysis, configure your API key in the web interface.")
    print("🔗 Run the Flask app and visit /api_key to configure your Gemini API key.")

if __name__ == "__main__":
    test_email_filtering()
