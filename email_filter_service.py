import requests
import json
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

class EmailCategory(Enum):
    ESSENTIAL = "essential"
    BUSINESS_LEAD = "business_lead"
    PARTNERSHIP = "partnership"
    INVOICE_PAYMENT = "invoice_payment"
    CUSTOMER_SUPPORT = "customer_support"
    MARKETING = "marketing"
    SPAM = "spam"
    PERSONAL = "personal"
    UNKNOWN = "unknown"

@dataclass
class EmailAnalysis:
    category: EmailCategory
    relevance_score: float  # 0.0 to 1.0
    is_essential: bool
    confidence: float  # 0.0 to 1.0
    reasoning: str
    suggested_actions: List[str]

class EmailFilterService:
    def __init__(self, api_key: str, provider: str = "gemini"):
        self.api_key = api_key
        self.provider = provider.lower()
        
    def analyze_email(self, email_data: Dict, company_info: Dict) -> EmailAnalysis:
        """
        Analyze an email to determine its category and relevance to the company.
        
        Args:
            email_data: Dictionary containing email subject, from, body, etc.
            company_info: Dictionary containing company details
            
        Returns:
            EmailAnalysis object with categorization results
        """
        try:
            if self.provider == "gemini":
                return self._analyze_with_gemini(email_data, company_info)
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
        except Exception as e:
            # Fallback to basic analysis if API fails
            return self._fallback_analysis(email_data, company_info)
    
    def _analyze_with_gemini(self, email_data: Dict, company_info: Dict) -> EmailAnalysis:
        """Analyze email using Google Gemini API"""
        prompt = self._build_analysis_prompt(email_data, company_info)
        
        headers = {
            "Content-Type": "application/json"
        }
        
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.3,
                "maxOutputTokens": 500,
                "topP": 0.8,
                "topK": 10
            }
        }
        
        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={self.api_key}",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            if 'candidates' in result and len(result['candidates']) > 0:
                analysis_text = result['candidates'][0]['content']['parts'][0]['text']
                return self._parse_analysis_response(analysis_text)
            else:
                raise Exception("No response from Gemini API")
        else:
            raise Exception(f"Gemini API error: {response.status_code} - {response.text}")
    
    def _build_analysis_prompt(self, email_data: Dict, company_info: Dict) -> str:
        """Build the analysis prompt for the AI API"""
        company_name = company_info.get('company_name', 'Unknown Company')
        industry = company_info.get('industry', 'Unknown Industry')
        description = company_info.get('description', 'No description provided')
        
        email_subject = email_data.get('subject', 'No Subject')
        email_from = email_data.get('from', 'Unknown Sender')
        email_body = email_data.get('body', 'No body content')
        
        prompt = f"""
Analyze the following email for relevance to this business:

COMPANY INFORMATION:
- Company Name: {company_name}
- Industry: {industry}
- Description: {description}

EMAIL TO ANALYZE:
- Subject: {email_subject}
- From: {email_from}
- Body: {email_body[:1000]}...

Please analyze this email and provide your response in the following JSON format:
{{
    "category": "essential|business_lead|partnership|invoice_payment|customer_support|marketing|spam|personal|unknown",
    "relevance_score": 0.85,
    "is_essential": true,
    "confidence": 0.9,
    "reasoning": "Brief explanation of why this email is categorized this way",
    "suggested_actions": ["action1", "action2"]
}}

Categories:
- essential: Critical business emails that require immediate attention
- business_lead: Potential customers or sales opportunities
- partnership: Business partnership or collaboration opportunities
- invoice_payment: Financial transactions, invoices, payments
- customer_support: Customer service, support requests
- marketing: Marketing emails, newsletters, promotional content
- spam: Unwanted, irrelevant, or suspicious emails
- personal: Personal emails not related to business
- unknown: Cannot determine category with confidence

Relevance score should be 0.0 (completely irrelevant) to 1.0 (highly relevant).
Confidence should be 0.0 (uncertain) to 1.0 (very confident).
"""
        return prompt
    
    def _parse_analysis_response(self, analysis_text: str) -> EmailAnalysis:
        """Parse the AI response into EmailAnalysis object"""
        try:
            # Try to extract JSON from the response
            start_idx = analysis_text.find('{')
            end_idx = analysis_text.rfind('}') + 1
            
            if start_idx != -1 and end_idx != -1:
                json_str = analysis_text[start_idx:end_idx]
                data = json.loads(json_str)
                
                return EmailAnalysis(
                    category=EmailCategory(data.get('category', 'unknown')),
                    relevance_score=float(data.get('relevance_score', 0.5)),
                    is_essential=data.get('is_essential', False),
                    confidence=float(data.get('confidence', 0.5)),
                    reasoning=data.get('reasoning', 'No reasoning provided'),
                    suggested_actions=data.get('suggested_actions', [])
                )
            else:
                raise ValueError("No JSON found in response")
                
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            # Fallback parsing if JSON parsing fails
            return self._fallback_analysis_from_text(analysis_text)
    
    def _fallback_analysis_from_text(self, analysis_text: str) -> EmailAnalysis:
        """Fallback analysis when JSON parsing fails"""
        # Simple keyword-based analysis
        text_lower = analysis_text.lower()
        
        if any(word in text_lower for word in ['essential', 'important', 'urgent', 'critical']):
            category = EmailCategory.ESSENTIAL
            relevance_score = 0.8
            is_essential = True
        elif any(word in text_lower for word in ['lead', 'customer', 'sale', 'opportunity']):
            category = EmailCategory.BUSINESS_LEAD
            relevance_score = 0.7
            is_essential = True
        elif any(word in text_lower for word in ['partnership', 'collaboration', 'joint']):
            category = EmailCategory.PARTNERSHIP
            relevance_score = 0.7
            is_essential = True
        elif any(word in text_lower for word in ['invoice', 'payment', 'bill', 'financial']):
            category = EmailCategory.INVOICE_PAYMENT
            relevance_score = 0.8
            is_essential = True
        elif any(word in text_lower for word in ['support', 'help', 'issue', 'problem']):
            category = EmailCategory.CUSTOMER_SUPPORT
            relevance_score = 0.6
            is_essential = True
        elif any(word in text_lower for word in ['marketing', 'newsletter', 'promotion']):
            category = EmailCategory.MARKETING
            relevance_score = 0.3
            is_essential = False
        elif any(word in text_lower for word in ['spam', 'unwanted', 'irrelevant']):
            category = EmailCategory.SPAM
            relevance_score = 0.1
            is_essential = False
        else:
            category = EmailCategory.UNKNOWN
            relevance_score = 0.5
            is_essential = False
        
        return EmailAnalysis(
            category=category,
            relevance_score=relevance_score,
            is_essential=is_essential,
            confidence=0.6,
            reasoning="Fallback analysis based on keyword matching",
            suggested_actions=["Review manually for accuracy"]
        )
    
    def _fallback_analysis(self, email_data: Dict, company_info: Dict) -> EmailAnalysis:
        """Fallback analysis when API is unavailable"""
        subject = email_data.get('subject', '').lower()
        from_addr = email_data.get('from', '').lower()
        body = email_data.get('body', '').lower()
        
        # Simple keyword-based relevance check
        company_name = company_info.get('company_name', '').lower()
        industry = company_info.get('industry', '').lower()
        
        relevance_keywords = [company_name, industry]
        if company_info.get('description'):
            relevance_keywords.extend(company_info['description'].lower().split()[:10])
        
        # Check for business-related keywords
        business_keywords = ['meeting', 'proposal', 'contract', 'invoice', 'payment', 'partnership', 'collaboration']
        spam_keywords = ['viagra', 'lottery', 'winner', 'congratulations', 'free money', 'click here']
        
        text_content = f"{subject} {from_addr} {body}"
        
        # Determine category based on keywords
        if any(keyword in text_content for keyword in spam_keywords):
            category = EmailCategory.SPAM
            relevance_score = 0.1
            is_essential = False
        elif any(keyword in text_content for keyword in business_keywords):
            category = EmailCategory.ESSENTIAL
            relevance_score = 0.7
            is_essential = True
        elif any(keyword in text_content for keyword in relevance_keywords if keyword):
            category = EmailCategory.ESSENTIAL
            relevance_score = 0.8
            is_essential = True
        else:
            category = EmailCategory.UNKNOWN
            relevance_score = 0.3
            is_essential = False
        
        return EmailAnalysis(
            category=category,
            relevance_score=relevance_score,
            is_essential=is_essential,
            confidence=0.4,
            reasoning="Fallback analysis - API unavailable",
            suggested_actions=["Review manually", "Check API key configuration"]
        )
    
    def batch_analyze_emails(self, emails: List[Dict], company_info: Dict) -> List[Tuple[Dict, EmailAnalysis]]:
        """
        Analyze multiple emails in batch for efficiency.
        
        Args:
            emails: List of email dictionaries
            company_info: Company information dictionary
            
        Returns:
            List of tuples containing (email_data, analysis)
        """
        results = []
        
        for email in emails:
            try:
                analysis = self.analyze_email(email, company_info)
                results.append((email, analysis))
            except Exception as e:
                # If individual email analysis fails, use fallback
                fallback_analysis = self._fallback_analysis(email, company_info)
                results.append((email, fallback_analysis))
        
        return results
