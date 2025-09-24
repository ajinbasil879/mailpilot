import requests
import json
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum

# New, more granular email categories
class EmailCategory(Enum):
    BUSINESS_CRITICAL = "business_critical"
    JOB_APPLICATION = "job_application"
    TECHNICAL_ALERT = "technical_alert"
    INVOICE_PAYMENT = "invoice_payment"
    CUSTOMER_SUPPORT = "customer_support"
    PARTNERSHIP = "partnership"
    MARKETING = "marketing"
    SPAM = "spam"
    PERSONAL = "personal"
    UNKNOWN = "unknown"

@dataclass
class EmailAnalysis:
    category: EmailCategory
    relevance_score: float
    is_essential: bool
    confidence: float
    reasoning: str
    suggested_actions: List[str]

class EmailFilterService:
    def __init__(self, api_key: str, provider: str = "gemini"):
        self.api_key = api_key
        self.provider = provider.lower()
        
    def analyze_email(self, email_data: Dict, company_info: Dict) -> EmailAnalysis:
        try:
            if self.provider == "gemini":
                return self._analyze_with_gemini(email_data, company_info)
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
        except Exception as e:
            print(f"DEBUG: AI analysis failed with error: {e}")
            return self._fallback_analysis(email_data, company_info)
    
    def _analyze_with_gemini(self, email_data: Dict, company_info: Dict) -> EmailAnalysis:
        prompt = self._build_analysis_prompt(email_data, company_info)
        
        headers = { "Content-Type": "application/json" }
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": 0.2, "maxOutputTokens": 500, "topP": 0.8, "topK": 10
            }
        }
        
        response = requests.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}",
            headers=headers, json=payload, timeout=30
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
        company_details = f"Name: {company_info.get('company_name', 'N/A')}, Industry: {company_info.get('industry', 'N/A')}, Description: {company_info.get('description', 'N/A')}"
        email_content = f"Subject: {email_data.get('subject', 'N/A')}, From: {email_data.get('from', 'N/A')}, Body: {email_data.get('body', 'N/A')[:1000]}"
        
        return f"""
Analyze the following email for a business with these details: {company_details}.
Email content: {email_content}

Your task is to classify this email into ONE of the following categories and determine if it's essential.
Provide your response in a valid JSON format only.

CATEGORIES:
- "business_critical": Direct client communications, urgent business proposals, partnership offers. High priority.
- "job_application": Resumes, CVs, or inquiries about job openings at the company.
- "technical_alert": Security warnings, API updates, subscription confirmations, domain renewals. Important but not directly business-related.
- "invoice_payment": Invoices, payment confirmations, billing questions.
- "customer_support": Questions or issues from existing customers.
- "marketing": Newsletters, promotional offers, sales pitches. Low priority.
- "spam": Unsolicited, irrelevant, or malicious emails.
- "personal": Non-business-related personal messages.
- "unknown": If the category cannot be determined.

JSON response format:
{{
    "category": "chosen_category_from_list",
    "relevance_score": 0.0 to 1.0,
    "is_essential": true (for business_critical, job_application, technical_alert, invoice_payment, customer_support) or false,
    "confidence": 0.0 to 1.0,
    "reasoning": "A brief explanation for your classification.",
    "suggested_actions": ["action1", "action2"]
}}
"""

    def _parse_analysis_response(self, analysis_text: str) -> EmailAnalysis:
        try:
            start_idx = analysis_text.find('{')
            end_idx = analysis_text.rfind('}') + 1
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
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            return self._fallback_analysis_from_text(analysis_text)
            
    def _fallback_analysis_from_text(self, text: str) -> EmailAnalysis:
        return EmailAnalysis(EmailCategory.UNKNOWN, 0.5, False, 0.4, "AI response was unreadable. Manual review needed.", ["Review manually"])

    def _fallback_analysis(self, email_data: Dict, company_info: Dict) -> EmailAnalysis:
        return EmailAnalysis(EmailCategory.UNKNOWN, 0.3, False, 0.2, "Fallback analysis - API unavailable", ["Check API key", "Review manually"])
    
    def batch_analyze_emails(self, emails: List[Dict], company_info: Dict) -> List[Tuple[Dict, EmailAnalysis]]:
        results = []
        for email in emails:
            analysis = self.analyze_email(email, company_info)
            results.append((email, analysis))
        return results