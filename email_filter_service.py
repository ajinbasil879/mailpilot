import json
from typing import Dict, List, Tuple
from dataclasses import dataclass
from enum import Enum
import google.generativeai as genai

# Email categories remain the same
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
    def __init__(self, api_key: str):
        self.api_key = api_key
        # Configure the generative AI client with the API key
        genai.configure(api_key=self.api_key)
        
    def analyze_email(self, email_data: Dict, company_info: Dict) -> EmailAnalysis:
        try:
            return self._analyze_with_gemini(email_data, company_info)
        except Exception as e:
            print(f"DEBUG: AI analysis failed with error: {e}")
            return self._fallback_analysis(f"AI analysis failed: {e}")
    
    def _analyze_with_gemini(self, email_data: Dict, company_info: Dict) -> EmailAnalysis:
        prompt = self._build_analysis_prompt(email_data, company_info)
        
        model = genai.GenerativeModel('models/gemini-2.5-flash')
        response = model.generate_content(prompt)
        
        # This block correctly handles responses blocked by safety filters
        try:
            analysis_text = response.text
            return self._parse_analysis_response(analysis_text)
        except ValueError:
            reason = f"Response blocked by API's safety filters. Reason: {response.prompt_feedback}"
            print(f"DEBUG: {reason}")
            return self._fallback_analysis(reason)
        except Exception as e:
            raise Exception(f"Failed to parse Gemini response: {e}")
    
    def _build_analysis_prompt(self, email_data: Dict, company_info: Dict) -> str:
        company_details = f"Company Name: {company_info.get('company_name', 'N/A')}, Industry: {company_info.get('industry', 'N/A')}, Detailed Description: {company_info.get('description', 'N/A')}"
        email_content = f"Subject: {email_data.get('subject', 'N/A')}, From: {email_data.get('from', 'N/A')}, Body Snippet: {email_data.get('body', 'N/A')[:1000]}"

        return f"""
You are an expert executive assistant for a company with the following profile:
{company_details}

Based on the company's focus on EV manufacturing, battery technology, supply chain logistics, and R&D, your primary goal is to identify and prioritize emails that are critical to these specific business operations.

Analyze the following email:
{email_content}

Your task is to classify this email into ONE of the following specific categories. Be highly critical in your analysis, using the company description to guide your decision.

CATEGORIES:
- "business_critical": Urgent client communications, supply chain disruptions (e.g., cobalt, lithium), critical financial matters, or major partnership opportunities. This should be used sparingly for high-impact events.
- "invoice_payment": Invoices from suppliers, payment confirmations, and billing questions.
- "customer_support": Questions, issues, or feedback from existing customers regarding their vehicles or energy products.
- "partnership": Potential collaborations, B2B fleet sales inquiries, or offers from charging network providers.
- "job_application": Resumes, CVs, or inquiries about job openings, especially for engineering and technical roles.
- "technical_alert": Security warnings, API updates from suppliers, software license renewals, or domain updates.
- "marketing": Newsletters, promotional offers, or sales pitches from other companies. Low priority.
- "spam": Unsolicited, irrelevant, or malicious emails.
- "personal": Non-business-related personal messages.
- "unknown": Only if the category cannot be determined from the content.

Provide your response in a valid JSON format only, with no additional text or explanations outside of the JSON structure.

JSON response format:
{{
    "category": "chosen_category_from_list",
    "relevance_score": 0.0 to 1.0,
    "is_essential": true (for business_critical, invoice_payment, customer_support, partnership, job_application, technical_alert) or false,
    "confidence": 0.0 to 1.0,
    "reasoning": "A brief, specific explanation for your classification, referencing keywords from the email and how they relate to the company's business.",
    "suggested_actions": ["action1", "action2"]
}}
"""

    def _parse_analysis_response(self, analysis_text: str) -> EmailAnalysis:
        try:
            start_idx = analysis_text.find('{')
            end_idx = analysis_text.rfind('}') + 1
            json_str = analysis_text[start_idx:end_idx].strip()
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
            return self._fallback_analysis("AI response was unreadable. Manual review needed.")
            
    def _fallback_analysis(self, reason: str) -> EmailAnalysis:
        return EmailAnalysis(
            category=EmailCategory.UNKNOWN,
            relevance_score=0.0,
            is_essential=False,
            confidence=0.0,
            reasoning=reason,
            suggested_actions=["Review manually"]
        )
    
    def batch_analyze_emails(self, emails: List[Dict], company_info: Dict) -> List[Tuple[Dict, EmailAnalysis]]:
        results = []
        for email in emails:
            analysis = self.analyze_email(email, company_info)
            results.append((email, analysis))
        return results