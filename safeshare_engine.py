"""SafeShare: Enterprise AI Privacy & Secret Firewall.

Powered by Google Gemma 4 (gemma-4-31b-it & gemma-4-26b-a4b-it) via the Gemini API.
Combines deterministic regex pattern heuristics with Gemma 4's deep semantic reasoning
to catch PII, banking details, API credentials, and confidential corporate data before
they leak to external LLMs.
"""

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

# Gemma 4 Models on Gemini API
GEMMA_4_MODELS = {
    "gemma-4-31b-it": {
        "name": "Gemma 4 31B (Dense)",
        "description": "31B parameter instruction-tuned dense model. Highest contextual classification accuracy.",
        "id": "gemma-4-31b-it",
    },
    "gemma-4-26b-a4b-it": {
        "name": "Gemma 4 26B/4B (MoE)",
        "description": "26B total / 4B active parameter Mixture-of-Experts. Ultra-fast audit latency.",
        "id": "gemma-4-26b-a4b-it",
    },
}

DEFAULT_MODEL = "gemma-4-31b-it"

# Deterministic Regex Patterns for Indian & Global PII / Secrets / Legal Documents / Financial Sentences
PATTERNS = {
    "Password / Credential": [
        re.compile(r"(?i)\b(?:pass(?:word|wrd)?|pwd|pw|secret|token|credential|creds?)\s*(?:is\s*|[:=]\s*|\s+)([^\s,;]+)"),
        re.compile(r"(?i)\b(?:pin|otp|cvv|security\s*code)\s*(?:is\s*|[:=]\s*|\s+)([0-9]{3,8})\b"),
    ],
    "Aadhaar Number": [
        # Contextual Aadhaar with arbitrary spacing / grouping (e.g. "aadhar 452009 25009 42009" or "adhar: 4892 7741 9023")
        re.compile(r"(?i)\b(?:aad?ha?a?r|uidai|adhar)\s*(?:no\.?|num(?:ber)?|is|card|[:=]|\s+)\s*([0-9\s-]{10,24})\b"),
        # Standard 4-4-4 digit format
        re.compile(r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b"),
        # Standalone 12 consecutive digits
        re.compile(r"\b[2-9]{1}[0-9]{11}\b"),
    ],
    "PAN Card Number": [
        re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b"),
        re.compile(r"(?i)\b(?:pan(?:\s*card|\s*no|\s*num|\s*number)?)\s*(?:is|[:=]|\s+)\s*([A-Za-z0-9]{10})\b"),
    ],
    "Indian Passport Number": [
        re.compile(r"(?i)\b(?:passport(?:\s*no|\s*num|\s*number)?)\s*(?:is|[:=]|\s+)\s*([A-Za-z0-9]{8,12})\b"),
        re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b"),
    ],
    "Voter ID / EPIC Card": [
        re.compile(r"\b[A-Z]{3}[0-9]{7}\b"),
        re.compile(r"(?i)\b(?:voter\s*id|epic(?:\s*no|\s*num)?|election\s*card)\s*(?:is|[:=]|\s+)\s*([A-Za-z0-9/]{8,18})\b"),
    ],
    "Driving License (DL)": [
        re.compile(r"(?i)\b(?:driving\s*licen[sc]e|dl\s*no|licen[sc]e\s*no)\s*(?:is|[:=]|\s+)\s*([A-Za-z0-9\s-]{8,22})\b"),
        re.compile(r"\b[A-Z]{2}[0-9]{2}\s?[0-9]{4}\s?[0-9]{7}\b"),
        re.compile(r"\b[A-Z]{2}[ -]?[0-9]{2}[ -]?[0-9]{11}\b"),
    ],
    "Vehicle Registration / RC": [
        re.compile(r"(?i)\b(?:rc\s*no|vehicle\s*no|car\s*no|bike\s*no|reg(?:istration)?\s*no)\s*(?:is|[:=]|\s+)\s*([A-Za-z0-9\s-]{6,16})\b"),
        re.compile(r"\b[A-Z]{2}[ -]?[0-9]{1,2}[ -]?[A-Z]{1,3}[ -]?[0-9]{4}\b"),
    ],
    "GSTIN / GST Number": [
        re.compile(r"\b[0-9]{2}[A-Z]{5}[0-9]{4}[A-Z]{1}[1-9A-Z]{1}Z[0-9A-Z]{1}\b"),
        re.compile(r"(?i)\b(?:gstin|gst\s*no|gst\s*number)\s*(?:is|[:=]|\s+)\s*([0-9A-Za-z]{15})\b"),
    ],
    "TAN (Tax Deduction Number)": [
        re.compile(r"(?i)\b(?:tan(?:\s*no|\s*num|\s*number)?)\s*(?:is|[:=]|\s+)\s*([A-Za-z0-9]{10})\b"),
        re.compile(r"\b[A-Z]{4}[0-9]{5}[A-Z]{1}\b"),
    ],
    "CIN (Corporate Identity No)": [
        re.compile(r"\b[UL][0-9]{5}[A-Z]{2}[0-9]{4}[A-Z]{3}[0-9]{6}\b"),
    ],
    "DIN (Director Identity No)": [
        re.compile(r"(?i)\b(?:din(?:\s*no|\s*number)?)\s*(?:is|[:=]|\s+)\s*([0-9]{8})\b"),
    ],
    "EPFO / UAN / PF Account": [
        re.compile(r"(?i)\b(?:uan(?:\s*no|\s*number)?|epf(?:\s*no)?|pf\s*acc(?:ount)?)\s*(?:is|[:=]|\s+)\s*([0-9A-Za-z\s/-]{8,24})\b"),
    ],
    "ABHA / Health ID / PMJAY": [
        re.compile(r"\b[0-9]{2}-[0-9]{4}-[0-9]{4}-[0-9]{4}\b"),
        re.compile(r"(?i)\b(?:abha(?:\s*id|\s*no)?|pmjay|health\s*id)\s*(?:is|[:=]|\s+)\s*([0-9\s-]{12,18})\b"),
    ],
    "Ration Card Number": [
        re.compile(r"(?i)\b(?:ration\s*card(?:\s*no|\s*number)?)\s*(?:is|[:=]|\s+)\s*([0-9A-Za-z\s-]{8,20})\b"),
    ],
    "Legal Court Case / FIR / Property Deed": [
        re.compile(r"(?i)\b(?:fir\s*no|case\s*no|crime\s*no|registry\s*no|deed\s*no|khasra\s*no|khatauni|survey\s*no|property\s*id|plot\s*no)\s*(?:is|[:=]|\s+)\s*([0-9A-Za-z\s/-]{3,24})\b"),
    ],
    "Financial Amount": [
        # Shorthand amounts e.g. "50k", "100k", "500k", "10cr", "5.5 crore", "50 lacs", "2.5L", "150000 rupees"
        re.compile(r"(?i)\b([0-9]+(?:\.[0-9]+)?\s*(?:k|m|l|cr|lac|lacs|lakh|lakhs|crore|crores|rupees|bucks|dollars|rs|inr|usd|eur|cents))\b"),
        # Currency symbols prefixed (₹, Rs, INR, $, USD, EUR, €, £) e.g. "₹ 45,000", "INR 1,20,000.50", "$50000"
        re.compile(r"(?i)\b(?:(?:rs\.?|inr|₹|\$|usd|eur|€|£|gbp)\s*[0-9]+(?:,[0-9]{2,3})*(?:\.[0-9]{1,2})?(?:\s*(?:lakhs?|crores?|k|m|million|billion|thousand))?)\b"),
        # Contextual amount keyword (e.g. "Amount: 45000", "salary is 120000", "balance: 50,000")
        re.compile(r"(?i)\b(?:amount|amt|balance|bal|salary|transfer|paid|fee|cost|price|payout|sum)\s*(?:is|of|[:=]|\s+)\s*([₹\$€£]?[0-9,]+(?:\.[0-9]{1,2})?(?:\s*(?:lakhs?|crores?|k|m|inr|usd|rupees))?)\b"),
    ],
    "Bank Account & Bank Reference": [
        # Bank institution phrase e.g. "hdfc account", "sbi bank", "icici account", "axis branch"
        re.compile(r"(?i)\b((?:hdfc|icici|sbi|axis|pnb|bob|kotak|canara|yes\s*bank|indusind|idfc|citi|hsbc|barclays|chase|wells\s*fargo)\s+(?:bank|account|a/c|acc|branch))\b"),
        # Account Number e.g. "Account: 91823719284", "A/C 123456789012", "Acc No: 9988776655", "A/C 9876543210"
        re.compile(r"(?i)\b(?:a/c|acct|acc(?:ount)?(?:\s*no|\s*num|\s*number)?|bank\s*acc(?:ount)?)\s*(?:is|[:=]|\s+)\s*([0-9A-Za-z-]{6,24})\b"),
        # e.g. "transfer to 91823719284"
        re.compile(r"(?i)\b(?:transfer\s+to|credit\s+to|debit\s+from|bank\s+account)\s*[:=]?\s*([0-9]{8,18})\b"),
    ],
    "Account Holder / Beneficiary": [
        # e.g. "Beneficiary: Rajesh Sharma", "Payee Name: Priya Patel", "Account Holder: Vikram Malhotra"
        re.compile(r"(?i)\b(?:beneficiary|payee|acc(?:ount)?\s*holder|holder\s*name|account\s*name)\s*(?:is|[:=]|\s+)\s*([A-Za-z]+(?:\s+[A-Za-z]+){0,3}?)(?=\s+(?:pass|pwd|pw|amount|amt|acc|a/c|ifsc|pan|adhar|aadhar|phone|mob|email|upi)|[,\n\r\.\;]|\s*$)"),
    ],
    "Customer / Transactor / Person Name": [
        # Conversational transactor e.g. "rqavi transferred 50k", "priya paid 2500", "rahul sent 1000", "amit deposited"
        re.compile(r"(?i)\b([a-z]{3,20})\s+(?:transferred|transfered|sent|send|paid|payed|received|recieved|deposited|withdrew|debited|credited|swiped|borrowed|lent)\b"),
        # Preceded by transfer action e.g. "transferred to rohan", "sent to priya"
        re.compile(r"(?i)\b(?:transferred\s+to|sent\s+to|paid\s+to|received\s+from|credited\s+to|debited\s+from)\s+([A-Za-z]{3,20})\b"),
        # Name preceded by label e.g. "Name: Rahul Sharma", "Patient: Suresh Gupta", "Client: Ananya"
        re.compile(r"(?i)\b(?:Name|Customer|Client|User|Patient|Emp(?:loyee)?|Mr\.?|Mrs\.?|Ms\.?|Dr\.?)\s*[:=]\s*([A-Za-z]+(?:\s+[A-Za-z]+){0,3}?)(?=\s+(?:pass|pwd|pw|amount|amt|acc|a/c|ifsc|pan|adhar|aadhar|phone|mob|email|upi)|[,\n\r\.\;]|\s*$)"),
        # Name followed by identifier comma
        re.compile(r"\b([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]+)?)\s*,\s*(?:adhar|aadhar|pan|passw|pwd|pw|phone|mobile|email|\+?91|[0-9]{4})\b"),
        # Common individual names (Indian + Global)
        re.compile(r"\b(Rajesh|Rahul|Vikram|Vikramaditya|Priya|Sneha|Amit|Suresh|Ramesh|Rohan|Pooja|Neha|Ananya|Deepak|Manoj|Kavita|Sunil|Anil|Sanjay|Ajay|Alok|Naveen|Alka|Gaurav|Sachin|Manish|Harsh|Dev|Ravi|John|Jane|Alice|Bob|David|Michael|Sarah|Emma)\b"),
    ],
    "Credit / Debit Card": [
        re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        re.compile(r"(?i)\b(?:card|cc)\s*(?:no\.?|num|number)?\s*[:=]?\s*([0-9\s-]{15,19})\b"),
    ],
    "Email Address": [
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
    ],
    "Phone Number": [
        re.compile(r"\b(?:\+?91[\s-]?)?[6-9]\d{9}\b|\b(?:\+?1[\s-]?)?\(?\d{3}\)?[\s-]?\d{3}[\s-]?\d{4}\b"),
        re.compile(r"(?i)\b(?:mob(?:ile)?|phone|ph|contact)\s*(?:no\.?|num|number)?\s*[:=]?\s*(\+?[0-9\s-]{10,15})\b"),
    ],
    "UPI ID / VPA": [
        re.compile(r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b"),
    ],
    "AWS Access Key": [
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ],
    "Generic API / Secret Key": [
        re.compile(r"\b(?:sk_live_|ghp_|gho_|xoxb-|eyJh|AIzaSy)[a-zA-Z0-9_\-\.]{16,}\b"),
    ],
    "IPv4 Address": [
        re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
    ],
    "Indian IFSC Code": [
        re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
    ],
}

SYSTEM_INSTRUCTION = """You are SafeShare, an advanced enterprise AI privacy auditor and cybersecurity firewall with human-grade contextual intelligence.
Your mission is to analyze logs, support tickets, informal messages, emails, or prompts to detect ALL sensitive information that would violate privacy laws (such as India's DPDP Act 2023, GDPR, RBI Banking Guidelines, and PCI-DSS) or leak corporate secrets if shared with an external AI.

CRITICAL INTELLIGENCE & ROBUSTNESS RULES:
1. INDIAN LEGAL DOCUMENTS & GOVERNMENT IDENTIFIERS: You MUST detect all Indian legal documents and linked identification numbers, including:
   - Aadhaar Cards (UIDAI) in any format or spacing
   - PAN Cards (Income Tax Department)
   - Indian Passports & Voter IDs (EPIC)
   - Driving Licenses (DL) & Vehicle Registration (RC / Vahan numbers)
   - GSTIN (GST numbers), TAN, CIN (Corporate Identity Numbers), DIN (Director IDs)
   - EPFO / UAN (Universal Account Numbers), ABHA Health IDs / PMJAY cards
   - Ration Cards, Land records / Registry numbers / Property IDs / Khasra / Khatauni
   - Police FIR numbers, Court Case numbers, and Crime reference numbers.
2. CONVERSATIONAL STATEMENTS & TYPO TOLERANCE: Detect sensitive subjects in natural language even with typos or slang (e.g., "rqavi transferred 50k from his hdfc account", "adhar 452009 25009 42009", "pancrd is ABCDE1234F", "passwrd LicTower@2026", "mob 9826014492").
3. FINANCIAL AMOUNTS & SHORTHAND: Detect financial values in any notation (e.g., "50k", "100k", "500k", "10cr", "5.5 crore", "2.5L", "50 lacs", "₹45,000", "INR 1,50,000", "$50000").
4. STRICT GROUNDING: For EVERY finding, verbatim_quote MUST be the EXACT character-for-character substring present in the source text.
5. SUGGESTED_SYNTHETIC: Provide a clean synthetic token preserving grammatical context (e.g., "rqavi" -> "[CUSTOMER_1]", "50k" -> "[AMOUNT_1]", "hdfc account" -> "[ACCOUNT_1]", "4892 7741 9023" -> "[AADHAAR_1]").

CATEGORIES TO DETECT:
1. "SECRET": Passwords, API keys, database connection strings, JWT tokens, private SSH/cloud keys, secret tokens, PINs, OTPs.
2. "FINANCIAL_PII": Bank account numbers, bank names, credit/debit card numbers, UPI handles, transaction amounts, shorthand currency (50k, 10cr), salary/compensation, IFSC codes.
3. "GOVERNMENT_ID": Aadhaar numbers, PAN cards, Passports, Voter IDs, Driving Licenses, Vehicle RC numbers, GSTIN, TAN, CIN, DIN, UAN, ABHA Health IDs, Ration cards, Court Case/FIR numbers.
4. "PERSONAL_CONTACT": Personal names, transactor names in conversation, phone numbers, personal email addresses, residential addresses, medical diagnoses/PHI, beneficiary names.
5. "BUSINESS_CONFIDENTIAL": Unannounced M&A deal terms, company valuations, unpublished patents, internal trade secrets.

Output strictly valid JSON with this schema:
{
  "findings": [
    {
      "id": "f1",
      "category": "SECRET | FINANCIAL_PII | GOVERNMENT_ID | PERSONAL_CONTACT | BUSINESS_CONFIDENTIAL",
      "severity": "CRITICAL | HIGH | MEDIUM",
      "verbatim_quote": "Exact substring from text",
      "entity_type": "Specific label like Aadhaar, PAN Card, Driving License, Financial Amount, Customer Name, Bank Account",
      "suggested_synthetic": "Replacement token like [CUSTOMER_1], [AMOUNT_1], or [AADHAAR_1]",
      "risk_explanation": "Why this cannot be shared with public AI models"
    }
  ],
  "risk_score": 0 to 100,
  "compliance_summary": "1-2 sentence assessment of regulatory exposure (DPDP Act, PCI-DSS, RBI, etc.)"
}
"""


def scan_patterns(text: str) -> List[Dict[str, Any]]:
    """Fast heuristic regex scan for Indian legal documents, formatted secrets, PII, amounts, and bank accounts."""
    findings = []
    seen = set()
    counter = 1

    for label, pattern_list in PATTERNS.items():
        for pattern in pattern_list:
            for match in pattern.finditer(text):
                # If pattern has capturing group, isolate sensitive secret part
                val = (match.group(1) if match.groups() else match.group(0)).strip()
                if val and val not in seen and len(val) >= 2:
                    seen.add(val)

                    # Classify category and synthetic token prefix
                    category = "PERSONAL_CONTACT"
                    severity = "HIGH"
                    synthetic_prefix = "PII"

                    if "Password" in label or "Credential" in label:
                        category = "SECRET"
                        severity = "CRITICAL"
                        synthetic_prefix = "PASSWORD"
                    elif "Key" in label or "API" in label:
                        category = "SECRET"
                        severity = "CRITICAL"
                        synthetic_prefix = "API_KEY"
                    elif "Aadhaar" in label:
                        category = "GOVERNMENT_ID"
                        severity = "CRITICAL"
                        synthetic_prefix = "AADHAAR"
                    elif "PAN" in label:
                        category = "GOVERNMENT_ID"
                        severity = "CRITICAL"
                        synthetic_prefix = "PAN_CARD"
                    elif "Passport" in label:
                        category = "GOVERNMENT_ID"
                        severity = "CRITICAL"
                        synthetic_prefix = "PASSPORT"
                    elif "Voter" in label or "EPIC" in label:
                        category = "GOVERNMENT_ID"
                        severity = "HIGH"
                        synthetic_prefix = "VOTER_ID"
                    elif "Driving License" in label or "DL" in label:
                        category = "GOVERNMENT_ID"
                        severity = "HIGH"
                        synthetic_prefix = "DRIVING_LICENSE"
                    elif "Vehicle" in label or "RC" in label:
                        category = "GOVERNMENT_ID"
                        severity = "HIGH"
                        synthetic_prefix = "VEHICLE_RC"
                    elif "GSTIN" in label or "GST" in label:
                        category = "GOVERNMENT_ID"
                        severity = "CRITICAL"
                        synthetic_prefix = "GSTIN"
                    elif "TAN" in label:
                        category = "GOVERNMENT_ID"
                        severity = "HIGH"
                        synthetic_prefix = "TAN"
                    elif "CIN" in label:
                        category = "GOVERNMENT_ID"
                        severity = "HIGH"
                        synthetic_prefix = "CIN"
                    elif "DIN" in label:
                        category = "GOVERNMENT_ID"
                        severity = "HIGH"
                        synthetic_prefix = "DIN"
                    elif "UAN" in label or "EPFO" in label:
                        category = "GOVERNMENT_ID"
                        severity = "CRITICAL"
                        synthetic_prefix = "UAN"
                    elif "Health" in label or "ABHA" in label:
                        category = "GOVERNMENT_ID"
                        severity = "CRITICAL"
                        synthetic_prefix = "HEALTH_ID"
                    elif "Ration" in label:
                        category = "GOVERNMENT_ID"
                        severity = "HIGH"
                        synthetic_prefix = "RATION_CARD"
                    elif "Legal" in label or "Case" in label or "FIR" in label:
                        category = "GOVERNMENT_ID"
                        severity = "HIGH"
                        synthetic_prefix = "LEGAL_DOC"
                    elif "Amount" in label:
                        category = "FINANCIAL_PII"
                        severity = "HIGH"
                        synthetic_prefix = "AMOUNT"
                    elif "Bank" in label or "Account" in label:
                        category = "FINANCIAL_PII"
                        severity = "CRITICAL"
                        synthetic_prefix = "ACCOUNT"
                    elif "Beneficiary" in label:
                        category = "PERSONAL_CONTACT"
                        severity = "HIGH"
                        synthetic_prefix = "BENEFICIARY"
                    elif "Card" in label:
                        category = "FINANCIAL_PII"
                        severity = "CRITICAL"
                        synthetic_prefix = "CARD"
                    elif "UPI" in label:
                        category = "FINANCIAL_PII"
                        severity = "CRITICAL"
                        synthetic_prefix = "UPI_ID"
                    elif "IFSC" in label:
                        category = "FINANCIAL_PII"
                        severity = "HIGH"
                        synthetic_prefix = "IFSC"
                    elif "Name" in label or "Transactor" in label or "Customer" in label:
                        category = "PERSONAL_CONTACT"
                        severity = "HIGH"
                        synthetic_prefix = "CUSTOMER"
                    elif "Email" in label:
                        category = "PERSONAL_CONTACT"
                        severity = "HIGH"
                        synthetic_prefix = "EMAIL"
                    elif "Phone" in label:
                        category = "PERSONAL_CONTACT"
                        severity = "HIGH"
                        synthetic_prefix = "PHONE"
                    elif "IPv4" in label:
                        category = "SECRET"
                        severity = "MEDIUM"
                        synthetic_prefix = "IP_ADDRESS"

                    findings.append(
                        {
                            "id": f"p{counter}",
                            "category": category,
                            "severity": severity,
                            "verbatim_quote": val,
                            "entity_type": label,
                            "suggested_synthetic": f"[{synthetic_prefix}_{counter}]",
                            "risk_explanation": f"Matches standard structure for sensitive {label}.",
                            "source": "pattern_rule",
                        }
                    )
                    counter += 1

    return findings


def call_gemma_4_safeshare(
    text: str,
    api_key: Optional[str] = None,
    model_id: str = DEFAULT_MODEL,
    temperature: float = 0.1,
) -> Dict[str, Any]:
    """Call Google Gemma 4 on the Gemini API for deep semantic PII/Secret detection."""
    key = api_key or os.environ.get("GEMINI_API_KEY", "").strip()
    if not key:
        raise ValueError("Gemini API key is required to run Gemma 4 semantic scanning.")

    if model_id not in GEMMA_4_MODELS:
        model_id = DEFAULT_MODEL

    endpoint = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent?key={key}"

    prompt_content = f"{SYSTEM_INSTRUCTION}\n\n=== TEXT TO AUDIT FOR SENSITIVE DATA ===\n{text}\n=== END TEXT ===\n\nGenerate the JSON audit report:"

    payload = {
        "contents": [{"role": "user", "parts": [{"text": prompt_content}]}],
        "generationConfig": {
            "temperature": temperature,
            "responseMimeType": "application/json",
        },
    }

    req = urllib.request.Request(
        endpoint,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw_json = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        try:
            err_json = json.loads(err_msg)
            detailed = err_json.get("error", {}).get("message", err_msg)
        except Exception:
            detailed = err_msg
        raise RuntimeError(f"Gemma 4 API Error ({e.code}): {detailed}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error contacting Gemma 4 API: {e.reason}")

    candidates = raw_json.get("candidates", [])
    if not candidates:
        raise RuntimeError("Gemma 4 returned no content candidates.")

    content_parts = candidates[0].get("content", {}).get("parts", [])
    if not content_parts:
        raise RuntimeError("Gemma 4 returned empty content parts.")

    raw_text = content_parts[0].get("text", "").strip()
    if raw_text.startswith("```json"):
        raw_text = raw_text[7:]
    if raw_text.startswith("```"):
        raw_text = raw_text[3:]
    if raw_text.endswith("```"):
        raw_text = raw_text[:-3]

    try:
        result = json.loads(raw_text.strip())
    except Exception as exc:
        m = re.search(r"\{[\s\S]*\}", raw_text)
        if m:
            result = json.loads(m.group(0))
        else:
            raise RuntimeError(f"Failed to parse Gemma 4 JSON: {exc}")

    result["model_used"] = model_id
    result["model_name"] = GEMMA_4_MODELS[model_id]["name"]
    return result


def merge_and_anonymize(
    original_text: str,
    pattern_findings: List[Dict[str, Any]],
    gemma_findings: List[Dict[str, Any]],
    mask_mode: str = "synthetic",  # 'synthetic' or 'redacted'
) -> Dict[str, Any]:
    """Merge pattern-based and semantic findings, calculate risk score, and generate sanitized text with vault."""
    all_findings = []
    seen_quotes = set()

    # Priority to Gemma findings (richer explanations), supplemented by pattern findings
    for f in gemma_findings + pattern_findings:
        quote = (f.get("verbatim_quote") or "").strip()
        if not quote:
            continue
        # Avoid duplicates or sub-string overlap
        if quote not in seen_quotes and quote in original_text:
            seen_quotes.add(quote)
            all_findings.append(f)

    # Sort findings by start position in text (descending) so string replacement doesn't shift indices
    findings_with_pos = []
    for f in all_findings:
        quote = f["verbatim_quote"]
        # Find all occurrences
        start = 0
        while True:
            idx = original_text.find(quote, start)
            if idx == -1:
                break
            findings_with_pos.append((idx, len(quote), f))
            start = idx + len(quote)

    # Remove overlapping ranges
    findings_with_pos.sort(key=lambda x: x[0])
    non_overlapping = []
    last_end = -1
    for start, length, f in findings_with_pos:
        if start >= last_end:
            non_overlapping.append((start, length, f))
            last_end = start + length

    # Build Sanitized Text and Reversible Vault
    vault = {}  # { "[TOKEN]": original_value }
    sanitized_parts = []
    curr_idx = 0
    token_counters = {}

    for start, length, f in non_overlapping:
        sanitized_parts.append(original_text[curr_idx:start])
        orig_val = original_text[start : start + length]
        cat = f.get("category", "PII")

        if mask_mode == "redacted":
            placeholder = f"[{cat}]"
        else:
            # Synthetic unique placeholder using suggested prefix or specific entity tag
            suggested = f.get("suggested_synthetic") or ""
            if suggested.startswith("[") and suggested.endswith("]"):
                tag = suggested.strip("[]").rsplit("_", 1)[0]
            elif "Password" in f.get("entity_type", "") or "Credential" in f.get("entity_type", ""):
                tag = "PASSWORD"
            elif "Aadhaar" in f.get("entity_type", ""):
                tag = "AADHAAR"
            elif "Passport" in f.get("entity_type", ""):
                tag = "PASSPORT"
            elif "Voter" in f.get("entity_type", "") or "EPIC" in f.get("entity_type", ""):
                tag = "VOTER_ID"
            elif "Driving License" in f.get("entity_type", "") or "DL" in f.get("entity_type", ""):
                tag = "DRIVING_LICENSE"
            elif "Vehicle" in f.get("entity_type", "") or "RC" in f.get("entity_type", ""):
                tag = "VEHICLE_RC"
            elif "GSTIN" in f.get("entity_type", "") or "GST" in f.get("entity_type", ""):
                tag = "GSTIN"
            elif "TAN" in f.get("entity_type", ""):
                tag = "TAN"
            elif "CIN" in f.get("entity_type", ""):
                tag = "CIN"
            elif "DIN" in f.get("entity_type", ""):
                tag = "DIN"
            elif "UAN" in f.get("entity_type", "") or "EPFO" in f.get("entity_type", ""):
                tag = "UAN"
            elif "Health" in f.get("entity_type", "") or "ABHA" in f.get("entity_type", ""):
                tag = "HEALTH_ID"
            elif "Ration" in f.get("entity_type", ""):
                tag = "RATION_CARD"
            elif "Legal" in f.get("entity_type", "") or "Case" in f.get("entity_type", "") or "FIR" in f.get("entity_type", ""):
                tag = "LEGAL_DOC"
            elif "Amount" in f.get("entity_type", ""):
                tag = "AMOUNT"
            elif "Bank" in f.get("entity_type", "") or "Account" in f.get("entity_type", ""):
                tag = "ACCOUNT"
            elif "Beneficiary" in f.get("entity_type", "") or "Payee" in f.get("entity_type", ""):
                tag = "BENEFICIARY"
            elif "Name" in f.get("entity_type", "") or "Transactor" in f.get("entity_type", ""):
                tag = "CUSTOMER"
            elif "PAN" in f.get("entity_type", ""):
                tag = "PAN_CARD"
            elif "Card" in f.get("entity_type", ""):
                tag = "CARD"
            elif "UPI" in f.get("entity_type", ""):
                tag = "UPI_ID"
            elif "IFSC" in f.get("entity_type", ""):
                tag = "IFSC"
            elif "Phone" in f.get("entity_type", ""):
                tag = "PHONE"
            elif "Email" in f.get("entity_type", ""):
                tag = "EMAIL"
            elif "Key" in f.get("entity_type", ""):
                tag = "API_KEY"
            else:
                tag = cat

            count = token_counters.get(tag, 1)
            token_counters[tag] = count + 1
            placeholder = f"[{tag}_{count}]"

        vault[placeholder] = orig_val
        sanitized_parts.append(placeholder)
        curr_idx = start + length

    sanitized_parts.append(original_text[curr_idx:])
    sanitized_text = "".join(sanitized_parts)

    # Calculate Risk Score (0 - 100)
    critical_count = sum(1 for f in all_findings if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in all_findings if f.get("severity") == "HIGH")
    med_count = sum(1 for f in all_findings if f.get("severity") == "MEDIUM")

    score = min(100, (critical_count * 30) + (high_count * 15) + (med_count * 5))

    return {
        "original_text": original_text,
        "sanitized_text": sanitized_text,
        "mask_mode": mask_mode,
        "findings": all_findings,
        "vault": vault,
        "stats": {
            "total_risks_detected": len(all_findings),
            "critical_risks": critical_count,
            "high_risks": high_count,
            "medium_risks": med_count,
            "risk_score": score,
            "risk_level": "CRITICAL RISK" if score >= 75 else ("HIGH RISK" if score >= 40 else "MODERATE"),
        },
    }


def restore_text(sanitized_text: str, vault: Dict[str, str]) -> str:
    """Re-identify synthetic placeholders using the local vault table."""
    restored = sanitized_text
    # Replace in order of longest token to shortest to avoid partial match bugs
    for token in sorted(vault.keys(), key=len, reverse=True):
        orig = vault[token]
        restored = restored.replace(token, orig)
    return restored
