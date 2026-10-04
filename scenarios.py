"""Realistic benchmark scenarios for SafeShare live demos & testing.
Tailored for IDFC FIRST Bank, fintech compliance, DevOps security, and corporate confidentiality.
"""

SCENARIOS = {
    "idfc_banking_dispute": {
        "title": "🏦 IDFC Customer Banking Dispute & Chargeback",
        "description": "Customer support ticket with Aadhaar, PAN, savings account, UPI ID, and disputed debit amount.",
        "text": """Ticket #IDFC-89421 - Escalated Fraud Dispute
Customer Name: Vikramaditya Singhania
Registered Mobile: +91 9826014492
Email: vikram.singhania78@gmail.com
Customer ID / CIF: 809441203
Aadhaar Card: 4892 7741 9023
Permanent Account Number (PAN): BDFPS8921K
Primary Savings Account: 100492819034 (IDFC FIRST Bank, Palasia Branch, Indore)

Complaint Details:
"I noticed an unauthorized UPI debit of Rs. 48,500 on 3rd October at 23:14 IST.
The payment was debited to merchant handle: quickpay_gateway@icici.
My linked UPI VPA is vikram.singhania@okhdfcbank.
I did not share any OTP or UPI PIN. Please freeze debit card ending in 4192-8801-4491-0021 immediately and initiate an RBI chargeback refund."

Agent Internal Note:
Verified customer via Aadhaar biometrics match. Balance currently Rs. 1,42,800. Needs immediate cyber cell escalation.""",
        "cached_audit": {
            "compliance_summary": "Violates RBI Digital Payment Security Guidelines and India's DPDP Act 2023. Contains full Aadhaar, PAN, Bank Account Number, and active UPI VPA.",
            "risk_score": 98,
            "risk_level": "CRITICAL RISK",
            "findings": [
                {
                    "id": "f1",
                    "category": "GOVERNMENT_ID",
                    "severity": "CRITICAL",
                    "verbatim_quote": "4892 7741 9023",
                    "entity_type": "Aadhaar Card Number",
                    "suggested_synthetic": "[AADHAAR_1]",
                    "risk_explanation": "Direct violation of Aadhaar Act & DPDP Act 2023. Storing or transmitting unmasked Aadhaar carries strict penalties.",
                },
                {
                    "id": "f2",
                    "category": "GOVERNMENT_ID",
                    "severity": "CRITICAL",
                    "verbatim_quote": "BDFPS8921K",
                    "entity_type": "PAN Card Number",
                    "suggested_synthetic": "[PAN_1]",
                    "risk_explanation": "Permanent Account Number is sensitive tax identity PII subject to mandatory data protection controls.",
                },
                {
                    "id": "f3",
                    "category": "FINANCIAL_PII",
                    "severity": "CRITICAL",
                    "verbatim_quote": "100492819034",
                    "entity_type": "Primary Bank Account Number",
                    "suggested_synthetic": "[BANK_ACCOUNT_1]",
                    "risk_explanation": "Direct bank account number exposed in plain text; triggers RBI Cyber Security Framework non-compliance.",
                },
                {
                    "id": "f4",
                    "category": "FINANCIAL_PII",
                    "severity": "CRITICAL",
                    "verbatim_quote": "4192-8801-4491-0021",
                    "entity_type": "Debit Card Number",
                    "suggested_synthetic": "[DEBIT_CARD_1]",
                    "risk_explanation": "Full 16-digit Primary Account Number (PAN) violation under PCI-DSS Requirement 3.3.",
                },
                {
                    "id": "f5",
                    "category": "FINANCIAL_PII",
                    "severity": "HIGH",
                    "verbatim_quote": "vikram.singhania@okhdfcbank",
                    "entity_type": "UPI VPA Handle",
                    "suggested_synthetic": "[UPI_ID_1]",
                    "risk_explanation": "Financial identifier linking person to bank handle.",
                },
                {
                    "id": "f6",
                    "category": "PERSONAL_CONTACT",
                    "severity": "HIGH",
                    "verbatim_quote": "+91 9826014492",
                    "entity_type": "Mobile Phone Number",
                    "suggested_synthetic": "[PHONE_1]",
                    "risk_explanation": "Personally identifiable contact number protected under DPDP Act.",
                },
                {
                    "id": "f7",
                    "category": "PERSONAL_CONTACT",
                    "severity": "HIGH",
                    "verbatim_quote": "Vikramaditya Singhania",
                    "entity_type": "Customer Full Name",
                    "suggested_synthetic": "[CUSTOMER_1]",
                    "risk_explanation": "Direct identity link to all financial and banking records.",
                },
            ],
        },
    },
    "devops_production_crash": {
        "title": "💻 DevOps Incident & Server Crash Stacktrace",
        "description": "Production bug log containing live AWS credentials, PostgreSQL root password, and internal server IP.",
        "text": """[2026-10-04 02:41:09 UTC] [CRITICAL] worker-pod-us-east-1a: Fatal DBConnectionException
Traceback (most recent call last):
  File "/app/services/payments.py", line 112, in execute_transaction
    db = PostgresPool.connect("postgres://admin_user:SuperSecretPass2026!@10.142.8.21:5432/fintech_prod")
  File "/app/utils/vault_client.py", line 45, in get_s3_backup
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    s3.upload_file(Bucket="internal-client-ledgers-prod", Key="backup_oct4.enc")

Authentication Header: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcmFkbWluIn0.sH92jF-09aklwjef902jflkwe
Server Internal IP: 10.142.8.21
Host: lic-tower-node-04.internal.walkover.net

Please paste this log into Claude / ChatGPT to generate a quick hotfix for the connection pooling leak.""",
        "cached_audit": {
            "compliance_summary": "Extremely hazardous secret exposure. Exposes production database credentials, AWS access keys, and superadmin JWT session token.",
            "risk_score": 100,
            "risk_level": "CRITICAL RISK",
            "findings": [
                {
                    "id": "f1",
                    "category": "SECRET",
                    "severity": "CRITICAL",
                    "verbatim_quote": "postgres://admin_user:SuperSecretPass2026!@10.142.8.21:5432/fintech_prod",
                    "entity_type": "Database Connection String with Password",
                    "suggested_synthetic": "[DB_CONN_STRING_1]",
                    "risk_explanation": "Direct database credentials leaked in plain text. Sharing with public AI could lead to database takeover.",
                },
                {
                    "id": "f2",
                    "category": "SECRET",
                    "severity": "CRITICAL",
                    "verbatim_quote": "AKIAIOSFODNN7EXAMPLE",
                    "entity_type": "AWS Access Key ID",
                    "suggested_synthetic": "[AWS_KEY_1]",
                    "risk_explanation": "Active cloud infrastructure credentials; automated bots crawl public/shared prompts for AWS keys.",
                },
                {
                    "id": "f3",
                    "category": "SECRET",
                    "severity": "CRITICAL",
                    "verbatim_quote": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJzdXBlcmFkbWluIn0.sH92jF-09aklwjef902jflkwe",
                    "entity_type": "Superadmin JWT Bearer Token",
                    "suggested_synthetic": "[JWT_TOKEN_1]",
                    "risk_explanation": "Valid session token with superadmin privileges allowing authentication bypass.",
                },
                {
                    "id": "f4",
                    "category": "SECRET",
                    "severity": "MEDIUM",
                    "verbatim_quote": "10.142.8.21",
                    "entity_type": "Internal VPC IPv4 Address",
                    "suggested_synthetic": "[INTERNAL_IP_1]",
                    "risk_explanation": "Reveals internal VPC private subnet architecture.",
                },
            ],
        },
    },
    "hr_payroll_medical": {
        "title": "🩺 HR Employee Health & Salary Record",
        "description": "Employee performance review, medical diagnosis, Aadhaar number, and CTC compensation breakdown.",
        "text": """CONFIDENTIAL HR RECORD - IDFC & WALKOVER JOINT TALENT REVIEW
Employee: Priya Sharma (EMP-90214)
Date of Birth: 14/08/1997
Aadhaar Number: 9102 3341 5509
Current Designation: Senior Backend Engineer
Annual CTC: ₹28,50,000 (Base: ₹24,00,000 + ESOPs: ₹4,50,000)
Salary Bank Account: HDFC Bank A/c 50100294819012 (IFSC: HDFC0001824)

Health Insurance Reimbursement Request:
Diagnosis: Stage-1 Diabetic Retinopathy & Chronic Hypertension
Hospital: Care CHL Hospital, AB Road, Indore
Claim Amount: ₹84,200

Performance Review Notes:
"Priya received a Performance Rating 4.8/5. Recommended for Tech Lead promotion in Q4 review cycle."

HR Coordinator: Ananya Mehta (ananya.mehta@company-internal.in)""",
        "cached_audit": {
            "compliance_summary": "Contains sensitive personal data (health/medical diagnosis, Aadhaar, salary breakdown) protected under India's Digital Personal Data Protection Act (DPDP Act 2023).",
            "risk_score": 92,
            "risk_level": "CRITICAL RISK",
            "findings": [
                {
                    "id": "f1",
                    "category": "GOVERNMENT_ID",
                    "severity": "CRITICAL",
                    "verbatim_quote": "9102 3341 5509",
                    "entity_type": "Aadhaar Card Number",
                    "suggested_synthetic": "[AADHAAR_1]",
                    "risk_explanation": "Government biometric identifier prohibited from being shared without tokenization.",
                },
                {
                    "id": "f2",
                    "category": "PERSONAL_CONTACT",
                    "severity": "HIGH",
                    "verbatim_quote": "Stage-1 Diabetic Retinopathy & Chronic Hypertension",
                    "entity_type": "Protected Health Information (PHI)",
                    "suggested_synthetic": "[MEDICAL_DIAGNOSIS_1]",
                    "risk_explanation": "Special category sensitive personal data under DPDP Act and international health privacy laws.",
                },
                {
                    "id": "f3",
                    "category": "FINANCIAL_PII",
                    "severity": "HIGH",
                    "verbatim_quote": "50100294819012",
                    "entity_type": "Salary Bank Account Number",
                    "suggested_synthetic": "[BANK_ACCOUNT_1]",
                    "risk_explanation": "Direct account details linked to salary disbursements.",
                },
                {
                    "id": "f4",
                    "category": "BUSINESS_CONFIDENTIAL",
                    "severity": "MEDIUM",
                    "verbatim_quote": "₹28,50,000 (Base: ₹24,00,000 + ESOPs: ₹4,50,000)",
                    "entity_type": "Confidential Employee CTC",
                    "suggested_synthetic": "[COMPENSATION_PACKAGE_1]",
                    "risk_explanation": "Proprietary internal salary benchmarking data.",
                },
            ],
        },
    },
    "merger_acquisition_leak": {
        "title": "🏢 Executive M&A Deal & Revenue Leak",
        "description": "Unreleased acquisition terms, company valuation, and customer contract figures.",
        "text": """STRICTLY CONFIDENTIAL - ATTORNEY-CLIENT PRIVILEGED
From: Rajiv Kapoor (Managing Director, Capital Partners)
To: Board of Directors
Subject: Project Garuda - Acquisition of CloudScale Networks Pvt Ltd

Dear Board,

Following our due diligence call with Walkover and IDFC Investment Banking:
1. Proposed Acquisition Valuation: $48,500,000 (Cash payout $32M + stock swap).
2. Key Client ARR Leak Risk: CloudScale currently bills Reliance Jio ₹14.8 Cr/year and Tata Digital ₹9.2 Cr/year.
3. Unannounced Patent: Their proprietary distributed caching protocol (Patent Application IN-202611094) must remain strictly undisclosed until IPO filing in March 2027.
4. Target Founder Escrow: Founder Rohan Deshmukh will receive an earnout of ₹18 Cr conditional on 25% YoY EBITDA retention.

Do not upload any part of this document to commercial LLMs for summarization under strict NDA terms.""",
        "cached_audit": {
            "compliance_summary": "Severe insider trading and NDA breach risk. Exposes unannounced M&A valuation ($48.5M), major client revenue figures, and unpublished patent IP.",
            "risk_score": 95,
            "risk_level": "CRITICAL RISK",
            "findings": [
                {
                    "id": "f1",
                    "category": "BUSINESS_CONFIDENTIAL",
                    "severity": "CRITICAL",
                    "verbatim_quote": "$48,500,000 (Cash payout $32M + stock swap)",
                    "entity_type": "M&A Acquisition Valuation",
                    "suggested_synthetic": "[DEAL_VALUATION_1]",
                    "risk_explanation": "Material Non-Public Information (MNPI). Leaking to AI models risks insider trading regulations.",
                },
                {
                    "id": "f2",
                    "category": "BUSINESS_CONFIDENTIAL",
                    "severity": "CRITICAL",
                    "verbatim_quote": "Patent Application IN-202611094",
                    "entity_type": "Unpublished Patent Application",
                    "suggested_synthetic": "[PATENT_REF_1]",
                    "risk_explanation": "Unpublished intellectual property. AI training or caching could invalidate global patent priority.",
                },
                {
                    "id": "f3",
                    "category": "BUSINESS_CONFIDENTIAL",
                    "severity": "HIGH",
                    "verbatim_quote": "Reliance Jio ₹14.8 Cr/year and Tata Digital ₹9.2 Cr/year",
                    "entity_type": "Enterprise Client ARR Contract Revenue",
                    "suggested_synthetic": "[CLIENT_REVENUE_METRICS_1]",
                    "risk_explanation": "Breaches confidential vendor NDAs with major telecommunications enterprise clients.",
                },
            ],
        },
    },
}
