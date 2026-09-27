 🛡️ DarkShield — AI Security Platform

   AI-Powered Defense Against Phishing, Scams & Social Engineering

DarkShield is a cybersecurity platform designed to help users identify phishing, scams, and social-engineering attacks by analyzing both **technical threat indicators** and **human-manipulation techniques**.

Unlike systems that only check whether a URL is suspicious, DarkShield also looks for tactics such as **fake urgency, scarcity, impersonation, fake social proof, credential requests, and suspicious payment behavior**.

---

 🚀 Live Demo

🔗 **Live Demo:**  
https://rococo-tulumba-594198.netlify.app/

🔗 **GitHub:**  
https://github.com/Vandana-s-h/DarkShield-

---

 🎯 Problem

AI is making phishing and social-engineering attacks more convincing and harder to detect.

Attackers can create realistic:

- Fake websites
- Phishing messages
- Product descriptions
- Reviews
- Brand impersonation
- Urgency and scarcity messages
- Fake social proof

These techniques can pressure users into revealing credentials, making payments, or sharing sensitive information.

Traditional protection often focuses primarily on suspicious links or known malicious domains, while the **psychological manipulation used by the attacker can remain difficult for users to understand**.

---

 💡 Our Solution

DarkShield combines two categories of signals:

 🔐 Technical Threat Signals

- Suspicious URL structure
- Domain anomalies
- Brand impersonation
- Suspicious login pages
- Payment information requests
- Redirect indicators
- Suspicious paths and parameters

 🧠 Social-Engineering Signals

- Fake urgency
- Fake scarcity
- Fear or pressure
- Impersonation
- Fake social proof
- Suspicious requests for credentials or payments

These signals are combined to produce a **transparent risk score** and an explanation of why the content may be dangerous.

---

 📊 Risk Scoring

DarkShield uses a transparent rule-based scoring approach.

Example signals include:

Signal	Weight
Suspicious domain	+15
Brand impersonation	+20
Fake countdown	+15
Fake social proof	+10
Fake scarcity	+10
Suspicious login request	+20
Suspicious payment form	+20

Risk levels:

0–25: Low
26–50: Moderate
51–75: High
76–100: Critical

The score represents a risk assessment, not a probability that a website is fraudulent.

🛒 Example Attack Scenario

DarkShield demonstrates an AI-assisted shopping scam where an attacker creates a convincing fake product page.

Example indicators:

Extremely low product price
Brand impersonation
"Only 2 left" scarcity message
Fake purchase activity
Countdown timer
Suspicious domain
Login or payment request

Instead of simply saying:

"This website is dangerous."

DarkShield explains the specific signals and manipulation techniques that contributed to the risk assessment.

✨ Key Features
🔎 URL Analysis

Analyzes URL structure for suspicious characteristics such as:

Domain anomalies
Suspicious TLDs
Excessive subdomains
Unusual characters
Suspicious paths
Redirect parameters
Brand impersonation patterns
🧠 Social-Engineering Detection

Identifies manipulation techniques including:

Urgency
Scarcity
Fake social proof
Impersonation
Credential pressure
Payment pressure
📈 Explainable Risk Score

Provides a transparent score instead of an unexplained classification.

🤖 AI Threat Analysis

Converts detected evidence into a human-readable security explanation.

🛡️ Protection Guidance

Helps users understand what makes the content suspicious and what action they should take.

📜 Scan History

Keeps track of previous security scans performed through the interface.

🎭 Demonstration Scenarios

Includes simulated phishing and scam scenarios for demonstrating different attack patterns.

🆚 What Makes DarkShield Different?

Traditional protection may focus primarily on:

Suspicious URL
       ↓
Warning

DarkShield aims to provide a broader explanation:

Technical Signals
       +
Social-Engineering Signals
       ↓
Risk Analysis
       ↓
"WHY is this suspicious?"
       ↓
"WHAT should the user do?"
USP

Don't just detect the threat. Explain the manipulation.

🏗️ Technology Stack
Frontend
HTML
CSS
JavaScript
Security Analysis
URL structure analysis
Rule-based threat detection
Pattern matching
Social-engineering signal detection
Explainable risk scoring
AI Layer
AI-assisted threat explanation architecture
Evidence-driven analysis
Deployment
Netlify
GitHub
🧩 Architecture
                ┌─────────────────┐
                │      User       │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │   DarkShield    │
                │    Interface    │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │ Signal Extraction│
                └────────┬────────┘
                         ↓
          ┌──────────────┴──────────────┐
          ↓                             ↓
 ┌─────────────────┐           ┌─────────────────┐
 │ Technical       │           │ Social           │
 │ Threat Signals  │           │ Engineering      │
 └────────┬────────┘           └────────┬────────┘
          └──────────────┬──────────────┘
                         ↓
                ┌─────────────────┐
                │  Risk Analysis  │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │ Risk Score +    │
                │ Explanation     │
                └────────┬────────┘
                         ↓
                ┌─────────────────┐
                │ User Protection │
                └─────────────────┘
🧪 Current Prototype

The current prototype demonstrates:

URL-based threat analysis
Social-engineering signal detection
Transparent risk scoring
Explainable security analysis
Multiple simulated attack scenarios
Scan history
Security dashboard
Deployed web interface

The standalone prototype analyzes the URL structure and user-provided content. It does not claim to fetch and inspect arbitrary remote webpages directly.

🔮 Future Scope

DarkShield can be extended with:

Live threat-intelligence APIs
Domain reputation checking
Browser extension integration
Real-time webpage DOM analysis
URL scanning through a secure backend
QR-code phishing detection
Email and SMS analysis
Multilingual scam detection
Threat intelligence correlation
Downloadable security reports
Automated browser warnings
🛡️ Security Philosophy

DarkShield follows an explainable security approach:

Detect → Correlate → Explain → Protect

The goal is not only to identify suspicious content, but also to help users understand how attackers are attempting to manipulate them.

📌 Project Status

Hackathon Prototype — Async'26

DarkShield is currently a functional proof-of-concept demonstrating explainable phishing, scam, and social-engineering detection.

👥 Team

Built for Async'26.

⚠️ Disclaimer

DarkShield is a cybersecurity research and demonstration prototype.

Its risk assessment should not be treated as a guarantee that a website or message is safe or malicious. Real-world deployment would require additional reputation services, threat intelligence, backend infrastructure, and continuous security validation.
 
