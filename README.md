# 🛡️ DarkShield — Explainable Security Platform

**Detect phishing, scams, and social-engineering attacks — and explain why they are suspicious.**

DarkShield is a cybersecurity research and demonstration platform that analyzes URLs and user-provided content for technical threat indicators and social-engineering signals.

Instead of only displaying a warning, DarkShield combines detected evidence into a **transparent risk score**, explains the signals that contributed to the result, and provides defensive guidance.

---

## 🚀 Live Demo

**Live Demo:**
https://rococo-tulumba-594198.netlify.app/

**GitHub:**
https://github.com/Vandana-s-h/DarkShield-

---

## 🎯 Problem

Phishing and social-engineering attacks increasingly rely on convincing messages, fake websites, impersonation, urgency, scarcity, and other manipulation techniques.

Attackers may use:

* Fake websites
* Brand impersonation
* Urgency and countdown messages
* Scarcity claims
* Fake social proof
* Credential requests
* Payment requests
* Suspicious redirects

A security warning is more useful when the user can understand **why** the target appears suspicious and what they should do next.

---

## 💡 Our Solution

DarkShield combines two categories of security signals.

### 🔐 Technical Threat Signals

* Suspicious URL structure
* Domain anomalies
* Higher-risk TLDs
* Excessive subdomains
* Heavy domain hyphenation
* Unusually long domain names
* Suspicious paths and parameters
* Suspicious login requests
* Suspicious payment requests
* Suspicious redirects
* Raw IP-based destinations
* Brand impersonation patterns

### 🧠 Social-Engineering Signals

* Fake urgency
* Fake scarcity
* Fear or pressure
* Fake social proof
* Prize or reward lures
* Credential pressure
* Payment pressure

These signals are correlated using a **transparent rule-based detection engine** and presented through an explanation engine.

---

## 📊 Transparent Risk Scoring

DarkShield uses weighted security signals to calculate a score from **0–100**.

Example signals include:

| Signal                   | Weight |
| ------------------------ | -----: |
| Suspicious domain        |    +15 |
| Brand impersonation      |    +20 |
| Fake countdown           |    +15 |
| Fake social proof        |    +10 |
| Fake scarcity            |    +10 |
| Suspicious login request |    +20 |
| Suspicious payment form  |    +20 |
| Prize / reward lure      |    +30 |

### Risk Levels

|  Score | Level    |
| -----: | -------- |
|   0–25 | Low      |
|  26–50 | Moderate |
|  51–75 | High     |
| 76–100 | Critical |

The score is a **heuristic risk assessment**, not a probability that a website is malicious.

---

## 🔎 URL Analysis

DarkShield analyzes URL structure for suspicious characteristics including:

* Domain anomalies
* Higher-risk TLDs
* Excessive subdomains
* Heavy domain hyphenation
* Unusually long domains
* Suspicious paths and parameters
* Raw IP destinations
* Brand impersonation
* Login and payment indicators
* Redirect indicators

---

## 🧠 Social-Engineering Detection

The detector identifies patterns associated with manipulation, including:

* Urgency
* Scarcity
* Fear or pressure
* Fake social proof
* Prize or reward lures
* Credential requests
* Payment requests

---

## 📈 Explainable Risk Assessment

DarkShield does not stop at a numerical score.

The interface shows:

**Detected Signals → Risk Score → Threat Explanation → Recommended Action**

The explanation engine describes the signals contributing to the result and provides context about the potential manipulation.

---

## 📜 DNS / Browser Log Import

DarkShield can analyze multiple domains from:

* DNS query logs
* Browser-history exports
* Hosts-style lists
* `.txt` files
* `.csv` files
* `.log` files

The domain column is automatically detected from imported data.

The interface displays:

* Domain
* Risk level
* Risk score
* Detected signals
* Individual explanations

---

## 🛡️ Blocklist Export

Flagged domains can be exported as a local blocklist.

Supported thresholds include:

* Moderate and above
* High and above

The generated list can be reviewed before being loaded into compatible tools such as Pi-hole or AdGuard.

---

## 🕘 Scan History

DarkShield keeps a local history of recent scans, including:

* Target
* Risk score
* Risk level
* Number of detected signals
* Scan time
* Detailed report

---

## 🎭 Demonstration Scenarios

The prototype includes simulated scenarios representing common attack patterns such as:

* Shopping scams
* Delivery scams
* Banking / KYC scams
* Safe websites

These scenarios are designed for demonstration and testing of the detection and explanation pipeline.

---

## 🆚 What Makes DarkShield Different?

### Traditional approach

```text
Suspicious URL
      ↓
   Warning
```

### DarkShield approach

```text
Technical Signals
        +
Social-Engineering Signals
        ↓
  Evidence Correlation
        ↓
   Risk Assessment
        ↓
 Threat Explanation
        ↓
 Defensive Guidance
```

### USP

> **Don't just detect the threat. Explain the manipulation.**

---

## 🏗️ Technology Stack

### Frontend

* HTML
* CSS
* JavaScript

### Security Analysis

* URL structure analysis
* Rule-based threat detection
* Pattern matching
* Social-engineering signal detection
* Explainable risk scoring
* Local log analysis

### Explanation Layer

* Evidence-driven threat explanation
* Rule-based signal correlation
* Human-readable security guidance

### Deployment

* Netlify
* GitHub

---

## 🧩 Architecture

```text
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
             ┌─────────────┴─────────────┐
             ↓                           ↓
    ┌─────────────────┐         ┌─────────────────┐
    │ Technical       │         │ Social-         │
    │ Threat Signals  │         │ Engineering     │
    └────────┬────────┘         └────────┬────────┘
             └─────────────┬─────────────┘
                           ↓
                  ┌─────────────────┐
                  │ Rule-Based      │
                  │ Correlation     │
                  └────────┬────────┘
                           ↓
                  ┌─────────────────┐
                  │ Risk Assessment │
                  └────────┬────────┘
                           ↓
                  ┌─────────────────┐
                  │ Explanation +   │
                  │ Protection      │
                  └─────────────────┘
```

---

## 🧪 Current Prototype

The current prototype demonstrates:

* URL-based threat analysis
* Social-engineering detection
* Transparent risk scoring
* Explainable threat analysis
* Brand impersonation detection
* DNS / browser log import
* Local blocklist generation
* Scan history
* Simulated attack scenarios
* Security dashboard
* Deployed web interface

### Important Limitation

The standalone browser prototype analyzes **URL structure and user-provided content**.

It does **not** directly fetch and inspect arbitrary remote webpages.

---

## 🔮 Future Scope

Potential extensions include:

* Live threat-intelligence APIs
* Domain reputation services
* Secure backend URL scanning
* Browser extension integration
* Real-time webpage DOM analysis
* QR-code phishing detection
* Email and SMS analysis
* Multilingual scam detection
* Threat-intelligence correlation
* Downloadable security reports
* Automated browser warnings

---

## 🛡️ Security Philosophy

DarkShield follows an explainable security workflow:

```text
Detect → Correlate → Explain → Protect
```

The goal is not only to identify suspicious content, but also to help users understand the techniques an attacker may be using and the actions they can take to verify a target safely.

---

## 📌 Project Status

**Hackathon Prototype — Async'26**

DarkShield is a functional proof-of-concept for explainable phishing, scam, and social-engineering detection.

---

## 👥 Team

Built for **Async'26**.

---

## ⚠️ Disclaimer

DarkShield is a cybersecurity research and demonstration prototype.

Its risk assessment should not be treated as a guarantee that a website or message is safe or malicious. Real-world deployment would require additional reputation services, threat intelligence, secure backend infrastructure, continuous security validation, and broader testing.
