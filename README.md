# DarkShield

**AI-Powered Defense Against Phishing, Scams & Social Engineering**
*Detect the attack. Understand the manipulation. Protect the user.*

Single-file, dependency-free HTML/CSS/JS app. No build step, no backend,
no API keys. Open `index.html` directly or run with VS Code Live Server.

## What it is
A cybersecurity dashboard that scans a URL + page/email text for phishing,
scam, and social-engineering indicators and returns a transparent, explainable
0–100 risk score.

## Why it was built
Built for ASYNC'26 (Track 03 — Cybersecurity & Defense) to address AI-assisted
phishing and scam content that ordinary users increasingly can't recognize on
sight.

## How it works
1. **Detection engine** — regex/heuristic checks over the domain and pasted
   text produce structured evidence flags (`brand_mismatch`, `fake_countdown`,
   `suspicious_payment_form`, etc.).
2. **Risk engine** — each flag carries a fixed, visible weight; flags sum to
   a 0–100 score mapped to LOW / MODERATE / HIGH / CRITICAL. The full
   point-by-point breakdown is shown via "Why this score?".
3. **AI Threat Analysis** — the structured evidence (not the raw page) is
   turned into a plain-English explanation: why it matters, what the
   attacker is trying to do, what to do next. This is deterministic
   template-based reasoning over the evidence — there is no external AI API
   call in this build (see Notes below).
4. **Manipulation Map & Attack Story** — visualize which social-engineering
   techniques were detected and the attack as a sequence, not just a list.
5. **Safety Mode** — on HIGH/CRITICAL results with a login or payment
   signal, a defensive-intervention modal blocks the simulated "proceed"
   action.

## Functional UI
- **Search** — searches demo scenarios, detection signals, and this
  session's recent scans; results scroll to the relevant section.
- **Notifications** — real session events (scan completed, threat detected,
  protection triggered), with unread state and "mark all as read".
- **Settings** — theme (Dark / Darker / High Contrast), notification
  toggle, technical/social-engineering signal visibility, compact/comfortable
  density. Persisted to `localStorage`.
- **Profile** — session scan count and threats detected.
- **Scan History** — every scan this session, with a per-scan Full Report
  (view + export as `.txt`), persisted to `localStorage` across refreshes.
- **4 demo scenarios** — Safe Website, Shopping Scam, Delivery Scam,
  Banking/KYC Scam — each produces distinct signals and risk levels.

## Unique selling point
Signals are shown as transparent, clickable evidence rather than a black-box
verdict — the user sees *which* manipulation techniques were detected, *why*
they matter, and the exact points behind the score.

## Run locally
```bash
# Option A — just open it
open index.html   # or double-click it

# Option B — simple static server
python3 -m http.server 8000   # then visit http://localhost:8000

# Option C — VS Code
# Right-click index.html → "Open with Live Server"
```

## Upload to GitHub
```bash
git init
git add .
git commit -m "DarkShield prototype"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```

## Notes / honest scope
- Risk scores are transparent rule-based prototype signals, not a
  statistically validated fraud probability, and are never shown as a
  percentage claim.
- "AI Threat Analysis" is deterministic template reasoning over structured
  evidence in this build — there is no real external AI/LLM API call, and
  none is faked.
- Dashboard stats and Threat Pulse only reflect this session's actual scans
  — no invented real-world statistics.
- No API keys or secrets are used anywhere in the code.
