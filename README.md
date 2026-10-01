# phish-analyzer

Parses raw `.eml` files and scores them 0–100 for phishing risk, explaining
every point it awards — the way you'd walk a user through a suspicious email
during a security-awareness session.

## What it does

For each email it extracts and checks:

| Check | What it looks at |
|---|---|
| Email authentication | SPF, DKIM, DMARC results from `Authentication-Results` |
| Sender mismatch | `Reply-To` / `Return-Path` domain vs `From` domain |
| Lookalike domains | Levenshtein-based typosquat detection against 16 well-known brands (catches `paypa1-secure.com`, `micorsoft-verify.com`) |
| Content tricks | urgency/threat keywords, URL shorteners, link text that doesn't match the real `href` |
| Attachments | risky extensions, with SHA256 hashes for every attachment |
| Hygiene | URLs are **defanged** (`hxxp://bit[.]ly/...`) so reports are safe to share |

## How to run

```bash
python analyze_phish.py samples/benign.eml
python analyze_phish.py samples/*.eml --report phishing_report.md
```

## Example output

```
======================================================================
samples/phish.eml
======================================================================
From:    PayPal Support <support@paypa1-secure.com>
Subject: URGENT: Your account will be suspended within 24 hours
Score:   100/100 [####################] HIGH RISK
Auth:    SPF=fail  DKIM=fail  DMARC=fail  Received-hops=1

Reasons:
  +15  SPF authentication failed
  +10  DKIM signature invalid
  +15  DMARC check failed
  +15  Reply-To domain (paypa1-secure.net) differs from From domain (paypa1-secure.com)
  + 5  Return-Path domain (paypa1-secure.net) differs from From domain (paypa1-secure.com)
  +20  From domain 'paypa1-secure.com' is a likely typosquat of 'paypal'
  +10  Urgency / threat language: immediately, within 24 hours, suspended, act now, ...
  +10  URL shortener hides the real destination: hxxp://bit[.]ly/3xPaypa1Verify
  +20  Link text shows 'https://www.paypal.com/verify' but points to hxxp://bit[.]ly/3xPaypa1Verify
```

The three samples are calibrated to land in different bands:

| Sample | Score | Verdict |
|---|---|---|
| `benign.eml` — internal IT maintenance notice, all auth passing | 0/100 | LOW RISK |
| `borderline.eml` — "new sign-in" alert from a lookalike domain, weak auth | 38/100 | MEDIUM RISK |
| `phish.eml` — fake PayPal suspension scare, every red flag firing | 100/100 | HIGH RISK |

## Skills demonstrated

- Email forensics: MIME parsing, header chain analysis, `Authentication-Results`
- URL extraction from plain-text and HTML parts (custom `HTMLParser`)
- String-similarity algorithms (Levenshtein) for typosquat detection
- Heuristic risk scoring with explainable, weighted reasons
- Safe handling: URL defanging, SHA256 hashing of attachments
- Markdown reporting for incident documentation

## Files

| File | Purpose |
|---|---|
| `analyze_phish.py` | The analyzer (CLI, multi-file, optional Markdown report) |
| `samples/benign.eml` | Clean internal email (control sample) |
| `samples/borderline.eml` | Gray-area "security alert" (medium risk) |
| `samples/phish.eml` | Blatant credential-harvesting phish (high risk) |
| `phishing_report.md` | Example analyzer output |

Requirements: Python 3.10+, standard library only — no dependencies to install.
