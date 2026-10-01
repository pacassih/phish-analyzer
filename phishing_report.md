# Phishing Analysis Report

Analyzed 3 message(s).

## benign.eml - 0/100 (LOW RISK)

- **From:** IT Helpdesk <it-helpdesk@company.example>
- **Subject:** Scheduled maintenance this Saturday
- **Authentication:** SPF=pass, DKIM=pass, DMARC=pass

### Reasons

- No phishing indicators found.

### URLs (defanged)

- None

### Attachments

- None

## borderline.eml - 38/100 (MEDIUM RISK)

- **From:** Microsoft Account Security <security@micorsoft-verify.com>
- **Subject:** New sign-in detected - please review
- **Authentication:** SPF=softfail, DKIM=none, DMARC=none

### Reasons

- (+5) SPF softfail - sending server not fully authorized
- (+3) No DKIM signature present
- (+20) From domain 'micorsoft-verify.com' is a likely typosquat of 'microsoft' (suspicious label: 'micorsoft-verify')
- (+10) Urgency / threat language: immediately

### URLs (defanged)

- `hxxps://micorsoft-verify[.]com/secure?id=99182`

### Attachments

- None

## phish.eml - 100/100 (HIGH RISK)

- **From:** PayPal Support <support@paypa1-secure.com>
- **Subject:** URGENT: Your account will be suspended within 24 hours
- **Authentication:** SPF=fail, DKIM=fail, DMARC=fail

### Reasons

- (+15) SPF authentication failed
- (+10) DKIM signature invalid
- (+15) DMARC check failed
- (+15) Reply-To domain (paypa1-secure.net) differs from From domain (paypa1-secure.com) - replies go to the attacker
- (+5) Return-Path domain (paypa1-secure.net) differs from From domain (paypa1-secure.com)
- (+20) From domain 'paypa1-secure.com' is a likely typosquat of 'paypal' (suspicious label: 'paypa1-secure')
- (+10) Urgency / threat language: immediately, within 24 hours, suspended, act now, account closure, verify immediately
- (+10) URL shortener hides the real destination: hxxp://bit[.]ly/3xPaypa1Verify
- (+20) Link text shows 'https://www.paypal.com/verify' but points to hxxp://bit[.]ly/3xPaypa1Verify

### URLs (defanged)

- `hxxp://bit[.]ly/3xPaypa1Verify`
- `hxxp://bit[.]ly/3xPaypa1Verify (displayed as: https://www.paypal.com/verify)`

### Attachments

- None
