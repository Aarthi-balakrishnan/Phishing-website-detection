# AI Phishing Shield — Chrome Extension

A real-time AI-powered Chrome extension that detects phishing, rogue websites, and malicious content using Gemini AI trained on live threat intelligence.

## Detection Coverage (5 Rogue Tactics + Malicious Content)

| Tactic | Examples | Result |
|---|---|---|
| **Fake Login Pages** | paypa1-secure-verify.net, netflix-login-verify.com | ⚠️ PHISHING |
| **Fake Product Launches** | brand-official-drop.xyz, fake-crypto-invest.net | ⚠️ PHISHING |
| **Fake Online Stores** | nike-outlet-sale-deals.xyz, gucci-clearance.net | ⚠️ PHISHING |
| **Fake Tech Support** | apple-techsupport-helpdesk.com, microsoft-security-alert.net | ⚠️ PHISHING |
| **Fake Supply Chain** | meta-recruiting-portal.net, invoice-portal-vendor.com | ⚠️ PHISHING |
| **Adult / 18+ Content** | dailymotion.com/video, any pornographic site | 🚫 MALICIOUS |
| **Malware / Dark Web** | crack-download.xyz, illegal content | 🚫 MALICIOUS |
| **Blocklist Aggregators** | cert.pl/warning-list, antifraud.drweb.com | ⚠️ PHISHING |
| **Legitimate Sites** | google.com, github.com, ebrand.com | ✅ SAFE |

## Features

- **Real-time detection** — Every URL analyzed as you navigate
- **Gemini AI** — Advanced ML model with structured threat intelligence
- **5 rogue tactics** — Covers all top scam patterns (fake logins, stores, support, launches, supply chain)
- **18+ priority filter** — Adult content blocked at highest priority, overrides all other rules
- **Typosquatting detection** — Catches amaz0n.com, paypa1.com, g00gle.com etc.
- **Homograph detection** — Unicode look-alike character attacks
- **Confidence score** — 0–100% AI confidence shown for every result
- **Risk factor breakdown** — Specific signals listed for every flagged URL
- **10-min result cache** — Fast re-checks without redundant API calls

## Install in Chrome

1. Download & extract this ZIP
2. Go to `chrome://extensions/`
3. Enable **Developer mode** (top-right toggle)
4. Click **Load unpacked** → select the `phishing-extension/` folder
5. Extension appears in toolbar — ready immediately

## API Configuration

Pre-configured to use your Replit backend:
```
https://7dec001e-a2cb-4bdb-bc80-a98d766241a3-00-1fbi5u7itjada.pike.replit.dev/api/phishing/check
```
Change it: click extension icon → ⚙️ → enter URL → Save.

## File Structure

```
phishing-extension/
├── manifest.json   — Manifest V3 Chrome extension config
├── background.js   — Service worker: monitors URLs, calls AI API, badge updates
├── content.js      — Injected: full-page blocking overlay on dangerous sites
├── popup.html      — Browser action popup UI
├── popup.js        — Popup: status display, confidence bar, risk factors, settings
└── icons/          — 16px / 48px / 128px extension icons
```

## API Reference

`POST /api/phishing/check`
```json
{ "url": "https://example.com" }
```
Response:
```json
{
  "url": "https://example.com",
  "classification": "SAFE | PHISHING | MALICIOUS",
  "confidence": 97,
  "reason": "Verified legitimate domain with no deceptive patterns.",
  "risk_factors": [],
  "is_safe": true
}
```
