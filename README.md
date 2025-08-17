---
sdk: gradio
sdk_version: 4.44.1
app_file: app.py
pinned: false
---
# PhishGuard Auto (Spaces version)

Small dashboard + **stable API** to score URLs / email text / SMS for phishing.

- UI tabs: Check URL • Check Email • Check SMS/Text • Feeds & Logs
- **Generic API** endpoint (works in every Gradio build): `/api/predict`
- Call it with JSON: `{"data": ["<text>"], "api_name": "score_email"}`
  - Other api names: `score_url`, `score_text`, `refresh_feeds`
