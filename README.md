# PhishGuard (Auto)
- REST API:
  - POST /api/score_url    { "url": "https://..." }
  - POST /api/score_email  { "text": "email body ..." }
- UI at /

## Local dev
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
export PORT=7860 && python app.py
