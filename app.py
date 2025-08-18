import os, re, time
from datetime import datetime
from collections import deque
from urllib.parse import urlparse

import tldextract
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import gradio as gr

# ---------- heuristics (pure-python, 3.13-safe) ----------
EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)  # offline; no network call

SUSPICIOUS_TLDS = {
    "zip","mov","xyz","click","top","fit","country","gq","ml","cf","tk",
    "work","support","rest","buzz","cam","party","review","kim","men","mom","cc","pw"
}
URGENCY_PHRASES = [
    "urgent","immediately","verify your account","suspended","unusual activity",
    "limited time","last warning","action required","update your details","confirm now",
    "security alert","password expires","account locked","click the link","reset now"
]
BRAND_IMPERSONATION = [
    "paypal","microsoft","outlook","office 365","amazon","apple","google",
    "facebook","instagram","bank","hsbc","barclays","revolut"
]

LOG = deque(maxlen=100)

def _add_log(kind, subject, result):
    LOG.appendleft({
        "time": datetime.utcnow().strftime("%H:%M:%S"),
        "type": kind,
        "input": (subject or "")[:120],
        "label": result.get("label","-"),
        "score": result.get("score",0),
        "reasons": "; ".join(result.get("reasons", []))[:240]
    })

def score_url_logic(url: str):
    if not url or url.strip() == "":
        res = {"score": 0, "label": "No URL", "reasons": ["No URL provided"]}
        _add_log("url", url or "", res)
        return res

    u = url.strip()
    reasons, risk = [], 0
    try:
        parsed = urlparse(u if re.match(r"^https?://", u, re.I) else "http://" + u)
    except Exception:
        res = {"score": 90, "label": "High Risk", "reasons": ["URL parsing failed"]}
        _add_log("url", url, res)
        return res

    host = parsed.hostname or ""
    path = parsed.path or ""
    full = parsed.geturl()

    if "@" in full:
        risk += 20; reasons.append("Contains '@' which can hide real destination")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        risk += 25; reasons.append("Raw IP address instead of domain")
    if host.count(".") >= 3:
        risk += 10; reasons.append("Many subdomains")
    if "-" in host:
        risk += 8; reasons.append("Hyphen in domain")

    ext = EXTRACTOR(host)
    tld = (ext.suffix or "").split(".")[-1].lower()
    if tld in SUSPICIOUS_TLDS:
        risk += 12; reasons.append(f"Suspicious TLD: .{tld}")

    if len(full) > 80:
        risk += 10; reasons.append("Very long URL")
    if len(path) > 40:
        risk += 5; reasons.append("Deep/long path")
    if re.search(r"(?:%[0-9a-fA-F]{2}){4,}", full) or re.search(r"[A-Za-z0-9]{24,}", full):
        risk += 10; reasons.append("Random-looking encoded string")
    if parsed.scheme != "https":
        risk += 10; reasons.append("Not using HTTPS")

    brand_hits = [b for b in BRAND_IMPERSONATION if b in full.lower()]
    if brand_hits:
        risk += 10; reasons.append("Mentions brand(s): " + ", ".join(brand_hits))

    score = max(0, min(100, risk))
    label = "Low Risk" if score < 30 else ("Medium Risk" if score < 60 else "High Risk")
    res = {"score": score, "label": label, "reasons": reasons}
    _add_log("url", url, res)
    return res

def extract_urls(text: str):
    return re.findall(r'(https?://[^\s<>()"]+|www\.[^\s<>()"]+)', text or "", re.I)

def score_email_logic(text: str):
    if not text or text.strip() == "":
        res = {"score": 0, "label": "No Content", "reasons": ["No email text provided"], "urls": []}
        _add_log("email", "", res)
        return res

    reasons, risk = [], 0
    lowered = text.lower()

    urgency_hits = [p for p in URGENCY_PHRASES if p in lowered]
    if urgency_hits:
        risk += 20
        reasons.append("Urgency language: " + ", ".join(urgency_hits[:5]) + ("..." if len(urgency_hits) > 5 else ""))

    if re.search(r"!!+|\?\?+", text):
        risk += 5; reasons.append("Excessive punctuation")
    if re.search(r"\b[A-Z]{6,}\b", text):
        risk += 5; reasons.append("ALL-CAPS wording")
    if "attached" in lowered or "attachment" in lowered:
        risk += 4; reasons.append("Mentions an attachment")
    if any(k in lowered for k in ["password", "otp", "one-time code", "credit card", "cvv", "bank details", "login"]):
        risk += 15; reasons.append("Requests sensitive information")
    brand_hits = [b for b in BRAND_IMPERSONATION if b in lowered]
    if brand_hits:
        risk += 8; reasons.append("Possible brand impersonation: " + ", ".join(brand_hits))

    urls = extract_urls(text)
    if urls:
        risk += min(12, 4 * len(urls)); reasons.append(f"Contains {len(urls)} link(s)")

    bads = []
    for u in urls:
        r = score_url_logic(u)
        if r["score"] >= 60: bads.append(f"{u} -> High")
        elif r["score"] >= 30: bads.append(f"{u} -> Medium")
    if bads:
        risk += 10; reasons.append("Risky links: " + "; ".join(bads[:3]) + ("..." if len(bads) > 3 else ""))

    score = max(0, min(100, risk))
    label = "Low Risk" if score < 30 else ("Medium Risk" if score < 60 else "High Risk")
    res = {"score": score, "label": label, "reasons": reasons, "urls": urls}
    _add_log("email", text[:80], res)
    return res

# ---------- FastAPI (stable API) ----------
class URLIn(BaseModel):
    url: str

class EmailIn(BaseModel):
    text: str

app = FastAPI(title="PhishGuard API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)

@app.post("/api/score_url")
def api_score_url(item: URLIn):
    return score_url_logic(item.url)

@app.post("/api/score_email")
def api_score_email(item: EmailIn):
    return score_email_logic(item.text)

# ---------- Gradio UI (mounted at "/") ----------
def url_ui(url):
    r = score_url_logic(url)
    reasons = "\n• " + "\n• ".join(r["reasons"]) if r["reasons"] else "—"
    return r["label"], r["score"], reasons

def email_ui(text):
    r = score_email_logic(text)
    reasons = "\n• " + "\n• ".join(r["reasons"]) if r["reasons"] else "—"
    urls = "\n".join(r["urls"]) if r.get("urls") else "None detected"
    return r["label"], r["score"], reasons, urls

def refresh_log_text():
    if not LOG: return "—"
    lines = []
    for row in list(LOG)[:30]:
        lines.append(f"[{row['time']}] {row['type'].upper()} | score={row['score']} | label={row['label']} | input={row['input']} | reasons={row['reasons']}")
    return "\n".join(lines)

SAMPLES = [
    "https://www.bbc.co.uk",
    "http://microsoft.verify-login.account-security.click/login.php?id=AJDKD83D9D39D9D933939939",
    "http://paypal.com.verify-account.support/secure",
    "http://185.199.108.153/account/verify",
    "https://app-secure-login-amazon.com/ref=account"
]
def auto_demo():
    for i in range(12):
        u = SAMPLES[i % len(SAMPLES)]
        r = score_url_logic(u)
        reasons = "\n• " + "\n• ".join(r["reasons"]) if r["reasons"] else "—"
        yield u, r["label"], r["score"], reasons
        time.sleep(1.2)

with gr.Blocks(title="PhishGuard – Automated Demo (Lite)") as demo:
    gr.Markdown("# 🛡️ PhishGuard (Automated Demo)\nFastAPI endpoints • Gradio UI • Python 3.13-ready")

    with gr.Tab("Check URL"):
        url_in = gr.Textbox(label="URL to check", placeholder="https://example.com/login")
        with gr.Row():
            url_label = gr.Label(num_top_classes=1, label="Risk Label")
            url_score = gr.Slider(0, 100, value=0, label="Risk Score", interactive=False)
        url_reasons = gr.Textbox(label="Reasons", lines=6)
        gr.Button("Analyze URL").click(url_ui, inputs=url_in, outputs=[url_label, url_score, url_reasons])

    with gr.Tab("Check Email"):
        email_in = gr.Textbox(label="Email text", placeholder="Paste the email text here…", lines=10)
        with gr.Row():
            email_label = gr.Label(num_top_classes=1, label="Risk Label")
            email_score = gr.Slider(0, 100, value=0, label="Risk Score", interactive=False)
        email_reasons = gr.Textbox(label="Reasons", lines=6)
        email_urls = gr.Textbox(label="Detected URLs", lines=4)
        gr.Button("Analyze Email").click(email_ui, inputs=email_in, outputs=[email_label, email_score, email_reasons, email_urls])

    with gr.Tab("Auto-Demo"):
        gr.Markdown("Click **Run 20-second auto demo** to stream results while you talk.")
        current = gr.Textbox(label="Current URL (auto)", interactive=False)
        auto_label = gr.Label(num_top_classes=1, label="Risk Label")
        auto_score = gr.Slider(0, 100, value=0, label="Risk Score", interactive=False)
        auto_reasons = gr.Textbox(label="Reasons", lines=6)
        gr.Button("Run 20-second auto demo").click(auto_demo, None, [current, auto_label, auto_score, auto_reasons])

    with gr.Tab("Event Log"):
        gr.Markdown("Last checks. Click **Refresh** to update.")
        log_text = gr.Textbox(label="Log", lines=15, interactive=False)
        gr.Button("Refresh").click(lambda: refresh_log_text(), outputs=[log_text])

# Mount Gradio under FastAPI root
app = gr.mount_gradio_app(app, demo, path="/")

# Render/Heroku-style boot
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "10000"))  # Render usually assigns 10000
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=False)
