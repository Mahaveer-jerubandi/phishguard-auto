# app.py — PhishGuard (Py 3.13 friendly: NO sklearn/numpy/scipy)
# - Pure heuristics (no ML) so it builds on Python 3.13 without compilers
# - Gradio UI + stable API endpoints:
#     POST /api/predict/score_url     body: {"data":["<url>"]}
#     POST /api/predict/score_email   body: {"data":["<email text>"]}
#   (Generic endpoint also works:)
#     POST /api/predict               body: {"data":[...], "api_name":"score_url"|"score_email"}

import os
import re
import time
from collections import deque
from datetime import datetime
from urllib.parse import urlparse

import gradio as gr
import tldextract

# ---- Make tldextract offline so the platform doesn't fetch PSL over network ----
EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)

# Simple rules (add/remove as you like)
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
    "paypal","microsoft","outlook","office 365","amazon","apple","google","facebook",
    "instagram","bank","hsbc","barclays","revolut"
]

LOG = deque(maxlen=100)

def _add_log(kind: str, input_preview: str, result: dict):
    LOG.appendleft({
        "time": datetime.utcnow().strftime("%H:%M:%S"),
        "type": kind,
        "input": (input_preview or "")[:120],
        "label": result.get("label","-"),
        "score": result.get("score",0),
        "reasons": "; ".join(result.get("reasons", []))[:240]
    })

def extract_urls(text: str):
    url_regex = re.compile(r'(https?://[^\s<>()"]+|www\.[^\s<>()"]+)', re.I)
    return url_regex.findall(text or "")

def score_url(url: str) -> dict:
    if not url or url.strip() == "":
        res = {"score": 0, "label": "No URL", "reasons": ["No URL provided"]}
        _add_log("url", url or "", res)
        return res

    u = url.strip()
    reasons = []
    risk = 0

    # normalize and parse
    try:
        parsed = urlparse(u if re.match(r'^https?://', u, re.I) else "http://" + u)
    except Exception:
        res = {"score": 90, "label": "High Risk", "reasons": ["URL parsing failed"]}
        _add_log("url", url, res)
        return res

    host = parsed.hostname or ""
    path = parsed.path or ""
    full = parsed.geturl()

    if "@" in full:
        risk += 20; reasons.append("Contains '@' which can hide real destination")

    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host):
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

    if re.search(r'(?:%[0-9a-fA-F]{2}){4,}', full) or re.search(r'[A-Za-z0-9]{24,}', full):
        risk += 10; reasons.append("Random-looking encoded string")

    if parsed.scheme != "https":
        risk += 10; reasons.append("Not using HTTPS")

    brand_hits = [b for b in BRAND_IMPERSONATION if b in full.lower()]
    if brand_hits:
        risk += 10; reasons.append("Mentions brand(s): " + ", ".join(brand_hits))

    score = max(0, min(100, risk))
    label = "Low Risk" if score < 30 else "Medium Risk" if score < 60 else "High Risk"
    res = {"score": score, "label": label, "reasons": reasons}
    _add_log("url", url, res)
    return res

def score_email(text: str) -> dict:
    if not text or text.strip() == "":
        res = {"score": 0, "label": "No Content", "reasons": ["No email text provided"], "urls": []}
        _add_log("email", "", res)
        return res

    reasons = []
    risk = 0
    lowered = text.lower()

    urgency_hits = [p for p in URGENCY_PHRASES if p in lowered]
    if urgency_hits:
        risk += 20
        reasons.append("Urgency language: " + ", ".join(urgency_hits[:5]) + ("..." if len(urgency_hits) > 5 else ""))

    if re.search(r'!!+|\?\?+', text):
        risk += 5; reasons.append("Excessive punctuation")

    if re.search(r'\b[A-Z]{6,}\b', text):
        risk += 5; reasons.append("ALL-CAPS wording")

    if "attached" in lowered or "attachment" in lowered:
        risk += 4; reasons.append("Mentions an attachment")

    if any(k in lowered for k in ["password", "otp", "one-time code", "credit card", "cvv", "bank details", "login"]):
        risk += 15; reasons.append("Requests sensitive information")

    brand_hits = [b for b in BRAND_IMPERSONATION if b in lowered]
    if brand_hits:
        risk += 8; reasons.append("Possible brand impersonation: " + ", ".join(brand_hits))

    urls = extract_urls(text)
    if len(urls) >= 1:
        risk += min(12, 4 * len(urls)); reasons.append(f"Contains {len(urls)} link(s)")

    bad_url_reasons = []
    for u in urls:
        r = score_url(u)
        if r["score"] >= 60:
            bad_url_reasons.append(f"{u} -> High")
        elif r["score"] >= 30:
            bad_url_reasons.append(f"{u} -> Medium")
    if bad_url_reasons:
        risk += 10
        reasons.append("Risky links: " + "; ".join(bad_url_reasons[:3]) + ("..." if len(bad_url_reasons) > 3 else ""))

    score = max(0, min(100, risk))
    label = "Low Risk" if score < 30 else "Medium Risk" if score < 60 else "High Risk"
    res = {"score": score, "label": label, "reasons": reasons, "urls": urls}
    _add_log("email", text[:80], res)
    return res

# ---- UI callbacks used by both UI and API ----
def url_ui(url):
    r = score_url(url)
    reasons = "\n• " + "\n• ".join(r["reasons"]) if r["reasons"] else "—"
    return r["label"], r["score"], reasons

def email_ui(text):
    r = score_email(text)
    reasons = "\n• " + "\n• ".join(r["reasons"]) if r["reasons"] else "—"
    urls = "\n".join(r["urls"]) if r.get("urls") else "None detected"
    return r["label"], r["score"], reasons, urls

def refresh_log_text():
    if not LOG:
        return "—"
    lines = []
    for row in list(LOG)[:30]:
        lines.append(
            f"[{row['time']}] {row['type'].upper()} | score={row['score']} | label={row['label']} | input={row['input']} | reasons={row['reasons']}"
        )
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
        r = score_url(u)
        reasons = "\n• " + "\n• ".join(r["reasons"]) if r["reasons"] else "—"
        yield u, r["label"], r["score"], reasons
        time.sleep(1.2)

with gr.Blocks(title="PhishGuard (Heuristic, Py3.13)") as demo:
    gr.Markdown("# 🛡️ PhishGuard — Heuristic Demo (Py 3.13)\nStable API endpoints • No heavy deps")

    with gr.Tab("Check URL"):
        url_in = gr.Textbox(label="URL to check", placeholder="https://example.com/login")
        with gr.Row():
            url_label = gr.Label(num_top_classes=1, label="Risk Label")
            url_score = gr.Slider(0, 100, value=0, label="Risk Score", interactive=False)
        url_reasons = gr.Textbox(label="Reasons", lines=6)
        gr.Button("Analyze URL").click(
            url_ui,
            inputs=url_in,
            outputs=[url_label, url_score, url_reasons],
            api_name="score_url",    # <-- named endpoint
        )

    with gr.Tab("Check Email"):
        email_in = gr.Textbox(label="Email text", placeholder="Paste the email text here...", lines=10)
        with gr.Row():
            email_label = gr.Label(num_top_classes=1, label="Risk Label")
            email_score = gr.Slider(0, 100, value=0, label="Risk Score", interactive=False)
        email_reasons = gr.Textbox(label="Reasons", lines=6)
        email_urls = gr.Textbox(label="Detected URLs", lines=4)
        gr.Button("Analyze Email").click(
            email_ui,
            inputs=email_in,
            outputs=[email_label, email_score, email_reasons, email_urls],
            api_name="score_email",  # <-- named endpoint
        )

    with gr.Tab("Auto-Demo"):
        gr.Markdown("Click **Run auto demo** to stream a quick set of examples.")
        current = gr.Textbox(label="Current URL (auto)", interactive=False)
        auto_label = gr.Label(num_top_classes=1, label="Risk Label")
        auto_score = gr.Slider(0, 100, value=0, label="Risk Score", interactive=False)
        auto_reasons = gr.Textbox(label="Reasons", lines=6)
        gr.Button("Run auto demo").click(
            auto_demo, None, [current, auto_label, auto_score, auto_reasons],
            api_name="auto_demo"
        )

    with gr.Tab("Event Log"):
        log_text = gr.Textbox(label="Log", lines=16, interactive=False)
        gr.Button("Refresh").click(lambda: refresh_log_text(), outputs=[log_text])

# Launch (Render sets $PORT)
demo.queue()
demo.launch(server_name="0.0.0.0", server_port=int(os.environ.get("PORT", 7860)))
