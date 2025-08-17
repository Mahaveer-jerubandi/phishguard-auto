import os, re, asyncio, json
from urllib.parse import urlparse
from collections import deque
from datetime import datetime

import gradio as gr
import tldextract, httpx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

# Optional: Supabase for telemetry + feedback + retrain
SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")
SB = None
if SUPABASE_URL and SUPABASE_KEY:
    from supabase import create_client
    SB = create_client(SUPABASE_URL, SUPABASE_KEY)

print(">>> Gradio", gr.__version__)
EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=None)  # offline PSL

SUSPICIOUS_TLDS = {"zip","mov","xyz","click","top","fit","country","gq","ml","cf","tk","work","support","rest","buzz","cam","party","review","kim","men","mom","cc","pw"}
URGENCY = ["urgent","immediately","verify your account","suspended","unusual activity",
           "limited time","last warning","action required","update your details","confirm now",
           "security alert","password expires","account locked","click the link","reset now"]
BRANDS = ["paypal","microsoft","outlook","office 365","amazon","apple","google",
          "facebook","instagram","bank","hsbc","barclays","revolut"]

FEEDS = {
    "openphish": "https://openphish.com/feed.txt",
    "sinking":   "https://phish.sinking.yachts/v2/all",
}
FEED_CACHE = {"domains": set(), "urls": set(), "last": None}

LOG = deque(maxlen=200)

# ---- ML pipeline (optional; loaded after /retrain) ----
ML = {"vec": None, "clf": None}

def _log(kind, text, label, score, reasons):
    LOG.appendleft({
        "time": datetime.utcnow().strftime("%H:%M:%S"),
        "type": kind,
        "label": label, "score": score,
        "input": (text or "")[:120],
        "reasons": "; ".join(reasons)[:240]
    })

async def refresh_feeds_async(timeout=20):
    new_domains, new_urls = set(), set()
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as cli:
        try:
            r = await cli.get(FEEDS["openphish"])
            if r.status_code == 200:
                for line in r.text.splitlines():
                    u = line.strip().lower()
                    if not u: continue
                    new_urls.add(u)
                    try:
                        h = (urlparse(u).hostname or "").lower()
                        if h: new_domains.add(h)
                    except: pass
        except: pass
        try:
            r = await cli.get(FEEDS["sinking"])
            if r.status_code == 200:
                data = r.json()
                for item in data:
                    if isinstance(item, str):
                        d = item.strip().lower()
                        if d: new_domains.add(d)
                    elif isinstance(item, dict):
                        d = (item.get("domain") or "").lower()
                        u = (item.get("url") or "").lower()
                        if d: new_domains.add(d)
                        if u: new_urls.add(u)
        except: pass
    if new_domains or new_urls:
        FEED_CACHE["domains"], FEED_CACHE["urls"] = new_domains, new_urls
    FEED_CACHE["last"] = datetime.utcnow()
    return f"feeds: domains={len(FEED_CACHE['domains'])} urls={len(FEED_CACHE['urls'])}"

def refresh_feeds_api():
    try:
        return asyncio.run(refresh_feeds_async())
    except RuntimeError:
        asyncio.get_event_loop().create_task(refresh_feeds_async())
        return "refresh scheduled"

def score_url(url: str):
    if not url or not url.strip():
        res = {"score": 0, "label": "No URL", "reasons": ["No URL provided"]}
        _log("url", url, res["label"], res["score"], res["reasons"]); return res

    reasons, risk = [], 0
    u = url.strip()
    try:
        parsed = urlparse(u if re.match(r"^https?://", u, re.I) else "http://" + u)
    except Exception:
        res = {"score": 90, "label": "High Risk", "reasons": ["URL parse failed"]}
        _log("url", url, res["label"], res["score"], res["reasons"]); return res

    host = (parsed.hostname or "").lower()
    full = parsed.geturl().lower()
    path = parsed.path or ""

    if "@" in full: risk += 20; reasons.append("Contains '@'")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host): risk += 25; reasons.append("Raw IP")
    if host.count(".") >= 3: risk += 10; reasons.append("Many subdomains")
    if "-" in host: risk += 8; reasons.append("Hyphen in domain")
    tld = (EXTRACTOR(host).suffix or "").split(".")[-1]
    if tld in SUSPICIOUS_TLDS: risk += 12; reasons.append(f"Suspicious TLD .{tld}")
    if len(full) > 80: risk += 10; reasons.append("Very long URL")
    if len(path) > 40: risk += 5; reasons.append("Deep path")
    if parsed.scheme != "https": risk += 10; reasons.append("Not HTTPS")
    if re.search(r"(?:%[0-9a-fA-F]{2}){4,}", full) or re.search(r"[A-Za-z0-9]{24,}", full):
        risk += 10; reasons.append("Encoded/random string")
    brands = [b for b in BRANDS if b in full]
    if brands: risk += 10; reasons.append("Mentions: " + ", ".join(brands))

    if FEED_CACHE["domains"] and host in FEED_CACHE["domains"]:
        risk = max(risk, 85); reasons.append("In phishing domain feed")
    if FEED_CACHE["urls"] and full in FEED_CACHE["urls"]:
        risk = max(risk, 95); reasons.append("In phishing URL feed")

    score = max(0, min(100, risk))
    label = "Low Risk" if score < 30 else ("Medium Risk" if score < 60 else "High Risk")
    res = {"score": score, "label": label, "reasons": reasons}
    _log("url", url, label, score, reasons)
    return res

def extract_urls(text: str):
    rx = re.compile(r'(https?://[^\s<>()"]+|www\.[^\s<>()"]+)', re.I)
    return rx.findall(text or "")

def rule_email_like(text: str):
    reasons, risk = [], 0
    lower = (text or "").lower()
    urg = [p for p in URGENCY if p in lower]
    if urg: risk += 20; reasons.append("Urgency: " + ", ".join(urg[:5]) + ("..." if len(urg)>5 else ""))
    if re.search(r"!!+|\?\?+", text): risk += 5; reasons.append("Excess punctuation")
    if re.search(r"\b[A-Z]{6,}\b", text): risk += 5; reasons.append("ALL-CAPS")
    if any(k in lower for k in ["password","otp","one-time code","credit card","cvv","bank details","login"]):
        risk += 15; reasons.append("Requests sensitive info")
    brands = [b for b in BRANDS if b in lower]
    if brands: risk += 8; reasons.append("Brand names: " + ", ".join(brands))
    urls = extract_urls(text)
    if urls: risk += min(12, 4*len(urls)); reasons.append(f"Contains {len(urls)} link(s)")
    risky = []
    for u in urls[:5]:
        r = score_url(u)
        if r["score"] >= 60: risky.append(f"{u} -> High")
        elif r["score"] >= 30: risky.append(f"{u} -> Medium")
    if risky: risk += 10; reasons.append("Risky links: " + "; ".join(risky[:3]))
    score = max(0, min(100, risk))
    label = "Low Risk" if score < 30 else ("Medium Risk" if score < 60 else "High Risk")
    return score, label, reasons, urls

def ml_boost(text: str):
    if ML["vec"] is None or ML["clf"] is None: return None   # ML not trained yet
    try:
        X = ML["vec"].transform([text])
        p = float(ML["clf"].predict_proba(X)[0,1])  # prob phishing
        return int(round(p*100))
    except: return None

def score_email_like(text: str, kind="email"):
    rule_score, label, reasons, urls = rule_email_like(text)
    p = ml_boost(text or "")
    if p is not None:
        # blend: take the max of rules and ML prob (scaled)
        final = max(rule_score, p)
        reasons = (["ML probability ~{}%".format(p)] + reasons)[:10]
    else:
        final = rule_score
    out = {"score": final, "label": ("Low Risk" if final<30 else "Medium Risk" if final<60 else "High Risk"),
           "reasons": reasons, "urls": urls}
    _log(kind, (text or "")[:80], out["label"], out["score"], out["reasons"])
    # optional telemetry
    if SB:
        try:
            SB.table("events").insert({
                "kind": kind, "text": text, "score": out["score"], "label_model": out["label"],
                "urls": json.dumps(urls)
            }).execute()
        except: pass
    return out

# --------- retrain from Supabase labels (optional; free tier) ----------
def retrain_from_supabase():
    if not SB: return "Supabase not configured"
    # Expect a table 'events' with columns: id (uuid), ts (default now()), kind, text, label_user
    # Use only rows with user labels (True phishing / false_positive etc.)
    try:
        res = SB.table("events").select("text,label_user").neq("label_user", None).limit(5000).execute()
        rows = res.data or []
        if not rows: return "no labeled samples"
        X = [r["text"] or "" for r in rows]
        # binary target: phishing (1) vs benign (0)
        y = [1 if str(r["label_user"]).lower() in ("phish","phishing","true_positive","malicious") else 0 for r in rows]
        vec = TfidfVectorizer(ngram_range=(1,2), max_features=40000)
        Xv = vec.fit_transform(X)
        clf = LogisticRegression(max_iter=200)
        clf.fit(Xv, y)
        ML["vec"], ML["clf"] = vec, clf
        return f"trained on {len(rows)} samples"
    except Exception as e:
        return f"retrain error: {e}"

# -------------------- UI callbacks (API-safe) --------------------
def ui_url(u):
    try:
        r = score_url(u)
        return r["label"], r["score"], ("\n• " + "\n• ".join(r["reasons"])) if r["reasons"] else "—"
    except Exception as e:
        return "Error", 0, f"Internal error: {e}"

def ui_email(t):
    try:
        r = score_email_like(t, "email")
        return r["label"], r["score"], ("\n• " + "\n• ".join(r["reasons"])) if r["reasons"] else "—", ("\n".join(r["urls"]) or "None")
    except Exception as e:
        return "Error", 0, f"Internal error: {e}", ""

def ui_text(t):
    try:
        r = score_email_like(t, "sms")
        return r["label"], r["score"], ("\n• " + "\n• ".join(r["reasons"])) if r["reasons"] else "—"
    except Exception as e:
        return "Error", 0, f"Internal error: {e}"

def ui_feeds():
    return refresh_feeds_api()

def ui_retrain():
    return retrain_from_supabase()

def log_dump():
    if not LOG: return "—"
    return "\n".join(f"[{r['time']}] {r['type']} | {r['label']}({r['score']}) | {r['input']} | {r['reasons']}" for r in list(LOG)[:40])

# -------------------- UI / API --------------------
with gr.Blocks(title="Auto-PhishGuard") as demo:
    gr.Markdown("### 🛡️ Auto-PhishGuard — Automated phishing scoring\nStable API via `/api/predict` with `api_name`:\n- `score_url`, `score_email`, `score_text`\n- `refresh_feeds`, `retrain` (optional)")

    with gr.Tab("Check URL"):
        url_in = gr.Textbox(label="URL")
        with gr.Row():
            url_label = gr.Label(num_top_classes=1, label="Risk")
            url_score = gr.Slider(0,100,0,label="Score",interactive=False)
        url_reasons = gr.Textbox(label="Reasons", lines=6)
        gr.Button("Analyze URL").click(ui_url, url_in, [url_label, url_score, url_reasons], api_name="score_url")

    with gr.Tab("Check Email"):
        email_in = gr.Textbox(label="Email text", lines=10)
        with gr.Row():
            email_label = gr.Label(num_top_classes=1, label="Risk")
            email_score = gr.Slider(0,100,0,label="Score",interactive=False)
        email_reasons = gr.Textbox(label="Reasons", lines=6)
        email_urls = gr.Textbox(label="Detected URLs", lines=4)
        gr.Button("Analyze Email").click(ui_email, email_in, [email_label, email_score, email_reasons, email_urls], api_name="score_email")

    with gr.Tab("Check SMS / Text"):
        sms_in = gr.Textbox(label="Text", lines=6)
        with gr.Row():
            sms_label = gr.Label(num_top_classes=1, label="Risk")
            sms_score = gr.Slider(0,100,0,label="Score",interactive=False)
        sms_reasons = gr.Textbox(label="Reasons", lines=6)
        gr.Button("Analyze Text").click(ui_text, sms_in, [sms_label, sms_score, sms_reasons], api_name="score_text")

    with gr.Tab("Feeds & Training"):
        out = gr.Textbox(label="Output", lines=12, interactive=False)
        with gr.Row():
            gr.Button("Refresh feeds").click(ui_feeds, outputs=[out], api_name="refresh_feeds")
            gr.Button("Retrain from Supabase").click(ui_retrain, outputs=[out], api_name="retrain")
        gr.Button("Show event log").click(log_dump, outputs=[out])

demo.queue()
demo.launch(server_name="0.0.0.0", server_port=int(os.environ.get("PORT", 7860)), show_api=True)
