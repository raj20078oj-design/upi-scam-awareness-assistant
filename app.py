import os
import re
import json
import sqlite3
import ipaddress
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from flask import Flask, render_template, request, jsonify

try:
    import cv2
    QR_AVAILABLE = True
except Exception:
    QR_AVAILABLE = False

try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    SKLEARN_AVAILABLE = True
except Exception:
    SKLEARN_AVAILABLE = False

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "upi_scam_awareness.db")
app = Flask(__name__)

RISK_ORDER = {"low": 0, "medium": 1, "high": 2}
RISK_SCORES = {"low": 0.20, "medium": 0.55, "high": 0.90}

WARNING_RULES = [
    ("Urgency", [r"\burgent\b", r"\bimmediately\b", r"\btoday\b", r"\bnow\b", r"\bexpires?\b", r"\blast chance\b"]),
    ("Unexpected Payment", [r"\bpay\b", r"\bpayment\b", r"\btransfer\b", r"\bsend money\b", r"\bfee\b"]),
    ("QR Code Request", [r"\bqr\b", r"\bscan\b.*\bqr\b"]),
    ("Suspicious Link", [r"\bclick\b.*\blink\b", r"\bopen\b.*\blink\b", r"https?://", r"\bbit\.ly\b"]),
    ("Pressure Language", [r"\bblocked\b", r"\bsuspended\b", r"\bdisconnected\b", r"\bpenalty\b", r"\bclaim\b.*\breward\b"]),
    ("Sensitive Information Request", [r"\bupi pin\b", r"\botp\b", r"\bpassword\b", r"\bpin\b"]),
    ("Unknown/Unverified Sender", [r"\bunknown\b", r"\bunverified\b", r"\bstranger\b"]),
]

GUIDANCE = {
    "low": [
        "Continue to use the official payment app or website.",
        "Verify transaction details before approving any payment.",
        "Never share your UPI PIN or OTP with anyone."
    ],
    "medium": [
        "Pause and verify the sender or request through a known channel.",
        "Check the recipient, amount and transaction details carefully.",
        "Do not share your UPI PIN, OTP or password."
    ],
    "high": [
        "Do not make the payment until the request is independently verified.",
        "Do not scan an unexpected QR code or open a suspicious link.",
        "Never share your UPI PIN, OTP or password.",
        "Contact the person or organization through an official/known channel."
    ]
}

# Common URL shorteners. Their presence is a warning indicator, not proof of a scam.
SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
    "ow.ly", "buff.ly", "rb.gy", "shorturl.at"
}

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def load_model():
    if not SKLEARN_AVAILABLE:
        return None
    conn = get_db()
    rows = conn.execute("SELECT text, label FROM training_examples").fetchall()
    conn.close()
    if len(rows) < 4:
        return None
    texts = [r["text"] for r in rows]
    labels = [r["label"] for r in rows]
    vectorizer = TfidfVectorizer(ngram_range=(1, 2), lowercase=True)
    X = vectorizer.fit_transform(texts)
    model = LogisticRegression(max_iter=1000, class_weight="balanced")
    model.fit(X, labels)
    return vectorizer, model

MODEL = load_model()

def rule_warnings(text):
    found = []
    for name, patterns in WARNING_RULES:
        if any(re.search(p, text, flags=re.I) for p in patterns):
            found.append(name)
    return found

def ml_prediction(text):
    if MODEL is None:
        return "medium", 0.55
    vectorizer, model = MODEL
    X = vectorizer.transform([text])
    pred = model.predict(X)[0]
    confidence = float(max(model.predict_proba(X)[0]))
    return pred, confidence

def extract_urls(text):
    pattern = r'(?:(?:https?|www)\S+)'
    return [u.rstrip('.,);]}>"\'') for u in re.findall(pattern, text, flags=re.I)]

def analyze_url(url):
    raw = url.strip()
    candidate = raw if re.match(r'^https?://', raw, re.I) else "http://" + raw
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower()
    findings = []

    if not host:
        return {"url": raw, "risk_level": "high", "risk_score": 0.9,
                "findings": ["URL could not be parsed safely."]}

    if parsed.scheme == "http":
        findings.append("Uses HTTP instead of HTTPS.")

    try:
        ipaddress.ip_address(host)
        findings.append("Uses an IP address instead of a normal domain.")
    except ValueError:
        pass

    if host.startswith("xn--") or ".xn--" in host:
        findings.append("Uses a punycode/IDN-style hostname; verify the domain carefully.")

    if host in SHORTENERS or any(host.endswith("." + d) for d in SHORTENERS):
        findings.append("Uses a URL-shortening service, which hides the final destination.")

    if "@" in parsed.netloc:
        findings.append("Contains @ in the network location, which can be misleading.")

    if len(host) > 45:
        findings.append("Has an unusually long hostname.")

    if host.count(".") >= 4:
        findings.append("Has many subdomain levels; verify the domain carefully.")

    query_keys = set(k.lower() for k in parse_qs(parsed.query).keys())
    if query_keys.intersection({"upi", "pin", "otp", "password", "passwd", "cvv", "card"}):
        findings.append("URL contains payment/security-related parameter names.")

    risk = "low"
    if len(findings) >= 3:
        risk = "high"
    elif findings:
        risk = "medium"

    # A payment/security-looking path with a suspicious domain gets extra caution.
    suspicious_words = ("kyc", "verify", "refund", "reward", "payment", "login", "update", "account")
    if any(w in (parsed.path + "?" + parsed.query).lower() for w in suspicious_words) and findings:
        risk = "high"

    return {
        "url": raw,
        "domain": host,
        "risk_level": risk,
        "risk_score": RISK_SCORES[risk],
        "findings": findings or ["No obvious structural warning found. Still verify the domain independently."]
    }

def analyze_qr_image(file_storage):
    if not QR_AVAILABLE:
        return {
            "decoded": False,
            "error": "QR analysis requires OpenCV. Install dependencies from requirements.txt."
        }

    data = file_storage.read()
    if not data:
        return {"decoded": False, "error": "Empty image."}

    import numpy as np
    image = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        return {"decoded": False, "error": "Could not read the image."}

    detector = cv2.QRCodeDetector()
    decoded, points, _ = detector.detectAndDecode(image)

    if not decoded:
        return {"decoded": False, "error": "No readable QR code was found in the image."}

    text = decoded.strip()
    url_results = []
    if re.search(r'(https?://|www\.)', text, re.I):
        url_results = [analyze_url(u) for u in extract_urls(text)]

    findings = []
    if text.lower().startswith("upi://"):
        findings.append("QR contains a UPI payment URI. Verify the payee name, UPI ID and amount in your payment app before approving.")
        risk = "medium"
    elif url_results:
        findings.extend([f for r in url_results for f in r["findings"]])
        risk = max((r["risk_level"] for r in url_results), key=lambda x: RISK_ORDER[x])
    else:
        findings.append("QR content was decoded. Do not trust it solely because it is a QR code; verify the destination or payment details.")
        risk = "medium"

    return {
        "decoded": True,
        "decoded_text": text,
        "risk_level": risk,
        "risk_score": RISK_SCORES[risk],
        "findings": list(dict.fromkeys(findings)),
        "links": url_results
    }

def analyze_text(text):
    warnings = rule_warnings(text)
    ml_risk, ml_confidence = ml_prediction(text)
    urls = [analyze_url(u) for u in extract_urls(text)]

    risk = ml_risk
    if len(warnings) >= 3:
        risk = "high"
    elif len(warnings) >= 1 and RISK_ORDER[risk] < RISK_ORDER["medium"]:
        risk = "medium"

    if any(r["risk_level"] == "high" for r in urls):
        risk = "high"
    elif urls and risk == "low":
        risk = "medium"

    score = RISK_SCORES[risk]
    if risk == "high":
        score = min(0.99, max(score, 0.65 + 0.07 * len(warnings)))
    elif risk == "medium":
        score = min(0.79, max(score, 0.45 + 0.05 * len(warnings)))
    else:
        score = max(0.10, min(0.40, 1 - ml_confidence))

    explanation = (
        "Possible warning indicators: " + ", ".join(warnings) + "."
        if warnings else
        "No strong warning indicators were detected by the current local model and rules. "
        "Still verify unexpected payment requests."
    )

    return {
        "risk_level": risk,
        "risk_score": round(float(score), 2),
        "warnings": warnings,
        "explanation": explanation,
        "guidance": GUIDANCE[risk],
        "links": urls,
        "model": "Local TF-IDF + Logistic Regression with transparent warning-sign and URL rules"
    }

def save_analysis(text, result, input_type="message"):
    conn = get_db()
    category_name = "Social Engineering" if "Pressure Language" in result.get("warnings", []) else "Fake Payment Request"
    row = conn.execute("SELECT category_id FROM scam_categories WHERE category_name=?", (category_name,)).fetchone()
    category_id = row["category_id"] if row else None

    cur = conn.execute("""
        INSERT INTO analyses
        (category_id, input_type, input_text, risk_level, risk_score, explanation)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (category_id, input_type, text, result["risk_level"], result["risk_score"], result["explanation"]))
    analysis_id = cur.lastrowid

    for warning in result.get("warnings", []):
        row = conn.execute("SELECT warning_id FROM warning_signs WHERE warning_name=?", (warning,)).fetchone()
        if row:
            conn.execute("INSERT OR IGNORE INTO analysis_warning_signs(analysis_id, warning_id) VALUES (?,?)",
                         (analysis_id, row["warning_id"]))

    for i, item in enumerate(result["guidance"], start=1):
        conn.execute("INSERT INTO safety_guidance(analysis_id, guidance_text, priority) VALUES (?,?,?)",
                     (analysis_id, item, i))

    for link in result.get("links", []):
        conn.execute("""
            INSERT INTO link_analysis(analysis_id, url, risk_level, risk_score, findings)
            VALUES (?, ?, ?, ?, ?)
        """, (analysis_id, link["url"], link["risk_level"], link["risk_score"], json.dumps(link["findings"])))

    conn.commit()
    conn.close()
    return analysis_id

def save_qr_analysis(decoded_text, result, analysis_id=None):
    conn = get_db()
    conn.execute("""
        INSERT INTO qr_analysis(analysis_id, decoded_text, risk_level, risk_score, findings)
        VALUES (?, ?, ?, ?, ?)
    """, (analysis_id, decoded_text, result["risk_level"], result["risk_score"], json.dumps(result["findings"])))
    conn.commit()
    conn.close()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "").strip()
    if not text:
        return jsonify({"error": "Please enter a message to analyze."}), 400
    result = analyze_text(text)
    analysis_id = save_analysis(text, result, "message")
    result["analysis_id"] = analysis_id
    result["created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return jsonify(result)

@app.route("/api/analyze-qr", methods=["POST"])
def api_analyze_qr():
    file = request.files.get("qr_image")
    if not file:
        return jsonify({"error": "Please upload a QR image."}), 400

    result = analyze_qr_image(file)
    if not result.get("decoded"):
        return jsonify(result), 400

    # Store QR as an analysis record too.
    text = result["decoded_text"]
    warnings = []
    if text.lower().startswith("upi://"):
        warnings.append("QR Code Request")
    if result.get("links"):
        warnings.append("Suspicious Link" if any(x["risk_level"] != "low" for x in result["links"]) else "QR Code Request")

    wrapper = {
        "risk_level": result["risk_level"],
        "risk_score": result["risk_score"],
        "warnings": list(dict.fromkeys(warnings)),
        "explanation": "QR code decoded successfully. " + " ".join(result["findings"]),
        "guidance": GUIDANCE[result["risk_level"]],
        "links": result.get("links", [])
    }
    analysis_id = save_analysis(text, wrapper, "qr_request")
    save_qr_analysis(text, result, analysis_id)
    result["analysis_id"] = analysis_id
    result["created_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return jsonify(result)

@app.route("/api/history", methods=["GET"])
def history():
    conn = get_db()
    rows = conn.execute("""
        SELECT analysis_id, input_text, risk_level, risk_score, input_type, created_at
        FROM analyses ORDER BY analysis_id DESC LIMIT 20
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/health")
def health():
    return jsonify({"status": "online", "app": "UPI Scam Awareness Assistant", "qr_analysis": QR_AVAILABLE})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
