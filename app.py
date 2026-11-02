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
    # Avoid treating ordinary words such as "today" or "payment received" as scams.
    ("Urgency", [r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"\bright now\b",
                  r"\blast chance\b", r"\bwithin\s+\d+\s+(?:minutes?|hours?)\b",
                  r"\bexpires?\s+(?:today|soon|tonight)\b"]),
    ("Unexpected Payment", [r"\bsend money\b", r"\btransfer money\b", r"\bpayment request\b",
                             r"\bpay\s+(?:rs\.?|inr|₹)?\s*\d+\b", r"\bpay (?:a|the) (?:fee|charge)\b",
                             r"\bpay now\b", r"\btransfer to (?:this|the)\b"]),
    ("QR Code Request", [r"\bscan (?:this |the )?(?:qr|qr code)\b", r"\bqr code\b.{0,35}\bpay\b",
                          r"\bscan\b.{0,25}\bto receive\b"]),
    ("Suspicious Link", [r"\bclick\b.{0,30}\blink\b", r"\bopen\b.{0,30}\blink\b", r"https?://", r"\bwww\."]),
    ("Pressure Language", [r"\baccount (?:will be )?(?:blocked|suspended)\b", r"\b(?:blocked|suspended|disconnected)\b",
                            r"\bpenalty\b", r"\bclaim\b.{0,30}\b(?:reward|prize)\b"]),
    ("Sensitive Information Request", [r"\b(?:share|send|enter|provide|tell|submit|reply with)\b.{0,35}\b(?:upi pin|pin|otp|password)\b",
                                        r"\b(?:upi pin|otp|password)\b.{0,30}\b(?:to receive|to claim|to get|with us)\b"]),
    ("Unknown/Unverified Sender", [r"\bunknown (?:number|sender)\b", r"\bunverified sender\b", r"\bstranger\b"]),
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
