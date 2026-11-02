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

# Context-aware rules: generic words such as "payment" or "today" alone
# must not create a high-risk result. Rules look for actionable scam patterns.
WARNING_RULES = [
    ("Urgency", [
        r"\bact immediately\b", r"\bwithin\s+\d+\s+(?:minutes?|hours?)\b",
        r"\blast chance\b", r"\bexpires?\s+(?:today|soon|tonight)\b",
        r"\bimmediate action required\b", r"\bdo not delay\b"
    ]),
    ("Unexpected Payment", [
        r"\b(?:send|transfer|pay)\s+(?:money|₹|inr|rs\.?\s*\d)",
        r"\bpayment request\b", r"\bpay\s+now\b",
        r"\bpay\s+(?:the|a)\s+(?:fee|charge|tax)\b",
        r"\btransfer\s+to\s+(?:this|the)\b", r"\bcollect\s+request\b"
    ]),
    ("QR Code Request", [
        r"\bscan\s+(?:this\s+|the\s+)?qr(?:\s+code)?\b",
        r"\bscan\b.{0,35}\bto\s+receive\b",
        r"\bscan\s+to\s+(?:get|claim|receive)\b"
    ]),
    ("Suspicious Link", [
        r"https?://", r"\bwww\.", r"\bclick\s+(?:this\s+)?link\b",
        r"\bopen\s+(?:this\s+)?link\b", r"\bverify\s+(?:your\s+)?(?:account|kyc)\s+(?:here|at)\b"
    ]),
    ("Pressure Language", [
        r"\baccount\s+(?:will\s+be\s+)?(?:blocked|suspended)\b",
        r"\b(?:account|upi)\s+will\s+be\s+deactivated\b",
        r"\bpenalty\s+(?:will\s+be\s+)?(?:charged|applied)\b",
        r"\bkyc\s+(?:has\s+)?expired\b", r"\bservice\s+will\s+be\s+disconnected\b"
    ]),
    ("Sensitive Information Request", [
        r"\b(?:share|send|enter|provide|tell|submit|reply\s+with)\b.{0,45}\b(?:upi\s+pin|pin|otp|password|cvv)\b",
        r"\b(?:upi\s+pin|otp|password|cvv)\b.{0,35}\b(?:to\s+receive|to\s+claim|to\s+get|with\s+us)\b"
    ]),
    ("Unknown/Unverified Sender", [
        r"\bunknown\s+(?:number|sender)\b", r"\bunverified\s+sender\b",
        r"\bstranger\s+(?:sent|contacted|messaged)\b"
    ]),
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
