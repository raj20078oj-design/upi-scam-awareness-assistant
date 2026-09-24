# UPI Scam Awareness Assistant

## Added in this version
- Message analysis
- URL/link analysis
- QR-code image decoding
- UPI QR awareness checks
- Local SQLite storage for link and QR analyses
- No paid API required

## Link analysis
The prototype checks structural warning indicators such as:
- HTTP instead of HTTPS
- IP-address hosts
- URL shorteners
- punycode/IDN-style hostnames
- unusually long/many subdomain hosts
- suspicious payment/security parameter names
- payment/KYC/login/refund wording combined with other indicators

These are warning indicators, not proof that a URL is malicious.

## QR analysis
Upload an image containing a QR code. OpenCV decodes it locally.
If the QR contains:
- a `upi://` payment URI, the app asks the user to verify payee, UPI ID and amount;
- a URL, the URL analyzer checks it;
- other text, the app displays the decoded content and advises verification.

## Run
```bash
python -m pip install -r requirements.txt
python app.py
```
Then open `http://127.0.0.1:5000`.

## Important
This is an educational cybersecurity prototype. It provides risk indicators and awareness guidance; it does not guarantee that a link, QR code or message is safe or malicious.


## Public deployment (Render)

This version includes Gunicorn and a server-friendly OpenCV package.

Build command:
```bash
pip install -r requirements.txt
```

Start command:
```bash
gunicorn app:app
```

For a public deployment, connect the project GitHub repository to Render and create a Python Web Service.

Note: the current SQLite database is suitable for a demo, but Render's default filesystem is ephemeral. Analysis history may reset after a restart/redeploy. Use PostgreSQL later if persistent history is required.
