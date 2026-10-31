# UPI Scam Awareness Assistant

An educational Flask application that highlights possible warning signs in UPI-related messages, URLs and QR codes.

## What's included

- **Message analysis:** rule-based warning signs plus a local TF-IDF / Logistic Regression text model when scikit-learn is available.
- **URL inspection:** checks structural indicators such as HTTP, IP hosts, URL shorteners, punycode and suspicious payment/security parameter names.
- **QR inspection:** decodes QR images locally with OpenCV and gives additional guidance for UPI payment URIs and URLs.
- **Analysis history:** stores recent checks in SQLite.
- **Responsive interface:** refreshed dark cybersecurity dashboard, mobile layout, message examples, drag-and-drop QR upload, inline errors and clearer result presentation.

## Run locally

Python 3.10+ is recommended.

```bash
python -m venv .venv
```

Activate the environment:

- Windows PowerShell: `.venv\\Scripts\\Activate.ps1`
- Windows Command Prompt: `.venv\\Scripts\\activate.bat`
- macOS / Linux: `source .venv/bin/activate`

Install dependencies and start the app:

```bash
python -m pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5000> in your browser.

## API quick reference

- `GET /api/health` — service status
- `POST /api/analyze` — JSON body: `{"text": "message to analyze"}`
- `POST /api/analyze-qr` — multipart image field: `qr_image`
- `GET /api/history` — latest 20 analysis records

## Public deployment (Render)

Build command:

```bash
pip install -r requirements.txt
```

Start command:

```bash
gunicorn app:app
```

Connect the GitHub repository to Render and create a Python Web Service. The SQLite database is suitable for a demo; Render's default filesystem may reset after a restart or redeploy. Use a managed database if persistent history is required.

## Important limitations

This is an awareness prototype, not a bank-grade fraud detection service. A risk indicator is **not a probability** and does not prove that a message, link or QR code is safe or malicious. The app does not verify payment recipients with banks or UPI providers. Always verify the payee and amount in your official payment app. Never share your UPI PIN, OTP or password.
