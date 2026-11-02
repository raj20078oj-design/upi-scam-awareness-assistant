# UScamDicomy — UPI Scam Analysis Assistant

UScamDicomy is an educational web application that reviews UPI-related messages, URLs and QR-code images for possible warning signs. It provides explainable indicators and safety guidance.

## Features

- Message analysis using contextual, explainable warning rules.
- URL structure checks for indicators such as shortened links, raw IP hosts, HTTP, punycode and suspicious URL parameters.
- QR image decoding (when OpenCV is installed) and review of decoded payment/link content.
- Recent analysis history stored in SQLite.
- Responsive dark interface with the official project name **UScamDicomy**.

## Run on Windows

1. Install Python 3.10 or newer.
2. Open Command Prompt in this project folder.
3. Run `python -m pip install -r requirements.txt`.
4. Run `python app.py`.
5. Open `http://127.0.0.1:5000` in your browser.

## Deploy on Render

Create a **Python Web Service** connected to this GitHub repository. Use these settings:

- Root Directory: leave blank
- Build Command: `pip install -r requirements.txt`
- Start Command: `gunicorn app:app`

The `render.yaml` file also contains these settings for Render Blueprint deployment.

## API endpoints

- `GET /` — web interface
- `GET /api/health` — service status
- `POST /api/analyze` — JSON body: `{"text": "message to analyze"}`
- `POST /api/analyze-qr` — multipart upload field: `qr_image`
- `GET /api/history` — latest 20 analyses

## Important limitations

This is an educational prototype, not an official bank, NPCI or government service and not a bank-grade fraud detector. Its score is a rule-based warning indicator, **not a probability** that fraud has occurred. A low score does not prove that a message, URL or QR code is safe, and a high score does not independently prove fraud. It does not contact banks or verify the identity of a payee. Always confirm the payee and amount inside your trusted payment app. Never share your UPI PIN, OTP or password.
