# Deploy on Render

1. Upload this project to a GitHub repository.
2. In Render choose New -> Web Service and connect the repository.
3. Runtime: Python 3.
4. Build Command:
   pip install -r requirements.txt
5. Start Command:
   gunicorn app:app
6. Create the Web Service and wait for the build to finish.
7. Open the public `onrender.com` URL.

Important:
- This project currently uses SQLite (`upi_scam_awareness.db`).
- On Render's normal ephemeral filesystem, new database records can be lost after a restart/redeploy.
- For a college/demo deployment this is acceptable if you only need the app publicly accessible.
- For permanent analysis history, migrate the database to a persistent PostgreSQL service later.
- Never put passwords, API keys, or other secrets into GitHub.
