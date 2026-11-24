# Forensic Evidence Ledger — Digital Evidence Chain-of-Custody & Tamper Detection System

A web-based digital forensic evidence management prototype built with **Python Flask, SQLite, SHA-256 cryptographic hashing, QR verification, and ReportLab PDF reporting**.

## Demo Accounts
- **Admin:** `admin` / `admin123`
- **Officer:** `officer` / `officer123`
- **Laboratory:** `lab` / `lab123`
- **Custodian:** `custodian` / `custodian123`
- **Reviewer:** `reviewer` / `reviewer123`

## Local Setup
```bash
pip install -r requirements.txt
python init_db.py
python app.py
```
Open `http://127.0.0.1:5000` in your browser.

## Cloud Deployment (Render)
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `gunicorn app:app`
- **Environment Variable:** `FEL_SECRET` (any random secret string)
