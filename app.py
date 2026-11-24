import os
import sqlite3
import uuid
from datetime import datetime, timezone
from flask import (
    Flask, g, request, session, render_template, redirect,
    url_for, jsonify, flash, abort
)
from werkzeug.utils import secure_filename
import auth
from hashing import sha256_file, event_digest, verify_chain, GENESIS
from init_db import init_database

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE, "ledger.db")
UPLOAD_DIR = os.path.join(BASE, "evidence_store")
ALLOWED_EXT = {
    "pdf", "jpg", "jpeg", "png", "txt", "log", "doc", "docx",
    "zip", "mp4", "mp3", "csv", "json", "eml"
}

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FEL_SECRET", "forensic-ledger-secret-key-2026")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB upload limit

# Ensure directories and database exist on boot (essential for cloud hosting)
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.join(BASE, "reports"), exist_ok=True)
init_database(DB_PATH)


@app.context_processor
def inject_helpers():
    return dict(has_perm=auth.has_permission)


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def audit(action, target="", detail=""):
    try:
        db().execute(
            "INSERT INTO audit_log (user_id, action, target, detail, ip_address, logged_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (session.get("user_id"), action, target, detail, request.remote_addr or "127.0.0.1", now()),
        )
        db().commit()
    except Exception:
        pass


def next_id(table, prefix, width=4):
    row = db().execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()
    return f"{prefix}{row['n'] + 1:0{width}d}"


def add_custody_event(evidence_id, action, from_user, to_user, location, condition, notes):
    last = db().execute(
        "SELECT event_hash FROM custody_events WHERE evidence_id=? ORDER BY id DESC LIMIT 1",
        (evidence_id,),
    ).fetchone()
    prev = last["event_hash"] if last else GENESIS
    t = now()
    digest = event_digest(prev, evidence_id, action, from_user, to_user, location, condition, notes, t)
    db().execute(
        "INSERT INTO custody_events (evidence_id, action, from_user, to_user, location, condition, "
        "notes, event_time, prev_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (evidence_id, action, from_user, to_user, location, condition, notes, t, prev, digest),
    )
    db().commit()


def run_verification(evidence_id):
    ev = db().execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
    if ev is None:
        return None
    if not ev["stored_path"] or not os.path.exists(ev["stored_path"]):
        return {
            "evidence_id": evidence_id,
            "registered_hash": ev["sha256"],
            "current_hash": "FILE MISSING",
            "hash_match": False,
            "chain_intact": False,
            "broken_at_event": None,
            "status": "FILE_MISSING",
            "checked_at": now(),
        }
    current = sha256_file(ev["stored_path"])
    rows = db().execute(
        "SELECT * FROM custody_events WHERE evidence_id=? ORDER BY id",
        (evidence_id,),
    ).fetchall()
    chain_ok, broken = verify_chain([dict(r) for r in rows])
    status = "VERIFIED" if (current == ev["sha256"] and chain_ok) else "POSSIBLE_TAMPERING"
    return {
        "evidence_id": evidence_id,
        "registered_hash": ev["sha256"],
        "current_hash": current,
        "hash_match": current == ev["sha256"],
        "broken_at_event": broken,
        "chain_intact": chain_ok,
        "status": status,
        "checked_at": now(),
    }


@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db().execute(
            "SELECT * FROM users WHERE username=? AND active=1", (username,)
        ).fetchone()
        if user and auth.check_password(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            audit("LOGIN", username, f"Role: {user['role']}")
            return redirect(url_for("dashboard"))
        audit("LOGIN_FAILED", username, "Invalid credentials")
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout")
def logout():
    uname = session.get("username", "")
    if uname:
        audit("LOGOUT", uname)
    session.clear()
    return redirect(url_for("login"))


@app.route("/cases")
@auth.login_required
def case_list():
    q = request.args.get("q", "").strip()
    if q:
        like = f"%{q}%"
        cases = db().execute(
            "SELECT * FROM cases WHERE case_id LIKE ? OR fir_number LIKE ? OR crime_type LIKE ? ORDER BY id DESC",
            (like, like, like),
        ).fetchall()
    else:
        cases = db().execute("SELECT * FROM cases ORDER BY id DESC").fetchall()
    return render_template("cases.html", cases=cases, q=q)


@app.route("/cases/new", methods=["GET", "POST"])
@auth.permission_required("cases")
def create_case():
    suggested_id = next_id("cases", "CASE-2026-", 3)
    if request.method == "POST":
        case_id = request.form.get("case_id", "").strip() or suggested_id
        fir_number = request.form.get("fir_number", "").strip()
        crime_type = request.form.get("crime_type", "").strip()
        police_station = request.form.get("police_station", "").strip()
        officer = request.form.get("officer", "").strip()
        description = request.form.get("description", "").strip()
        if not (fir_number and crime_type and police_station and officer):
            flash("All required fields must be filled.", "error")
            return render_template("create_case.html", suggested_id=case_id)
        try:
            db().execute(
                "INSERT INTO cases (case_id, fir_number, crime_type, police_station, officer, description, created_by, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (case_id, fir_number, crime_type, police_station, officer, description, session["user_id"], now()),
            )
            db().commit()
            audit("CASE_CREATED", case_id, f"FIR: {fir_number}")
            flash(f"Case {case_id} created successfully.", "success")
            return redirect(url_for("case_list"))
        except sqlite3.IntegrityError:
            flash("Case ID already exists. Choose a unique Case ID.", "error")
    return render_template("create_case.html", suggested_id=suggested_id)


@app.route("/evidence")
@auth.login_required
def evidence_list():
    q = request.args.get("q", "").strip()
    if q:
        like = f"%{q}%"
        items = db().execute(
            "SELECT e.*, c.fir_number FROM evidence e JOIN cases c ON e.case_id = c.case_id "
            "WHERE e.evidence_id LIKE ? OR e.case_id LIKE ? OR c.fir_number LIKE ? OR e.evidence_type LIKE ? "
            "ORDER BY e.id DESC",
            (like, like, like, like),
        ).fetchall()
    else:
        items = db().execute(
            "SELECT e.*, c.fir_number FROM evidence e JOIN cases c ON e.case_id = c.case_id ORDER BY e.id DESC"
        ).fetchall()
    return render_template("evidence_list.html", items=items, q=q)


@app.route("/evidence/register", methods=["GET", "POST"])
@auth.permission_required("evidence")
def register_evidence():
    cases = db().execute("SELECT case_id, fir_number, crime_type FROM cases ORDER BY id DESC").fetchall()
    suggested_id = next_id("evidence", "EV-2026-", 4)
    if request.method == "GET":
        return render_template("register_evidence.html", cases=cases, suggested_id=suggested_id)

    f = request.files.get("file")
    if not f or not f.filename:
        flash("Evidence file is required.", "error")
        return render_template("register_evidence.html", cases=cases, suggested_id=suggested_id), 400

    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED_EXT:
        flash(f"File type '.{ext}' is not permitted.", "error")
        return render_template("register_evidence.html", cases=cases, suggested_id=suggested_id), 400

    evidence_id = request.form.get("evidence_id", "").strip() or suggested_id
    case_id = request.form.get("case_id", "").strip()
    evidence_type = request.form.get("evidence_type", "").strip()
    description = request.form.get("description", "").strip()
    serial_no = request.form.get("serial_no", "").strip()
    condition = request.form.get("condition", "").strip() or "Intact"
    seizure_location = request.form.get("seizure_location", "").strip()
    seizure_at = request.form.get("seizure_at", "").strip()
    seal_no = request.form.get("seal_no", "").strip()
    location = request.form.get("location", "").strip() or "Evidence Locker"
    notes = request.form.get("notes", "").strip()

    if not (case_id and evidence_type):
        flash("Case and Evidence Type are required.", "error")
        return render_template("register_evidence.html", cases=cases, suggested_id=evidence_id), 400

    os.makedirs(UPLOAD_DIR, exist_ok=True)
    safe_name = secure_filename(f.filename)
    stored = os.path.join(UPLOAD_DIR, f"{evidence_id}_{uuid.uuid4().hex[:8]}_{safe_name}")
    f.save(stored)
    digest = sha256_file(stored)

    try:
        db().execute(
            "INSERT INTO evidence (evidence_id, case_id, evidence_type, description, serial_no, "
            "seizure_location, seizure_at, seal_no, file_name, stored_path, sha256, condition, "
            "location, notes, registered_by, registered_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                evidence_id, case_id, evidence_type, description, serial_no,
                seizure_location, seizure_at, seal_no, safe_name, stored, digest,
                condition, location, notes, session["user_id"], now()
            ),
        )
        db().commit()
    except sqlite3.IntegrityError:
        if os.path.exists(stored):
            os.remove(stored)
        flash("Evidence ID already exists or Case ID is invalid.", "error")
        return render_template("register_evidence.html", cases=cases, suggested_id=suggested_id), 400

    add_custody_event(
        evidence_id, "COLLECTED", None, session["username"],
        location, condition, notes or "Initial registration. SHA-256 recorded."
    )
    audit("EVIDENCE_REGISTERED", evidence_id, f"SHA-256: {digest[:16]}...")
    flash(f"Evidence {evidence_id} registered & hashed successfully.", "success")
    return redirect(url_for("evidence_detail", evidence_id=evidence_id))


@app.route("/custody/<evidence_id>/transfer", methods=["POST"])
@auth.permission_required("custody")
def transfer(evidence_id):
    ev = db().execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
    if ev is None:
        abort(404)
    action = request.form.get("action", "TRANSFERRED").strip() or "TRANSFERRED"
    from_user = request.form.get("from_user", "").strip() or session["username"]
    to_user = request.form.get("to_user", "").strip()
    location = request.form.get("location", "").strip()
    condition = request.form.get("condition", "").strip() or ev["condition"]
    notes = request.form.get("notes", "").strip()

    if not (to_user and location):
        flash("Recipient and Location are required for custody transfer.", "error")
        return redirect(url_for("evidence_detail", evidence_id=evidence_id))

    add_custody_event(evidence_id, action, from_user, to_user, location, condition, notes)
    db().execute("UPDATE evidence SET location=?, condition=? WHERE evidence_id=?", (location, condition, evidence_id))
    db().commit()
    audit("CUSTODY_TRANSFER", evidence_id, f"{from_user} -> {to_user} ({location})")
    flash("Custody transfer recorded.", "success")
    return redirect(url_for("evidence_detail", evidence_id=evidence_id))


@app.route("/verify/<evidence_id>")
@auth.permission_required("verify")
def verify_page(evidence_id):
    result = run_verification(evidence_id)
    if result is None:
        abort(404)
    events = db().execute(
        "SELECT * FROM custody_events WHERE evidence_id=? ORDER BY id", (evidence_id,)
    ).fetchall()
    audit("VERIFY", evidence_id, result["status"])
    return render_template("verify.html", r=result, events=events)


@app.route("/api/verify/<evidence_id>")
@auth.permission_required("verify")
def api_verify(evidence_id):
    result = run_verification(evidence_id)
    if result is None:
        return jsonify(error="Evidence not found"), 404
    audit("API_VERIFY", evidence_id, result["status"])
    return jsonify(result)


# Import extra routes (dashboard, QR, JSON export, PDF report, audit, user management)
import extra_routes  # noqa: E402, F401


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Access Denied: Your role does not have permission for this action."), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Record or page not found."), 404


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
