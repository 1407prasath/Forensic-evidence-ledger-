import io
import os
from flask import jsonify, send_file, render_template, abort, request, redirect, url_for, flash, session
from app import app, db, audit, run_verification, now, BASE
import auth
from qr_report import make_qr_png, build_evidence_report


@app.route("/dashboard")
@auth.permission_required("dashboard")
def dashboard():
    q = lambda sql: db().execute(sql).fetchone()[0]
    stats = {
        "cases": q("SELECT COUNT(*) FROM cases"),
        "evidence": q("SELECT COUNT(*) FROM evidence"),
        "transfers": q("SELECT COUNT(*) FROM custody_events WHERE action != 'COLLECTED'"),
        "alerts": q("SELECT COUNT(*) FROM audit_log WHERE action IN ('VERIFY', 'API_VERIFY') AND detail != 'VERIFIED'"),
        "verified": q("SELECT COUNT(*) FROM audit_log WHERE action IN ('VERIFY', 'API_VERIFY') AND detail = 'VERIFIED'"),
    }
    recent = db().execute(
        "SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.id DESC LIMIT 12"
    ).fetchall()
    return render_template("dashboard.html", stats=stats, recent=recent)


@app.route("/evidence/<evidence_id>")
@auth.login_required
def evidence_detail(evidence_id):
    ev = db().execute(
        "SELECT e.*, c.fir_number, c.crime_type FROM evidence e JOIN cases c ON e.case_id = c.case_id WHERE e.evidence_id=?",
        (evidence_id,),
    ).fetchone()
    if ev is None:
        abort(404)
    events = db().execute(
        "SELECT * FROM custody_events WHERE evidence_id=? ORDER BY id", (evidence_id,)
    ).fetchall()
    status_info = run_verification(evidence_id)
    return render_template("evidence_detail.html", ev=ev, events=events, status_info=status_info)


@app.route("/evidence/<evidence_id>/download")
@auth.login_required
def download_evidence_file(evidence_id):
    ev = db().execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
    if ev is None or not ev["stored_path"] or not os.path.exists(ev["stored_path"]):
        abort(404)
    audit("DOWNLOAD_EVIDENCE", evidence_id, ev["file_name"])
    return send_file(ev["stored_path"], as_attachment=True, download_name=ev["file_name"])


@app.route("/evidence/<evidence_id>/qr")
@auth.permission_required("verify")
def evidence_qr(evidence_id):
    ev = db().execute("SELECT evidence_id FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
    if ev is None:
        abort(404)
    # Dynamically uses current live domain (localhost, Render URL, or custom domain)
    verify_url = request.url_root.rstrip("/") + url_for("verify_page", evidence_id=evidence_id)
    return send_file(io.BytesIO(make_qr_png(verify_url)), mimetype="image/png")


@app.route("/evidence/<evidence_id>/export.json")
@auth.permission_required("report")
def export_json(evidence_id):
    ev = db().execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
    if ev is None:
        abort(404)
    case = db().execute("SELECT * FROM cases WHERE case_id=?", (ev["case_id"],)).fetchone()
    events = db().execute("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY id", (evidence_id,)).fetchall()
    audit("EXPORT_JSON", evidence_id)
    return jsonify(
        case_id=case["case_id"],
        fir_number=case["fir_number"],
        evidence_id=evidence_id,
        file_name=ev["file_name"],
        hash=ev["sha256"],
        verification=run_verification(evidence_id),
        custody_events=[dict(e) for e in events],
    )


@app.route("/evidence/<evidence_id>/report.pdf")
@auth.permission_required("report")
def evidence_report(evidence_id):
    ev = db().execute("SELECT * FROM evidence WHERE evidence_id=?", (evidence_id,)).fetchone()
    if ev is None:
        abort(404)
    case = db().execute("SELECT * FROM cases WHERE case_id=?", (ev["case_id"],)).fetchone()
    events = db().execute("SELECT * FROM custody_events WHERE evidence_id=? ORDER BY id", (evidence_id,)).fetchall()
    rep_dir = os.path.join(BASE, "reports")
    os.makedirs(rep_dir, exist_ok=True)
    path = os.path.join(rep_dir, f"{evidence_id}_report.pdf")
    build_evidence_report(path, case, ev, events, run_verification(evidence_id))
    audit("REPORT_PDF", evidence_id)
    return send_file(path, mimetype="application/pdf", as_attachment=True, download_name=f"{evidence_id}_Report.pdf")


@app.route("/reports")
@auth.permission_required("report")
def reports_page():
    items = db().execute("SELECT evidence_id, case_id, evidence_type, file_name FROM evidence ORDER BY id DESC").fetchall()
    return render_template("reports.html", items=items)


@app.route("/export/ledger.json")
@auth.permission_required("report")
def export_full_ledger():
    cases = [dict(c) for c in db().execute("SELECT * FROM cases ORDER BY id").fetchall()]
    evidence = [dict(e) for e in db().execute("SELECT * FROM evidence ORDER BY id").fetchall()]
    custody = [dict(k) for k in db().execute("SELECT * FROM custody_events ORDER BY id").fetchall()]
    audit("EXPORT_FULL_LEDGER", "ALL")
    return jsonify(exported_at=now(), cases=cases, evidence=evidence, custody_events=custody)


@app.route("/audit")
@auth.permission_required("audit")
def audit_view():
    rows = db().execute(
        "SELECT a.*, u.username FROM audit_log a LEFT JOIN users u ON a.user_id = u.id ORDER BY a.id DESC LIMIT 200"
    ).fetchall()
    return render_template("audit.html", rows=rows)


@app.route("/users", methods=["GET", "POST"])
@auth.permission_required("users")
def users_view():
    if request.method == "POST":
        action = request.form.get("form_action", "create")
        if action == "create":
            username = request.form.get("username", "").strip()
            full_name = request.form.get("full_name", "").strip()
            role = request.form.get("role", "").strip()
            password = request.form.get("password", "").strip()
            if username and full_name and role and password:
                try:
                    db().execute(
                        "INSERT INTO users (username, password_hash, full_name, role, created_at) VALUES (?, ?, ?, ?, ?)",
                        (username, auth.make_hash(password), full_name, role, now()),
                    )
                    db().commit()
                    audit("USER_CREATED", username, f"Role: {role}")
                    flash(f"User '{username}' created.", "success")
                except Exception:
                    flash("Username already exists or invalid role.", "error")
        elif action == "toggle":
            uid = request.form.get("user_id")
            if uid and str(uid) != str(session.get("user_id")):
                db().execute("UPDATE users SET active = 1 - active WHERE id=?", (uid,))
                db().commit()
                audit("USER_TOGGLED", str(uid))
                flash("User status updated.", "success")
        return redirect(url_for("users_view"))

    users = db().execute("SELECT id, username, full_name, role, active, created_at FROM users ORDER BY id").fetchall()
    return render_template("users.html", users=users)
