from functools import wraps
from flask import session, redirect, url_for, abort
from werkzeug.security import generate_password_hash, check_password_hash

PERMISSIONS = {
    "Admin": {"users", "cases", "evidence", "evidence_view", "custody", "verify", "report", "audit", "dashboard"},
    "Officer": {"cases", "evidence", "evidence_view", "custody", "verify", "report", "dashboard"},
    "Laboratory": {"evidence_view", "custody", "verify", "report", "dashboard"},
    "Custodian": {"evidence_view", "custody", "verify", "dashboard"},
    "Reviewer": {"evidence_view", "verify", "report", "audit", "dashboard"},
}


def make_hash(password):
    return generate_password_hash(password)


def check_password(stored_hash, password):
    return check_password_hash(stored_hash, password)


def has_permission(perm):
    allowed = PERMISSIONS.get(session.get("role"), set())
    return perm in allowed


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapped


def permission_required(perm):
    def deco(view):
        @wraps(view)
        def wrapped(*a, **kw):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if not has_permission(perm):
                abort(403)
            return view(*a, **kw)
        return wrapped
    return deco
