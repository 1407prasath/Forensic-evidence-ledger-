import hashlib

CHUNK = 1024 * 1024  # Read files in 1 MB blocks
GENESIS = "0" * 64


def sha256_file(path):
    """Return the SHA-256 hex digest of a file without loading it fully."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def event_digest(prev_hash, evidence_id, action, from_user, to_user,
                 location, condition, notes, event_time):
    """Digest of one custody event, linked to the previous event."""
    parts = [
        prev_hash,
        evidence_id,
        action,
        from_user or "",
        to_user or "",
        location or "",
        condition or "",
        notes or "",
        event_time,
    ]
    return sha256_text("|".join(parts))


def verify_chain(events):
    """events: list of dict rows ordered by id. Returns (ok, broken_index)."""
    prev = GENESIS
    for i, e in enumerate(events):
        if e["prev_hash"] != prev:
            return False, i
        calc = event_digest(
            e["prev_hash"],
            e["evidence_id"],
            e["action"],
            e["from_user"],
            e["to_user"],
            e["location"],
            e["condition"],
            e["notes"],
            e["event_time"],
        )
        if calc != e["event_hash"]:
            return False, i
        prev = e["event_hash"]
    return True, None
