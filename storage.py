"""ASI Mini storage layer.

SQLite persistence with Fernet encryption-at-rest, seeded 4-role RBAC,
persistent analyst overrides, host stability history and scan jobs.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from cryptography.fernet import Fernet, InvalidToken

# ---------------------------------------------------------------------------
# Paths / encryption
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parent
ENC_PREFIX = "enc:"
PBKDF2_ITERATIONS = 210_000

_FERNET: Fernet | None = None
_FERNET_LOCK = threading.Lock()
_INIT_LOCK = threading.Lock()
_INITIALIZED: set[str] = set()


def db_path() -> str:
    """Resolved at call time so tests can point ASI_DB_PATH at a temp file."""
    return os.environ.get("ASI_DB_PATH") or str(ROOT / "asi_mini.db")


def _key_file() -> Path:
    return Path(os.environ.get("ASI_KEY_FILE") or (ROOT / ".asi_key"))


def _derive_key(secret: str) -> bytes:
    raw = base64.urlsafe_b64encode(hashlib.sha256(secret.encode("utf-8")).digest())
    return raw


def _load_fernet() -> Fernet:
    global _FERNET
    if _FERNET is not None:
        return _FERNET
    with _FERNET_LOCK:
        if _FERNET is not None:
            return _FERNET
        env_key = (os.environ.get("ASI_MASTER_KEY") or "").strip()
        if env_key:
            try:
                _FERNET = Fernet(env_key.encode("utf-8"))
            except Exception:
                _FERNET = Fernet(_derive_key(env_key))
            return _FERNET
        path = _key_file()
        if path.exists():
            key = path.read_bytes().strip()
        else:
            key = Fernet.generate_key()
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(key)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        _FERNET = Fernet(key)
        return _FERNET


def encrypt_text(plain: str | None) -> str | None:
    if plain is None:
        return None
    return ENC_PREFIX + _load_fernet().encrypt(str(plain).encode("utf-8")).decode("ascii")


def decrypt_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value)
    if not text.startswith(ENC_PREFIX):
        return text
    try:
        return _load_fernet().decrypt(text[len(ENC_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


def encrypt_json(obj: Any) -> str:
    return encrypt_text(json.dumps(obj, ensure_ascii=False, default=str)) or ""


def decrypt_json(value: str | None, default: Any = None) -> Any:
    text = decrypt_text(value)
    if text is None or text == "":
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


def is_encrypted(value: str | None) -> bool:
    return bool(value) and str(value).startswith(ENC_PREFIX)


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------
def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _connect():
    conn = sqlite3.connect(db_path(), timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        yield conn
        conn.commit()
    finally:
        conn.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS roles (
    key TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    permissions TEXT NOT NULL,
    is_system INTEGER NOT NULL DEFAULT 0,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT,
    last_login TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT,
    expires_at TEXT
);
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    mode TEXT NOT NULL,
    scanned_at TEXT,
    duration_sec REAL NOT NULL DEFAULT 0,
    scan_status TEXT NOT NULL DEFAULT 'completed',
    summary_enc TEXT,
    payload_enc TEXT,
    host_count INTEGER NOT NULL DEFAULT 0,
    findings_total INTEGER NOT NULL DEFAULT 0,
    exposure_score INTEGER NOT NULL DEFAULT 0,
    grade TEXT,
    created_by TEXT,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS overrides (
    asset_key TEXT PRIMARY KEY,
    asset_type TEXT NOT NULL DEFAULT 'host',
    notes_enc TEXT,
    tags_enc TEXT,
    custom_severity TEXT,
    status_override TEXT,
    scan_id INTEGER,
    updated_by TEXT,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL DEFAULT 'Signature Match',
    match_type TEXT NOT NULL DEFAULT 'html',
    match_key TEXT,
    match_value TEXT,
    path TEXT,
    severity TEXT NOT NULL DEFAULT 'MEDIUM',
    description TEXT,
    remediation TEXT,
    mitre_id TEXT,
    cve TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    builtin INTEGER NOT NULL DEFAULT 0,
    created_at TEXT
);
CREATE TABLE IF NOT EXISTS host_history (
    asset_key TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    first_seen TEXT,
    last_seen TEXT,
    seen_count INTEGER NOT NULL DEFAULT 0,
    scan_count INTEGER NOT NULL DEFAULT 0,
    missed_streak INTEGER NOT NULL DEFAULT 0,
    time_slots_json TEXT,
    stability TEXT NOT NULL DEFAULT 'active',
    confidence_pct INTEGER NOT NULL DEFAULT 0,
    last_status TEXT,
    last_scan_id INTEGER,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS scan_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_name TEXT,
    targets_enc TEXT,
    chunk_size INTEGER NOT NULL DEFAULT 256,
    cursor INTEGER NOT NULL DEFAULT 0,
    window_start TEXT,
    window_end TEXT,
    interval_minutes INTEGER NOT NULL DEFAULT 60,
    rate_limit_rps REAL NOT NULL DEFAULT 5,
    status TEXT NOT NULL DEFAULT 'pending',
    total_hosts INTEGER NOT NULL DEFAULT 0,
    last_scan_id INTEGER,
    created_by TEXT,
    created_at TEXT,
    updated_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(id DESC);
CREATE INDEX IF NOT EXISTS idx_host_history_stability ON host_history(stability);
"""

ROLE_SEEDS: list[tuple[str, str, list[str]]] = [
    ("admin", "Administracja", ["read", "modify", "add", "delete", "manage_users", "manage_config"]),
    ("add_delete_modify", "Dodawanie, usuwanie, modyfikacja", ["read", "modify", "add", "delete"]),
    ("modify_read", "Modyfikacja i odczyt", ["read", "modify"]),
    ("read", "Odczyt", ["read"]),
]

USER_SEEDS: list[tuple[str, str, str]] = [
    ("admin", "admin123", "admin"),
    ("analyst", "analyst123", "add_delete_modify"),
    ("operator", "operator123", "modify_read"),
    ("auditor", "auditor123", "read"),
]

ALL_PERMISSIONS = ["read", "modify", "add", "delete", "manage_users", "manage_config"]


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt, expected = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), int(iterations))
        return hmac.compare_digest(digest.hex(), expected)
    except Exception:
        return False


def _permissions_list(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(x) for x in raw]
    try:
        parsed = json.loads(raw or "[]")
        return [str(x) for x in parsed] if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return [x.strip() for x in str(raw or "").split(",") if x.strip()]


def _user_dict(row: sqlite3.Row | dict) -> dict:
    data = dict(row)
    perms = _permissions_list(data.get("permissions"))
    return {
        "id": data.get("id"),
        "username": data.get("username"),
        "role": data.get("role"),
        "role_label": data.get("role_label") or data.get("label") or data.get("role"),
        "permissions": perms,
        "active": bool(data.get("active", 1)),
        "created_at": data.get("created_at"),
        "last_login": data.get("last_login"),
    }


def _seed(conn: sqlite3.Connection) -> None:
    now = _now()
    for key, label, perms in ROLE_SEEDS:
        conn.execute(
            "INSERT OR IGNORE INTO roles (key, label, permissions, is_system, created_at) VALUES (?,?,?,?,?)",
            (key, label, json.dumps(perms), 1, now),
        )
    for username, password, role in USER_SEEDS:
        exists = conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone()
        if not exists:
            conn.execute(
                "INSERT INTO users (username, password_hash, role, active, created_at) VALUES (?,?,?,?,?)",
                (username, _hash_password(password), role, 1, now),
            )
    try:
        from scanner import DEFAULT_SIGNATURES
    except Exception:
        DEFAULT_SIGNATURES = []
    for sig in DEFAULT_SIGNATURES:
        conn.execute(
            """INSERT OR IGNORE INTO signatures
               (name, category, match_type, match_key, match_value, path, severity,
                description, remediation, mitre_id, cve, enabled, builtin, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                sig.get("name"), sig.get("category", "Signature Match"), sig.get("match_type", "html"),
                sig.get("match_key"), sig.get("match_value"), sig.get("path"), sig.get("severity", "MEDIUM"),
                sig.get("description"), sig.get("remediation"), sig.get("mitre_id"), sig.get("cve"),
                1 if sig.get("enabled", True) else 0, 1, now,
            ),
        )


def init_db() -> None:
    _load_fernet()  # ensure .asi_key exists even before the first write
    path = db_path()
    with _INIT_LOCK:
        if path in _INITIALIZED and Path(path).exists():
            return
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with _connect() as conn:
            conn.executescript(SCHEMA)
            _seed(conn)
        _INITIALIZED.add(path)


# ---------------------------------------------------------------------------
# Auth / RBAC
# ---------------------------------------------------------------------------
def list_roles() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM roles ORDER BY is_system DESC, key").fetchall()
    return [
        {
            "key": r["key"],
            "label": r["label"],
            "permissions": _permissions_list(r["permissions"]),
            "is_system": bool(r["is_system"]),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def create_role(key: str, label: str, permissions: Iterable[str]) -> dict:
    key = (key or "").strip().lower().replace(" ", "_")
    if not key:
        raise ValueError("Role key is required.")
    perms = [p for p in dict.fromkeys(str(x).strip() for x in permissions) if p]
    invalid = [p for p in perms if p not in ALL_PERMISSIONS]
    if invalid:
        raise ValueError(f"Unknown permissions: {', '.join(invalid)}")
    if not perms:
        raise ValueError("At least one permission is required.")
    with _connect() as conn:
        if conn.execute("SELECT 1 FROM roles WHERE key=?", (key,)).fetchone():
            raise ValueError(f"Role '{key}' already exists.")
        conn.execute(
            "INSERT INTO roles (key, label, permissions, is_system, created_at) VALUES (?,?,?,?,?)",
            (key, label or key, json.dumps(perms), 0, _now()),
        )
    return {"key": key, "label": label or key, "permissions": perms, "is_system": False}


def list_users() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            """SELECT u.*, r.label AS role_label, r.permissions AS permissions
               FROM users u LEFT JOIN roles r ON r.key = u.role ORDER BY u.id"""
        ).fetchall()
    return [_user_dict(r) for r in rows]


def get_user(username: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            """SELECT u.*, r.label AS role_label, r.permissions AS permissions
               FROM users u LEFT JOIN roles r ON r.key = u.role WHERE u.username=?""",
            (username,),
        ).fetchone()
    return _user_dict(row) if row else None


def create_user(username: str, password: str, role: str) -> dict:
    username = (username or "").strip()
    if not username or not password:
        raise ValueError("Username and password are required.")
    if len(password) < 4:
        raise ValueError("Password must be at least 4 characters.")
    with _connect() as conn:
        if not conn.execute("SELECT 1 FROM roles WHERE key=?", (role,)).fetchone():
            raise ValueError(f"Unknown role '{role}'.")
        if conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
            raise ValueError(f"User '{username}' already exists.")
        conn.execute(
            "INSERT INTO users (username, password_hash, role, active, created_at) VALUES (?,?,?,?,?)",
            (username, _hash_password(password), role, 1, _now()),
        )
    return get_user(username) or {}


def authenticate(username: str, password: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute(
            """SELECT u.*, r.label AS role_label, r.permissions AS permissions
               FROM users u LEFT JOIN roles r ON r.key = u.role WHERE u.username=?""",
            (username,),
        ).fetchone()
        if not row or not row["active"] or not verify_password(password, row["password_hash"]):
            return None
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (_now(), row["id"]))
    return _user_dict(row)


def create_session(user_id: int, ttl_hours: int = 12) -> str:
    token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    with _connect() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            (token, user_id, now.isoformat(), (now + timedelta(hours=ttl_hours)).isoformat()),
        )
    return token


def get_user_by_token(token: str | None) -> dict | None:
    if not token:
        return None
    with _connect() as conn:
        row = conn.execute(
            """SELECT u.*, r.label AS role_label, r.permissions AS permissions, s.expires_at
               FROM sessions s JOIN users u ON u.id = s.user_id
               LEFT JOIN roles r ON r.key = u.role
               WHERE s.token=? AND u.active=1""",
            (token,),
        ).fetchone()
        if not row:
            return None
        try:
            if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
                conn.execute("DELETE FROM sessions WHERE token=?", (token,))
                return None
        except (TypeError, ValueError):
            return None
    return _user_dict(row)


def login(username: str, password: str) -> dict | None:
    user = authenticate(username, password)
    if not user:
        return None
    token = create_session(user["id"])
    return {"user": user, "token": token}


def revoke_token(token: str | None) -> None:
    if not token:
        return
    with _connect() as conn:
        conn.execute("DELETE FROM sessions WHERE token=?", (token,))


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------
def save_scan(
    target: str,
    mode: str,
    result: dict,
    analysis: dict,
    duration_sec: float | None = None,
    scan_status: str | None = None,
    user: str | None = None,
) -> int:
    summary = analysis.get("summary") or {}
    assets = result.get("subdomains") or result.get("assets") or []
    duration = duration_sec if duration_sec is not None else float(result.get("duration_sec") or 0)
    status = scan_status or result.get("scan_status") or "completed"
    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO scans
               (target, mode, scanned_at, duration_sec, scan_status, summary_enc, payload_enc,
                host_count, findings_total, exposure_score, grade, created_by, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                target or "unknown", mode or "live", result.get("scanned_at") or _now(),
                round(float(duration or 0), 3), status, encrypt_json(summary), encrypt_json(result),
                len(assets), int(summary.get("findings_total", len(analysis.get("findings") or []))),
                int(summary.get("exposure_score", 0)), summary.get("grade"), user, _now(),
            ),
        )
        return int(cur.lastrowid)


def update_scan_result(scan_id: int, result: dict, analysis: dict | None = None) -> bool:
    analysis = analysis or result
    summary = analysis.get("summary") or result.get("summary") or {}
    assets = result.get("subdomains") or result.get("assets") or []
    with _connect() as conn:
        cur = conn.execute(
            """UPDATE scans SET summary_enc=?, payload_enc=?, host_count=?, findings_total=?,
               exposure_score=?, grade=?, duration_sec=?, scan_status=? WHERE id=?""",
            (
                encrypt_json(summary), encrypt_json(result), len(assets),
                int(summary.get("findings_total", 0)), int(summary.get("exposure_score", 0)),
                summary.get("grade"), round(float(result.get("duration_sec") or 0), 3),
                result.get("scan_status") or "completed", scan_id,
            ),
        )
        return cur.rowcount > 0


def _scan_row(row: sqlite3.Row, include_payload: bool = False) -> dict:
    data = {
        "scan_id": row["id"],
        "id": row["id"],
        "target": row["target"],
        "mode": row["mode"],
        "scanned_at": row["scanned_at"],
        "duration_sec": row["duration_sec"],
        "scan_status": row["scan_status"],
        "host_count": row["host_count"],
        "findings_total": row["findings_total"],
        "exposure_score": row["exposure_score"],
        "grade": row["grade"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
    }
    if include_payload:
        payload = decrypt_json(row["payload_enc"], {}) or {}
        summary = decrypt_json(row["summary_enc"], {}) or {}
        if isinstance(payload, dict):
            data.update(payload)
        if summary:
            data["summary"] = summary
        data["scan_id"] = row["id"]
        data["id"] = row["id"]
        data["duration_sec"] = row["duration_sec"]
        data["scan_status"] = row["scan_status"]
    return data


def list_scans(limit: int = 100, offset: int = 0) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ? OFFSET ?", (max(1, int(limit)), max(0, int(offset)))
        ).fetchall()
    return [_scan_row(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (int(scan_id),)).fetchone()
    return _scan_row(row, include_payload=True) if row else None


def delete_scan(scan_id: int) -> bool:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM scans WHERE id=?", (int(scan_id),))
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Persistent overrides
# ---------------------------------------------------------------------------
def _normalise_tags(tags: Any) -> list[str]:
    if tags is None:
        return []
    if isinstance(tags, str):
        return [t.strip() for t in tags.split(",") if t.strip()]
    if isinstance(tags, (list, tuple, set)):
        return [str(t).strip() for t in tags if str(t).strip()]
    return [str(tags).strip()]


def _normalise_severity(value: Any) -> str | None:
    if value is None:
        return None
    sev = str(value).strip().upper()
    return sev if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else None


def _override_row(row: sqlite3.Row) -> dict:
    return {
        "asset_key": row["asset_key"],
        "asset_type": row["asset_type"],
        "notes": decrypt_text(row["notes_enc"]) or "",
        "tags": decrypt_json(row["tags_enc"], []) or [],
        "custom_severity": row["custom_severity"],
        "status_override": row["status_override"],
        "scan_id": row["scan_id"],
        "updated_by": row["updated_by"],
        "updated_at": row["updated_at"],
    }


def save_override(data: dict, updated_by: str | None = None) -> dict:
    asset_key = str(data.get("asset_key") or "").strip()
    if not asset_key:
        raise ValueError("asset_key is required.")
    asset_type = str(data.get("asset_type") or "host").strip().lower()
    if asset_type not in ("host", "finding"):
        asset_type = "host"
    with _connect() as conn:
        existing = conn.execute("SELECT * FROM overrides WHERE asset_key=?", (asset_key,)).fetchone()
        current = _override_row(existing) if existing else {
            "asset_type": asset_type, "notes": "", "tags": [], "custom_severity": None,
            "status_override": None, "scan_id": None,
        }
        notes = current["notes"]
        if "notes" in data and data["notes"] is not None:
            notes = str(data["notes"])
        tags = current["tags"]
        if "tags" in data and data["tags"] is not None:
            tags = _normalise_tags(data["tags"])
        severity = current["custom_severity"]
        if "custom_severity" in data and data["custom_severity"] is not None:
            severity = _normalise_severity(data["custom_severity"])
        status = current["status_override"]
        if "status_override" in data and data["status_override"] is not None:
            status = str(data["status_override"]).strip().lower() or None
        scan_id = current.get("scan_id")
        if data.get("scan_id") is not None:
            try:
                scan_id = int(data["scan_id"])
            except (TypeError, ValueError):
                scan_id = None
        conn.execute(
            """INSERT INTO overrides
               (asset_key, asset_type, notes_enc, tags_enc, custom_severity, status_override,
                scan_id, updated_by, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?)
               ON CONFLICT(asset_key) DO UPDATE SET
                 asset_type=excluded.asset_type, notes_enc=excluded.notes_enc,
                 tags_enc=excluded.tags_enc, custom_severity=excluded.custom_severity,
                 status_override=excluded.status_override, scan_id=excluded.scan_id,
                 updated_by=excluded.updated_by, updated_at=excluded.updated_at""",
            (
                asset_key, asset_type, encrypt_text(notes), encrypt_json(tags), severity, status,
                scan_id, updated_by, _now(),
            ),
        )
    return get_override(asset_key) or {}


def get_override(asset_key: str) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM overrides WHERE asset_key=?", (asset_key,)).fetchone()
    return _override_row(row) if row else None


def get_overrides() -> dict[str, dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM overrides ORDER BY updated_at DESC").fetchall()
    return {r["asset_key"]: _override_row(r) for r in rows}


def list_overrides() -> list[dict]:
    return list(get_overrides().values())


def delete_override(asset_key: str) -> bool:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM overrides WHERE asset_key=?", (asset_key,))
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------
def _signature_row(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "category": row["category"],
        "match_type": row["match_type"],
        "match_key": row["match_key"],
        "match_value": row["match_value"],
        "path": row["path"],
        "severity": row["severity"],
        "description": row["description"],
        "remediation": row["remediation"],
        "mitre_id": row["mitre_id"],
        "cve": row["cve"],
        "enabled": bool(row["enabled"]),
        "builtin": bool(row["builtin"]),
        "created_at": row["created_at"],
    }


def list_signatures(enabled_only: bool = False) -> list[dict]:
    query = "SELECT * FROM signatures"
    if enabled_only:
        query += " WHERE enabled=1"
    query += " ORDER BY id"
    with _connect() as conn:
        rows = conn.execute(query).fetchall()
    return [_signature_row(r) for r in rows]


def add_signature(data: dict) -> dict:
    name = str(data.get("name") or "").strip()
    if not name:
        raise ValueError("Signature name is required.")
    match_type = str(data.get("match_type") or "html").strip().lower()
    severity = _normalise_severity(data.get("severity") or "MEDIUM") or "MEDIUM"
    with _connect() as conn:
        if conn.execute("SELECT 1 FROM signatures WHERE name=?", (name,)).fetchone():
            raise ValueError(f"Signature '{name}' already exists.")
        cur = conn.execute(
            """INSERT INTO signatures
               (name, category, match_type, match_key, match_value, path, severity,
                description, remediation, mitre_id, cve, enabled, builtin, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                name, str(data.get("category") or "Signature Match"), match_type,
                data.get("match_key"), data.get("match_value"), data.get("path"), severity,
                data.get("description"), data.get("remediation"), data.get("mitre_id"),
                data.get("cve"), 1 if data.get("enabled", True) else 0, 0, _now(),
            ),
        )
        row = conn.execute("SELECT * FROM signatures WHERE id=?", (cur.lastrowid,)).fetchone()
    return _signature_row(row)


def delete_signature(sig_id: int) -> bool:
    with _connect() as conn:
        cur = conn.execute("DELETE FROM signatures WHERE id=?", (int(sig_id),))
        return cur.rowcount > 0


# ---------------------------------------------------------------------------
# Host history / stability
# ---------------------------------------------------------------------------
def _asset_reachable(asset: dict) -> bool:
    http = asset.get("http") or {}
    tls = asset.get("tls") or {}
    return bool(http.get("reachable") or asset.get("open_ports") or tls.get("valid") is True)


def _compute_stability(row: dict) -> tuple[str, int]:
    seen = int(row.get("seen_count") or 0)
    scans = max(int(row.get("scan_count") or 1), 1)
    missed = int(row.get("missed_streak") or 0)
    last = row.get("last_status")
    ratio = seen / scans
    if last == "reachable":
        stability = "active" if ratio >= 0.6 else "flaky"
    elif last == "unreachable":
        if seen == 0:
            stability = "unreachable"
        elif missed <= 2:
            stability = "flaky"
        else:
            stability = "inactive"
    else:
        stability = "flaky" if missed <= 1 else "inactive"
    if stability == "active":
        confidence = min(99, max(70, round(ratio * 100)))
    elif stability == "flaky":
        confidence = max(35, round(ratio * 60))
    elif stability == "inactive":
        confidence = max(10, round(ratio * 40))
    else:
        confidence = 20
    return stability, int(confidence)


def update_host_history(assets: list[dict], scan_id: int | None = None) -> dict[str, dict]:
    now = _now()
    slot = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H")
    with _connect() as conn:
        rows = {r["asset_key"]: dict(r) for r in conn.execute("SELECT * FROM host_history").fetchall()}
        for row in rows.values():
            row["scan_count"] = int(row.get("scan_count") or 0) + 1
        current: set[str] = set()
        for asset in assets or []:
            host = str(asset.get("host") or "").strip()
            if not host:
                continue
            key = host.lower()
            current.add(key)
            reachable = _asset_reachable(asset)
            status = "reachable" if reachable else "unreachable"
            row = rows.get(key)
            if row is None:
                row = {
                    "asset_key": key, "host": host, "first_seen": now,
                    "last_seen": now if reachable else None,
                    "seen_count": 1 if reachable else 0, "scan_count": 1,
                    "missed_streak": 0 if reachable else 1,
                    "time_slots_json": "[]", "last_status": status,
                }
                rows[key] = row
            else:
                row["host"] = host
                if reachable:
                    row["seen_count"] = int(row.get("seen_count") or 0) + 1
                    row["last_seen"] = now
                    row["missed_streak"] = 0
                else:
                    row["missed_streak"] = int(row.get("missed_streak") or 0) + 1
                row["last_status"] = status
            try:
                slots = json.loads(row.get("time_slots_json") or "[]")
            except (TypeError, ValueError):
                slots = []
            if slot not in slots:
                slots.append(slot)
            row["time_slots_json"] = json.dumps(slots[-48:])
            row["last_scan_id"] = scan_id
            row["stability"], row["confidence_pct"] = _compute_stability(row)
            row["updated_at"] = now
        for key, row in rows.items():
            if key in current:
                continue
            row["missed_streak"] = int(row.get("missed_streak") or 0) + 1
            row["last_status"] = "missing"
            row["stability"], row["confidence_pct"] = _compute_stability(row)
            row["updated_at"] = now
        for row in rows.values():
            conn.execute(
                """INSERT INTO host_history
                   (asset_key, host, first_seen, last_seen, seen_count, scan_count, missed_streak,
                    time_slots_json, stability, confidence_pct, last_status, last_scan_id, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                   ON CONFLICT(asset_key) DO UPDATE SET
                     host=excluded.host, last_seen=excluded.last_seen, seen_count=excluded.seen_count,
                     scan_count=excluded.scan_count, missed_streak=excluded.missed_streak,
                     time_slots_json=excluded.time_slots_json, stability=excluded.stability,
                     confidence_pct=excluded.confidence_pct, last_status=excluded.last_status,
                     last_scan_id=excluded.last_scan_id, updated_at=excluded.updated_at""",
                (
                    row["asset_key"], row["host"], row.get("first_seen"), row.get("last_seen"),
                    int(row.get("seen_count") or 0), int(row.get("scan_count") or 1),
                    int(row.get("missed_streak") or 0), row.get("time_slots_json") or "[]",
                    row.get("stability") or "inactive", int(row.get("confidence_pct") or 0),
                    row.get("last_status"), row.get("last_scan_id"), row.get("updated_at") or now,
                ),
            )
    return {key: _stats_for(rows[key]) for key in current if key in rows}


def _stats_for(row: dict) -> dict:
    try:
        slots = json.loads(row.get("time_slots_json") or "[]")
    except (TypeError, ValueError):
        slots = []
    return {
        "asset_key": row.get("asset_key"),
        "host": row.get("host"),
        "stability": row.get("stability") or "inactive",
        "confidence_pct": int(row.get("confidence_pct") or 0),
        "seen_count": int(row.get("seen_count") or 0),
        "scan_count": int(row.get("scan_count") or 0),
        "missed_streak": int(row.get("missed_streak") or 0),
        "first_seen": row.get("first_seen"),
        "last_seen": row.get("last_seen"),
        "last_status": row.get("last_status"),
        "time_slots": slots,
    }


def get_host_stats() -> dict[str, dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM host_history").fetchall()
    return {r["asset_key"]: _stats_for(dict(r)) for r in rows}


def list_host_history() -> list[dict]:
    return list(get_host_stats().values())


# ---------------------------------------------------------------------------
# Scan jobs
# ---------------------------------------------------------------------------
def _job_row(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "job_name": row["job_name"],
        "targets": decrypt_json(row["targets_enc"], []),
        "chunk_size": row["chunk_size"],
        "cursor": row["cursor"],
        "window_start": row["window_start"],
        "window_end": row["window_end"],
        "interval_minutes": row["interval_minutes"],
        "rate_limit_rps": row["rate_limit_rps"],
        "status": row["status"],
        "total_hosts": row["total_hosts"],
        "last_scan_id": row["last_scan_id"],
        "created_by": row["created_by"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def create_scan_job(data: dict, user: str | None = None) -> dict:
    targets = data.get("targets") or []
    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO scan_jobs
               (job_name, targets_enc, chunk_size, cursor, window_start, window_end,
                interval_minutes, rate_limit_rps, status, total_hosts, created_by, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                data.get("job_name") or "asi-job", encrypt_json(targets),
                int(data.get("chunk_size") or 256), int(data.get("cursor") or 0),
                data.get("window_start"), data.get("window_end"),
                int(data.get("interval_minutes") or 60), float(data.get("rate_limit_rps") or 5),
                data.get("status") or "pending", int(data.get("total_hosts") or 0), user, _now(), _now(),
            ),
        )
        row = conn.execute("SELECT * FROM scan_jobs WHERE id=?", (cur.lastrowid,)).fetchone()
    return _job_row(row)


def update_scan_job(job_id: int, **fields: Any) -> dict | None:
    allowed = {
        "job_name", "chunk_size", "cursor", "window_start", "window_end", "interval_minutes",
        "rate_limit_rps", "status", "total_hosts", "last_scan_id",
    }
    sets: list[str] = []
    values: list[Any] = []
    for key, value in fields.items():
        if key not in allowed:
            continue
        sets.append(f"{key}=?")
        values.append(value)
    if "targets" in fields:
        sets.append("targets_enc=?")
        values.append(encrypt_json(fields["targets"]))
    if not sets:
        return get_scan_job(job_id)
    sets.append("updated_at=?")
    values.append(_now())
    values.append(int(job_id))
    with _connect() as conn:
        conn.execute(f"UPDATE scan_jobs SET {', '.join(sets)} WHERE id=?", values)
        row = conn.execute("SELECT * FROM scan_jobs WHERE id=?", (int(job_id),)).fetchone()
    return _job_row(row) if row else None


def get_scan_job(job_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM scan_jobs WHERE id=?", (int(job_id),)).fetchone()
    return _job_row(row) if row else None


def list_scan_jobs() -> list[dict]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM scan_jobs ORDER BY id DESC").fetchall()
    return [_job_row(r) for r in rows]
