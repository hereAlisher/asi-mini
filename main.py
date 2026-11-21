"""ASI Mini FastAPI application.

X-Auth-Token authenticated RBAC API, 10k+ IP planning, encrypted scan
persistence, persistent overrides, diffing, imports, signatures and exports.
"""
from __future__ import annotations

import json
import re
import asyncio
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import storage
from analyzer import analyze_scan, compute_drift, export_csv, export_defectdojo_json
from scanner import (
    DEFAULT_SIGNATURES,
    SAMPLE_NMAP_XML,
    get_demo_scan,
    parse_nmap_xml,
    parse_structured_import,
    plan_targets,
    scan_domain,
    scan_targets,
)

storage.init_db()


# ---------------------------------------------------------------------------
# Background cyclic scheduler
# ---------------------------------------------------------------------------
_scheduler_task: asyncio.Task | None = None
SCHEDULER_TICK_SEC = 15


async def _scheduler_loop() -> None:
    """Background tick that runs the next chunk of each active scan job."""
    while True:
        await asyncio.sleep(SCHEDULER_TICK_SEC)
        try:
            await _run_due_jobs()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never let a scheduler error kill the app.
            pass


async def _run_due_jobs() -> None:
    """Iterate scan_jobs and run the next chunk for any job due for execution."""
    now = datetime.now(timezone.utc)
    jobs = storage.list_scan_jobs()
    for job in jobs:
        status = job.get("status") or "pending"
        if status not in ("active", "paused_window_expired"):
            continue

        # Parse window.
        ws = job.get("window_start")
        we = job.get("window_end")
        try:
            ws_dt = datetime.fromisoformat(str(ws).replace("Z", "+00:00")) if ws else None
        except (TypeError, ValueError):
            ws_dt = None
        try:
            we_dt = datetime.fromisoformat(str(we).replace("Z", "+00:00")) if we else None
        except (TypeError, ValueError):
            we_dt = None

        # Window checks.
        if ws_dt and now < ws_dt:
            continue
        if we_dt and now >= we_dt:
            if status != "paused_window_expired":
                storage.update_scan_job(job["id"], status="paused_window_expired")
            continue

        # If previously paused due to expired window, a new open window clears it.
        if status == "paused_window_expired":
            storage.update_scan_job(job["id"], status="active")

        # Interval check.
        interval = int(job.get("interval_minutes") or 60)
        updated_at = job.get("updated_at")
        if updated_at:
            try:
                updated_dt = datetime.fromisoformat(str(updated_at).replace("Z", "+00:00"))
                if (now - updated_dt).total_seconds() < interval * 60:
                    continue
            except (TypeError, ValueError):
                pass

        # Run the next chunk immediately (scheduler context, no user token needed).
        await _run_job_chunk(job, user=None)


async def _run_job_chunk(job: dict, user: dict | None) -> None:
    """Execute the next subgroup chunk of a scan job, update cursor, save encrypted scan."""
    job_id = int(job["id"])
    targets = job.get("targets") or []
    cursor = int(job.get("cursor") or 0)
    chunk_size = int(job.get("chunk_size") or 256)

    # Resolve host_history for flaky-host retry.
    host_stats = storage.get_host_stats()

    try:
        raw = await scan_targets(
            targets,
            domain=None,
            rate_limit_rps=float(job.get("rate_limit_rps") or 5),
            window_start=job.get("window_start"),
            window_end=job.get("window_end"),
            cursor=cursor,
            batch_limit=chunk_size,
            scan_ports=bool(job.get("scan_ports")),
            allowed_ports=job.get("allowed_ports"),
            signatures=storage.list_signatures(enabled_only=True),
            host_stats=host_stats,
        )
    except Exception:
        return

    status = raw.get("scan_status") or "completed"
    next_cursor = raw.get("next_cursor")
    total_hosts = int(raw.get("total_hosts") or 0)

    # Window closed mid-run -> pause cleanly.
    if status == "paused_window_expired":
        storage.update_scan_job(job["id"], status="paused_window_expired",
                                updated_at=datetime.now(timezone.utc).isoformat())
        return

    # Wrap cursor back to 0 when the full target space is finished.
    if next_cursor is None or next_cursor >= total_hosts:
        new_cursor = 0
    else:
        new_cursor = int(next_cursor)

    # Finalise and save the encrypted scan (reuse the shared scan pipeline).
    scan_user = user or {"username": "scheduler"}
    try:
        result = _finalize_scan(raw, scan_user, duration_sec=raw.get("duration_sec"))
    except Exception:
        return

    storage.update_scan_job(
        job["id"],
        cursor=new_cursor,
        last_scan_id=result.get("scan_id"),
        status="active" if status == "completed" else status,
        updated_at=datetime.now(timezone.utc).isoformat(),
    )


@asynccontextmanager
async def lifespan(_: FastAPI):
    storage.init_db()
    global _scheduler_task
    _scheduler_task = asyncio.create_task(_scheduler_loop())
    try:
        yield
    finally:
        if _scheduler_task:
            _scheduler_task.cancel()
            try:
                await _scheduler_task
            except asyncio.CancelledError:
                pass


app = FastAPI(title="ASI Mini - CBI AGH", version="2.0.0", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class LoginPayload(BaseModel):
    username: str
    password: str


class UserPayload(BaseModel):
    username: str
    password: str
    role: str = "read"


class RolePayload(BaseModel):
    key: str
    label: str | None = None
    permissions: list[str] = []


class PlanPayload(BaseModel):
    targets: Any = None
    target: str | None = None
    rate_limit_rps: float = 5.0
    window_minutes: float = 60.0


class ScanPayload(BaseModel):
    mode: str = "demo1"
    targets: Any = None
    target: str | None = None
    domain: str | None = None
    rate_limit_rps: float = 5.0
    window_start: Any = None
    window_end: Any = None
    cursor: int = 0
    batch_limit: int | None = None
    scan_ports: bool = False
    allowed_ports: list[int] | None = None


class OverridePayload(BaseModel):
    asset_key: str
    asset_type: str = "host"
    scan_id: int | None = None
    notes: str | None = None
    tags: Any = None
    custom_severity: str | None = None
    status_override: str | None = None


class ImportPayload(BaseModel):
    format: str = "nmap"
    filename: str = "internal-net.xml"
    content: str = ""
    sample: bool = False
    target: str | None = None
    hosts: Any = None


class SignaturePayload(BaseModel):
    name: str
    category: str = "Signature Match"
    match_type: str = "html"
    match_key: str | None = None
    match_value: str | None = None
    path: str | None = None
    severity: str = "MEDIUM"
    description: str | None = None
    remediation: str | None = None
    mitre_id: str | None = None
    cve: str | None = None
    enabled: bool = True


class DojoPushPayload(BaseModel):
    scan_id: int
    url: str | None = None
    defectdojo_url: str | None = None
    api_token: str | None = None
    token: str | None = None
    engagement_id: int | None = None
    engagement: int | None = None
    minimum_severity: str = "Low"
    close_old_findings: bool = False
    finding_ids: list[str] | None = None
    as_info_evidence: bool = False


# ---------------------------------------------------------------------------
# RBAC middleware
# ---------------------------------------------------------------------------
PERMISSION_RULES: list[tuple[str, str, Any]] = [
    ("GET", r"^/api/me$", "auth"),
    ("GET", r"^/api/users$", "manage_users"),
    ("POST", r"^/api/users$", "manage_users"),
    ("GET", r"^/api/roles$", "manage_users"),
    ("POST", r"^/api/roles$", "manage_users"),
    ("POST", r"^/api/plan$", "read"),
    ("POST", r"^/api/scan$", ("add", "modify")),
    ("GET", r"^/api/scans$", "read"),
    ("GET", r"^/api/scans/\d+$", "read"),
    ("DELETE", r"^/api/scans/\d+$", "delete"),
    ("GET", r"^/api/diff$", "read"),
    ("POST", r"^/api/overrides$", "modify"),
    ("GET", r"^/api/overrides$", "read"),
    ("POST", r"^/api/import$", "add"),
    ("GET", r"^/api/signatures$", "read"),
    ("POST", r"^/api/signatures$", "add"),
    ("PUT", r"^/api/signatures/\d+$", "modify"),
    ("GET", r"^/api/signatures/export$", "read"),
    ("POST", r"^/api/signatures/import$", "add"),
    ("DELETE", r"^/api/signatures/\d+$", "delete"),
    ("GET", r"^/api/export/\d+$", "read"),
    ("GET", r"^/api/timeline$", "read"),
    ("GET", r"^/api/admin/encryption-proof$", "manage_config"),
    ("POST", r"^/api/defectdojo/push$", "modify"),
    ("GET", r"^/api/host-history$", "read"),
    ("GET", r"^/api/jobs$", "read"),
    ("POST", r"^/api/jobs$", "add"),
    ("PUT", r"^/api/jobs/\d+$", "modify"),
    ("POST", r"^/api/jobs/\d+/run-now$", ("modify", "add")),
    ("DELETE", r"^/api/jobs/\d+$", "delete"),
]

PUBLIC_EXACT = {"/", "/api/health", "/api/login", "/docs", "/redoc", "/openapi.json", "/favicon.ico"}


def _is_public(request: Request) -> bool:
    path = request.url.path
    if path in PUBLIC_EXACT or path.startswith("/static"):
        return True
    if request.method == "GET" and path == "/api/scan":
        return True
    return False


def _required(request: Request) -> Any:
    path = request.url.path
    for method, pattern, permission in PERMISSION_RULES:
        if request.method == method and re.match(pattern, path):
            return permission
    if path.startswith("/api/"):
        return "auth"
    return None


def _token_from_request(request: Request) -> str | None:
    token = request.headers.get("x-auth-token")
    if token:
        return token.strip()
    auth = request.headers.get("authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


@app.middleware("http")
async def rbac_middleware(request: Request, call_next):
    request.state.user = None
    if _is_public(request):
        return await call_next(request)
    required = _required(request)
    user = storage.get_user_by_token(_token_from_request(request))
    request.state.user = user
    if required is None:
        return await call_next(request)
    if user is None:
        return JSONResponse(status_code=401, content={"detail": "Authentication required (X-Auth-Token)."})
    permissions = set(user.get("permissions") or [])
    if required == "auth":
        return await call_next(request)
    needed = required if isinstance(required, tuple) else (required,)
    if not any(permission in permissions for permission in needed):
        return JSONResponse(
            status_code=403,
            content={"detail": f"Forbidden: requires permission '{' or '.join(needed)}'."},
        )
    return await call_next(request)


def current_user(request: Request) -> dict:
    user = getattr(request.state, "user", None)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def require(*permissions: str):
    def dependency(user: dict = Depends(current_user)) -> dict:
        if permissions and not any(p in (user.get("permissions") or []) for p in permissions):
            raise HTTPException(status_code=403, detail=f"Requires permission: {' or '.join(permissions)}")
        return user
    return dependency


# ---------------------------------------------------------------------------
# Scan finalisation
# ---------------------------------------------------------------------------
def _finalize_scan(raw: dict, user: dict, duration_sec: float | None = None) -> dict:
    assets = raw.get("subdomains") or raw.get("assets") or []
    stats = storage.update_host_history(assets)
    overrides = storage.get_overrides()
    analysis = analyze_scan(raw, overrides=overrides, host_stats=stats)
    result = {**raw, **analysis}
    result["subdomains"] = analysis["assets"]
    result["host_stats"] = stats
    result["duration_sec"] = round(float(duration_sec if duration_sec is not None else raw.get("duration_sec") or 0), 3)
    result["scan_status"] = raw.get("scan_status") or "completed"
    scan_id = storage.save_scan(
        target=str(raw.get("target") or "unknown"),
        mode=str(raw.get("mode") or "live"),
        result=result,
        analysis=analysis,
        duration_sec=result["duration_sec"],
        scan_status=result["scan_status"],
        user=user.get("username"),
    )
    result["scan_id"] = scan_id
    return result


# ---------------------------------------------------------------------------
# Auth / users
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "ASI Mini", "version": "2.0.0"}


@app.post("/api/login")
async def login(payload: LoginPayload):
    session = storage.login(payload.username, payload.password)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    user = session["user"]
    return {
        "ok": True,
        "token": session["token"],
        "user": user,
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "role_label": user["role_label"],
        "permissions": user["permissions"],
    }


@app.get("/api/me")
async def me(user: dict = Depends(require())):
    return user


@app.post("/api/logout")
async def logout(request: Request):
    storage.revoke_token(_token_from_request(request))
    return {"ok": True}


@app.get("/api/users")
async def users(user: dict = Depends(require("manage_users"))):
    return storage.list_users()


@app.post("/api/users")
async def add_user(payload: UserPayload, user: dict = Depends(require("manage_users"))):
    try:
        return storage.create_user(payload.username, payload.password, payload.role)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/roles")
async def roles(user: dict = Depends(require("manage_users"))):
    return storage.list_roles()


@app.post("/api/roles")
async def add_role(payload: RolePayload, user: dict = Depends(require("manage_users"))):
    try:
        return storage.create_role(payload.key, payload.label or payload.key, payload.permissions)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ---------------------------------------------------------------------------
# Planning / scanning
# ---------------------------------------------------------------------------
@app.post("/api/plan")
async def plan(payload: PlanPayload, user: dict = Depends(require("read"))):
    targets = payload.targets if payload.targets is not None else payload.target
    if not targets:
        raise HTTPException(status_code=400, detail="Provide targets (IP, CIDR, domain or list).")
    return plan_targets(targets, payload.rate_limit_rps, payload.window_minutes)


@app.post("/api/scan")
async def scan_post(payload: ScanPayload, user: dict = Depends(require("add", "modify"))):
    mode = (payload.mode or "demo1").strip().lower()
    domain = payload.domain or payload.target
    signatures = storage.list_signatures(enabled_only=True)
    try:
        if mode in ("demo", "demo1", "demo2"):
            variant = 2 if mode == "demo2" else 1
            raw = get_demo_scan(domain or payload.target or "agh-infra.demo", variant, signatures=signatures)
            raw["mode"] = mode
        else:
            targets = payload.targets if payload.targets is not None else payload.target
            if targets:
                raw = await scan_targets(
                    targets,
                    domain=domain,
                    rate_limit_rps=payload.rate_limit_rps,
                    window_start=payload.window_start,
                    window_end=payload.window_end,
                    cursor=payload.cursor,
                    batch_limit=payload.batch_limit,
                    scan_ports=payload.scan_ports,
                    allowed_ports=payload.allowed_ports,
                    signatures=signatures,
                )
            elif domain:
                raw = await scan_domain(domain, payload.rate_limit_rps, signatures=signatures)
            else:
                raise HTTPException(status_code=400, detail="Live scan requires targets or domain.")
        return _finalize_scan(raw, user)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Scan failed: {exc}")


@app.get("/api/scan")
async def scan_get(domain: str = Query("example.com"), demo: bool = Query(False), mode: str | None = Query(None)):
    """Simple public fallback kept for the original single-page UI."""
    signatures = storage.list_signatures(enabled_only=True)
    try:
        selected = (mode or "").lower()
        if demo or selected in ("demo", "demo1", "demo2"):
            raw = get_demo_scan(domain, 2 if selected == "demo2" else 1, signatures=signatures)
        else:
            raw = await scan_domain(domain, signatures=signatures)
        analysis = analyze_scan(raw, overrides=storage.get_overrides(), host_stats=storage.get_host_stats())
        result = {**raw, **analysis}
        result["subdomains"] = analysis["assets"]
        return result
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Scan failed: {exc}")


# ---------------------------------------------------------------------------
# History / diff / overrides
# ---------------------------------------------------------------------------
@app.get("/api/scans")
async def scans(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0),
                user: dict = Depends(require("read"))):
    return storage.list_scans(limit, offset)


@app.get("/api/scans/{scan_id}")
async def scan_detail(scan_id: int, user: dict = Depends(require("read"))):
    result = storage.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return result


@app.delete("/api/scans/{scan_id}")
async def scan_delete(scan_id: int, user: dict = Depends(require("delete"))):
    if not storage.delete_scan(scan_id):
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {"ok": True, "deleted": scan_id}


@app.get("/api/diff")
async def diff(base_id: int = Query(...), curr_id: int = Query(...), user: dict = Depends(require("read"))):
    base = storage.get_scan(base_id)
    current = storage.get_scan(curr_id)
    if not base or not current:
        raise HTTPException(status_code=404, detail="Base or current scan not found.")
    result = compute_drift(base, current)
    result["base_id"] = base_id
    result["curr_id"] = curr_id
    result["base_target"] = base.get("target")
    result["curr_target"] = current.get("target")
    return result


@app.post("/api/overrides")
async def save_override(payload: OverridePayload, user: dict = Depends(require("modify"))):
    try:
        saved = storage.save_override(payload.model_dump(), user.get("username"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    updated = None
    if payload.scan_id:
        stored = storage.get_scan(payload.scan_id)
        if stored:
            analysis = analyze_scan(
                stored,
                overrides=storage.get_overrides(),
                host_stats=stored.get("host_stats") or {},
            )
            result = {**stored, **analysis}
            result["subdomains"] = analysis["assets"]
            storage.update_scan_result(payload.scan_id, result, analysis)
            updated = {"scan_id": payload.scan_id, "summary": analysis["summary"]}
    return {"ok": True, "override": saved, "scan_id": payload.scan_id, "scan": updated}


@app.get("/api/overrides")
async def overrides(user: dict = Depends(require("read"))):
    return storage.list_overrides()


@app.get("/api/host-history")
async def host_history(user: dict = Depends(require("read"))):
    return storage.list_host_history()


# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
@app.post("/api/import")
async def import_scan(payload: ImportPayload, user: dict = Depends(require("add"))):
    fmt = (payload.format or "nmap").strip().lower()
    signatures = storage.list_signatures(enabled_only=True)
    try:
        if fmt == "nmap":
            xml_text = SAMPLE_NMAP_XML if payload.sample else payload.content
            if not xml_text:
                raise HTTPException(status_code=400, detail="Nmap import requires content or sample=true.")
            raw = parse_nmap_xml(xml_text, payload.filename, signatures=signatures)
        elif fmt in ("csv", "json"):
            raw = parse_structured_import(payload.content, payload.filename, signatures=signatures)
        elif fmt == "manual":
            hosts = payload.hosts
            if hosts is None and payload.content:
                try:
                    hosts = json.loads(payload.content)
                except ValueError:
                    hosts = [line.strip() for line in payload.content.splitlines() if line.strip()]
            if not hosts:
                raise HTTPException(status_code=400, detail="Manual import requires hosts.")
            raw = parse_structured_import(
                json.dumps({"target": payload.target or "manual-import", "hosts": hosts}),
                "manual.json",
                signatures=signatures,
            )
        else:
            raise HTTPException(status_code=400, detail="format must be nmap, csv, json or manual.")
        return _finalize_scan(raw, user)
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------
@app.get("/api/signatures")
async def signatures(user: dict = Depends(require("read"))):
    return storage.list_signatures()


@app.post("/api/signatures")
async def add_signature(payload: SignaturePayload, user: dict = Depends(require("add"))):
    try:
        return storage.add_signature(payload.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.delete("/api/signatures/{sig_id}")
async def remove_signature(sig_id: int, user: dict = Depends(require("delete"))):
    if not storage.delete_signature(sig_id):
        raise HTTPException(status_code=404, detail="Signature not found.")
    return {"ok": True, "deleted": sig_id}


# ---------------------------------------------------------------------------
# Exports / DefectDojo
# ---------------------------------------------------------------------------
@app.get("/api/export/{scan_id}")
async def export(scan_id: int, fmt: str = Query("json"),
                 ids: str | None = Query(None, description="Comma-separated finding IDs"),
                 evidence: bool = Query(False, description="Export as Info/Evidence"),
                 user: dict = Depends(require("read"))):
    result = storage.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found.")
    fmt = (fmt or "json").lower()
    finding_ids = [x.strip() for x in ids.split(",") if x.strip()] if ids else None
    if fmt == "json":
        return JSONResponse(result)
    if fmt == "csv":
        return PlainTextResponse(
            export_csv(result),
            media_type="text/csv",
            headers={"Content-Disposition": f'attachment; filename="asi-scan-{scan_id}.csv"'},
        )
    if fmt in ("defectdojo", "dojo"):
        return JSONResponse(export_defectdojo_json(result, finding_ids=finding_ids, as_info_evidence=evidence))
    raise HTTPException(status_code=400, detail="fmt must be json, csv or defectdojo.")


@app.post("/api/defectdojo/push")
async def defectdojo_push(payload: DojoPushPayload, user: dict = Depends(require("modify"))):
    result = storage.get_scan(payload.scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan not found.")
    if httpx is None:
        raise HTTPException(status_code=503, detail="httpx is not available.")
    target_url = (payload.url or payload.defectdojo_url or "").strip()
    api_token = payload.api_token or payload.token
    engagement_id = payload.engagement_id if payload.engagement_id is not None else payload.engagement
    if not target_url or not api_token or engagement_id is None:
        raise HTTPException(status_code=400, detail="url, api_token and engagement_id are required.")
    body = export_defectdojo_json(result, finding_ids=payload.finding_ids, as_info_evidence=payload.as_info_evidence)
    url = target_url.rstrip("/")
    if "/api/v2/import-scan" not in url:
        url = f"{url}/import-scan" if url.endswith("/api/v2") else f"{url}/api/v2/import-scan"
    if not url.endswith("/"):
        url += "/"
    data = {
        "scan_type": "Generic Findings Import",
        "engagement": str(engagement_id),
        "active": "true",
        "verified": "false",
        "minimum_severity": payload.minimum_severity,
        "close_old_findings": "true" if payload.close_old_findings else "false",
        "deduplication_on_engagement": "true",
    }
    files = {"file": ("asi-findings.json", json.dumps(body).encode("utf-8"), "application/json")}
    headers = {"Authorization": f"Token {api_token}"}
    try:
        async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
            response = await client.post(url, data=data, files=files, headers=headers)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"DefectDojo connection failed: {exc}")
    if response.status_code >= 400:
        detail = (response.text or "")[:600]
        raise HTTPException(status_code=502, detail=f"DefectDojo rejected the import ({response.status_code}): {detail}")
    try:
        parsed = response.json()
    except ValueError:
        parsed = {"raw": response.text[:1000]}
    return {"ok": True, "status_code": response.status_code, "findings": len(body["findings"]), "response": parsed}


# ---------------------------------------------------------------------------
# Scan jobs (persisted chunk/window state)
# ---------------------------------------------------------------------------
@app.get("/api/jobs")
async def jobs(user: dict = Depends(require("read"))):
    return storage.list_scan_jobs()


@app.post("/api/jobs")
async def create_job(payload: dict = Body(default={}), user: dict = Depends(require("add"))):
    return storage.create_scan_job(payload, user.get("username"))


@app.put("/api/jobs/{job_id}")
async def update_job(job_id: int, payload: dict = Body(default={}), user: dict = Depends(require("modify"))):
    job = storage.get_scan_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    updated = storage.update_scan_job(job_id, **payload)
    return updated or job


@app.post("/api/jobs/{job_id}/run-now")
async def run_job_now(job_id: int, user: dict = Depends(require("modify", "add"))):
    job = storage.get_scan_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    await _run_job_chunk(job, user=user)
    storage.update_scan_job(
        job["id"],
        updated_at=datetime.now(timezone.utc).isoformat(),
    )
    return storage.list_scan_jobs()


@app.delete("/api/jobs/{job_id}")
async def delete_job(job_id: int, user: dict = Depends(require("delete"))):
    if not storage.delete_scan_job(job_id):
        raise HTTPException(status_code=404, detail="Job not found.")
    return {"ok": True, "deleted": job_id}


# ---------------------------------------------------------------------------
# Timeline / trend chart data
# ---------------------------------------------------------------------------
@app.get("/api/timeline")
async def timeline(user: dict = Depends(require("read"))):
    scans = storage.list_scans(limit=50, offset=0)
    points = []
    for s in reversed(scans):
        points.append({
            "scan_id": s.get("scan_id") or s.get("id"),
            "scanned_at": s.get("scanned_at"),
            "target": s.get("target"),
            "exposure_score": s.get("exposure_score") or 0,
            "assets_discovered": s.get("host_count") or 0,
            "findings_total": s.get("findings_total") or 0,
            "critical_count": 0,
            "flaky_count": 0,
        })
    return points


# ---------------------------------------------------------------------------
# Admin: encryption-at-rest proof
# ---------------------------------------------------------------------------
@app.get("/api/admin/encryption-proof")
async def encryption_proof(user: dict = Depends(require("manage_config"))):
    return storage.get_encryption_proof()


# ---------------------------------------------------------------------------
# Signature export / import
# ---------------------------------------------------------------------------
@app.get("/api/signatures/export")
async def export_signatures(user: dict = Depends(require("read"))):
    sigs = storage.list_signatures()
    return JSONResponse(sigs, headers={"Content-Disposition": "attachment; filename=asi-signatures.json"})


@app.post("/api/signatures/import")
async def import_signatures(payload: list[dict] = Body(default=[]), user: dict = Depends(require("add"))):
    imported = []
    updated = []
    errors = []
    existing = {str(s.get("name") or "").strip().lower(): s for s in storage.list_signatures()}
    for sig in payload:
        if not isinstance(sig, dict):
            errors.append("Non-dict signature skipped.")
            continue
        name = str(sig.get("name") or "").strip()
        if not name:
            errors.append("Signature without name skipped.")
            continue
        match = existing.get(name.lower())
        try:
            if match:
                result = storage.update_signature(match["id"], sig)
                updated.append(result)
            else:
                result = storage.add_signature(sig)
                imported.append(result)
        except ValueError as e:
            errors.append(str(e))
    return {"ok": True, "imported": len(imported), "updated": len(updated),
            "errors": errors, "signatures": imported + updated}


@app.put("/api/signatures/{sig_id}")
async def update_sig(sig_id: int, payload: dict = Body(default={}), user: dict = Depends(require("modify"))):
    result = storage.update_signature(sig_id, payload)
    if not result:
        raise HTTPException(status_code=404, detail="Signature not found.")
    return result


@app.get("/")
async def index():
    return FileResponse("static/index.html")
