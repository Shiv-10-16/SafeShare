"""SafeShare - Application Backend Server.

FastAPI / Starlette server powering the Enterprise AI Privacy & Secret Firewall.
Integrates with Google Gemma 4 on the Gemini API.
"""

import json
import os
import subprocess
import sys
from typing import Optional

def ensure_dependencies():
    required = ["uvicorn", "starlette"]
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[*] Installing required dependencies: {', '.join(missing)}...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing, "--quiet"])
        except Exception:
            pass

ensure_dependencies()

from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse, PlainTextResponse
from starlette.routing import Mount, Route
from starlette.staticfiles import StaticFiles

from safeshare_engine import (
    DEFAULT_MODEL,
    GEMMA_4_MODELS,
    call_gemma_4_safeshare,
    merge_and_anonymize,
    restore_text,
    scan_patterns,
)
from scenarios import SCENARIOS

import datetime

RUNTIME_API_KEY: Optional[str] = None

# Guardian Telemetry
GUARDIAN_LOGS = []
GUARDIAN_STATS = {
    "total_scanned": 0,
    "total_threats_blocked": 0,
    "desktop_interceptions": 0,
    "extension_interceptions": 0,
}


async def api_health(request):
    """Health & config probe."""
    has_env = bool(os.environ.get("GEMINI_API_KEY", "").strip())
    has_runtime = bool(RUNTIME_API_KEY)
    return JSONResponse(
        {
            "status": "healthy",
            "has_api_key": has_env or has_runtime,
            "models": GEMMA_4_MODELS,
            "default_model": DEFAULT_MODEL,
            "runtime": f"Python {sys.version.split()[0]}",
            "scenarios": list(SCENARIOS.keys()),
            "guardian_stats": GUARDIAN_STATS,
        }
    )


async def api_config(request):
    """Configure runtime Gemini API Key."""
    global RUNTIME_API_KEY
    if request.method == "POST":
        try:
            body = await request.json()
            key = (body.get("api_key") or "").strip()
            if key:
                RUNTIME_API_KEY = key
                return JSONResponse({"status": "ok", "message": "API key successfully saved in session."})
            else:
                RUNTIME_API_KEY = None
                return JSONResponse({"status": "ok", "message": "Runtime API key cleared."})
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=400)

    has_key = bool(os.environ.get("GEMINI_API_KEY", "").strip() or RUNTIME_API_KEY)
    return JSONResponse({"has_api_key": has_key})


async def api_scenarios(request):
    """List available pre-configured scenarios."""
    items = []
    for sid, s in SCENARIOS.items():
        items.append(
            {
                "id": sid,
                "title": s["title"],
                "description": s["description"],
                "text": s["text"],
            }
        )
    return JSONResponse({"scenarios": items})


async def api_audit(request):
    """Core audit endpoint: Runs pattern scanner + Gemma 4 semantic analysis."""
    global RUNTIME_API_KEY, GUARDIAN_STATS
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body"}, status_code=400)

    text = (body.get("text") or "").strip()
    if not text:
        return JSONResponse({"error": "Text cannot be empty."}, status_code=400)

    scenario_id = body.get("scenario_id")
    use_cached_benchmark = body.get("use_cached_benchmark", False)
    mask_mode = body.get("mask_mode", "synthetic")
    model_id = body.get("model_id", DEFAULT_MODEL)
    api_key = (body.get("api_key") or "").strip() or RUNTIME_API_KEY or os.environ.get("GEMINI_API_KEY", "").strip()
    source = body.get("source", "web_app")

    # Step 1: Always run local regex pattern scan
    pattern_findings = scan_patterns(text)

    # Step 2: Semantic scan via Gemma 4 (or benchmark fallback)
    gemma_findings = []
    compliance_summary = "Audit performed by SafeShare."
    is_benchmark = False

    if (use_cached_benchmark or not api_key) and scenario_id in SCENARIOS:
        # Use verified benchmark
        cached = SCENARIOS[scenario_id]["cached_audit"]
        gemma_findings = cached.get("findings", [])
        compliance_summary = cached.get("compliance_summary", "")
        is_benchmark = True
    elif api_key:
        try:
            gemma_out = call_gemma_4_safeshare(
                text=text,
                api_key=api_key,
                model_id=model_id,
                temperature=float(body.get("temperature", 0.1)),
            )
            gemma_findings = gemma_out.get("findings", [])
            compliance_summary = gemma_out.get("compliance_summary", "")
        except Exception as e:
            # Fallback to scenario if available, otherwise fallback to patterns with notice
            if scenario_id in SCENARIOS:
                cached = SCENARIOS[scenario_id]["cached_audit"]
                gemma_findings = cached.get("findings", [])
                compliance_summary = cached.get("compliance_summary", "")
                is_benchmark = True
            else:
                compliance_summary = f"Gemma 4 service notice: {str(e)[:120]}. High-confidence pattern firewall active."
    else:
        # Fallback when key is missing: Use pattern engine smoothly
        compliance_summary = (
            "Pattern Firewall active. Connect a Gemini API key to activate Gemma 4's deep semantic & typo detection."
        )

    # Step 3: Merge findings and produce sanitized output + vault
    merged_report = merge_and_anonymize(
        original_text=text,
        pattern_findings=pattern_findings,
        gemma_findings=gemma_findings,
        mask_mode=mask_mode,
    )
    merged_report["compliance_summary"] = compliance_summary
    merged_report["is_benchmark"] = is_benchmark
    merged_report["model_used"] = model_id
    merged_report["model_name"] = GEMMA_4_MODELS.get(model_id, {}).get("name", "Gemma 4")

    # Update guardian telemetry
    findings_count = len(merged_report.get("findings", []))
    GUARDIAN_STATS["total_scanned"] += 1
    if findings_count > 0:
        GUARDIAN_STATS["total_threats_blocked"] += findings_count
        if source == "desktop":
            GUARDIAN_STATS["desktop_interceptions"] += 1
        elif source == "extension":
            GUARDIAN_STATS["extension_interceptions"] += 1

    return JSONResponse(merged_report)


from audit_store import (
    get_audit_summary,
    is_guardian_paused,
    load_logs,
    save_log_entry,
    set_guardian_paused,
)


async def api_restore(request):
    """Re-identify synthetic text back to original using client vault."""
    try:
        body = await request.json()
        sanitized_text = body.get("sanitized_text", "")
        vault = body.get("vault", {})
        restored = restore_text(sanitized_text, vault)
        return JSONResponse({"restored_text": restored})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def api_guardian_stats(request):
    """Telemetry stats, chart points, and recent logs from persistent disk store."""
    summary = get_audit_summary()
    return JSONResponse(summary)


async def api_guardian_toggle(request):
    """Toggle or set pause state for the desktop clipboard guardian."""
    try:
        body = await request.json()
        desired = body.get("paused")
        if desired is None:
            desired = not is_guardian_paused()
        state = set_guardian_paused(desired)
        return JSONResponse({"is_paused": state})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


async def api_guardian_logs(request):
    """Return full historical audit log on this system."""
    return JSONResponse({"logs": load_logs()})


async def api_guardian_log(request):
    """Receive live interception events and update telemetry without creating corrupt dummy entries."""
    try:
        body = await request.json()
        source = body.get("source", "desktop")
        threats_count = int(body.get("threats_count", 0))
        categories = body.get("categories", [])
        original_text = body.get("original_text")
        sanitized_text = body.get("sanitized_text")
        vault = body.get("vault", {})

        # If full text and vault were provided by the caller, persist them
        entry = None
        if original_text and sanitized_text and original_text != sanitized_text:
            entry = save_log_entry(
                original_text=original_text,
                sanitized_text=sanitized_text,
                threats_count=threats_count,
                categories=categories,
                vault=vault,
                source=source,
            )

        GUARDIAN_STATS["total_scanned"] += 1
        if threats_count > 0:
            GUARDIAN_STATS["total_threats_blocked"] += threats_count

        return JSONResponse({"status": "ok", "logged": bool(entry)})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)


# Ensure static directory exists
os.makedirs(os.path.join(os.path.dirname(__file__), "static"), exist_ok=True)

routes = [
    Route("/api/health", api_health, methods=["GET"]),
    Route("/api/config", api_config, methods=["GET", "POST"]),
    Route("/api/scenarios", api_scenarios, methods=["GET"]),
    Route("/api/audit", api_audit, methods=["POST"]),
    Route("/api/restore", api_restore, methods=["POST"]),
    Route("/api/guardian/stats", api_guardian_stats, methods=["GET"]),
    Route("/api/guardian/toggle", api_guardian_toggle, methods=["POST"]),
    Route("/api/guardian/logs", api_guardian_logs, methods=["GET"]),
    Route("/api/guardian/log", api_guardian_log, methods=["POST"]),
    Mount("/", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static"), html=True)),
]

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )
]

app = Starlette(routes=routes, middleware=middleware)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
