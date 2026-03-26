"""
ARCADA REST API
GET  /        — web frontend
POST /audit   — run a full audit (advanced)
POST /scan    — scan a GitHub repo (simple)
GET  /health  — health check
GET  /scanners — list available scanners
"""

from __future__ import annotations
import asyncio
import hmac
import os
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, HTTPException, Depends, Security, Request
from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from arcada.models import AuditRequest, AuditReport
from arcada.orchestrator import Orchestrator
from arcada.report import format_report
from arcada.scanners import ALL_SCANNERS
from arcada.github_clone import clone_repo, cleanup_repo, is_github_url

# --- Auth ---
ARCADA_API_KEY = os.environ.get("ARCADA_API_KEY", "")
if not ARCADA_API_KEY:
    import warnings

    warnings.warn(
        "ARCADA_API_KEY is not set (optional). "
        "For AI analysis, ensure DEEPSEEK_API_KEY is set.",
        UserWarning,
    )
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)

# --- Rate Limiting ---
limiter = Limiter(key_func=get_remote_address)

# --- Concurrency control ---
_scan_semaphore = asyncio.Semaphore(5)  # Max 5 concurrent scans


async def verify_api_key(key: str = Security(api_key_header)):
    """Require API key if ARCADA_API_KEY env var is set."""
    if ARCADA_API_KEY and not hmac.compare_digest(key or "", ARCADA_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return key


def _validate_target(target: str) -> str:
    """Validate target input to prevent path traversal and filesystem access.

    Allowed targets:
      - GitHub URLs: https://github.com/user/repo
      - Other URLs: https://... or http://...
      - Inline content: non-path strings under 100KB
      - Relative file paths: no absolute paths, no ../ traversal

    Rejects:
      - Absolute paths (/etc/passwd, C:\\Windows)
      - Path traversal (../../../etc/passwd)
      - Inline content over 100KB
    """
    if not target or not target.strip():
        raise HTTPException(status_code=400, detail="Empty target")

    target = target.strip()

    # Allow URLs
    if target.startswith(("http://", "https://")):
        return target
    # Detect Windows absolute paths like C:\ or D:\
    if re.match(r"^[a-zA-Z]:\\", target):
       raise HTTPException(
        status_code=400,
        detail="Windows absolute paths are not allowed. Use a GitHub URL or paste code directly.",
    )
    # Reject absolute paths
    if os.path.isabs(target) or target.startswith("/") or target.startswith("\\"):
        raise HTTPException(
            status_code=400,
            detail="Absolute paths are not allowed. Use a GitHub URL or paste code directly.",
        )

    # Reject path traversal
    normalized = os.path.normpath(target)
    if (
        normalized.startswith("..")
        or "/../" in normalized
        or "\\..\\" in normalized
        or normalized.startswith("/")
    ):
        raise HTTPException(
            status_code=400,
            detail="Path traversal detected. Use a GitHub URL or paste code directly.",
        )

    # Reject inline content over 100KB
    if len(target.encode("utf-8")) > 100_000:
        raise HTTPException(
            status_code=400,
            detail="Inline content exceeds 100KB limit. Use a GitHub URL instead.",
        )

    return target


# --- App ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.orchestrator = Orchestrator()
    yield


app = FastAPI(
    title="ARCADA — AI Runtime & Trust Evaluator",
    description=(
        "Zero-trust security auditor for AI systems, LLM infrastructure, "
        "agent frameworks, and supply-chain attacks."
    ),
    version="0.1.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"detail": f"Rate limit exceeded: {exc.detail}"},
    )


# CORS — filter empty strings before passing to middleware
_cors_origins = os.environ.get("CORS_ORIGINS", "")
_origins = [o.strip() for o in _cors_origins.split(",") if o.strip()] or [
    "http://localhost:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# --- Routes ---


@app.get("/health", tags=["System"])
async def health():
    """Health check endpoint."""
    return {
        "status": "ok",
        "service": "arcada",
        "version": "0.1.0",
    }


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def frontend():
    """Serve the web frontend."""
    html_path = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@app.post("/scan", tags=["Scan"], dependencies=[Depends(verify_api_key)])
@limiter.limit("20/minute")
async def scan_repo(request: Request, body: dict):
    """
    Scan a public GitHub repository.

    **Request body:**
    - `url`: GitHub repository URL (e.g. https://github.com/user/repo)
    - `deep`: boolean — enable deep dependency scanning (default: false)

    **Returns:** Full audit report as JSON.
    """
    if not os.environ.get("DEEPSEEK_API_KEY"):
        raise HTTPException(
            status_code=503,
            detail="DEEPSEEK_API_KEY not configured on this server.",
        )

    url = body.get("url", "").strip()
    deep = body.get("deep", False)

    if not url:
        raise HTTPException(status_code=400, detail="Missing 'url' field")
    if not is_github_url(url):
        raise HTTPException(
            status_code=400,
            detail="Only https://github.com/ URLs are supported",
        )

    # Clone the repo
    import logging

    logger = logging.getLogger(__name__)
    logger.info(f"Starting scan for: {url}")
    try:
        repo_dir = clone_repo(url)
        logger.info(f"Cloned repo to: {repo_dir}")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Clone failed: {e}")
        raise HTTPException(status_code=400, detail=f"Failed to clone repository: {e}")

    # Run the audit with concurrency control and timeout
    SCAN_TIMEOUT = int(os.environ.get("ARCADA_SCAN_TIMEOUT", "900"))  # 15 min default
    async with _scan_semaphore:
        try:
            orchestrator: Orchestrator = request.app.state.orchestrator
            audit_request = AuditRequest(
                target=repo_dir,
                target_type="directory",
                deep=deep,
            )
            try:
                # Use limited scanners for faster response
                if deep:
                    report = await asyncio.wait_for(
                        orchestrator.deep_audit(audit_request), timeout=SCAN_TIMEOUT
                    )
                else:
                    # Run standard audit
                    report = await asyncio.wait_for(
                        orchestrator.audit(audit_request), timeout=SCAN_TIMEOUT
                    )

                logger.info(f"Audit complete: score={report.summary.risk_score}")
            except asyncio.TimeoutError:
                logger.error(f"Scan timed out after {SCAN_TIMEOUT} seconds")
                raise HTTPException(
                    status_code=504,
                    detail=f"Scan timed out after {SCAN_TIMEOUT} seconds. Try a smaller repository.",
                )
        except HTTPException:
            raise
        except Exception as e:
            import traceback

            logger.error(f"Scan failed: {e}")
            traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")
        finally:
            cleanup_repo(repo_dir)

    return JSONResponse(content=report.model_dump())


@app.get("/scanners", tags=["System"], dependencies=[Depends(verify_api_key)])
@limiter.limit("60/minute")
async def list_scanners(request: Request):
    """List all available scanner modules."""
    return {"scanners": [{"name": s.name, "class": s.__name__} for s in ALL_SCANNERS]}


@app.post(
    "/audit",
    tags=["Audit"],
    dependencies=[Depends(verify_api_key)],
    response_model=None,  # Dynamic based on format
)
@limiter.limit("20/minute")
async def run_audit(request: Request, body: AuditRequest):
    """
    Run a full ARCADA security audit.

    **Request body:**
    - `target`: file path, directory, URL, or inline code/config content
    - `target_type`: `auto` | `code` | `dependencies` | `docker` | `config` | `url`
    - `scanners`: list of scanner names to run (empty = all 17)
    - `output_format`: `json` | `markdown` | `sarif`

    **Returns:** Structured audit report with severity-ranked findings,
    risk score, security maturity rating, and AI-generated remediation guidance.
    """
    if not os.environ.get("DEEPSEEK_API_KEY"):
        raise HTTPException(
            status_code=503, detail="DEEPSEEK_API_KEY not configured on this server."
        )

    # Validate target to prevent path traversal
    body.target = _validate_target(body.target)

    start = time.monotonic()

    async with _scan_semaphore:
        try:
            orchestrator: Orchestrator = request.app.state.orchestrator
            report: AuditReport = await orchestrator.audit(body)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Audit failed: {e}")

    elapsed = round(time.monotonic() - start, 2)

    if body.output_format == "markdown":
        content = format_report(report, "markdown")
        return PlainTextResponse(content=content, media_type="text/markdown")

    if body.output_format == "sarif":
        content = format_report(report, "sarif")
        return PlainTextResponse(content=content, media_type="application/sarif+json")

    # Default: JSON
    data = report.model_dump()
    data["audit_duration_seconds"] = elapsed
    return JSONResponse(content=data)
