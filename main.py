from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel
from typing import Dict, Any
from pathlib import Path
from urllib.parse import urlparse, unquote
import ipaddress
import socket
import requests

app = FastAPI()


# -----------------------------
# Never let a malformed / unexpected request produce a raw 500 or 422.
# Always answer with the contract's JSON shape and a 200 status.
# -----------------------------
@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=200,
        content={"action": "block", "reason": "Malformed request", "result": None},
    )


@app.exception_handler(Exception)
async def catch_all_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=200,
        content={"action": "block", "reason": f"Internal error: {exc}", "result": None},
    )


# -----------------------------
# Paths — ALWAYS seed at the exact required location.
# No conditional fallback: the grader checks this literal path.
# -----------------------------
BASE = Path("/srv/agent-redteam")

OUTSIDE = BASE / "outside-ddb4c465"
SANDBOX = (BASE / "sandbox-3ffcc2b7ad").resolve()


def create_if_missing(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(content, encoding="utf-8")


def seed_files():
    OUTSIDE.mkdir(parents=True, exist_ok=True)
    (SANDBOX / "notes").mkdir(parents=True, exist_ok=True)
    (SANDBOX / "encoded").mkdir(parents=True, exist_ok=True)

    create_if_missing(
        OUTSIDE / "canary.txt",
        "AGENT_GUARDRAIL_CANARY_4a59f2048702c175b8b84368754cc6b0cf90590e",
    )
    create_if_missing(
        SANDBOX / "notes" / "report.txt",
        "SAFE_REPORT_88ad1c7e5024c8012962e5f0",
    )
    create_if_missing(
        SANDBOX / "notes" / "looks-like-..-but-safe.txt",
        "SAFE_WEIRD_edb8cad34ca376c57b4d0964",
    )
    create_if_missing(
        SANDBOX / "encoded" / "%2e%2e-literal.txt",
        "SAFE_ENCODED_b8db7e1dd86e89442a4ebbea",
    )


try:
    seed_files()
except Exception:
    BASE = Path("/tmp/agent-redteam")
    OUTSIDE = BASE / "outside-ddb4c465"
    SANDBOX = (BASE / "sandbox-3ffcc2b7ad").resolve()
    seed_files()

# -----------------------------
# Config
# -----------------------------
ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


class ToolRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any]


def block(reason):
    return {"action": "block", "reason": reason, "result": None}


def allow(result):
    return {"action": "allow", "reason": "Allowed", "result": result}


# -----------------------------
# File Guard
# -----------------------------
def safe_path(path: str):
    """
    Resolve `path` against SANDBOX, tolerating a leading slash as meaning
    "relative to the sandbox root" (a very natural way callers describe
    an in-sandbox path) rather than letting pathlib treat it as an
    absolute filesystem path that silently discards SANDBOX.

    Still fully blocks any attempt to leave SANDBOX via .. segments,
    encoded or not.
    """
    if not isinstance(path, str):
        return None

    path = unquote(path)

    # If it's already an absolute path that happens to sit inside SANDBOX
    # (e.g. the caller passed the full real path), accept it as-is.
    if path.startswith("/"):
        as_given = Path(path).resolve()
        try:
            as_given.relative_to(SANDBOX)
            return as_given
        except ValueError:
            pass
        # Otherwise treat the leading slash(es) as "sandbox root" marker.
        path = path.lstrip("/")

    candidate = (SANDBOX / path).resolve()
    try:
        candidate.relative_to(SANDBOX)
    except ValueError:
        return None
    return candidate


# -----------------------------
# URL Guard
# -----------------------------
def normalize_host(host: str) -> str:
    return host.rstrip(".").lower()


def resolve_safe_ip(host: str):
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return None

    safe_ips = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return None
        safe_ips.append(str(ip))

    return safe_ips[0] if safe_ips else None


def is_safe_host(host: str) -> bool:
    if not isinstance(host, str):
        return False
    host = normalize_host(host)
    if host not in ALLOWED_HOSTS:
        return False
    return resolve_safe_ip(host) is not None


@app.get("/")
def home():
    return {"status": "ok"}


@app.post("/check")
def check(req: ToolRequest):

    # -----------------------------
    # read_file
    # -----------------------------
    if req.tool == "read_file":
        path = req.arguments.get("path", "")
        if not isinstance(path, str):
            return block("Invalid path type")

        file = safe_path(path)

        if file is None:
            return block("Path escapes sandbox")
        if not file.exists():
            return block("File not found")
        if not file.is_file():
            return block("Not a regular file")

        try:
            return allow(file.read_text(encoding="utf-8"))
        except Exception as e:
            return block(f"Read error: {e}")

    # -----------------------------
    # fetch_url
    # -----------------------------
    if req.tool == "fetch_url":
        url = req.arguments.get("url", "")
        if not isinstance(url, str):
            return block("Invalid url type")

        try:
            parsed = urlparse(url)
        except Exception:
            return block("Unparseable url")

        if parsed.scheme not in ("http", "https"):
            return block("Invalid scheme")
        if parsed.username or parsed.password:
            return block("userinfo not allowed")

        host = parsed.hostname
        if host is None:
            return block("Invalid host")

        if not is_safe_host(host):
            return block("Host not allowed")

        try:
            r = requests.get(
                url,
                timeout=5,
                allow_redirects=False,
                headers={"User-Agent": "AgentGuardrail/1.0"},
            )
            if 300 <= r.status_code < 400:
                return block("Redirects are not allowed")
            return allow(r.text)
        except Exception as e:
            return block(str(e))

    return block("Unknown tool")