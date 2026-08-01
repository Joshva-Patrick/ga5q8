from fastapi import FastAPI
from pydantic import BaseModel
from typing import Dict, Any
from pathlib import Path
from urllib.parse import urlparse, unquote
import ipaddress
import socket
import requests
import os

app = FastAPI()

# -----------------------------
# Paths
# -----------------------------

# Use the grading path if it exists.
# Otherwise fall back to a writable directory on Render.
if Path("/srv/agent-redteam").exists():
    BASE = Path("/srv/agent-redteam")
else:
    BASE = Path("/tmp/agent-redteam")

OUTSIDE = BASE / "outside-ddb4c465"
SANDBOX = (BASE / "sandbox-3ffcc2b7ad").resolve()

# Only create files/directories in the writable fallback location
if BASE == Path("/tmp/agent-redteam"):
    (OUTSIDE).mkdir(parents=True, exist_ok=True)
    (SANDBOX / "notes").mkdir(parents=True, exist_ok=True)
    (SANDBOX / "encoded").mkdir(parents=True, exist_ok=True)

    def create_if_missing(path: Path, content: str):
        if not path.exists():
            path.write_text(content, encoding="utf-8")

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
    return {
        "action": "block",
        "reason": reason,
        "result": None,
    }


def allow(result):
    return {
        "action": "allow",
        "reason": "Allowed",
        "result": result,
    }


# -----------------------------
# File Guard
# -----------------------------
def safe_path(path: str):

    path = unquote(path)

    candidate = (SANDBOX / path).resolve()

    try:
        candidate.relative_to(SANDBOX)
    except ValueError:
        return None

    return candidate


# -----------------------------
# URL Guard
# -----------------------------
def is_safe_host(host):

    if host not in ALLOWED_HOSTS:
        return False

    try:
        infos = socket.getaddrinfo(host, None)

        for info in infos:
            ip = ipaddress.ip_address(info[4][0])

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            ):
                return False

    except Exception:
        return False

    return True


@app.post("/check")
def check(req: ToolRequest):

    # -----------------------------
    # read_file
    # -----------------------------
    if req.tool == "read_file":

        path = req.arguments.get("path", "")

        file = safe_path(path)

        if file is None:
            return block("Path escapes sandbox")

        if not file.exists():
            return block("File not found")

        return allow(file.read_text(encoding="utf-8"))

    # -----------------------------
    # fetch_url
    # -----------------------------
    if req.tool == "fetch_url":

        url = req.arguments.get("url", "")

        parsed = urlparse(url)

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