"""
Operator console: `bid console`.

    bid console                                   # http://127.0.0.1:8799, opens a browser
    bid console --no-open --port 8000
    BID_CONSOLE_TOKEN=... bid console --host 0.0.0.0 --profile sovereign

A FastAPI backend and one self-contained HTML page (no build step, nothing loaded
from other origins, works offline). Run the pipeline, review the ranked queue with
the signals, model and prompt template behind each verdict, record a person's
confirm, reject or escalation as a signed receipt, release a confirm, stop or resume
the queue, export a confirmed finding as report payloads, and verify receipts with
the public key alone. See bid.api for what each action records.

Access: binds 127.0.0.1 by default. Any other address needs BID_CONSOLE_TOKEN;
every /api call then needs that token, as a bearer header or as the HttpOnly
SameSite=Strict session cookie that /api/login sets. The token is one shared
secret: it admits people to the console, it does not tell them apart.

Identity: by default the person acting is the name typed into the page ("Acting
as"). It is recorded on every receipt and journal record but not authenticated.
Behind an authenticating reverse proxy, set BID_CONSOLE_ACTOR_HEADER to the header
that proxy sets (for example X-Forwarded-User): the console then takes the actor
from that header only, and refuses actions without it. Do this only when the
console is reachable through the proxy alone.

The page carries a per-request script nonce in its Content-Security-Policy, and
scraped content is rendered with textContent, never innerHTML. Secrets are read from
the environment and never sent to the page. Runtime data goes to
$BID_DATA_DIR/console; governance settings and the journal are the deployment's
(governance.load_config), shared with the command line.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Literal

from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from . import api, paths
from .governance import load_config

_HTML = paths.PACKAGE_DIR / "static" / "dashboard.html"
_TOKEN_ENV = "BID_CONSOLE_TOKEN"
_ACTOR_HEADER_ENV = "BID_CONSOLE_ACTOR_HEADER"
_COOKIE = "bid_console"
_LOOPBACK = {"127.0.0.1", "localhost", "::1"}

# Set once by main(); tests and embedders may set them directly.
SETTINGS: dict = {"brands_file": None, "governance": None, "policy_pack": None, "attestation_hash": None}

app = FastAPI(title="Brand impersonation detector: operator console")


def _root() -> Path:
    return paths.store_dir("console")


def _token() -> str:
    return os.environ.get(_TOKEN_ENV, "")


def _actor_header() -> str:
    return os.environ.get(_ACTOR_HEADER_ENV, "").strip()


def _signing() -> dict:
    """What every receipt the console signs records about the deployment."""
    return {"policy_pack": SETTINGS["policy_pack"], "attestation_hash": SETTINGS["attestation_hash"]}


def _session_value(token: str) -> str:
    # The cookie carries a value derived from the token, never the token itself.
    return hmac.new(token.encode(), b"bid-console-session", hashlib.sha256).hexdigest()


def _authorized(request: Request, token: str) -> bool:
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return hmac.compare_digest(auth[7:].strip().encode(), token.encode())
    cookie = request.cookies.get(_COOKIE, "")
    return hmac.compare_digest(cookie.encode(), _session_value(token).encode())


def _actor(request: Request, typed: str) -> str:
    """The person acting: the authenticating proxy's header when one is configured,
    else the name typed into the page."""
    header = _actor_header()
    if not header:
        return typed
    value = request.headers.get(header, "").strip()
    if not value:
        raise PermissionError(f"no signed-in user in the {header} header")
    return value


def _respond(action: Callable[[], dict]) -> JSONResponse:
    """Run one console action; map its refusal to an HTTP status with the reason."""
    try:
        return JSONResponse(action())
    except PermissionError as e:
        return JSONResponse({"error": str(e)}, status_code=403)
    except LookupError as e:
        return JSONResponse({"error": str(e)}, status_code=404)
    except (api.QueueStopped, ValueError) as e:
        return JSONResponse({"error": str(e)}, status_code=409)


@app.middleware("http")
async def _guard(request: Request, call_next):
    token = _token()
    path = request.url.path
    if token and path.startswith("/api/") and path != "/api/login" and not _authorized(request, token):
        response = JSONResponse({"error": "authentication required"}, status_code=401)
    else:
        response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Cache-Control", "no-store")
    return response


class LoginReq(BaseModel):
    token: str


class RunReq(BaseModel):
    live: bool = False
    embeddings: bool = False
    broad: bool = False
    k: int = 10


class DecideReq(BaseModel):
    candidate_id: str
    decision: Literal["confirm", "reject", "escalate"]
    analyst_id: str = ""
    note: str = ""


class ReleaseReq(BaseModel):
    candidate_id: str
    actor: str = ""
    reason: str


class QueueReq(BaseModel):
    actor: str = ""
    reason: str = ""


class EnrichReq(BaseModel):
    domain: str


@app.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    nonce = secrets.token_urlsafe(16)
    html = _HTML.read_text(encoding="utf-8").replace("<script>", f'<script nonce="{nonce}">')
    csp = ("default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
           f"script-src 'nonce-{nonce}'; connect-src 'self'; frame-ancestors 'none'; "
           "base-uri 'none'; form-action 'self'")
    return HTMLResponse(html, headers={"Content-Security-Policy": csp})


@app.post("/api/login")
def api_login(req: LoginReq, request: Request):
    token = _token()
    if not token:
        return JSONResponse({"ok": True, "auth": "disabled"})
    if not hmac.compare_digest(req.token.encode(), token.encode()):
        return JSONResponse({"ok": False, "error": "wrong token"}, status_code=401)
    response = JSONResponse({"ok": True})
    secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(_COOKIE, _session_value(token), httponly=True, samesite="strict",
                        secure=secure, path="/")
    return response


@app.post("/api/run")
def api_run(req: RunReq):
    if req.live:
        from .run_pipeline import load_dotenv
        load_dotenv()
    return _respond(lambda: api.run_pipeline_api(
        _root(), k=req.k, live=req.live, embeddings=req.embeddings, broad=req.broad,
        brands_file=SETTINGS["brands_file"], **_signing()))


@app.get("/api/run")
def api_current_run():
    return _respond(lambda: api.run_view(_root()))


@app.post("/api/decide")
def api_decide(req: DecideReq, request: Request):
    return _respond(lambda: api.decide(_root(), req.candidate_id, req.decision,
                                       _actor(request, req.analyst_id), note=req.note, **_signing()))


@app.post("/api/release")
def api_release(req: ReleaseReq, request: Request):
    return _respond(lambda: api.release_api(_root(), req.candidate_id, _actor(request, req.actor), req.reason,
                                            load_config(SETTINGS["governance"])[0], **_signing()))


@app.post("/api/halt")
def api_halt(req: QueueReq, request: Request):
    return _respond(lambda: api.set_queue(True, _actor(request, req.actor), req.reason,
                                          load_config(SETTINGS["governance"])[0]))


@app.post("/api/resume")
def api_resume(req: QueueReq, request: Request):
    return _respond(lambda: api.set_queue(False, _actor(request, req.actor), req.reason,
                                          load_config(SETTINGS["governance"])[0]))


@app.get("/api/governance")
def api_governance(request: Request):
    def state() -> dict:
        config, source = load_config(SETTINGS["governance"])
        header = _actor_header()
        return {**api.governance_state(_root(), config, source),
                "actor_header": header or None,
                "actor": (request.headers.get(header, "").strip() or None) if header else None}
    return _respond(state)


@app.get("/api/project/{candidate_id}")
def api_project(candidate_id: str, kind: str = "all"):
    return _respond(lambda: api.project_api(_root(), candidate_id, kind))


@app.post("/api/verify")
def api_verify():
    return JSONResponse(api.verify_sample(_root()))


@app.post("/api/tamper")
def api_tamper():
    return JSONResponse(api.tamper_sample(_root()))


@app.post("/api/enrich")
def api_enrich(req: EnrichReq):
    try:
        from .enrich import pivot
        return JSONResponse(pivot(req.domain))
    except Exception as e:  # public sources are best-effort; report, never crash
        return JSONResponse({"error": f"{type(e).__name__}: {e}", "seed": req.domain, "edges": []})


@app.get("/api/asset/{sha256}")
def api_asset(sha256: str):
    try:
        path = api.asset_path(_root(), sha256)
    except ValueError:
        return Response(status_code=400)
    if path is None:
        return Response(status_code=404)
    return Response(content=path.read_bytes(), media_type="image/png")


@app.get("/api/feedback")
def api_feedback():
    return JSONResponse(api.feedback_summary(_root()))


@app.post("/api/apply_recalibration")
def api_apply_recalibration():
    return JSONResponse(api.apply_recalibration(_root()))


@app.get("/api/health")
def api_health():
    from . import embeddings as emb
    from .classify import api_key
    return {"embeddings_available": emb.available(), "model_api_key": bool(api_key()),
            "auth": bool(_token()), "actor_header": _actor_header() or None}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Brand impersonation detector operator console")
    ap.add_argument("--host", default="127.0.0.1",
                    help="listen address; anything but loopback needs BID_CONSOLE_TOKEN")
    ap.add_argument("--port", type=int, default=8799)
    ap.add_argument("--no-open", action="store_true")
    ap.add_argument("--brands", type=Path, help="brands file (default: the bundled example brands)")
    ap.add_argument("--governance", type=Path,
                    help="governance settings (default: $BID_DATA_DIR/governance.json, else the bundled example)")
    ap.add_argument("--policy-pack", help="policy pack recorded in every receipt (bid packs list)")
    ap.add_argument("--profile", help="deployment profile (default, sovereign or a path); its attestation is "
                                      "recorded in the governance journal and bound into every receipt")
    ap.add_argument("--deployment-id", default="bid-console", help="deployment name in the attestation record")
    args = ap.parse_args(argv)

    if args.host not in _LOOPBACK and not _token():
        print(f"bid console: refusing to listen on {args.host} without {_TOKEN_ENV}. "
              "Set it to a long random value, or listen on 127.0.0.1.", file=sys.stderr)
        return 2
    from .evidence import development_keys
    dev_keys = development_keys()
    if dev_keys and args.host not in _LOOPBACK:
        print(f"bid console: refusing to listen on {args.host} with the public development signing "
              f"keys ({', '.join(dev_keys)}): anyone could sign receipts under them. "
              "Set each to a long random value from your secret store.", file=sys.stderr)
        return 2
    try:
        _, source = load_config(args.governance)
    except (OSError, ValueError) as e:
        print(f"bid console: governance settings: {e}", file=sys.stderr)
        return 2
    SETTINGS.update(brands_file=args.brands, governance=args.governance)
    if args.policy_pack:
        from .packs import load_pack, pack_ref
        SETTINGS["policy_pack"] = pack_ref(load_pack(args.policy_pack))
    if args.profile:
        from .attestation import load_profile, put_in_force
        SETTINGS["attestation_hash"] = put_in_force(load_profile(args.profile), args.deployment_id,
                                                    api.default_journal(), datetime.now(timezone.utc))

    shown = "127.0.0.1" if args.host in _LOOPBACK else args.host
    url = f"http://{shown}:{args.port}"
    print(f"\n  Operator console -> {url}\n  governance settings: {source}")
    if dev_keys:
        print(f"  development signing keys in use ({', '.join(dev_keys)}): receipts are for trying it out only")
    if _actor_header():
        print(f"  actor identity from the {_actor_header()} header (authenticating proxy)")
    print("  (Ctrl-C to stop)\n")
    if not args.no_open and args.host in _LOOPBACK:
        import threading
        import webbrowser
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()

    import uvicorn
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
