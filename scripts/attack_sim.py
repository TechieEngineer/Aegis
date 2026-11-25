#!/usr/bin/env python3
"""Local-only defensive integration tests. Never accepts a remote base URL."""
import json
import os
import pathlib
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookies import SimpleCookie

BASE = "http://localhost:3000"
ROOT = pathlib.Path(__file__).resolve().parents[1]

class LocalOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), LocalOnly())

class Client:
    def __init__(self):
        self.cookies = {}
    def request(self, path, method="GET", data=None, headers=None, cookie_override=None, update=True):
        assert path.startswith("/api/") or path == "/health"
        h = {"Origin": BASE, **(headers or {})}
        # The local test harness emulates localhost Secure cookies. Never use over a network.
        jar = self.cookies if cookie_override is None else cookie_override
        if jar:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
        raw = None
        if data is not None:
            raw = json.dumps(data).encode()
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(BASE + path, raw, h, method=method)
        try:
            response = OPENER.open(req, timeout=15)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            if update:
                for value in response.headers.get_all("Set-Cookie", []):
                    parsed = SimpleCookie(); parsed.load(value)
                    for k, m in parsed.items():
                        if m["max-age"] == "-1": self.cookies.pop(k, None)
                        else: self.cookies[k] = m.value
            body = response.read()
            return response.status, json.loads(body) if body else {}, response.headers

def expect(result, code, label):
    status, body, _ = result
    if status != code: raise AssertionError(f"{label}: expected {code}, got {status}: {body}")
    print(f"PASS {label} ({status})")
    return body

def main():
    env = dict(line.strip().split("=", 1) for line in (ROOT / ".env").read_text(encoding="utf-8-sig").splitlines() if line.strip() and not line.lstrip().startswith("#") and "=" in line)
    admin = Client(); viewer = Client(); anonymous = Client()
    expect(anonymous.request("/health"), 200, "health")
    login = {"email":env["ADMIN_EMAIL"],"password":env["ADMIN_PASSWORD"],"code":os.getenv("AEGIS_TEST_TOTP", "")}
    expect(admin.request("/api/auth/login", "POST", login), 200, "admin login")
    expect(admin.request("/api/me"), 200, "authenticated session")
    # These synthetic signatures are sent only to the fixed loopback Aegis probe.
    for name, text in [("SQLi", "' OR 1=1"), ("XSS", "<script>demo</script>"), ("traversal", "../demo")]:
        expect(anonymous.request("/api/probe?" + urllib.parse.urlencode({"q":text})), 403, name + " query filter")
    expect(anonymous.request("/api/probe", headers={"X-Demo":"<script>"}), 403, "header filter")
    expect(anonymous.request("/api/auth/register", "POST", {"email":"bad@example.test","password":"<script>demo</script>"}), 403, "JSON filter")
    for target in ("127.0.0.1", "169.254.169.254", "::1"):
        expect(admin.request("/api/scans", "POST", {"target":target}), 400, "SSRF validation " + target)
    job = expect(admin.request("/api/scans", "POST", {"target":"demo.aegis.test"}), 202, "offline recon job")
    # Read actual SSE frames; no remote DNS or ports are contacted by the fixture.
    req = urllib.request.Request(BASE+"/api/scans/"+job["id"]+"/events",headers={"Cookie":"; ".join(f"{k}={v}" for k,v in admin.cookies.items())})
    with OPENER.open(req,timeout=30) as response:
        assert response.headers.get_content_type()=="text/event-stream"
        final=None
        for raw in response:
            if raw.startswith(b"data: "):
                final=json.loads(raw[6:]); print("SSE",final["status"],final["progress"])
                if final["status"] in ("completed","failed"):break
        assert final and final["status"]=="completed" and final.get("report"), "demo scan failed"
    print("PASS SSE and report")
    account={"email":f"test-{secrets.token_hex(6)}@aegis.local","password":secrets.token_hex(20),"code":""}
    expect(viewer.request("/api/auth/register","POST",account),201,"Viewer registration")
    expect(viewer.request("/api/auth/login","POST",account),200,"Viewer login")
    expect(viewer.request("/api/scans","POST",{"target":"demo.aegis.test"}),403,"RBAC")
    expect(viewer.request("/api/scans/"+job["id"]),404,"report ownership")
    old=dict(viewer.cookies)
    expect(viewer.request("/api/auth/refresh","POST"),200,"refresh rotation")
    fresh=dict(viewer.cookies)
    expect(viewer.request("/api/auth/refresh","POST",cookie_override=old,update=False),401,"refresh replay detection")
    expect(viewer.request("/api/me",cookie_override=fresh,update=False),401,"family access revocation")
    import base64
    b64=lambda x:base64.urlsafe_b64encode(x).decode().rstrip("=")
    # Random opaque bytes verify the storage contract, not AES correctness.
    envelope={"ciphertext":b64(secrets.token_bytes(32)),"iv":b64(secrets.token_bytes(12)),"ttl":"5m"}
    v=expect(admin.request("/api/vault","POST",envelope),201,"vault create")
    path="/api/vault/"+v["id"]+"/consume"
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(lambda _:Client().request(path,"POST"),range(2)))
    assert sorted(r[0] for r in results)==[200,404], results
    assert next(r[1] for r in results if r[0]==200)==envelope
    print("PASS atomic one-time vault retrieval")
    limited=False
    for _ in range(24):
        r=anonymous.request("/api/probe")
        if r[0]==429:
            assert r[2].get("Retry-After") and r[2].get("X-RateLimit-Remaining")=="0"
            limited=True;break
        assert r[0]==200,r
    assert limited,"rate limiting not observed"
    print("PASS bounded loopback rate limiter check (429)")
    print("All local integration checks passed. Browser AES-GCM round trip is a separate manual test.")

if __name__ == "__main__": main()
