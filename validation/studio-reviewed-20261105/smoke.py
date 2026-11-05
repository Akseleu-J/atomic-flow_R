"""Run the installed Rust reviewed-edit API and a real, independent host oracle."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
EXE = ".exe" if os.name == "nt" else ""
BINARY = ROOT / "rust/target/debug" / ("af" + EXE)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def run(output):
    with tempfile.TemporaryDirectory(prefix="af-reviewed-edit-") as temporary:
        base = Path(temporary).resolve()
        state, project = base / "state", base / "source"
        state.mkdir()
        project.mkdir()
        source = project / "policy.txt"
        source.write_bytes(b"0\n")
        oracle_src = base / "oracle.rs"
        oracle_src.write_text(r'''
fn main() {
    let days = std::fs::read_to_string("policy.txt").ok()
        .and_then(|text| text.trim().parse::<u32>().ok());
    let status = if days.is_some_and(|n| (1..=30).contains(&n)) { "passed" } else { "failed" };
    println!(r#"{{"schema_version":1,"assertions":[{{"id":"refund-window","status":"{status}"}}]}}"#);
}
''', encoding="utf-8")
        oracle = base / ("oracle" + EXE)
        subprocess.run(["rustc", str(oracle_src), "-o", str(oracle)], cwd=base, check=True, timeout=90)
        token = secrets.token_hex(24)
        env = {name: os.environ[name] for name in ("PATH", "SYSTEMROOT", "USERPROFILE", "TEMP", "TMP") if name in os.environ}
        env.update(ATOMIC_FLOW_HOME=str(state), AF_REVIEW_SMOKE_TOKEN=token)
        grant = json.loads(subprocess.check_output([
            str(BINARY), "sandbox", "grant", "--root-id", "fixture",
            "--path", str(project), "--write", "policy.txt", "--host-approved",
        ], env=env, cwd=project, timeout=15))["granted"]
        studio = ROOT / "ts/af-studio/dist"
        profile_path = base / "profile.json"
        reports = []
        for replacement, expected in [("31\n", "refused"), ("14\n", "published")]:
            profile = dict(schema_version=1, root_id="fixture", root_generation=grant["generation"],
                file="policy.txt", before_sha256=sha(b"0\n"),
                replacement_sha256=sha(replacement.encode()), requirement_id="refund-window",
                requirement_contract_sha256=sha(b"refund days must be an integer from 1 to 30"),
                executable=str(oracle), executable_sha256=sha(oracle.read_bytes()),
                assertions=["refund-window"], timeout_secs=20)
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            with socket.socket() as port_socket:
                port_socket.bind(("127.0.0.1", 0))
                port = port_socket.getsockname()[1]
            address = f"127.0.0.1:{port}"
            with (base / "server.log").open("wb") as log:
                process = subprocess.Popen([
                    str(BINARY), "serve", "--bind", address, "--token-env", "AF_REVIEW_SMOKE_TOKEN",
                    "--studio-dist", str(studio), "--reviewed-edit-profile", str(profile_path),
                ], cwd=project, env=env, stdout=log, stderr=log,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                def request(path, body=None, status=200, authorized=True):
                    headers = {"Authorization": "Bearer " + token} if authorized else {}
                    if body is not None:
                        headers["Content-Type"] = "application/json"
                    req = Request("http://" + address + path, headers=headers,
                                  data=None if body is None else json.dumps(body).encode())
                    try:
                        response = urlopen(req, timeout=30)
                    except HTTPError as error:
                        response = error
                    with response:
                        data = response.read(2 * 1024 * 1024 + 1)
                        assert response.status == status, (path, response.status, data[:1000])
                        assert len(data) <= 2 * 1024 * 1024
                        return data, response.headers
                try:
                    for _ in range(80):
                        try:
                            request("/health")
                            break
                        except OSError:
                            if process.poll() is not None:
                                raise RuntimeError((base / "server.log").read_text(encoding="utf-8"))
                            time.sleep(.1)
                    else:
                        raise RuntimeError("native server did not start")
                    html, headers = request("/studio/", authorized=False)
                    assert "default-src 'none'" in headers["Content-Security-Policy"]
                    import re
                    assets = re.findall(rb'["\x27](/studio/assets/[^"\x27]+)', html)
                    assert assets and any(asset.endswith(b".js") for asset in assets)
                    for asset in assets:
                        assert request(asset.decode(), authorized=False)[0]
                    request("/studio/assets/missing.js", status=404, authorized=False)
                    request("/v1/reviewed-edit", status=401, authorized=False)
                    summary = json.loads(request("/v1/reviewed-edit")[0])
                    assert summary["replacement_sha256"] == profile["replacement_sha256"]
                    unbound = json.loads(request("/v1/sessions", {})[0])["session_id"]
                    request("/v1/reviewed-edit", {"session_id": unbound, "replacement": replacement}, status=409)
                    session = json.loads(request("/v1/sessions", {"root_id": "fixture"})[0])["session_id"]
                    request("/v1/reviewed-edit", {"session_id": session, "replacement": "unreviewed"}, status=400)
                    body = {"session_id": session, "replacement": replacement}
                    result = json.loads(request("/v1/reviewed-edit", body)[0])
                    assert result["status"] == expected and result["published"] == (expected == "published"), result
                    assert source.read_bytes() == (replacement.encode() if expected == "published" else b"0\n")
                    history = json.loads(request(f"/v1/sessions/{session}/history")[0])
                    assert history["effect_admission_clear"]
                    if expected == "published":
                        assert len(result["evidence_sha256"]) == 64
                        request("/v1/reviewed-edit", body, status=409)
                    reports.append({"status":expected,"evidence_sha256":result.get("evidence_sha256"),
                                    "live_sha256":sha(source.read_bytes()),"session_clear":True})
                finally:
                    process.terminate()
                    process.wait(timeout=10)
            assert not list((state / "review-candidates").iterdir())
        result = {"status":"passed","cases":reports,"oracle_sha256":sha(oracle.read_bytes()),
                  "native_binary_sha256":sha(BINARY.read_bytes()),"provider_calls":0,
                  "studio_http_assets":"passed","browser_visual_qa":"not_assessed"}
        output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(result, indent=2))

if __name__ == "__main__":
    run(Path(sys.argv[1]))
