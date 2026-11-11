"""Create and verify an engineer beta archive from native and Studio build outputs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
from tempfile import TemporaryDirectory
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener
from zipfile import ZIP_DEFLATED, ZipFile

REPO = Path(__file__).resolve().parents[1]
QUICKSTART = """# Atomic Flow Studio engineer beta candidate

Compare the downloaded archive with SHA256SUMS.txt from the distribution
channel, then extract it to a new directory. From that directory run
`./af doctor` on Linux or `.\\af.exe doctor` in PowerShell.

On Linux, run `chmod +x ./af` if your extractor did not preserve permissions.
Start Studio using `./af serve --studio-dist studio` on Linux or
`.\\af.exe serve --studio-dist studio` in PowerShell, then open
http://127.0.0.1:8787/studio/ in your browser. Leave the server bound to loopback.
Stop it with Ctrl+C.

Use the main dashboard at http://127.0.0.1:8787/dashboard to register the
extracted demo directory and build its graph. Open Studio and select its root
to explore the Rust and TypeScript source. This is a read-only rehearsal
fixture for onboarding. Isolation and beta access require separate acceptance.
"""


def sha(data):
    return hashlib.sha256(data).hexdigest()


def package(binary, studio, commit, output):
    if binary.name not in {"af", "af.exe"} or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("expected an af binary and a full Git commit")
    assets = sorted((studio / "assets").iterdir())
    if not any(p.suffix == ".js" for p in assets) or any(
        not p.is_file() or p.is_symlink() or not re.fullmatch(r"[A-Za-z0-9._-]+", p.name)
        or p.suffix not in {".js", ".css"} for p in assets
    ):
        raise ValueError("unexpected Studio build output")
    files = {
        binary.name: binary.read_bytes(),
        "studio/index.html": (studio / "index.html").read_bytes(),
        "LICENSE": (REPO / "LICENSE").read_bytes(),
        "README.md": QUICKSTART.encode(),
        "demo/refund.rs": b"/// Return the refund window in days.\npub fn refund_days() -> u32 { 14 }\n",
        "demo/refund.ts": b"/** Return the refund window in days. */\nexport function refundDays(): number { return 14; }\n",
    }
    files.update({f"studio/assets/{p.name}": p.read_bytes() for p in assets})
    manifest = {
        "schema_version": 1,
        "source_commit": commit,
        "platform": "windows-x64" if binary.name == "af.exe" else "linux-x64",
        "files": {name: {"bytes": len(data), "sha256": sha(data)} for name, data in files.items()},
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    with ZipFile(output, "x", compression=ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
        archive.writestr("manifest.json", manifest_bytes)


def smoke_studio(binary, root, env, files):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    base = f"http://127.0.0.1:{port}/studio/"
    http = build_opener(ProxyHandler({}))
    with subprocess.Popen(
        [str(binary), "serve", "--bind", f"127.0.0.1:{port}", "--studio-dist", "studio"],
        cwd=root, env=env, stdout=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    ) as process:
        try:
            for _ in range(50):
                if process.poll() is not None:
                    raise RuntimeError("extracted af serve exited before Studio was available")
                try:
                    with http.open(base, timeout=1) as response:
                        index = response.read()
                    break
                except URLError:
                    time.sleep(0.1)
            else:
                raise RuntimeError("extracted Studio did not start")
            if index != (root / "studio/index.html").read_bytes():
                raise ValueError("server returned a different Studio index")
            for name in files:
                if name.startswith("studio/assets/"):
                    with http.open(base + name.removeprefix("studio/"), timeout=2) as response:
                        if response.read() != (root / name).read_bytes():
                            raise ValueError(f"server returned different Studio asset: {name}")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    print("Extracted Studio index and assets match over loopback HTTP")


def smoke(archive_path):
    with ZipFile(archive_path) as archive, TemporaryDirectory(prefix="af-beta-extracted-") as tmp:
        root = Path(tmp)
        manifest = json.loads(archive.read("manifest.json"))
        files = manifest["files"]
        names = archive.namelist()
        if len(names) != len(files) + 1 or set(names) != {*files, "manifest.json"}:
            raise ValueError("beta archive inventory differs from manifest")
        for name, record in files.items():
            if not all(re.fullmatch(r"[A-Za-z0-9_-][A-Za-z0-9._-]*", part) for part in name.split("/")):
                raise ValueError("unsafe beta archive path")
            data = archive.read(name)
            if record != {"bytes": len(data), "sha256": sha(data)}:
                raise ValueError(f"beta archive checksum mismatch: {name}")
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        binary = root / ("af.exe" if manifest["platform"] == "windows-x64" else "af")
        binary.chmod(0o755)
        env = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "TEMP", "TMP") if key in os.environ}
        env["ATOMIC_FLOW_HOME"] = str(root / "state")
        for command in ("--version", "doctor", "self-test"):
            subprocess.run([str(binary), command], cwd=root, env=env, check=True, timeout=60)
        smoke_studio(binary, root, env, files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--studio", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip()
    with TemporaryDirectory(prefix="af-beta-build-", dir=args.output.parent) as tmp:
        candidate = Path(tmp) / args.output.name
        package(args.binary, args.studio, commit, candidate)
        smoke(candidate)
        digest = sha(candidate.read_bytes())
        with candidate.open("rb") as source, args.output.open("xb") as destination:
            shutil.copyfileobj(source, destination)
    print(f"{digest}  {args.output.name}")


if __name__ == "__main__":
    main()
