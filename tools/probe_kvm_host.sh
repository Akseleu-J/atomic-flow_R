#!/usr/bin/env bash
# Host capability probe for the atomic-flow beta worker acceptance (S0/S1,
# B4a). Run on any candidate Linux host BEFORE planning the Firecracker
# slice: prints PASS/FAIL per capability and a final verdict line.
# Usage: bash tools/probe_kvm_host.sh
set -u
pass=0; fail=0
check() { # name, command...
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then
        echo "PASS  $name"; pass=$((pass+1))
    else
        echo "FAIL  $name"; fail=$((fail+1))
    fi
}
echo "== atomic-flow worker host probe =="
echo "host: $(uname -a)"
check "linux"                [ "$(uname -s)" = "Linux" ]
check "arch-x86_64-or-arm64" [ "$(uname -m)" = "x86_64" ] || [ "$(uname -m)" = "aarch64" ]
check "cpu-virtualization-flags" grep -qE '(vmx|svm)' /proc/cpuinfo
check "dev-kvm-present"      [ -e /dev/kvm ]
check "dev-kvm-accessible"   [ -w /dev/kvm ]
check "firecracker-binary"   command -v firecracker
check "systemd"              [ -d /run/systemd/system ]
check "curl"                 command -v curl
check "python3"              command -v python3
check "openssl"              command -v openssl
check "git"                  command -v git
check "rust-toolchain"       command -v cargo
check "docker"               command -v docker
MEM_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)
DISK_GB=$(df -BG . 2>/dev/null | awk 'NR==2 {print int($4)}' | tr -dc '0-9')
echo "info  mem=${MEM_MB}MB free-disk=${DISK_GB}GB"
if [ "${MEM_MB:-0}" -ge 4000 ]; then echo "PASS  mem>=4GB"; pass=$((pass+1)); else echo "FAIL  mem>=4GB"; fail=$((fail+1)); fi
if [ "${DISK_GB:-0}" -ge 20 ]; then echo "PASS  disk>=20GB"; pass=$((pass+1)); else echo "FAIL  disk>=20GB"; fail=$((fail+1)); fi
echo "== verdict =="
if [ "$(uname -s)" = "Linux" ] && [ -w /dev/kvm ]; then
    echo "VERDICT: KVM-capable host — Firecracker slice (S0/S1 live runs) possible."
else
    echo "VERDICT: NO usable KVM — fine for the issuance service and worker-auth tests, NOT for microVM lifecycle runs."
fi
echo "passed=$pass failed=$fail"
