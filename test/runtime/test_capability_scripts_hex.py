"""Capability entrypoint scripts must handle CapBnd values above 2**31 (no 32-bit overflow)."""

import subprocess
from pathlib import Path

import pytest

ENTRYPOINT_D = Path(__file__).resolve().parents[2] / "install" / "production-filesystem" / "entrypoint.d"

# Docker default caps + NET_ADMIN + NET_RAW; value exceeds 2**31 - 1.
CAPBND_HIGH_WITH_REQUIRED = "00000000a80435fb"
# Same set without NET_ADMIN (12) and NET_RAW (13).
CAPBND_HIGH_WITHOUT_NET = "00000000a80405fb"


def _run(script: str, tmp_path: Path, capbnd: str) -> str:
    """Run an entrypoint script against a fake /proc/self/status and return its output."""
    status = tmp_path / "status"
    status.write_text(f"CapBnd:\t{capbnd}\n")
    body = (ENTRYPOINT_D / script).read_text().replace("/proc/self/status", str(status))
    patched = tmp_path / script
    patched.write_text(body)
    result = subprocess.run(["sh", str(patched)], capture_output=True, text=True, timeout=30, env={"PATH": "/usr/bin:/bin"})
    return result.stdout + result.stderr


def test_audit_no_false_missing_alert_for_high_capbnd(tmp_path):
    """Required caps present in a >32-bit bounding set must not trigger the missing-caps alert."""
    out = _run("10-capabilities-audit.sh", tmp_path, CAPBND_HIGH_WITH_REQUIRED)
    assert "NET_RAW/NET_ADMIN) are missing" not in out
    assert "NET_BIND_SERVICE missing" not in out


def test_audit_alerts_when_net_caps_really_missing(tmp_path):
    """The missing-caps alert still fires when NET_ADMIN/NET_RAW are truly absent."""
    out = _run("10-capabilities-audit.sh", tmp_path, CAPBND_HIGH_WITHOUT_NET)
    assert "NET_RAW/NET_ADMIN) are missing" in out


@pytest.mark.parametrize("capbnd,expected", [("00000000a80435fb", True), ("00000000000034c1", False)])
def test_excessive_caps_detection(tmp_path, capbnd, expected):
    """Excessive-capability warning reflects the real bits for high and low bounding sets."""
    out = _run("90-excessive-capabilities.sh", tmp_path, capbnd)
    assert ("Excessive capabilities detected" in out) is expected
