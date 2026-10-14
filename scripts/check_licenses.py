"""Fail if any runtime dependency of a package has a non-permissive licence.

    python scripts/check_licenses.py packages/arpa-auth

Resolves the package's runtime dependencies into a throwaway venv and reads each distribution's
licence metadata. Allowed: MIT, BSD, Apache-2.0, ISC, PSF and the unencumbered public-domain style
licences. Anything copyleft or unknown fails, so a new dependency gets looked at before it ships.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ALLOWED = ("MIT", "BSD", "APACHE", "ISC", "PSF", "PYTHON SOFTWARE FOUNDATION", "UNLICENSE", "CC0", "0BSD")
FORBIDDEN = ("GPL", "AGPL", "LGPL", "SSPL", "EUPL", "MPL")

PROBE = r"""
import json, importlib.metadata as md
out = {}
for d in md.distributions():
    m = d.metadata
    lic = m.get("License-Expression") or ""
    if not lic:
        cls = [c.split("::")[-1].strip() for c in (m.get_all("Classifier") or []) if c.startswith("License ::")]
        lic = "; ".join(cls) or (m.get("License") or "")[:80]
    out[m["Name"]] = lic
print(json.dumps(out))
"""


def main(pkg_dir: str) -> int:
    pkg = Path(pkg_dir).resolve()
    with tempfile.TemporaryDirectory() as tmp:
        venv = Path(tmp) / "v"
        subprocess.run(["uv", "venv", "-q", str(venv)], check=True)
        py = venv / "bin" / "python"
        subprocess.run(["uv", "pip", "install", "-q", "--python", str(py), str(pkg)], check=True)
        found = json.loads(subprocess.run([str(py), "-c", PROBE], check=True, capture_output=True,
                                          text=True).stdout)
    name = pkg.name
    bad = []
    for dist, lic in sorted(found.items()):
        if dist.lower().replace("_", "-") == name:
            continue
        up = lic.upper()
        ok = any(a in up for a in ALLOWED) and not any(f in up.replace("LGPL", "GPL") for f in FORBIDDEN)
        print(f"{'ok ' if ok else 'BAD'} {dist}: {lic or 'unknown'}")
        if not ok:
            bad.append(dist)
    if bad:
        print(f"non-permissive or unknown licences: {', '.join(bad)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
