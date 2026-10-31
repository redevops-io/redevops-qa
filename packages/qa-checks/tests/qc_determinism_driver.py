# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Prints one digest over every program's output for a fixed case tree; run under different hash seeds by the tests."""
import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import qc_fixtures as F                                            # noqa: E402
from redevops_qa_checks.canonical import canonical_bytes           # noqa: E402
from redevops_qa_checks.engine import CheckEngine                  # noqa: E402
from redevops_qa_checks.registry import builtin_registry           # noqa: E402

root = F.write_tree(Path(tempfile.mkdtemp()) / "case", F.good_set())
reg = builtin_registry()
engine = CheckEngine(root, reg)
h = hashlib.sha256()
for spec in reg.entries():
    out = engine.run_check({"check_program_ref": spec.ref, "inputs": [{"kind": "MANIFEST_PATH", "path": "."}], "tier": "OFFLINE"})
    h.update(spec.program_hash.encode())
    h.update(canonical_bytes(out.value))
import qc_images as I                                              # noqa: E402
from redevops_qa_checks.image_store import ImageStore              # noqa: E402

lay = I.Layout(root.parent / "img")
info = I.add_image(lay, labels={"b": "2", "a": "1"}, ports=("9090/tcp", "80/tcp", "443/tcp"), layers=3)
I.add_buildx_attestation(lay, info["manifest_digest"])
iengine = CheckEngine(root.parent, reg, image_store=ImageStore(root.parent))
for spec in reg.entries():
    if spec.id.startswith("image."):
        out = iengine.run_check({"check_program_ref": spec.ref, "inputs": [{"kind": "IMAGE_DIGEST", "digest": info["manifest_digest"]}], "tier": "OFFLINE"})
        h.update(spec.program_hash.encode())
        h.update(canonical_bytes(out.value))
print(h.hexdigest())
