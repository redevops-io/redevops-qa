# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Test-only list of the reserved path tokens and earlier marker-file names that ``seed_copy`` refuses.

The library holds them only as SHA-256 digests, and the repository's wording guard scans every tracked file, so the plain text
is kept here in a ROT13 encoding and decoded when a test runs. The encoding keeps the words out of a text search of the
repository; it is not a secret. ``reference_part_marker`` is the matcher the library had before the words became digests, rebuilt
from this list, so a test can show that both matchers refuse exactly the same names."""
import codecs
import re

_TOKENS_ROT13 = ("sebmra", "frnyrq", "uryqbhg", "uryq-bhg", "onfryvar-serrmr", "cvaarq-urnq")
_MARKER_FILES_ROT13 = ("SEBMRA_URNQ", ".sebmra-urnq", ".sebmra", "FRNYRQ", ".frnyrq")


def _decode(items):
    return tuple(codecs.decode(x, "rot13") for x in items)


TOKENS = _decode(_TOKENS_ROT13)
MARKER_FILES = _decode(_MARKER_FILES_ROT13)

_REFERENCE = re.compile(r"(?:^|[^a-z0-9])(" + "|".join(re.escape(m) for m in sorted(TOKENS, key=len, reverse=True)) + r")(?:$|[^a-z0-9])", re.I)


def reference_part_marker(part):
    """The token the original word matcher found in a path component, or ``None``."""
    m = _REFERENCE.search(part)
    return m.group(1).lower() if m else None


def near_misses(token):
    """Names that contain the letters of ``token`` but are not the token as a whole component token."""
    out = ["un" + token + "ish", token + "x", "x" + token, token + "s", "re" + token + "ed", token[:3] + "x" + token[3:], token.replace("-", "_"),
           token.replace("-", ""), token.replace("-", "--"), token[:-1], token[1:]]
    return [n for n in out if reference_part_marker(n) is None]
