# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Program hashes are part of what an assertion freezes. These are the hashes of the manifest programs as first registered; a
change to a program, its support files, the loader, the serialisation or the input type changes them, and this test makes that
visible. A deliberate change updates the table and is a new program version in the same commit."""
import pytest

GOLDEN = {
    'manifest.cross-references': 'sha256:510755c75748f909d92211c13812f681d8651db00122dfee29130917c4016795',
    'manifest.cross-references.counts': 'sha256:56c041d2af529896cd9a3e5508652ef0558244bf0a0090e3db3efc7596e74d58',
    'manifest.env-and-secret-refs': 'sha256:c1a5e116b4fa7d382381652366c8af7e1f1d8eabceb96d7f7e1f7fbf2a6b2664',
    'manifest.env-and-secret-refs.counts': 'sha256:f326280b167cee4c40900d31cd77cbaed5c8d85545e61d36c0c1a2fb7bc7e033',
    'manifest.gateway-routes': 'sha256:489564742501c432fdb86cec2be5201f6c4851c88e82f6883c554085227ecb8c',
    'manifest.gateway-routes.counts': 'sha256:597a382d524d50e84e2106561649821170e5877be03434bb8c0e185e149b690f',
    'manifest.image-name-map': 'sha256:e9e62d777044a05319ef00eeb5d095383929e1b9e9a8bbb825679123416d9f39',
    'manifest.image-name-map.counts': 'sha256:612a1ca0ca1f8e165b082264df819f2ec783a011f7756804940cea4d8b7e7cfb',
    'manifest.image-references': 'sha256:f621e3132b688bc3c587b2446c5c1061d6914af10688f7284db9a6114e89c74f',
    'manifest.image-references.counts': 'sha256:62d8427eaac697413e2b249ade6f2d66dccac3594a1c0a619971bc7ea2185c87',
    'manifest.kyverno-policies': 'sha256:f979043072978deaef90fac643b445555d204e0721b35a5f6353d0cf73840bd0',
    'manifest.kyverno-policies.counts': 'sha256:792961901efef541512a0ed4d7fc32142e9115455e236ec19e57617ea9c5515f',
    'manifest.network-policies': 'sha256:b5f0e411652dfa39e2ac6d7d190a1aee1f2dbc10498922ea2b7c7d3138c6fb61',
    'manifest.network-policies.counts': 'sha256:cd92029115b84a346228b0655fd74736960beefba082615f6131b8c34e55bccf',
    'manifest.probes': 'sha256:34dade8ddfa80b8b503f4e4afc4e924a602bed047ada5e2f8b400c772ccc077f',
    'manifest.probes.counts': 'sha256:ed273d6e01858d30543ab0ad63ad32ae15c1dc8fe9e0920a389e2b9c1830138e',
    'manifest.resources': 'sha256:d8bcfe82ebe960e28639302a9a518901ece61bad836272d6c1548b0044d2b45c',
    'manifest.resources.counts': 'sha256:542a7523f8e42d7cb020eb7608ba668d9ee10f9a2d682c8ac77902a4fcade026',
    'manifest.security-context': 'sha256:346856a2f891d59cfaf7608aaed482745add44849cacbffc24b29f9af1f01a71',
    'manifest.security-context.counts': 'sha256:9fd71b87929fcaa0d95acd7830b4cf9cbf65f0038df72d18696909e733f761a4',
    'manifest.structure': 'sha256:de0f4940215d3d283e5f50d2652813429e4fba3585fdabfff1a8519cae3ee27d',
    'manifest.structure.counts': 'sha256:8a7ff82977f104e082e845e3e2f254fbbd7212fc7bf49528e39f5b8bc724e4a1',
}


@pytest.mark.parametrize("pid", sorted(GOLDEN))
def test_the_registered_hash_is_the_recorded_one(registry, pid):
    assert registry.registered_program_hash(pid, "1.0.0") == GOLDEN[pid]


def test_the_recorded_table_covers_every_manifest_program(registry):
    manifest_ids = {e.id for e in registry.entries() if e.id.startswith("manifest.")}
    assert manifest_ids == set(GOLDEN)
