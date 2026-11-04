# ReDevOps release and evidence signing key

This page publishes the public key that ReDevOps uses to sign release manifests and, optionally, evidence-bundle anchors.
Only the public key appears here. The private key never leaves its owner's machine.

* Owner: ReDevOps.io LLC
* Key type: ssh-ed25519
* Created: 2026-11
* Fingerprint (SHA-256): `SHA256:wUoE8wxKJpmtTH7GqWXMIl9/BW0SH1Isc5/w9HEiwqA`
* Signature namespaces: `redevops-qa-release@v1` (release manifests) and `redevops-qa-anchor@v1` (optional evidence anchors)

Public key (one line):

    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFQXIYIulaoPRsSjGCNjypV15bwGKtfVEt652S4rd1Lu redevops-qa evidence anchor 2026-11

## Verify a signature

Save the key as `allowed_signers` in this form (replace nothing; the line is public):

    release@redevops namespaces="redevops-qa-release@v1" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFQXIYIulaoPRsSjGCNjypV15bwGKtfVEt652S4rd1Lu

Then, with OpenSSH 8.0 or later:

    ssh-keygen -Y verify -f allowed_signers -I release@redevops \
      -n redevops-qa-release@v1 -s release-manifest.json.sig < release-manifest.json

A good result prints `Good "redevops-qa-release@v1" signature ... SHA256:wUoE8wxKJpmtTH7GqWXMIl9/BW0SH1Isc5/w9HEiwqA`. Compare the fingerprint with the value above and with at least one other channel before trusting it.

## Limits

A signature shows that the holder of this key signed those exact bytes. It does not show when it was signed, who holds the key, or that the software is free of defects. Check this fingerprint through a channel you trust that does not depend on the one that delivered the signature. Rotation or revocation will be announced on this page and on the other channels that list this key.
