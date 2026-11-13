# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``qa_service``: a small authenticated HTTP service around the ``redevops-qa`` command (standard library only).

It adds no test logic: every run, report and verification is the ``redevops-qa`` command run as a child process, and the service only keeps what that command wrote.
It cannot be pointed at an external application: the plans it starts are the shipped ones, which run against the bundled fixture app."""
__version__ = "0.1.0.dev0"
