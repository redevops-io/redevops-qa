# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""Disposable-cluster tier: guard, bring-up plan as data, kubectl argv allow-list, runner, drivers, lane reporting.

Nothing in this package starts a cluster. The real cluster lane is disabled by default and cannot be enabled without an
explicit disposable-host acknowledgement; every test runs against a fake runner.
"""
