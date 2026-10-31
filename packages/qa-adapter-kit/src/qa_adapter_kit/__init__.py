# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``qa_adapter_kit``: product-local protocol, typed models and shared supervisor for the optional execution adapters.

Standard library only. It imports no framework (Selenium, Robot Framework, Appium, Playwright), no harness module and no contracts
package, and it is not part of the frozen qa/v1 surface.
"""
from .adapter import (ActionOutcome, ArtifactRef, ImportedReport, InteractiveAdapter, InteractiveLayout, MalformedReport, RunLayout,
                      SuiteAdapter)
from .errors import (AdapterFault, AdapterKitError, AdapterUnavailable, ModelError, PathRefused, PolicyRefused)
from .mapping import CanonicalEvidence, MappingReport, OracleVerdict, canonical_status, map_to_canonical
from .models import (AdapterManifest, AdapterResult, EvidenceArtifact, FrameworkRef, HARD_CAPS, InteractiveActionRequest,
                     InteractiveObservation, Limits, NativeAssertion, PinnedFile, SuiteRunRequest, aggregate_status)
from .paths import PathPolicy, is_denied
from .redact import REDACTED, Redactor
from .runner import InteractiveSession, SuiteRunner
from .status import AdapterClass, ErrorCode, Status
from .supervisor import CancelToken, CommandSpec, ProcessOutcome

__version__ = "0.1.0.dev0"
