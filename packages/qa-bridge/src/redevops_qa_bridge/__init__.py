# SPDX-License-Identifier: LicenseRef-AGPL-3.0-or-later-with-Commons-Clause
"""``redevops_qa_bridge``: the only code that imports both ``runtime-contracts`` (qa/v1) and the harness neutral module.

Importing this package imports neither dependency; they are loaded on first use through :mod:`redevops_qa_bridge.deps`,
which fails (never skips) when one is unavailable. Only plain data crosses the boundary.
"""
from .adapters import (ContractsBlobStoreFromNeutral, ContractsCheckAdapterFromNeutral, ContractsQAAdapterFromNeutral,
                       ContractsRedactorFromNeutral, NeutralBlobSinkFromContracts, NeutralCheckAdapterFromContracts,
                       NeutralQAAdapterFromContracts, NeutralRedactorFromContracts)
from .convert import (assert_data_only, contracts_data_to_neutral, contracts_digest, from_contracts,
                      from_contracts_sequence, neutral_data_to_contracts, neutral_digest, registry, to_contracts,
                      to_contracts_sequence)
from .errormap import (contracts_error_for_neutral, contracts_to_neutral, neutral_error_for_contracts,
                       neutral_to_contracts)
from .errors import BridgeError, Codes
from .hashing import to_contracts_hash, to_neutral_hash
from .plan import runnable_items, validate_plan
from .policy import PolicyPlaneActionPolicy
from .stores import ContractsSpecStore, EvidenceSink

__version__ = "0.1.0.dev0"

__all__ = [
    "BridgeError", "Codes", "__version__",
    "assert_data_only", "contracts_data_to_neutral", "neutral_data_to_contracts", "from_contracts", "to_contracts",
    "from_contracts_sequence", "to_contracts_sequence", "contracts_digest", "neutral_digest", "registry",
    "to_contracts_hash", "to_neutral_hash",
    "contracts_error_for_neutral", "neutral_error_for_contracts", "contracts_to_neutral", "neutral_to_contracts",
    "validate_plan", "runnable_items",
    "NeutralQAAdapterFromContracts", "ContractsQAAdapterFromNeutral", "NeutralCheckAdapterFromContracts",
    "ContractsCheckAdapterFromNeutral", "NeutralBlobSinkFromContracts", "ContractsBlobStoreFromNeutral",
    "NeutralRedactorFromContracts", "ContractsRedactorFromNeutral",
    "ContractsSpecStore", "EvidenceSink", "PolicyPlaneActionPolicy",
]
