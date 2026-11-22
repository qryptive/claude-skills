"""What counts (plan D4).

- FEEDBACK (the agent is told to fix it): a crypto finding (`operation`, `dependency`,
  `algorithm`) or a protocol/IaC finding (`protocol`) whose `pq_status` is `vulnerable`.
- WARN (shown, never fed back as a demand): an asset finding (`private_key`, `certificate`,
  `key_file`, `token`), and any finding whose `pq_status` is something other than `vulnerable`.
- None (never reported): `secret` findings (other tools own secrets), and findings the scanner
  itself marks quantum-safe (the scanner emits safe algorithms too; they are not problems).
"""
from typing import Iterable, List, Optional

FEEDBACK = "feedback"
WARN = "warn"

CRYPTO_TYPES = frozenset({"operation", "dependency", "algorithm"})
PROTOCOL_TYPES = frozenset({"protocol"})
ASSET_TYPES = frozenset({"private_key", "certificate", "key_file", "token"})
NEVER_TYPES = frozenset({"secret"})
SAFE_STATUSES = frozenset({"secure", "safe", "quantum_safe", "quantum-safe", "pq_safe", "pq-safe",
                           "hybrid", "pq-hybrid", "pq_hybrid"})


def classify(finding: dict) -> Optional[str]:
    ftype = str(finding.get("finding_type") or "").strip().lower()
    status = str(finding.get("pq_status") or "").strip().lower()
    if ftype in NEVER_TYPES:
        return None
    if status in SAFE_STATUSES:
        return None
    if status == "vulnerable" and (ftype in CRYPTO_TYPES or ftype in PROTOCOL_TYPES):
        return FEEDBACK
    return WARN


def apply_allow(findings: Iterable[dict], pol) -> List[dict]:
    """Drop findings an `allow` entry (with a reason) covers."""
    return [f for f in findings if not pol.allowed(f)]
