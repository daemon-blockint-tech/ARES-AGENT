"""ARES CVE: Offline CVE enrichment for Solana audit findings.

Integrates Trail of Bits' CVEdb for offline-first CVE lookups.
Two enrichment modes:
1. Dependency scan: cross-reference program dependencies (Anchor, Solana SDK, etc.)
   against CVEdb to flag known-vulnerable versions.
2. Finding enrichment: link detector findings to known CVEs, adding CVSS scores,
   affected CPE ranges, and official references to evidence bundles.
"""

from __future__ import annotations

from .enricher import CVEEnricher, CVEEntry, DependencyCVE

__all__ = ["CVEEnricher", "CVEEntry", "DependencyCVE"]
