"""Benchmark corpus of known Solana vulnerabilities for evaluation."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CorpusEntry:
    """A single benchmark entry: a known vulnerability in a program."""

    program_id: str
    title: str
    severity: str
    vulnerability_class: str  # C1, C2, C3
    description: str
    detector_id: str  # Which detector should find this
    exploit_scenario: str | None = None


class BenchmarkCorpus:
    """Load and manage benchmark corpus of known vulnerabilities.

    Based on aggregated findings from Solana security reviews
    (1,669 vulnerabilities from 163 audits across 8 firms).
    """

    def __init__(self) -> None:
        self.entries: list[CorpusEntry] = []

    def load(self, path: str | Path) -> None:
        """Load corpus from a JSON file."""
        data = json.loads(Path(path).read_text())
        for entry in data.get("entries", []):
            self.entries.append(
                CorpusEntry(
                    program_id=entry["program_id"],
                    title=entry["title"],
                    severity=entry["severity"],
                    vulnerability_class=entry["vulnerability_class"],
                    description=entry["description"],
                    detector_id=entry.get("detector_id", "any"),
                    exploit_scenario=entry.get("exploit_scenario"),
                )
            )

    def save(self, path: str | Path) -> None:
        """Save corpus to a JSON file."""
        data = {
            "entries": [
                {
                    "program_id": e.program_id,
                    "title": e.title,
                    "severity": e.severity,
                    "vulnerability_class": e.vulnerability_class,
                    "description": e.description,
                    "detector_id": e.detector_id,
                    "exploit_scenario": e.exploit_scenario,
                }
                for e in self.entries
            ]
        }
        Path(path).write_text(json.dumps(data, indent=2))

    def add_entry(self, entry: CorpusEntry) -> None:
        self.entries.append(entry)

    def filter_by_class(self, vuln_class: str) -> list[CorpusEntry]:
        return [e for e in self.entries if e.vulnerability_class == vuln_class]

    def filter_by_detector(self, detector_id: str) -> list[CorpusEntry]:
        return [e for e in self.entries if e.detector_id == detector_id or e.detector_id == "any"]

    @property
    def count(self) -> int:
        return len(self.entries)

    def class_distribution(self) -> dict[str, int]:
        dist: dict[str, int] = {}
        for e in self.entries:
            dist[e.vulnerability_class] = dist.get(e.vulnerability_class, 0) + 1
        return dist


__all__ = ["BenchmarkCorpus", "CorpusEntry"]
