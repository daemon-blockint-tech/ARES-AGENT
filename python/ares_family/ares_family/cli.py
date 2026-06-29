"""CLI for ARES Family clone detection."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .clusterer import FamilyClusterer
from .risk_propagator import FamilyRiskPropagator

console = Console()


@click.group()
def cli() -> None:
    """ARES Family: Clone detection and program family risk intelligence."""


@cli.command()
@click.option("--input", "-i", type=click.Path(exists=True), help="JSON file with program bytecode data")
@click.option("--threshold", "-t", type=float, default=0.95, help="Similarity threshold")
def cluster(input: str, threshold: float) -> None:
    """Cluster programs into families by bytecode similarity."""
    clusterer = FamilyClusterer(similarity_threshold=threshold)

    data = json.loads(Path(input).read_text())
    for prog in data.get("programs", []):
        bytecode = bytes.fromhex(prog.get("bytecode_hex", ""))
        clusterer.add_program(bytecode, prog["program_id"])

    families = clusterer.cluster()

    table = Table(title="Program Families")
    table.add_column("Family ID")
    table.add_column("Template")
    table.add_column("Members")
    table.add_column("Count")

    for fam in families.values():
        table.add_row(fam.family_id, fam.template_id, ", ".join(fam.members[:3]), str(len(fam.members)))

    console.print(table)
    console.print(f"\nTotal families: {len(families)}")


@cli.command()
@click.option("--input", "-i", type=click.Path(exists=True), help="JSON file with family data")
@click.option("--risk", "-r", type=float, required=True, help="Template risk score")
def propagate(input: str, risk: float) -> None:
    """Propagate risk across a program family."""
    propagator = FamilyRiskPropagator()

    data = json.loads(Path(input).read_text())
    for fam_data in data.get("families", []):
        from .clusterer import ProgramFamily

        family = ProgramFamily(
            family_id=fam_data["family_id"],
            template_id=fam_data["template_id"],
            members=fam_data["members"],
        )
        state = propagator.update_family_risk(family, risk)

        console.print(f"[bold]{family.family_id}[/bold]: risk={state.total_risk:.4f} ({len(state.member_risks)} members)")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
