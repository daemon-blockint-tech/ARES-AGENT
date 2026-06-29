"""CLI for ARES CVE enrichment layer.

Usage:
    ares-cve search <keyword>
    ares-cve dep-scan <name> <version>
    ares-cve enrich <findings.json>
    ares-cve lookup <cve-id>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .enricher import CVEEnricher

console = Console()


@click.group()
def main() -> None:
    """ARES CVE: Offline CVE enrichment for Solana audit findings."""


@main.command()
@click.argument("keyword")
@click.option("--db-path", type=click.Path(), default=None, help="Path to CVEdb SQLite database")
def search(keyword: str, db_path: str | None) -> None:
    """Search CVEs by keyword (e.g., 'solana', 'anchor', 'wormhole')."""
    with CVEEnricher(db_path=db_path) as enricher:
        results = enricher.search_by_keyword(keyword)

    if not results:
        console.print(f"[yellow]No CVEs found for '{keyword}'[/yellow]")
        sys.exit(0)

    table = Table(title=f"CVE Results: '{keyword}' ({len(results)} found)")
    table.add_column("CVE ID", style="cyan")
    table.add_column("CVSS v3", style="red")
    table.add_column("Severity", style="yellow")
    table.add_column("Description", max_width=60)

    for cve in results:
        score = f"{cve.cvss_v3_score}" if cve.cvss_v3_score else "N/A"
        sev = cve.cvss_v3_severity or "N/A"
        table.add_row(cve.cve_id, score, sev, cve.description[:80])

    console.print(table)


@main.command(name="dep-scan")
@click.argument("name")
@click.argument("version")
@click.option("--db-path", type=click.Path(), default=None, help="Path to CVEdb SQLite database")
def dep_scan(name: str, version: str, db_path: str | None) -> None:
    """Scan a dependency for known CVEs."""
    with CVEEnricher(db_path=db_path) as enricher:
        result = enricher.scan_dependency(name, version)

    if not result.cves:
        console.print(f"[green]No CVEs found for {name}@{version}[/green]")
        sys.exit(0)

    console.print(f"[red]Found {len(result.cves)} CVEs for {name}@{version}[/red]")
    console.print(f"  Max CVSS: {result.max_cvss}")
    console.print(f"  Has Critical: {result.has_critical}")
    console.print(f"  Has High: {result.has_high}")
    console.print()

    for cve in result.cves:
        console.print(f"  [cyan]{cve.cve_id}[/cyan] (CVSS: {cve.cvss_v3_score})")
        console.print(f"    {cve.description[:100]}")
        if cve.references:
            console.print(f"    References: {len(cve.references)}")
        console.print()


@main.command()
@click.argument("findings_path", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), default=None, help="Output path for enriched findings")
@click.option("--db-path", type=click.Path(), default=None, help="Path to CVEdb SQLite database")
def enrich(findings_path: str, output: str | None, db_path: str | None) -> None:
    """Enrich findings from a JSON file with CVE references."""
    data = json.loads(Path(findings_path).read_text())
    findings = data.get("findings", data) if isinstance(data, dict) else data

    with CVEEnricher(db_path=db_path) as enricher:
        results = enricher.enrich_findings(findings)

    enriched = [r.to_dict() for r in results if r.has_cve]
    total_cves = sum(len(r.cve_refs) for r in results)

    console.print(f"[green]Enriched {len(results)} findings, {len(enriched)} have CVE refs[/green]")
    console.print(f"Total CVE references: {total_cves}")

    if enricher.is_offline:
        console.print("[yellow]Note: Running in offline mode (CVEdb not installed)[/yellow]")

    output_data = {
        "enriched_findings": enriched,
        "summary": {
            "total_findings": len(results),
            "findings_with_cve": len(enriched),
            "total_cve_refs": total_cves,
        },
    }

    if output:
        Path(output).write_text(json.dumps(output_data, indent=2))
        console.print(f"Results written to {output}")
    else:
        console.print_json(json.dumps(output_data))


@main.command()
@click.argument("cve_id")
@click.option("--db-path", type=click.Path(), default=None, help="Path to CVEdb SQLite database")
def lookup(cve_id: str, db_path: str | None) -> None:
    """Look up a specific CVE by ID."""
    with CVEEnricher(db_path=db_path) as enricher:
        metadata = enricher.get_evidence_metadata(cve_id)

    if not metadata:
        console.print(f"[yellow]CVE {cve_id} not found[/yellow]")
        sys.exit(1)

    console.print(f"[cyan]CVE: {metadata.get('cve_id', cve_id)}[/cyan]")
    console.print(f"  Description: {metadata.get('description', 'N/A')}")
    console.print(f"  CVSS v3: {metadata.get('cvss_v3_score', 'N/A')}")
    console.print(f"  Severity: {metadata.get('cvss_v3_severity', 'N/A')}")

    refs = metadata.get("references", [])
    if refs:
        console.print(f"  References ({len(refs)}):")
        for ref in refs:
            console.print(f"    - {ref}")

    cpe = metadata.get("cpe_matches", [])
    if cpe:
        console.print(f"  CPE Matches ({len(cpe)}):")
        for c in cpe:
            console.print(f"    - {c}")


if __name__ == "__main__":
    main()
