"""CLI for ARES Eval Lab."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

from .corpus import BenchmarkCorpus, CorpusEntry
from .runner import EvalRunner

console = Console()


@click.group()
def cli() -> None:
    """ARES Eval: Agent evaluation lab for Solana audit detectors."""


@cli.command()
@click.option("--corpus", "-c", type=click.Path(exists=True), required=True, help="Benchmark corpus JSON")
@click.option("--findings", "-f", type=click.Path(exists=True), required=True, help="Detector findings JSON")
@click.option("--detector-id", "-d", required=True, help="Detector ID to evaluate")
def run(corpus: str, findings: str, detector_id: str) -> None:
    """Run evaluation of a detector against the benchmark corpus."""
    bench = BenchmarkCorpus()
    bench.load(corpus)

    with open(findings) as f:
        det_findings = json.load(f)

    runner = EvalRunner(bench)
    result = runner.evaluate(detector_id, det_findings)

    # Summary table
    table = Table(title=f"Evaluation Results: {detector_id}")
    table.add_column("Metric")
    table.add_column("Value")

    table.add_row("Precision", f"{result.precision:.4f}")
    table.add_row("Recall", f"{result.recall:.4f}")
    table.add_row("F1", f"{result.f1:.4f}")
    table.add_row("True Positives", str(result.true_positives))
    table.add_row("False Positives", str(result.false_positives))
    table.add_row("False Negatives", str(result.false_negatives))

    console.print(table)

    # Per-class table
    class_table = Table(title="Per-Class Breakdown")
    class_table.add_column("Class")
    class_table.add_column("Precision")
    class_table.add_column("Recall")
    class_table.add_column("F1")
    class_table.add_column("TP/FP/FN")

    for cls, metrics in result.per_class.items():
        class_table.add_row(
            cls,
            f"{metrics['precision']:.4f}",
            f"{metrics['recall']:.4f}",
            f"{metrics['f1']:.4f}",
            f"{metrics['tp']}/{metrics['fp']}/{metrics['fn']}",
        )

    console.print(class_table)


@cli.command()
@click.option("--corpus", "-c", type=click.Path(), default="benchmark_corpus/corpus.json")
def init(corpus: str) -> None:
    """Initialize a benchmark corpus with sample entries."""
    bench = BenchmarkCorpus()

    # Seed with known Solana vulnerabilities
    samples = [
        CorpusEntry(
            program_id="Wormhole3Tm...1111",
            title="Forged instructions sysvar bypass",
            severity="critical",
            vulnerability_class="C2",
            description="Wormhole bridge used forged sysvar to bypass signature verification ($320M loss)",
            detector_id="static_rules",
            exploit_scenario="Attacker forges sysvar account to bypass verification of transfer instructions",
        ),
        CorpusEntry(
            program_id="Cashio...1111",
            title="Missing account validation in collateral backing",
            severity="critical",
            vulnerability_class="C2",
            description="Cashio failed to validate collateral accounts, allowing minting of unbacked CASH ($52M loss)",
            detector_id="static_rules",
        ),
        CorpusEntry(
            program_id="Crema...1111",
            title="Forged price tick account",
            severity="critical",
            vulnerability_class="C2",
            description="Crema allowed attacker to report fake liquidity price via forged tick account ($8.8M loss)",
            detector_id="cpi_tracer",
        ),
        CorpusEntry(
            program_id="Mango...1111",
            title="Price manipulation via oracle",
            severity="critical",
            vulnerability_class="C1",
            description="Mango Markets exploited via price manipulation of oracle feeds ($114M loss)",
            detector_id="any",
        ),
        CorpusEntry(
            program_id="Nirvana...1111",
            title="Economic exploit via bonding curve",
            severity="critical",
            vulnerability_class="C1",
            description="Nirvana Finance bonding curve exploited for risk-free profit ($3.5M loss)",
            detector_id="any",
        ),
    ]

    for s in samples:
        bench.add_entry(s)

    bench.save(corpus)
    console.print(f"[green]Initialized benchmark corpus with {bench.count} entries at {corpus}[/green]")
    console.print(f"Class distribution: {bench.class_distribution()}")


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
