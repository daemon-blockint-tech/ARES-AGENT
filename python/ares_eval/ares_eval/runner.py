"""Evaluation runner: measure precision, recall, and F1 for audit detectors."""

from __future__ import annotations

from dataclasses import dataclass, field

from .corpus import BenchmarkCorpus


@dataclass
class EvalResult:
    """Evaluation results for a single detector."""

    detector_id: str
    total_ground_truth: int = 0
    total_detected: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    per_class: dict[str, dict[str, float]] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        if self.total_detected == 0:
            return 0.0
        return self.true_positives / self.total_detected

    @property
    def recall(self) -> float:
        if self.total_ground_truth == 0:
            return 0.0
        return self.true_positives / self.total_ground_truth

    @property
    def f1(self) -> float:
        p = self.precision
        r = self.recall
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)

    def to_dict(self) -> dict:
        return {
            "detector_id": self.detector_id,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "per_class": self.per_class,
        }


class EvalRunner:
    """Run evaluation of a detector against a benchmark corpus.

    Measures precision, recall, and F1 per vulnerability class (C1, C2, C3).
    """

    def __init__(self, corpus: BenchmarkCorpus) -> None:
        self.corpus = corpus

    def evaluate(
        self,
        detector_id: str,
        detected_findings: list[dict],
    ) -> EvalResult:
        """Evaluate a detector's findings against the ground truth corpus.

        Args:
            detector_id: ID of the detector being evaluated.
            detected_findings: List of finding dicts with keys:
                program_id, title, severity, vulnerability_class.

        Returns:
            EvalResult with precision/recall/F1 metrics.
        """
        ground_truth = self.corpus.filter_by_detector(detector_id)
        result = EvalResult(detector_id=detector_id)
        result.total_ground_truth = len(ground_truth)
        result.total_detected = len(detected_findings)

        # Match detected findings to ground truth
        gt_matched = [False] * len(ground_truth)

        for det in detected_findings:
            matched = False
            for i, gt in enumerate(ground_truth):
                if gt_matched[i]:
                    continue
                if (
                    det.get("program_id") == gt.program_id
                    and det.get("title", "").lower() in gt.title.lower()
                ):
                    gt_matched[i] = True
                    result.true_positives += 1
                    matched = True
                    break
            if not matched:
                result.false_positives += 1

        result.false_negatives = sum(1 for m in gt_matched if not m)

        # Per-class breakdown
        for vuln_class in ["C1", "C2", "C3"]:
            class_gt = [gt for gt in ground_truth if gt.vulnerability_class == vuln_class]
            class_det = [d for d in detected_findings if d.get("vulnerability_class") == vuln_class]

            class_tp = 0
            class_gt_matched = [False] * len(class_gt)
            for d in class_det:
                for i, gt in enumerate(class_gt):
                    if class_gt_matched[i]:
                        continue
                    if d.get("program_id") == gt.program_id and d.get("title", "").lower() in gt.title.lower():
                        class_gt_matched[i] = True
                        class_tp += 1
                        break

            class_fp = len(class_det) - class_tp
            class_fn = len(class_gt) - class_tp
            class_precision = class_tp / max(1, len(class_det))
            class_recall = class_tp / max(1, len(class_gt))
            class_f1 = (
                2 * class_precision * class_recall / max(0.001, class_precision + class_recall)
                if class_precision + class_recall > 0
                else 0.0
            )

            result.per_class[vuln_class] = {
                "precision": round(class_precision, 4),
                "recall": round(class_recall, 4),
                "f1": round(class_f1, 4),
                "tp": class_tp,
                "fp": class_fp,
                "fn": class_fn,
            }

        return result


__all__ = ["EvalRunner", "EvalResult"]
