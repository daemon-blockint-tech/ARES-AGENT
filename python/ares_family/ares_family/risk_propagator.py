"""Family risk propagation: when a template has a bug, elevate risk for all clones."""

from __future__ import annotations

from dataclasses import dataclass, field

from .clusterer import ProgramFamily


@dataclass
class FamilyRiskState:
    """Risk state for a program family."""

    family_id: str
    template_id: str
    base_risk: float = 0.0
    propagated_risk: float = 0.0
    total_risk: float = 0.0
    vulnerability_count: int = 0
    member_risks: dict[str, float] = field(default_factory=dict)


class FamilyRiskPropagator:
    """Propagate risk across program families.

    If a template program has a known vulnerability, all clones in the family
    inherit elevated risk priors. This creates a data network effect:
    each new finding improves risk assessment for the entire family.
    """

    def __init__(self, propagation_factor: float = 0.8) -> None:
        """Initialize the propagator.

        Args:
            propagation_factor: How much risk propagates from template to clones.
                1.0 = full propagation, 0.0 = no propagation.
        """
        self.factor = propagation_factor
        self.family_states: dict[str, FamilyRiskState] = {}

    def update_family_risk(
        self,
        family: ProgramFamily,
        template_risk: float,
        vulnerability_count: int = 1,
    ) -> FamilyRiskState:
        """Update risk for an entire family based on template findings."""

        propagated = template_risk * self.factor
        total = max(template_risk, propagated)

        state = FamilyRiskState(
            family_id=family.family_id,
            template_id=family.template_id,
            base_risk=template_risk,
            propagated_risk=propagated,
            total_risk=total,
            vulnerability_count=vulnerability_count,
        )

        # Set risk for each member
        for member in family.members:
            state.member_risks[member] = total

        self.family_states[family.family_id] = state
        return state

    def get_program_risk(self, program_id: str, families: dict[str, ProgramFamily]) -> float:
        """Get the propagated risk for a specific program."""
        for family in families.values():
            if program_id in family.members:
                state = self.family_states.get(family.family_id)
                if state:
                    return state.member_risks.get(program_id, 0.0)
        return 0.0

    def get_family_stats(self) -> list[dict]:
        """Get summary statistics for all families."""
        return [
            {
                "family_id": s.family_id,
                "template_id": s.template_id,
                "total_risk": s.total_risk,
                "vulnerability_count": s.vulnerability_count,
                "member_count": len(s.member_risks),
            }
            for s in self.family_states.values()
        ]


__all__ = ["FamilyRiskPropagator", "FamilyRiskState"]
