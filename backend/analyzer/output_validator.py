"""
Output Quality Validator — Post-analysis quality gate.
Validates every analysis result for completeness, accuracy, and specificity.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import List
from models.schemas import AnalysisResult, Severity


@dataclass
class QualityFlag:
    code: str
    message: str
    severity: str = "WARNING"  # ERROR, WARNING, INFO


@dataclass
class ValidationReport:
    passed: bool = True
    flags: List[QualityFlag] = field(default_factory=list)
    quality_score: int = 100


VAGUE_PHRASES = [
    "issue", "problem", "something", "check your", "verify your",
    "configure appropriately", "review settings",
]


class AnalysisQualityValidator:
    """Validates analysis output quality before returning to user."""

    def validate(self, result: AnalysisResult) -> ValidationReport:
        flags: List[QualityFlag] = []

        # CHECK 1: Root cause is not generic/vague
        rc_lower = result.rca.root_cause.lower()
        if any(vague in rc_lower for vague in VAGUE_PHRASES):
            if not any(specific in rc_lower for specific in ["488", "503", "401", "403", "404", "408", "codec", "srtp", "timeout"]):
                flags.append(QualityFlag("ROOT_CAUSE_VAGUE", "Root cause uses generic language", "WARNING"))

        # CHECK 2: At least one fix recommendation for failures
        if result.call_timeline.final_disposition.value in ("FAILED",) and not result.rca.recommended_fixes:
            flags.append(QualityFlag("NO_FIX", "Failed call has no fix recommendations", "WARNING"))

        # CHECK 3: Confidence not overinflated
        if result.rca.confidence > 85 and len(result.rca.contributing_factors) < 1:
            flags.append(QualityFlag("OVERCONFIDENT", "High confidence but no contributing factors cited", "WARNING"))

        # CHECK 4: Successful call not marked as failure
        if result.call_timeline.final_disposition.value == "ANSWERED":
            if "failed" in result.rca.root_cause.lower() and "quality" not in result.rca.root_cause.lower():
                flags.append(QualityFlag("FALSE_FAILURE", "Answered call incorrectly marked as failure", "ERROR"))

        # CHECK 5: Ladder data has messages
        if not result.ladder_data.messages:
            flags.append(QualityFlag("NO_LADDER", "Ladder diagram has no messages", "WARNING"))

        # CHECK 6: SDP analysis when SDP exists in trace
        has_sdp = any(m.has_sdp for m in result.ladder_data.messages)
        if has_sdp and not result.sdp_pairs:
            flags.append(QualityFlag("MISSING_SDP", "SDP found in trace but not analyzed", "WARNING"))

        # CHECK 7: At least some messages parsed
        if result.parsed_message_count == 0:
            flags.append(QualityFlag("NO_MESSAGES", "No SIP messages were parsed", "ERROR"))

        # Calculate score
        error_count = len([f for f in flags if f.severity == "ERROR"])
        warning_count = len([f for f in flags if f.severity == "WARNING"])
        score = max(0, 100 - (error_count * 25) - (warning_count * 10))

        return ValidationReport(
            passed=error_count == 0,
            flags=flags,
            quality_score=score,
        )
