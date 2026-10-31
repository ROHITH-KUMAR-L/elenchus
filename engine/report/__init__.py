"""Human-readable and SARIF reporting."""

from engine.report.coverage import build_coverage_report
from engine.report.sarif import to_sarif
from engine.report.text import format_comparison, format_text

__all__ = ["build_coverage_report", "format_comparison", "format_text", "to_sarif"]
