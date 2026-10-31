"""Finding validation, deduplication, and correlation."""

from engine.correlate.core import correlate
from engine.correlate.models import Finding, Issue

__all__ = ["Finding", "Issue", "correlate"]
