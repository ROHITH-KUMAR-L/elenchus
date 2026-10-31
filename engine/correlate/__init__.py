"""Finding validation, deduplication, and correlation."""

from common.record import Finding
from engine.correlate.core import correlate
from engine.correlate.models import Issue

__all__ = ["Finding", "Issue", "correlate"]
