"""Finding validation, deduplication, and correlation."""

from engine.correlate.core import correlate
from common.record import Finding
from engine.correlate.models import Issue

__all__ = ["Finding", "Issue", "correlate"]
