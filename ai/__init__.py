"""Optional AI advisory side channel.

All AI is off by default (`ai.enabled`) and off in judging mode. AI never creates
or deletes a finding, sets an oracle verdict or decides a link. Every AI output is
validated against a schema, cached by content hash and capped by `ai.max_calls`.
No AI task is default-on until a with/without run shows no loss in correct links
or false alarms. Hard rules: AGENTS.md.
"""

from ai.client import AiClient
from ai.harness import ArmMeasure, HarnessResult, measure, with_without

__all__ = ["AiClient", "ArmMeasure", "HarnessResult", "measure", "with_without"]
