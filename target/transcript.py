"""The complete record of one target-agent conversation.

This is the single artifact everything downstream consumes: the deterministic
scorer reads tool_calls, the LLM judge reads messages, storage and reports read
the rest. Everything in here is plain JSON-friendly data (no SDK objects) and
provider-neutral, so later phases never depend on OpenAI's response shapes.
"""

from dataclasses import dataclass, field
from typing import Any

# Normalized ways a conversation can end, independent of the provider's wording.
STOP_COMPLETED = "completed"    # model gave a final answer
STOP_REFUSAL = "refusal"        # model explicitly refused
STOP_INCOMPLETE = "incomplete"  # cut off (output token limit, content filter)
STOP_MAX_TURNS = "max_turns"    # our loop cap hit while model was still calling tools


# One tool invocation the agent made: which turn it happened on, what it asked
# for, and what the (mocked) tool returned.
@dataclass
class ToolCallRecord:
    turn: int
    call_id: str
    name: str
    input: dict[str, Any]
    output: str
    is_error: bool


# Inputs that define the run (so it can be reproduced), what happened
# (messages, tool calls, final reply), how it ended, and what it cost in tokens.
# messages is a readable projection for the judge: entries of type "message",
# "refusal", "function_call", or "function_call_output". Encrypted reasoning
# items are sent back to the API but deliberately not stored here.
@dataclass
class Transcript:
    user_message: str
    system_prompt: str
    model: str
    messages: list[dict[str, Any]] = field(default_factory=list)
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    final_text: str = ""
    stop_reason: str = ""
    turns_used: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
