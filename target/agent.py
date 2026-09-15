"""The target agent's ReAct loop on the OpenAI Responses API: call the model, run
any tools it asks for, repeat.

The OpenAI client is passed in rather than created here, so tests can supply
a fake client with scripted responses and exercise the loop with no API calls.
"""

import json
from typing import Any

import openai

from config import TargetConfig
from target.environment import FakeEnvironment
from target.policy import Policy, build_system_prompt
from target.tools import TOOL_DEFINITIONS, ToolResult, execute_tool
from target.transcript import (
    STOP_COMPLETED,
    STOP_INCOMPLETE,
    STOP_MAX_TURNS,
    STOP_REFUSAL,
    ToolCallRecord,
    Transcript,
)

MAX_OUTPUT_TOKENS_PER_CALL = 16000


# Run one single-message conversation against the target and return its transcript.
def run_agent(
    user_message: str,
    env: FakeEnvironment,
    client: openai.OpenAI,
    config: TargetConfig,
    policy: Policy,
) -> Transcript:
    system_prompt = build_system_prompt(policy)
    transcript = Transcript(user_message=user_message, system_prompt=system_prompt, model=config.model)
    transcript.messages.append({"type": "message", "role": "user", "text": user_message})

    # Two separate histories: input_items is replayed verbatim to the API each
    # turn (including encrypted reasoning); transcript.messages is the readable copy.
    input_items: list[dict[str, Any]] = [{"role": "user", "content": user_message}]

    for turn in range(1, config.max_turns + 1):
        # Ask the model for its next step. store=False keeps transcripts (which
        # contain canaries) off OpenAI's servers; because nothing is stored, we
        # request encrypted reasoning so we can send it back ourselves.
        response = client.responses.create(
            model=config.model,
            instructions=system_prompt,
            input=input_items,
            tools=TOOL_DEFINITIONS,
            max_output_tokens=MAX_OUTPUT_TOKENS_PER_CALL,
            store=False,
            include=["reasoning.encrypted_content"],
        )
        transcript.turns_used = turn
        if response.usage is not None:
            transcript.input_tokens += response.usage.input_tokens
            transcript.output_tokens += response.usage.output_tokens

        # Replay every output item (reasoning, text, function calls) next turn,
        # in order, and add the readable parts to the transcript.
        input_items.extend(item.model_dump(exclude={"status"}) for item in response.output)
        _record_output(response.output, transcript)

        # Model wants tools: run each call, append one function_call_output per
        # call (matched by call_id), and go around the loop again.
        function_calls = [item for item in response.output if item.type == "function_call"]
        if function_calls:
            input_items.extend(_run_tool_calls(function_calls, turn, env, transcript))
            continue

        # No tool calls means the model is done (answered, refused, or was cut off).
        transcript.final_text = _extract_text(response.output)
        transcript.stop_reason = _stop_reason(response)
        break
    else:
        # for-else: runs only if the loop finished without `break`,
        # i.e. the model was still calling tools when we ran out of turns.
        transcript.stop_reason = STOP_MAX_TURNS

    return transcript


# Execute each function_call, record it on the transcript, and build the
# function_call_output items the API expects next turn.
def _run_tool_calls(
    function_calls: list[Any], turn: int, env: FakeEnvironment, transcript: Transcript
) -> list[dict[str, Any]]:
    outputs: list[dict[str, Any]] = []
    for call in function_calls:
        # arguments arrive as a JSON string; unparseable ones become an error result.
        arguments = _parse_arguments(call.arguments)
        if arguments is None:
            result = ToolResult("Error: tool arguments were not valid JSON", is_error=True)
            recorded_input: dict[str, Any] = {"_raw_arguments": call.arguments}
        else:
            result = execute_tool(call.name, arguments, env)
            recorded_input = arguments

        transcript.tool_calls.append(
            ToolCallRecord(
                turn=turn,
                call_id=call.call_id,
                name=call.name,
                input=recorded_input,
                output=result.output,
                is_error=result.is_error,
            )
        )
        transcript.messages.append({"type": "function_call_output", "call_id": call.call_id, "output": result.output})
        outputs.append({"type": "function_call_output", "call_id": call.call_id, "output": result.output})
    return outputs


# Parse a JSON arguments string into a dict, or None if it isn't a JSON object.
def _parse_arguments(raw: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


# Add the human-readable parts of one response to transcript.messages.
# Reasoning items are skipped: they're encrypted and only useful to the API.
def _record_output(output: list[Any], transcript: Transcript) -> None:
    for item in output:
        if item.type == "message":
            for part in item.content:
                if part.type == "output_text":
                    transcript.messages.append({"type": "message", "role": "assistant", "text": part.text})
                elif part.type == "refusal":
                    transcript.messages.append({"type": "refusal", "role": "assistant", "text": part.refusal})
        elif item.type == "function_call":
            transcript.messages.append(
                {"type": "function_call", "call_id": item.call_id, "name": item.name, "arguments": item.arguments}
            )


# Join all output_text parts of a response into the agent's visible reply.
def _extract_text(output: list[Any]) -> str:
    return "\n".join(
        part.text
        for item in output if item.type == "message"
        for part in item.content if part.type == "output_text"
    )


# Map the provider's ending into our normalized stop reasons. A refusal is
# reported inside message content, not in status, so check for it first.
def _stop_reason(response: Any) -> str:
    refused = any(
        part.type == "refusal"
        for item in response.output if item.type == "message"
        for part in item.content
    )
    if refused:
        return STOP_REFUSAL
    if response.status == "completed":
        return STOP_COMPLETED
    return STOP_INCOMPLETE
