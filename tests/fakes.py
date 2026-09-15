"""Test doubles for the OpenAI client, so the agent loop can be tested with no API calls."""

import json
from typing import Any

from openai.types.responses import (
    Response,
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputRefusal,
    ResponseOutputText,
    ResponseReasoningItem,
    ResponseUsage,
)


# Build a real SDK Response object with the given output items and status.
# model_construct skips validation (as the SDK does when parsing real responses),
# so tests only need to fill in the fields the agent actually reads.
def make_response(
    output: list[Any], status: str = "completed", input_tokens: int = 10, output_tokens: int = 5
) -> Response:
    return Response.model_construct(
        id="resp_test",
        object="response",
        model="test-model",
        status=status,
        output=output,
        usage=ResponseUsage.model_construct(input_tokens=input_tokens, output_tokens=output_tokens),
    )


# Shorthands for the output item types the target's responses contain.
def text(value: str) -> ResponseOutputMessage:
    return ResponseOutputMessage.model_construct(
        id="msg_test", type="message", role="assistant", status="completed",
        content=[ResponseOutputText.model_construct(type="output_text", text=value, annotations=[])],
    )


def refusal(value: str) -> ResponseOutputMessage:
    return ResponseOutputMessage.model_construct(
        id="msg_test", type="message", role="assistant", status="completed",
        content=[ResponseOutputRefusal.model_construct(type="refusal", refusal=value)],
    )


# arguments is serialized to a JSON string, as the real API sends it.
# Pass raw_arguments to simulate malformed JSON.
def function_call(
    call_id: str, name: str, arguments: dict[str, Any] | None = None, raw_arguments: str | None = None
) -> ResponseFunctionToolCall:
    return ResponseFunctionToolCall.model_construct(
        type="function_call", id=f"fc_{call_id}", call_id=call_id, name=name, status="completed",
        arguments=raw_arguments if raw_arguments is not None else json.dumps(arguments or {}),
    )


def reasoning(encrypted: str = "opaque-blob") -> ResponseReasoningItem:
    return ResponseReasoningItem.model_construct(
        type="reasoning", id="rs_test", summary=[], encrypted_content=encrypted,
    )


# Stand-in for openai.OpenAI. Returns scripted responses in order and records
# every request. input is copied at call time because the agent keeps
# appending to the same list after the call returns.
class FakeClient:
    def __init__(self, responses: list[Response]) -> None:
        self._responses = list(responses)
        self.requests: list[dict[str, Any]] = []

    # Mimics the client.responses.create(...) call path.
    @property
    def responses(self) -> "FakeClient":
        return self

    def create(self, **kwargs: Any) -> Response:
        self.requests.append({**kwargs, "input": list(kwargs["input"])})
        if not self._responses:
            raise AssertionError("FakeClient ran out of scripted responses")
        return self._responses.pop(0)
