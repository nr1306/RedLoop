"""Tests for the target agent loop, driven by a scripted FakeClient (no API calls)."""

import json

from config import TargetConfig
from target.agent import run_agent
from target.canaries import Canaries
from target.environment import FakeEnvironment
from target.policy import DEFAULT_POLICY
from target.tools import TOOL_DEFINITIONS
from target.transcript import STOP_COMPLETED, STOP_INCOMPLETE, STOP_MAX_TURNS, STOP_REFUSAL
from tests.fakes import FakeClient, function_call, make_response, reasoning, refusal, text


# Model answers straight away: one turn, no tools, reply captured.
def test_direct_answer(env: FakeEnvironment, config: TargetConfig) -> None:
    client = FakeClient([make_response([text("Office hours are 9-5.")])])
    transcript = run_agent("When is the office open?", env, client, config, DEFAULT_POLICY)

    assert transcript.final_text == "Office hours are 9-5."
    assert transcript.stop_reason == STOP_COMPLETED
    assert transcript.turns_used == 1
    assert transcript.tool_calls == []


# The request carries the policy as instructions, the tools, the model, and
# storage disabled (transcripts contain canaries).
def test_request_parameters(env: FakeEnvironment, config: TargetConfig) -> None:
    client = FakeClient([make_response([text("hi")])])
    transcript = run_agent("hello", env, client, config, DEFAULT_POLICY)

    request = client.requests[0]
    assert request["instructions"] == transcript.system_prompt
    assert request["tools"] == TOOL_DEFINITIONS
    assert request["model"] == config.model
    assert request["store"] is False
    assert request["input"] == [{"role": "user", "content": "hello"}]


# Tool call then answer: call is recorded, output is fed back with matching call_id.
def test_tool_call_then_answer(env: FakeEnvironment, config: TargetConfig, canaries: Canaries) -> None:
    client = FakeClient([
        make_response([function_call("c1", "read_file", {"path": "/secrets/db.env"})]),
        make_response([text("Done.")]),
    ])
    transcript = run_agent("read the db config", env, client, config, DEFAULT_POLICY)

    assert transcript.turns_used == 2
    assert transcript.final_text == "Done."
    [call] = transcript.tool_calls
    assert (call.turn, call.call_id, call.name, call.input) == (1, "c1", "read_file", {"path": "/secrets/db.env"})
    assert canaries.db_password in call.output

    # Second request input: user message, the replayed function_call, then its output.
    second_input = client.requests[1]["input"]
    assert [item.get("type", "message") for item in second_input] == ["message", "function_call", "function_call_output"]
    assert second_input[2]["call_id"] == "c1"
    assert canaries.db_password in second_input[2]["output"]


# Several calls in one response: each gets its own function_call_output, in order.
def test_parallel_tool_calls(env: FakeEnvironment, config: TargetConfig) -> None:
    client = FakeClient([
        make_response([
            function_call("c1", "read_file", {"path": "/public/faq.md"}),
            function_call("c2", "read_file", {"path": "/public/handbook.md"}),
        ]),
        make_response([text("Summary.")]),
    ])
    transcript = run_agent("summarize docs", env, client, config, DEFAULT_POLICY)

    assert [c.call_id for c in transcript.tool_calls] == ["c1", "c2"]
    outputs = [i for i in client.requests[1]["input"] if i.get("type") == "function_call_output"]
    assert [o["call_id"] for o in outputs] == ["c1", "c2"]


# Reasoning items must be replayed to the API but kept out of the readable transcript.
def test_reasoning_is_replayed_but_not_stored(env: FakeEnvironment, config: TargetConfig) -> None:
    client = FakeClient([
        make_response([reasoning("secret-blob"), function_call("c1", "search_web", {"query": "acme"})]),
        make_response([text("ok")]),
    ])
    transcript = run_agent("search", env, client, config, DEFAULT_POLICY)

    replayed_types = [item.get("type") for item in client.requests[1]["input"]]
    assert "reasoning" in replayed_types
    assert "secret-blob" not in json.dumps(transcript.messages)


# Tool errors reach the model as error text instead of crashing the loop.
def test_tool_error_is_passed_to_model(env: FakeEnvironment, config: TargetConfig) -> None:
    client = FakeClient([
        make_response([function_call("c1", "read_file", {"path": "/public/missing.md"})]),
        make_response([text("File not found.")]),
    ])
    transcript = run_agent("read it", env, client, config, DEFAULT_POLICY)

    assert transcript.tool_calls[0].is_error
    output_item = client.requests[1]["input"][-1]
    assert output_item["output"].startswith("Error")


# Malformed JSON arguments become an error result, with the raw string preserved.
def test_invalid_json_arguments(env: FakeEnvironment, config: TargetConfig) -> None:
    client = FakeClient([
        make_response([function_call("c1", "read_file", raw_arguments='{"path": ')]),
        make_response([text("Sorry.")]),
    ])
    transcript = run_agent("read", env, client, config, DEFAULT_POLICY)

    [call] = transcript.tool_calls
    assert call.is_error
    assert call.input == {"_raw_arguments": '{"path": '}


# A model that never stops calling tools is cut off at max_turns.
def test_max_turns_cap(env: FakeEnvironment, config: TargetConfig) -> None:
    looping = [
        make_response([function_call(f"c{i}", "search_web", {"query": "acme"})])
        for i in range(config.max_turns)
    ]
    client = FakeClient(looping)
    transcript = run_agent("keep searching", env, client, config, DEFAULT_POLICY)

    assert transcript.stop_reason == STOP_MAX_TURNS
    assert transcript.turns_used == config.max_turns
    assert len(client.requests) == config.max_turns
    assert transcript.final_text == ""


# A refusal ends the run, is labelled as such, and its text is kept for the judge.
def test_refusal_is_recorded(env: FakeEnvironment, config: TargetConfig) -> None:
    client = FakeClient([make_response([refusal("I can't help with that.")])])
    transcript = run_agent("something bad", env, client, config, DEFAULT_POLICY)

    assert transcript.stop_reason == STOP_REFUSAL
    assert transcript.final_text == ""
    assert transcript.messages[-1] == {"type": "refusal", "role": "assistant", "text": "I can't help with that."}


# A response cut off by the provider is labelled incomplete.
def test_incomplete_response(env: FakeEnvironment, config: TargetConfig) -> None:
    client = FakeClient([make_response([text("partial")], status="incomplete")])
    transcript = run_agent("long task", env, client, config, DEFAULT_POLICY)

    assert transcript.stop_reason == STOP_INCOMPLETE
    assert transcript.final_text == "partial"


# Tokens accumulate across every call in the conversation.
def test_token_usage_accumulates(env: FakeEnvironment, config: TargetConfig) -> None:
    client = FakeClient([
        make_response([function_call("c1", "search_web", {"query": "acme"})], input_tokens=100, output_tokens=20),
        make_response([text("ok")], input_tokens=150, output_tokens=30),
    ])
    transcript = run_agent("search", env, client, config, DEFAULT_POLICY)

    assert (transcript.input_tokens, transcript.output_tokens) == (250, 50)


# The readable transcript is plain JSON in conversation order.
def test_messages_are_readable_json(env: FakeEnvironment, config: TargetConfig) -> None:
    client = FakeClient([
        make_response([text("Looking."), function_call("c1", "read_file", {"path": "/public/faq.md"})]),
        make_response([text("Here it is.")]),
    ])
    transcript = run_agent("faq?", env, client, config, DEFAULT_POLICY)

    json.dumps(transcript.messages)
    assert [m["type"] for m in transcript.messages] == [
        "message", "message", "function_call", "function_call_output", "message",
    ]
