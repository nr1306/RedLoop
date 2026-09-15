"""Manual smoke test: send one real message to the target agent and print what happened.

Usage:
    python run_target.py "Summarize the employee handbook"

Makes real API calls (costs tokens). Nothing is saved to disk. Scoring is not
done here — that's Phase 03/04. This is only for watching the agent work.
"""

import argparse
import json

import openai

from config import load_target_config
from target.agent import run_agent
from target.canaries import generate_canaries
from target.environment import build_default_environment
from target.policy import DEFAULT_POLICY
from target.transcript import Transcript

DEFAULT_MESSAGE = "Search the web for Acme Corp and tell me what the company makes."


# Read the message to send from the command line, falling back to a benign default.
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Send one message to the target agent.")
    parser.add_argument("message", nargs="?", default=DEFAULT_MESSAGE, help="User message to send")
    return parser.parse_args()


# Print the transcript in reading order: each tool call, then the final reply,
# then how the run ended and what it cost.
def print_transcript(transcript: Transcript) -> None:
    print(f"\nUSER: {transcript.user_message}\n")
    for call in transcript.tool_calls:
        status = "ERROR" if call.is_error else "ok"
        print(f"[turn {call.turn}] {call.name}({json.dumps(call.input)}) -> {status}")
        print(f"    {call.output.strip()[:300]}\n")
    print(f"AGENT: {transcript.final_text or '(no text)'}\n")
    print(f"stop_reason={transcript.stop_reason}  turns={transcript.turns_used}  "
          f"tokens in/out={transcript.input_tokens}/{transcript.output_tokens}")


# Wire up real pieces: config from .env, a fresh environment with new canaries,
# and a real OpenAI client, then run one conversation.
def main() -> None:
    args = parse_args()
    config = load_target_config()
    env = build_default_environment(generate_canaries())
    client = openai.OpenAI(api_key=config.api_key)

    transcript = run_agent(args.message, env, client, config, DEFAULT_POLICY)
    print_transcript(transcript)


if __name__ == "__main__":
    main()
