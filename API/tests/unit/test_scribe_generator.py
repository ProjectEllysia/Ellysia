"""Unit tests for the Scribe payload-size guardrail (Issue #118).

Covers the heuristic token estimate (``estimate_tokens`` / ``AIInput.estimated_tokens``)
and ``AIGenerator``'s pre-flight check: an oversized prompt must be rejected
with ``AIPayloadTooLargeError`` *before* the strategy is ever called, and
without burning a retry.
"""

import pytest

import src.modules.system.config_reading as CR
from src.modules.tools.scribe import AIInput, AIGenerator, AIPayloadTooLargeError, estimate_tokens
from src.modules.tools.scribe.inputs import Example

pytestmark = pytest.mark.unit


# --------------------------------------------------------------- estimate_tokens

def test_estimate_tokens_roughly_four_chars_per_token():
    assert estimate_tokens("a" * 400) == 100


def test_estimate_tokens_empty_string_is_zero():
    assert estimate_tokens("") == 0


def test_estimate_tokens_rounds_up_partial_token():
    assert estimate_tokens("abc") == 1  # 3 chars, 1 token, not 0


# ------------------------------------------------------- AIInput.estimated_tokens

def test_ai_input_estimated_tokens_sums_all_messages():
    ai_input = AIInput(system_prompt="s" * 40, user_prompt="u" * 40)
    # system + user = 80 chars = 20 tokens
    assert ai_input.estimated_tokens() == 20


def test_ai_input_estimated_tokens_includes_examples():
    ai_input = AIInput(
        system_prompt="s" * 40,
        user_prompt="u" * 40,
        examples=[Example(user="e" * 40, assistant="a" * 40)],
    )
    # 40*4 chars = 160 chars = 40 tokens
    assert ai_input.estimated_tokens() == 40


# ------------------------------------------------------------------ AIGenerator

class _FakeStrategy:
    """A strategy stub that records whether it was ever called."""

    name = "fake"

    def __init__(self, response: str = "ok"):
        self._response = response
        self.calls = 0

    def complete(self, ai_input, tool_executor=None):
        self.calls += 1
        return self._response


def test_digest_rejects_oversized_prompt_without_calling_strategy(monkeypatch):
    monkeypatch.setattr(CR, "scribe_config", lambda: CR.ScribeConfig(max_input_tokens=10))
    strategy = _FakeStrategy()
    generator = AIGenerator(strategy)
    ai_input = AIInput(system_prompt="x" * 1000, user_prompt="y")  # far over 10 tokens

    with pytest.raises(AIPayloadTooLargeError):
        generator.digest(ai_input)

    assert strategy.calls == 0  # never reached the backend — no wasted retry


def test_digest_allows_prompt_within_limit(monkeypatch):
    monkeypatch.setattr(CR, "scribe_config", lambda: CR.ScribeConfig(max_input_tokens=1000))
    strategy = _FakeStrategy(response="respuesta")
    generator = AIGenerator(strategy)
    ai_input = AIInput(system_prompt="hola", user_prompt="mundo")

    result = generator.digest(ai_input)

    assert result.text == "respuesta"
    assert strategy.calls == 1


def test_ai_payload_too_large_error_is_not_retried(monkeypatch):
    """Distinguishes the size guardrail from a normal transient failure: a
    normal exception is retried up to max_retries times, but a payload that's
    too large must fail on the very first check, every time, so retrying it
    would be pure waste."""
    monkeypatch.setattr(CR, "scribe_config", lambda: CR.ScribeConfig(max_input_tokens=1))
    strategy = _FakeStrategy()
    generator = AIGenerator(strategy, max_retries=3)
    ai_input = AIInput(system_prompt="way too long for the limit", user_prompt="y")

    with pytest.raises(AIPayloadTooLargeError):
        generator.digest(ai_input)

    assert strategy.calls == 0
