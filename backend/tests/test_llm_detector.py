"""Tests for LLM detector JSON parsing."""
from __future__ import annotations

from detection.llm_detector import _extract_json


class TestExtractJson:
    def test_plain_json(self):
        text = '{"is_injection": true, "confidence": 0.9, "explanation": "test"}'
        result = _extract_json(text)
        assert result is not None
        assert result["is_injection"] is True
        assert result["confidence"] == 0.9

    def test_fenced_json(self):
        text = '```json\n{"is_injection": false, "confidence": 0.1}\n```'
        result = _extract_json(text)
        assert result is not None
        assert result["is_injection"] is False

    def test_fenced_no_lang(self):
        text = '```\n{"is_injection": true, "confidence": 0.8}\n```'
        result = _extract_json(text)
        assert result is not None
        assert result["is_injection"] is True

    def test_preamble_text(self):
        text = 'Here is my analysis:\n\n{"is_injection": true, "confidence": 0.95, "explanation": "override"}'
        result = _extract_json(text)
        assert result is not None
        assert result["confidence"] == 0.95

    def test_missing_required_key(self):
        text = '{"is_injection": true}'  # Missing confidence
        result = _extract_json(text)
        assert result is None

    def test_invalid_json(self):
        text = "This is not JSON at all"
        result = _extract_json(text)
        assert result is None

    def test_confidence_clamped_high(self):
        text = '{"is_injection": true, "confidence": 1.5}'
        result = _extract_json(text)
        assert result is not None
        assert result["confidence"] == 1.0

    def test_confidence_clamped_low(self):
        text = '{"is_injection": false, "confidence": -0.5}'
        result = _extract_json(text)
        assert result is not None
        assert result["confidence"] == 0.0

    def test_empty_string(self):
        assert _extract_json("") is None

    def test_partial_json(self):
        text = '{"is_injection": true, "confiden'
        result = _extract_json(text)
        assert result is None
