"""Plain-language notes for the human approver on exceptions.

Fixed decisions are explained by the rule text written in ``policy.py``; the
model is used only to explain *exceptions* (escalations and approval gates).
Its note is display-only: it is never parsed back into amounts or decisions,
and it is discarded in favour of the deterministic template if it mentions any
figure that is not in the facts it was given.
"""
from __future__ import annotations

import json
import re
from decimal import Decimal, InvalidOperation
from typing import Mapping

from llm import LLMClient, LLMError
from models import clean_text

SYSTEM = """You write short notes for a human who must approve or reject a treasury action.
Write 2-3 plain sentences: what is being asked, why the system stopped for a human, and what
the evidence says. Use only the facts provided. Do not recommend approving or rejecting.
Do not introduce any number that is not in the facts."""

_NUM = re.compile(r"\d[\d,]*(?:\.\d+)?(?: ?(?:bn|b|m|k))?", re.IGNORECASE)
# "12 000" and "1 000 000" are single amounts written with spaces. Joining them before reading the
# numerals is what closes the grouping hole: tokenised as they come, "12" and "000" looked harmless.
_GROUPED = re.compile(r"(?<=\d)[ \u00a0]+(?=\d{3}(?:\D|$))")
_SCALE = {"k": Decimal(1000), "m": Decimal(1000000), "b": Decimal(1000000000)}


def _as_decimal(token: str) -> Decimal | None:
    text = token.replace(",", "").replace(" ", "")
    scale = Decimal(1)
    for suffix, factor in (("bn", _SCALE["b"]), ("b", _SCALE["b"]), ("m", _SCALE["m"]), ("k", _SCALE["k"])):
        if text.lower().endswith(suffix):
            text, scale = text[:-len(suffix)], factor
            break
    try:
        return Decimal(text) * scale
    except InvalidOperation:
        return None


def _numbers(text: str) -> set[Decimal]:
    out = set()
    for raw in _NUM.findall(_GROUPED.sub("", text)):
        value = _as_decimal(raw)
        if value is not None:
            out.add(value)
    return out


def numbers_grounded(note: str, facts: Mapping) -> bool:
    """Every figure in the note must be a figure the code wrote into the facts. Small integers get
    no exemption: read without normalisation, "1 000 000" is two harmless-looking numbers. What the
    rule costs is only that an ungrounded note falls back to the deterministic template."""
    return _numbers(note) <= _numbers(json.dumps(facts, default=str))


def template_note(facts: Mapping) -> str:
    return " ".join(str(facts[k]) for k in ("ask", "why", "evidence_summary") if facts.get(k))


class Explainer:
    def __init__(self, llm: LLMClient | None):
        self.llm = llm

    def explain(self, facts: Mapping) -> tuple[str, str]:
        """Returns (note, source) where source is the model name or 'template'."""
        fallback = template_note(facts)
        if self.llm is None:
            return fallback, "template"
        try:
            note = clean_text(self.llm.complete(system=SYSTEM, user=json.dumps(facts, indent=2, default=str),
                                                max_tokens=220), single_line=True)
        except LLMError:
            return fallback, "template (model unavailable)"
        if not note or len(note) > 900 or not numbers_grounded(note, facts):
            return fallback, "template (model note rejected)"
        return note, self.llm.name
