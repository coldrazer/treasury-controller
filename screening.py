"""Counterparty screening hook.

Before cash is planned for a counterparty and again immediately before money moves, every
payee name (obligation counterparty, beneficiary company name and account holder) is
screened. A hit stops the payment and routes it to a compliance officer; the agent cannot
approve it and neither can treasury.

``ListScreener`` matches against a local list file (normalised names, legal suffixes and
punctuation ignored). Matching is by containment, not by exact equality: extra words on the
payment name ("Blackwater Shell Trading Ltd Consultants") or a shorter form of a listed
entity are still that counterparty, and a designated party rarely appears verbatim.
It is a hook, not a sanctions programme: in production, plug in your screening provider here
(and Airwallex screens its own payments).
"""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Protocol

LEGAL_SUFFIXES = {"gmbh", "ltd", "limited", "llc", "inc", "incorporated", "co", "corp", "corporation", "plc",
                  "sa", "ag", "bv", "nv", "srl", "spa", "pte", "pty", "company", "the", "and"}

# Containment only counts when the shorter name carries this many tokens: one shared word is not
# the same counterparty, or every "Alpha Trading" would screen against anything holding "trading".
MIN_CONTAINMENT_TOKENS = 2


# Targeted Unicode TR39 skeleton fold: Cyrillic and Greek letters that render identically
# to Latin ones. Without it, dropping non-ASCII deletes the letter instead of reading it,
# so "Blаckwater" (Cyrillic а) screens clear while "Blackwater" hits. Applied after
# casefold, so only the lowercase forms are needed; anything still non-ASCII after the
# fold (genuinely foreign script) is dropped as before.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "ј": "j", "ѕ": "s",
    "і": "i", "ї": "i", "һ": "h", "ԁ": "d", "ɡ": "g", "ᴡ": "w",
    "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "χ": "x", "υ": "u", "ι": "i", "κ": "k", "α": "a",
    "β": "b", "ε": "e", "η": "n", "μ": "u", "π": "n", "ω": "w", "ζ": "z",
})


def normalise(name: str) -> frozenset[str]:
    text = unicodedata.normalize("NFKD", str(name)).casefold().translate(_CONFUSABLES)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = text.replace("&", " and ")
    tokens = re.findall(r"[a-z0-9]+", text)
    return frozenset(t for t in tokens if t not in LEGAL_SUFFIXES)


def matches(candidate: frozenset[str], listed: frozenset[str]) -> bool:
    """Exact equality is the easy case. Real designations drift: a front adds a descriptor, a payment
    name drops one, so a name that CONTAINS a listed entity is that entity, and a shorter form of one
    is treated as the same counterparty too. Either way a human reviews the hit, never the agent."""
    if candidate == listed:
        return True
    shorter, longer = sorted((candidate, listed), key=len)
    return len(shorter) >= MIN_CONTAINMENT_TOKENS and shorter <= longer


@dataclass(frozen=True)
class ScreenResult:
    hit: bool
    screened: tuple[str, ...]
    matched_name: str | None
    list_entry: str | None
    list_version: str


class Screener(Protocol):
    version: str

    def screen(self, names: Iterable[str]) -> ScreenResult: ...


class ListScreener:
    def __init__(self, path: Path):
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        self.version = str(raw.get("version", "unversioned"))
        self._entries: list[tuple[frozenset[str], str]] = []
        for entry in raw.get("entries", []):
            for name in [entry["name"], *entry.get("aliases", [])]:
                tokens = normalise(name)
                if tokens:
                    self._entries.append((tokens, entry["name"]))

    def screen(self, names: Iterable[str]) -> ScreenResult:
        screened = tuple(n for n in dict.fromkeys(names) if n)
        for name in screened:
            tokens = normalise(name)
            for listed, label in self._entries:
                if tokens and matches(tokens, listed):
                    return ScreenResult(True, screened, name, label, self.version)
        return ScreenResult(False, screened, None, None, self.version)
