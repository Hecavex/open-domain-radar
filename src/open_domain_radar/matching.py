"""Conservative, explainable watch-target matching."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from datetime import UTC, datetime

from .models import Suppression, WatchTarget
from .security import normalize_domain

SUSPICIOUS_TERMS = frozenset(
    {
        "account",
        "auth",
        "billing",
        "confirm",
        "helpdesk",
        "login",
        "pay",
        "payment",
        "portal",
        "recover",
        "secure",
        "signin",
        "support",
        "update",
        "verify",
        "wallet",
    }
)


@dataclass(frozen=True, slots=True)
class MatchDecision:
    """Explain whether one domain belongs to exactly one watch target."""

    target_id: int | None
    target_name: str | None
    score: int
    reasons: tuple[str, ...]
    rejected_reason: str | None = None

    @property
    def accepted(self) -> bool:
        return self.target_id is not None


def match_domain(
    domain: str,
    targets: list[WatchTarget],
    suppressions: list[Suppression] | None = None,
) -> MatchDecision:
    """Match a normalized domain using conservative, target-scoped rules.

    A domain is accepted only when exactly one enabled target reaches its own
    score threshold. Returning no match is safer than assigning ambiguous CTI
    to the wrong organization.
    """
    host = normalize_domain(domain)
    current_suppressions = [item for item in (suppressions or []) if _suppression_active(item)]

    global_suppressions = [item for item in current_suppressions if item.target_id is None]
    if any(_suppression_matches(host, item) for item in global_suppressions):
        return MatchDecision(None, None, 0, (), "global_suppression")

    if _belongs_to_any_official_domain(host, targets):
        return MatchDecision(None, None, 0, (), "official_domain")

    ranked: list[tuple[int, WatchTarget, tuple[str, ...]]] = []
    for target in targets:
        if not target.enabled:
            continue

        target_suppressions = [item for item in current_suppressions if item.target_id == target.id]
        if any(_suppression_matches(host, item) for item in target_suppressions):
            continue

        score, reasons = _score_target(host, target)
        if score >= target.minimum_score:
            ranked.append((score, target, tuple(reasons)))

    if not ranked:
        return MatchDecision(None, None, 0, (), "no_conservative_match")

    ranked.sort(key=lambda item: (-item[0], item[1].id))
    best_score, best_target, best_reasons = ranked[0]
    if len(ranked) > 1:
        # Even a large score gap can hide a shared alias or a poorly scoped
        # watchlist. An analyst should fix that ambiguity instead of the code
        # silently choosing a brand.
        return MatchDecision(None, None, best_score, best_reasons, "ambiguous_target")
    return MatchDecision(best_target.id, best_target.name, best_score, best_reasons)


def _score_target(host: str, target: WatchTarget) -> tuple[int, list[str]]:
    # Certificate names can contain several subdomain labels. The last label is
    # treated as the public suffix hint and is not useful brand evidence.
    name_part = ".".join(host.split(".")[:-1])
    labels = re.findall(r"[a-z0-9]+", name_part)
    compact_labels = "".join(labels)
    target_terms = _normalized_terms(target.keywords or [])
    has_suspicious_context = bool(set(labels) & (SUSPICIOUS_TERMS | target_terms))
    best_score = 0
    best_reasons: list[str] = []

    aliases = {target.name, *target.aliases}
    for raw_alias in aliases:
        alias = _compact_text(raw_alias)
        if len(alias) < 3:
            continue

        score = 0
        reasons: list[str] = []
        if alias in labels:
            score = 72 if len(alias) >= 5 else 60
            reasons.append("alias_exact_label")
        elif alias in compact_labels and len(alias) >= 5:
            score = 66
            reasons.append("alias_embedded")
        elif len(alias) >= 6 and has_suspicious_context and _has_one_edit_alias(alias, labels):
            # Fuzzy matching is deliberately narrow: one edit, a reasonably
            # long alias, and phishing-related context must all be present.
            score = 58
            reasons.extend(("alias_one_edit", "suspicious_context"))

        if has_suspicious_context and score:
            score += 14
            if "suspicious_context" not in reasons:
                reasons.append("suspicious_context")
        if score and ("-" in name_part or len(labels) >= 2):
            score += 4
            reasons.append("compound_hostname")
        if score > best_score:
            best_score = min(score, 100)
            best_reasons = reasons
    return best_score, best_reasons


def _compact_text(value: str) -> str:
    return "".join(re.findall(r"[a-z0-9]+", value.lower()))


def _normalized_terms(values: list[str]) -> set[str]:
    return {term for value in values if (term := _compact_text(value))}


def _has_one_edit_alias(alias: str, labels: list[str]) -> bool:
    possible_labels = [label for label in labels if abs(len(label) - len(alias)) <= 1]
    return any(bounded_levenshtein(alias, label, 1) <= 1 for label in possible_labels)


def bounded_levenshtein(left: str, right: str, maximum: int) -> int:
    """Return edit distance up to ``maximum``, counting an adjacent swap once.

    Values beyond the requested bound return ``maximum + 1``. This early exit
    keeps fuzzy matching cheap while CertStream is producing many names.
    """
    if abs(len(left) - len(right)) > maximum:
        return maximum + 1
    previous_previous: list[int] | None = None
    previous = list(range(len(right) + 1))
    for row, left_char in enumerate(left, 1):
        current = [row]
        row_min = current[0]
        for column, right_char in enumerate(right, 1):
            distance = min(
                current[column - 1] + 1,
                previous[column] + 1,
                previous[column - 1] + (left_char != right_char),
            )
            if (
                previous_previous is not None
                and row > 1
                and column > 1
                and left_char == right[column - 2]
                and left[row - 2] == right_char
            ):
                distance = min(distance, previous_previous[column - 2] + 1)
            current.append(distance)
            row_min = min(row_min, current[-1])
        if row_min > maximum:
            return maximum + 1
        previous_previous = previous
        previous = current
    return previous[-1]


def _is_domain_or_subdomain(host: str, domain: str) -> bool:
    try:
        official = normalize_domain(domain)
    except ValueError:
        return False
    return host == official or host.endswith(f".{official}")


def _belongs_to_any_official_domain(host: str, targets: list[WatchTarget]) -> bool:
    # Official properties are a global allow boundary, including properties of
    # disabled targets. They must never be reassigned through a similar alias.
    return any(
        _is_domain_or_subdomain(host, official_domain)
        for target in targets
        for official_domain in target.official_domains
    )


def _suppression_active(item: Suppression) -> bool:
    if not item.enabled:
        return False
    if item.expires_at is None:
        return True
    expiry = item.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=UTC)
    return expiry > datetime.now(UTC)


def _suppression_matches(host: str, item: Suppression) -> bool:
    pattern = item.pattern.lower().strip().rstrip(".")
    if item.match_type == "exact":
        return host == pattern
    if item.match_type == "suffix":
        return host == pattern or host.endswith(f".{pattern}")
    if item.match_type == "glob" and len(pattern) <= 253:
        return fnmatch.fnmatchcase(host, pattern)
    return False
