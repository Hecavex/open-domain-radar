from __future__ import annotations

from open_domain_radar.matching import bounded_levenshtein, match_domain
from open_domain_radar.models import Suppression, WatchTarget


def target(identifier: int, name: str, aliases: list[str], official: list[str] | None = None) -> WatchTarget:
    return WatchTarget(
        id=identifier, name=name, aliases=aliases, official_domains=official or [], minimum_score=65, enabled=True
    )


def test_official_domains_and_subdomains_are_never_candidates() -> None:
    watched = target(1, "Example Bank", ["examplebank"], ["examplebank.com"])
    assert not match_domain("examplebank.com", [watched]).accepted
    assert not match_domain("login.examplebank.com", [watched]).accepted


def test_exact_alias_with_suspicious_context_is_accepted() -> None:
    watched = target(1, "Example Bank", ["examplebank"])
    decision = match_domain("secure-examplebank-login.test", [watched])
    assert decision.accepted
    assert decision.target_id == 1
    assert decision.score >= 80
    assert "suspicious_context" in decision.reasons


def test_two_edit_cross_brand_name_is_not_fuzzy_matched() -> None:
    watched = target(1, "Acme Bank", ["acmebank"])
    decision = match_domain("secure-acnebonk-login.test", [watched])
    assert not decision.accepted
    assert decision.rejected_reason == "no_conservative_match"


def test_one_edit_requires_suspicious_context() -> None:
    watched = target(1, "Example", ["example"])
    assert not match_domain("exampel.test", [watched]).accepted
    assert match_domain("login-exampel.test", [watched]).accepted


def test_near_tied_targets_are_rejected_as_ambiguous() -> None:
    targets = [target(1, "Acme North", ["acme"]), target(2, "Acme South", ["acme"])]
    decision = match_domain("acme-login.test", targets)
    assert not decision.accepted
    assert decision.rejected_reason == "ambiguous_target"


def test_every_multi_target_match_is_rejected_even_with_score_gap() -> None:
    precise = target(1, "Example Exact", ["example"])
    broader = target(2, "Example Fuzzy", ["examplf"])
    broader.minimum_score = 55
    decision = match_domain("secure-example.test", [precise, broader])
    assert not decision.accepted
    assert decision.rejected_reason == "ambiguous_target"


def test_official_domain_is_global_even_when_its_target_is_disabled() -> None:
    northbank = target(1, "Northbank", ["northbank"])
    southbank = target(2, "Southbank", ["southbank"], ["southbank.example"])
    southbank.enabled = False
    decision = match_domain("northbank.southbank.example", [northbank, southbank])
    assert not decision.accepted
    assert decision.rejected_reason == "official_domain"


def test_suppression_can_be_global_or_target_scoped() -> None:
    watched = target(1, "Example", ["example"])
    suppression = Suppression(pattern="example-login.test", match_type="exact", target_id=1, enabled=True)
    assert not match_domain("example-login.test", [watched], [suppression]).accepted


def test_bounded_levenshtein_stops_beyond_limit() -> None:
    assert bounded_levenshtein("example", "exampel", 1) == 1
    assert bounded_levenshtein("example", "examplf", 1) == 1
