# Detection and scoring

Detection answers one narrow question: does an observed domain contain enough explainable evidence to become a review candidate for exactly one configured target?

## Target registry

An operator supplies a display name, reviewed aliases, optional context keywords, every known official domain under any TLD, an optional two-letter country metadata tag and a per-target minimum score. The tag provides analyst context only and does not affect matching or provider queries. The repository includes no real registry; its disabled example is fictional.

Official domains remain globally protected even when their target is disabled. This prevents a legitimate property belonging to one target from being reassigned to another.

## Evidence order

An exact alias token is strongest. An embedded alias of at least five characters is accepted conservatively. A one-edit Damerau-Levenshtein match requires an alias of at least six characters plus a suspicious or operator-supplied context term. Compound hostnames add only a small supporting increment.

Official domains and their subdomains are suppressed before scoring. A domain meeting the threshold for more than one target is rejected as ambiguous.

## Score meaning

The 0–100 score ranks deterministic matching strength. It is not a probability, maliciousness verdict, provider consensus score or risk calculation.

## False positives

Review actions append events; observations are never rewritten or deleted. Exact target-scoped suppression is the default false-positive action. A restore disables the linked suppression and re-evaluates the domain under the current registry and rules before returning it to `potential`.

Free-form detection regex is deliberately excluded because catastrophic patterns and broad substring rules create operational and false-positive risk.
