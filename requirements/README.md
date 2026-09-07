# Reviewed Python 3.12 dependency set

The runtime and development locks contain exact transitive versions and distribution hashes, including platform markers. They are generated with uv 0.12.5 against Python 3.12. CI and the container install the reviewed set before installing the project without dependency resolution.

Regenerate intentionally with `python -m pip install uv==0.12.5` followed by `python scripts/lock_dependencies.py`. Review both diffs, run the runtime tests, dependency audit, wheel test and container test before merging. Range-based dependency PRs do not replace this review.

`python scripts/lock_dependencies.py --check` checks normalized source and lock hashes against the reviewed manifest. A dependency-source edit without regenerating its locks fails CI. The manifest is a drift guard, not a signature or an independent security review.

For a local Python 3.12 virtual environment:

```sh
python -m pip install --require-hashes -r requirements/dev-py312.lock
python -m pip install --no-deps --no-build-isolation -e .
python -m unittest discover -s tests -v
```

Synthetic runtime tests cover initialization, login/origin/CSRF, public/private boundaries, encrypted provider-secret redaction, repeated worker ingestion, review/suppression/restore and SQLite backup recovery. They do not call external providers or establish production collection coverage. Open Domain Radar remains self-hosted alpha software, not the hosted HECAVEX Radar service.
