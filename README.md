# CRA_Test

Control test for a Semgrep Community Edition (LGPL 2.1) pull request gate.

> **Warning**
> The branch `demo/vulnerable-endpoint` contains **deliberately vulnerable code**.
> It is a test fixture, not a component. Nothing here is deployed or importable
> by any Cybertec system. Do not copy from it.

## What this proves

| Branch | Findings | Exit | Gate |
|---|---|---|---|
| `main` | 0 | 0 | passes |
| `demo/vulnerable-endpoint` | 9 | 1 | fails, merge blocked |

The negative control matters as much as the positive one: a gate that has only
ever passed has never been tested.

## The gate

`.github/workflows/semgrep.yml` runs Semgrep CE from the pinned official image,
uploads SARIF to GitHub code scanning on every run (`if: always()`, so evidence
survives a red build), then fails the pull request if anything was found.

## Reproduce locally

    docker run --rm -v "$PWD:/src" semgrep/semgrep:1.175.0 \
      semgrep scan --config=p/default --config=p/python --metrics=off --error /src

## Known coverage gap

Hardcoded secrets are **not** detected by Semgrep CE. Semantic secret detection
is part of the paid Semgrep Secrets product. Pair this gate with gitleaks before
treating secret exposure as covered.
