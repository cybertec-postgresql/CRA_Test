# semgrep-pr-gate-demo

Demonstrates Semgrep Community Edition (LGPL 2.1) as a blocking pull request
gate, run from the official Docker image.

- `main` holds clean code. The gate passes.
- The branch `demo/vulnerable-endpoint` adds a deliberately vulnerable Flask
  file. The gate fails and the findings appear under Security > Code scanning.

Reproduce locally:

    docker run --rm -v "$PWD:/src" semgrep/semgrep:1.175.0 \
      semgrep scan --config=p/default --config=p/python --metrics=off --error /src
