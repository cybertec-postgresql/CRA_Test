# CRA_Test

Control test for a Semgrep Community Edition (LGPL 2.1) pull request gate.

`main` is clean: the gate passes here with 0 findings. The branch
`demo/vulnerable-endpoint` adds a **deliberately vulnerable test fixture** so the
gate has something to catch, and fails with 9 findings.

## Reproduce locally

    docker run --rm -v "$PWD:/src" semgrep/semgrep:1.175.0 \
      semgrep scan --config=p/default --config=p/python --metrics=off --error /src
