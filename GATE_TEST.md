# Gate test record

The record of the last end to end test of the two gates. Kept in the
repository because it is the evidence that the control works, not a
description of how it should. Re-run and replace when a gate changes.

| | |
|---|---|
| Date | 7 September 2026 |
| Repository | cybertec-postgresql/CRA_Test, branch `feat/gate1-secrets-cves` then `demo/local-gate-test` |
| Dev A, author | Claude, driving a fresh clone at `~/Desktop/CRA_Test` |
| Dev B, reviewer | to be recorded on the pull request |
| Manager | Bhupender Verma, CRA and IT manager |
| Tools | gitleaks v8.30.1, OSV-Scanner v2.5.1, Semgrep CE 1.175.0, all from pinned container images |

## What was planted

One commit on a branch with three deliberate problems:

1. `requirements.txt`: `requests==2.31.0`. Carries GHSA-9wx4-h78v-vm56
   (CVE-2024-35195, CVSS 5.6), GHSA-9hjg-9r4m-mvj7 (CVSS 5.3) and
   GHSA-gc5v-m9x4-r6x2 (CVSS 5.5). All medium, all P3.
2. `app/config.py`: an AWS format access key id. Synthetic, generated for the
   test, never a real credential. It matches the gitleaks `aws-access-token`
   rule and is not on the AWS documentation example allowlist, so the check
   had to work for real. It is never printed unredacted, here or in any log.
3. `app/upstream.py`: `requests.get(url, verify=False)`.

No SQL injection fixture, by decision recorded in INCIDENTS.md.

## Gate 1, the pre-push hook

Run in a scratch clone with a local bare repository as `origin`, so nothing
reached GitHub while the hook itself was being proven.

### Attempt 1: the test found a bug in the gate

The first version of the hook built the gitleaks revision range with a
leading space. gitleaks received an empty argument, git failed, and gitleaks
still exited 0 with "no leaks found". The secrets check showed **PASS** on a
commit that contained a key.

Fix: the hook now enumerates the range with `git rev-list` before calling
gitleaks and refuses the push if that fails. A check that has never failed has
never been tested; this one had to fail once to be trusted.

### Attempt 2: refused, all three checks

```
1 new commit(s) to scan
9:33AM INF Unknown SCM platform. Use --platform to include links in findings. host=
9:33AM INF 1 commits scanned.
9:33AM INF scanned ~314 bytes (314 bytes) in 60.9ms
9:33AM WRN leaks found: 1
```

```
Total 2 packages affected by 4 known vulnerabilities (0 Critical, 0 High, 4 Medium, 0 Low, 0 Unknown) from 1 ecosystem.
4 vulnerabilities can be fixed.
+-------------------------------------+------+-----------+----------+---------+---------------+------------------+
| OSV URL                             | CVSS | ECOSYSTEM | PACKAGE  | VERSION | FIXED VERSION | SOURCE           |
+-------------------------------------+------+-----------+----------+---------+---------------+------------------+
| https://osv.dev/PYSEC-2026-1872     | 5.3  | PyPI      | requests | 2.31.0  | 2.32.4        | requirements.txt |
| https://osv.dev/GHSA-9hjg-9r4m-mvj7 |      |           |          |         |               |                  |
| https://osv.dev/PYSEC-2026-1873     | 5.6  | PyPI      | requests | 2.31.0  | 2.32.0        | requirements.txt |
| https://osv.dev/GHSA-9wx4-h78v-vm56 |      |           |          |         |               |                  |
| https://osv.dev/PYSEC-2026-2275     | 5.5  | PyPI      | requests | 2.31.0  | 2.33.0        | requirements.txt |
| https://osv.dev/GHSA-gc5v-m9x4-r6x2 |      |           |          |         |               |                  |
| https://osv.dev/PYSEC-2026-215      | 6.9  | PyPI      | idna     | 3.9.0   | 3.15          | requirements.txt |
| https://osv.dev/GHSA-65pc-fj4g-8rjx |      |           |          |         |               |                  |
+-------------------------------------+------+-----------+----------+---------+---------------+------------------+
```

```
    app/config.py
   ❯❯❱ generic.secrets.security.detected-aws-access-key-id-value.detected-aws-access-key-id-value
          AWS Access Key ID Value detected. This is a sensitive credential and should not be hardcoded here.
          Instead, read this value from an environment variable or keep it in a separate, private file.
          Details: https://sg.run/GeD1
           29┆ AWS_ACCESS_KEY_ID = "<synthetic-key>"
    app/upstream.py
   ❯❯❱ python.requests.security.disabled-cert-validation.disabled-cert-validation
          Certificate verification has been explicitly disabled. This permits insecure connections to insecure
          servers. Re-enable certification validation.
          Details: https://sg.run/AlYp
            7┆ return requests.get(url, verify=False, timeout=5).content
```

```
Gate 1 summary
  secrets   gitleaks     FAIL
  packages  osv-scanner  FAIL
  code      semgrep      FAIL
```

Exit status 1. The branch did not reach `origin`.

### Attempt 3: the fix, and a second lesson

Dev A fixed all three (`requests==2.33.0`, key moved to an environment
variable, `verify=True`) and, because the key was already in a commit,
rewrote that commit so the branch history no longer carries it. The push was
still refused:

```
Total 1 package affected by 1 known vulnerability (0 Critical, 0 High, 1 Medium, 0 Low, 0 Unknown) from 1 ecosystem.
1 vulnerability can be fixed.
+-------------------------------------+------+-----------+---------+---------+---------------+------------------+
| OSV URL                             | CVSS | ECOSYSTEM | PACKAGE | VERSION | FIXED VERSION | SOURCE           |
+-------------------------------------+------+-----------+---------+---------+---------------+------------------+
| https://osv.dev/PYSEC-2026-215      | 6.9  | PyPI      | idna    | 3.9.0   | 3.15          | requirements.txt |
| https://osv.dev/GHSA-65pc-fj4g-8rjx |      |           |         |         |               |                  |
+-------------------------------------+------+-----------+---------+---------+---------------+------------------+
```

```
Gate 1 summary
  secrets   gitleaks     PASS
  packages  osv-scanner  FAIL
  code      semgrep      PASS
```

Nothing pins `idna`. OSV-Scanner resolves the transitive dependencies of a
plain `requirements.txt` by choosing versions itself, and without a lockfile
that choice is not what pip installs. Gate 2's dependency review judges the
pins, so Gate 1 must too or the two gates disagree. The hook now passes
`--no-resolve`; the lockfile upgrade that would give both gates transitive
coverage is noted in MERGE_GATES.md.

### Attempt 4: accepted

```
Gate 1 summary
  secrets   gitleaks     PASS
  packages  osv-scanner  PASS
  code      semgrep      PASS
Clean. Pushing.
To /tmp/claude-1002/-home-bhupender-verma-Desktop-grc-console/4d322201-501f-4eb0-a8be-af92f7a32818/scratchpad/proof/origin.git
 * [new branch]      demo/local-gate-test -> demo/local-gate-test
branch 'demo/local-gate-test' set up to track 'origin/demo/local-gate-test'.
```

Exit status 0. The clean commit reached `origin`.

## Gate 2, the pull request

The planted commit was pushed with `git push --no-verify`, which is what a
laptop without the hook looks like. GitHub accepted the push: its own push
protection did not stop the synthetic key. Pull request
[#18](https://github.com/cybertec-postgresql/CRA_Test/pull/18) was opened
by the manager.

### The checks

| Check | Result | What it said |
|---|---|---|
| `secret-scan` | failed, 24 s | `gitleaks found a committed secret. Rotate it, remove it and rewrite the branch.` SARIF uploaded to code scanning under `gitleaks`, handed to triage |
| `dependency-review` | failed, 28 s | three moderate advisories on `requests 2.31.0`, summary commented on the pull request |
| `scan` | failed | two Semgrep findings: the disabled certificate check and the key; the triage step ran before the failure |

The merge box stayed blocked: failing required checks and no approving review.

### The issues the bot opened

One issue per finding, all assigned to the pull request author, all labelled
`cra-triage` plus the priority:

| Issue | Priority | Finding | CVSS 3.1 |
|---|---|---|---|
| [#19](https://github.com/cybertec-postgresql/CRA_Test/issues/19) | P3 | CVE-2026-25645, requests 2.31.0, insecure temp file reuse | 4.4 |
| [#20](https://github.com/cybertec-postgresql/CRA_Test/issues/20) | P3 | CVE-2024-47081, requests 2.31.0, .netrc credential leak | 5.3 |
| [#21](https://github.com/cybertec-postgresql/CRA_Test/issues/21) | P3 | CVE-2024-35195, requests 2.31.0, verify=False persists on the session | 5.6 |
| [#22](https://github.com/cybertec-postgresql/CRA_Test/issues/22) | P2 | CWE-295, `app/upstream.py:7`, certificate validation disabled | 7.4, assessed |
| [#23](https://github.com/cybertec-postgresql/CRA_Test/issues/23) | P2 | CWE-798, `app/config.py:29`, hard-coded credential | 7.5, assessed |

Five issues for three planted problems, because one pin carried three
advisories and the decision on record is one issue per CVE. The key was seen
by both gitleaks and Semgrep's generic secrets rule and became one issue, not
two. The same table was posted as a comment on the pull request.

### Two things noticed on the way

- GitHub's `github-advanced-security[bot]` also left a review comment on the
  key, from the SARIF uploaded to code scanning. Free on a public repository.
- The workflow log carried two deprecation warnings unrelated to the gates:
  Node.js 20 actions should move to Node.js 24, and CodeQL Action v3 is
  deprecated with a December 2026 deadline. Both are pinned by SHA in the
  workflows and are a maintenance item, not a gate defect.

### The fix

Dev A fixed all three on the same branch: `requests==2.33.0`, the key read
from the environment, `verify=True`. Because the key was in a commit, the
commit was rewritten rather than followed by a second one, so the history the
pull request adds no longer contains it. The push went through Gate 1 (all
three PASS) and re-ran Gate 2. The bot closes the issues it opened once the
findings are gone from the pull request head; the result of that run and the
approval are recorded below.

### After the fix

To be recorded once the checks report.
