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

To be recorded from the pull request opened from `demo/local-gate-test`:
the three required checks, the issues the triage bot opened with their
priority labels and assignee, the fix, the approval and the merge.
