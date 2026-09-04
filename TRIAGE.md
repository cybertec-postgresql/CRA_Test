# Finding to issue: how a scanner result becomes a prioritised record

Every security finding in this repository ends up as one GitHub issue that
carries the CVE, the CVSS score and vector, the fix version, a link to where it
was found and a P1 to P4 priority. The issue is assigned to the developer who
introduced the finding. This file explains the pipeline, the scoring and the
decisions behind both. The code is in [`triage/`](triage/), the tests in
[`tests/triage_suite/`](tests/triage_suite/).

## The flow

```
laptop                                 GitHub
------                                 ------
git push
  |
  pre-push hook runs Semgrep
  |   fail: "fix locally", push refused
  |   pass
  v
                                       pull request opened, assigned to author
                                         |
                                         +-- scan (Semgrep)            required check
                                         +-- dependency-review         required check
                                         +-- triage step (always runs)
                                               |
                                               new pins  -> GitHub Advisory Database -> CVE, CVSS 3.1 and 4.0
                                               SARIF     -> CWE -> .cra/cwe-vectors.json -> CVSS 3.1
                                               |
                                               score -> P1..P4 -> one issue per finding, assigned to author
                                               table with score, priority and issue link commented on the PR
                                         |
                                       merge blocked until both checks pass and a reviewer approves

                                       default branch, every 15 minutes
                                         Dependabot alerts + code scanning alerts
                                           -> same scoring, same issues
                                           -> fixed or dismissed alert closes the issue with the reason
                                           -> reopened alert reopens the issue
```

## Priority chart

| Priority | CVSS 3.1 base score | Meaning |
|---|---|---|
| P1 | 9.0 to 10.0 | Full compromise of confidentiality, integrity or availability. Remote, unauthenticated. |
| P2 | 7.0 to 8.9 | Compromise possible but needs interaction or privileged access. |
| P3 | 4.0 to 6.9 | Limited access or partial degradation of service. |
| P4 | 0.1 to 3.9 | Little immediate risk, still to be patched. |
| needs-scoring | none | No CVSS vector on file for this weakness class. |

Priority is internal triage. It is not the Cyber Resilience Act Article 14
reporting trigger. That clock starts on evidence that a vulnerability is being
actively exploited, not on a score, and every issue says so.

## Where the score comes from

**Dependencies.** The GitHub Advisory Database record for the advisory. It
carries the CVE id, the CVSS 3.1 score and vector, the CVSS 4.0 score and
vector where published, the vulnerable range and the first patched version.
The 3.1 score drives the priority; both are recorded. The issue links the GHSA
page and the NVD page.

**Code findings.** Semgrep reports a CWE, not a CVSS score, because nobody
publishes a score for a code pattern. But a score is not a lookup, it is a
formula. NVD analysts produce every published score the same way: assign a
vector from the weakness and its context, compute the base score. We do the
same. [`.cra/cwe-vectors.json`](.cra/cwe-vectors.json) holds one reviewed
vector per weakness class with a rationale, and the score is computed from it
with the CVSS 3.1 formula in [`triage/cvss.py`](triage/cvss.py). The issue
states that the score is assessed from the vector, not published, so the
record is honest about its provenance.

A test asserts that every row's stated score is what its vector computes to,
so the table cannot drift. A finding whose CWE is not in the table gets the
`needs-scoring` label and no priority, never a guessed number. Adding the
vector and rerunning rescores it.

## One issue per finding

The issue key is the identity of the finding, not where it was seen:

- dependency: package and advisory id, `dep:pyyaml:GHSA-8q59-q68h-6hv4`
- code: rule and file, `code:<rule id>:<path>`

So the same CVE seen on a pull request and later as a Dependabot alert on main
is one issue, and a package with three advisories gets three issues, each with
its own score and fix version. The key lives in an HTML comment at the top of
the issue body and the `cra-triage` label marks the issue as script managed.

## Lifecycle

| Alert state on GitHub | Issue | Action |
|---|---|---|
| open | none | create, label, assign |
| open | open | nothing |
| open | closed by the script earlier | reopen with a comment |
| open | closed by a person | leave closed |
| fixed or dismissed | open | close, comment says why and who |
| fixed or dismissed | none | nothing |

A finding that disappears from a pull request head closes its issue with a
note; if the same finding is open on main, the scheduled run reopens it.

## Who is assigned

On a pull request, the author. On the default branch there is no author, so
in order: the last person to touch the line (git blame, resolved to a GitHub
login), the CODEOWNERS entry for the file, then the repository variable
`TRIAGE_DEFAULT_ASSIGNEE`. Teams in CODEOWNERS are skipped because an issue
cannot be assigned to a team.

## Why the default branch is polled

Dependabot alerts fire a webhook but cannot start a workflow. The options were
a scheduled poll or an external webhook receiver. The poll is inside GitHub,
free on a public repository, and has a worst case latency of 15 minutes. A
receiver is real time but is one more thing to host and keep alive. Both run
the same script, so moving to a receiver later is a trigger change, not a
rewrite. Note that GitHub disables scheduled workflows in a public repository
after 60 days without a commit.

## Setup on a new repository

1. Copy `triage/`, `.cra/`, `scripts/hooks/`, `scripts/install-hooks.sh` and
   the two workflow files.
2. Set the repository variable `TRIAGE_DEFAULT_ASSIGNEE`.
3. Add `dependency-review` to the required status checks in the live ruleset,
   next to `scan`. The JSON in `.github/rulesets/` is the documented shape;
   the enforcing copy lives in repository settings and does not read the file.
4. Every developer runs `scripts/install-hooks.sh` once per clone.

## Testing it

The scoring, chart, rendering, client and lifecycle logic are unit tested:
`python -m pytest tests`. The end to end path is proven by planting a
finding on a branch and opening a pull request; the checks go red, the issue
appears, the table lands on the pull request. The pre-push hook is proven by
planting a finding locally and watching the push refuse.
