# Merge gates

Three conditions must hold before anything reaches the default branch:

1. The Semgrep scan passed.
2. The dependency review passed: no newly added package carries a known advisory.
3. Another team member approved.

What happens to a finding after the gate catches it is in [TRIAGE.md](TRIAGE.md).

This file is the configuration and the reasoning behind it. The machine
readable form is [`.github/rulesets/default-branch.json`](.github/rulesets/default-branch.json).

## They are not a sequence

A common request is "scan first, then allow approval" or "approve first, then
scan". Neither is how GitHub works, and neither is needed.

Required status checks and required approvals are **independent conditions**,
evaluated continuously. The merge button unlocks the moment both are satisfied,
in whatever order they arrive. There is no setting that makes an approval
conditional on a check having already passed.

In practice this gives you the ordering you wanted anyway. The scan starts
automatically when the pull request opens and finishes in about a minute. A
human arrives minutes or hours later and finds the result already there.

```
PR opened
   |
   +-- Semgrep scan starts immediately, ~1 min  --+
   |                                              +--> merge unlocks when BOTH pass
   +-- Reviewer reviews whenever they review    --+
```

### Why "approve first, then scan, close the PR if it fails" is worse

- It spends the scarcest resource first. Reviewer time costs more than CI time.
  Making a person read code a machine would reject in sixty seconds is
  backwards.
- Closing a failing pull request is the wrong action. Fix and push on the same
  branch, so the discussion, the review history and the record that a
  vulnerability was caught all stay in one place. That record is the audit
  evidence. Closing throws it away and the developer opens a fresh pull request
  with no history.

A failing check should leave the pull request **open and blocked**. That is the
control working, not an error state.

## The setting people forget

Without stale approval dismissal the gate is theatre:

> A reviewer approves clean code. The author then pushes anything they like.
> The approval still stands.

Two settings close that:

| Setting | Stops |
|---|---|
| `dismiss_stale_reviews_on_push` | An approval carrying over to code nobody approved |
| `require_last_push_approval` | Someone approving commits they pushed themselves |

Self approval is already impossible: GitHub does not let an author approve their
own pull request. So `required_approving_review_count: 1` already means "another
team member".

## Pin the status check to GitHub Actions

`integration_id: 15368` is GitHub Actions. Pinning it is not cosmetic.

Without it, a required check named `scan` is satisfied by **any** commit status
with that name. Anyone with write access can post one with a token:

```sh
# this would satisfy an unpinned required check
curl -X POST .../statuses/$SHA -d '{"state":"success","context":"scan"}'
```

With `integration_id` pinned, only a status originating from GitHub Actions
counts. Verify the id for your own tenant with `GET /apps/github-actions`.

## Configuration

| Rule | Value | Why |
|---|---|---|
| Require a pull request | approvals `1` | Another team member must sign off |
| Dismiss stale approvals on push | on | See above |
| Require approval of most recent push | on | See above |
| Require status checks | `scan`, pinned to app `15368` | The gate itself |
| Require branches up to date | on | See trade-off below |
| Block force pushes | on | History cannot be rewritten under a merged review |
| Restrict deletions | on | The branch cannot be removed to dodge the rule |
| Bypass list | **empty** | A bypass nobody audits is not a control |

### The up to date trade-off

`strict_required_status_checks_policy: true` means a branch must be current with
the default branch before it merges. This matters for security: two branches can
each pass on their own and still introduce a flaw once combined, and only a scan
of the merged result catches that.

The cost is rebasing churn on a busy repository. If that becomes painful, the
usual answer is a merge queue. Availability of merge queues on the Team plan is
**NOT VERIFIED** here, confirm before relying on it.

## Applying it

### Through the interface

Settings, Rules, Rulesets, New ruleset, New branch ruleset. Target
**Default branch**. Enable the rules in the table above. Enforcement
**Active**. Bypass list empty.

### Through the API

Needs a token with repository admin.

```sh
curl -X POST \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/cybertec-postgresql/CRA_Test/rulesets \
  -d @.github/rulesets/default-branch.json
```

For the whole organisation, post the same body to
`/orgs/{org}/rulesets`. Organisation rulesets are available on the Team plan.
Note that the Team plan has **no Evaluate (dry run) mode**, so roll out by
targeting a few repositories through a custom property before widening.

## Steps: adding the approver gate

Fifteen minutes, including the tests. You need repository admin.

### 1. Create the ruleset

Repository **Settings**, **Rules**, **Rulesets**, **New ruleset**,
**New branch ruleset**.

- **Name:** `Default branch: scan and review`
- **Enforcement status:** `Active`
- **Bypass list:** leave empty. Add nothing, not even yourself. An
  administrator who can bypass silently is not covered by the control, and that
  is the first thing an auditor asks about.
- **Target branches:** Add target, **Include default branch**.

### 2. Turn on the review requirement

Tick **Require a pull request before merging**, then set:

| Field | Value | Why |
|---|---|---|
| Required approvals | `1` | GitHub already forbids approving your own pull request, so 1 means another person |
| Dismiss stale pull request approvals when new commits are pushed | **on** | Without this an approval carries over to code nobody reviewed |
| Require approval of the most recent reviewable push | **on** | Stops someone approving commits they pushed themselves |
| Require review from Code Owners | off for now | Turn on once a `CODEOWNERS` file exists |
| Require conversation resolution before merging | optional | Blocks merging over unresolved review comments |

### 3. Turn on the scan requirement

Tick **Require status checks to pass**, then:

1. Click **Add checks** and search for `scan`. It only appears if it has run at
   least once on this repository, which it has.
2. Set the source to **GitHub Actions**, not "any source". This is the pinning
   described above, and it is the difference between a gate and a gate with the
   key left in it.
3. Tick **Require branches to be up to date before merging**.

### 4. Block the escape routes

Still in the same ruleset:

- **Block force pushes**, so history cannot be rewritten under an approval.
- **Restrict deletions**, so the branch cannot be deleted and recreated.

**Create**.

### 5. Prove it works

Do not skip this. The four tests are in the next section. A ruleset that has
never refused anything has never been tested.

### Doing it through the API instead

```sh
curl -X POST \
  -H "Accept: application/vnd.github+json" \
  -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/cybertec-postgresql/CRA_Test/rulesets \
  -d @.github/rulesets/default-branch.json
```

Confirm afterwards, and check that `bypass_actors` really is empty:

```sh
curl -sS -H "Authorization: Bearer $GITHUB_TOKEN" \
  https://api.github.com/repos/cybertec-postgresql/CRA_Test/rulesets \
  | python3 -m json.tool
```

### Rolling it to the organisation

Same body, posted to `/orgs/{org}/rulesets`, with the target set to all
repositories or a subset selected by repository custom property. Organisation
rulesets are included in the Team plan.

The Team plan has **no Evaluate (dry run) mode**, so there is no way to see what
a ruleset would have blocked before it blocks it. Roll out to a handful of
repositories by custom property first, then widen.

Note that a required check named `scan` only exists in repositories that run a
job with that name. In a repository without the workflow, the check never
reports and every pull request blocks forever. Roll out the workflow first, the
ruleset second.

## Test it before you trust it

A protection rule nobody has tried to bypass has never been tested. Confirm all
four:

1. **Blocked while running.** Open a pull request, and while the scan is still
   in progress confirm the merge button is disabled.
2. **Blocked on failure.** Use `feat/asset-search`. The scan fails, merge stays
   blocked, and the pull request stays open.
3. **Blocked without review.** Use a clean branch. The scan passes, but with no
   approval merge is still blocked.
4. **Approval does not survive a push.** Get a clean branch approved, then push
   another commit. Confirm the approval was dismissed.

Record the result of each. An untested control is an assumption.

## Known failure mode, and why it is the right one

If the workflow is deleted or the job renamed, the `scan` check never reports,
and the pull request stays blocked forever.

That looks like an outage. It is the gate failing safe: the way to remove the
check is to change the ruleset, which is audited, not to edit a file in a
feature branch. Do not "fix" it by removing the requirement.

## Dependency review is not Dependabot

Dependabot alerts scan the **default branch only**. A vulnerable pin added on a
pull request branch raises no alert until it has already been merged, at which
point the gate has done nothing.

The `dependency-review` job closes that gap. It diffs the dependency graph of
the pull request against the base branch and fails on any newly added package
with a published advisory, at `fail-on-severity: low`. It needs the dependency
graph, which is on by default for public repositories, and a `pull_request`
trigger; it cannot run on `push`.

The check is required in the ruleset alongside `scan`, pinned to the same
GitHub Actions integration id for the same reason.

Dependabot still has a job: it watches the default branch for advisories
published **after** a package was merged, and opens the bump pull request.
Dependency review stops the known bad version at the door; Dependabot handles
the ones that turn bad later.
