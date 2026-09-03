# Merge gates

Two conditions must hold before anything reaches the default branch:

1. The Semgrep scan passed.
2. Another team member approved.

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
