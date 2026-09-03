# How Semgrep runs, and what it can see

Two separate executions, sharing nothing but the rules.

| | Local | CI |
|---|---|---|
| Runs on | Your machine, in Docker | A GitHub runner |
| Reads | Your working directory, including uncommitted edits | A fresh `git clone` of the branch |
| Started by | You | The `pull_request` trigger |
| Result | Terminal output, exit code | The `scan` check, plus SARIF alerts |

The local run has no connection to GitHub. The CI run has no connection to your
machine. They agree because they use the same pinned image and the same rules,
not because one talks to the other.

## How the container sees local files

```sh
docker run --rm -v "$PWD:/src" semgrep/semgrep:1.175.0 semgrep scan /src
                 ^^^^^^^^^^^^^
```

`-v "$PWD:/src"` is a **bind mount**. It makes the current directory on your
machine appear inside the container at `/src`. Nothing is copied and nothing is
uploaded: the container reads the same bytes on the same disk, through the
kernel.

This is why the local scan sees code that exists nowhere else: uncommitted
changes, a branch never pushed, a repository with no remote at all. Git and
GitHub are not involved.

## Does the code leave the machine?

**No.** Demonstrated rather than assumed, with the container's network switched
off entirely:

```sh
# local rules, no network: works
docker run --rm --network none -v "$PWD:/src" semgrep/semgrep \
  semgrep scan --config=.semgrep/ --metrics=off /src
# Ran 1 rule on 5 files: 0 findings.

# registry rules, no network: fails
docker run --rm --network none -v "$PWD:/src" semgrep/semgrep \
  semgrep scan --config=p/python --metrics=off /src
# ConnectionError: HTTPSConnectionPool(host='semgrep.dev', port=443)
#   Max retries exceeded with url: /c/p/python
```

The second command fails while **fetching the ruleset**, before any file is
read. That establishes the direction of traffic: rules come down, code does not
go up. Analysis is entirely local either way.

Use `--metrics=off`, as every command here does, to suppress anonymous usage
telemetry. For a fully air-gapped scan, vendor the rules locally and pass
`--config=` a path, as the first command does.

## "Scanning N files tracked by git" is misleading

Semgrep uses git to decide what to scan, and the wording in its output does not
mean what it looks like. Tested with three identical files:

| File | State | Scanned? |
|---|---|---|
| `tracked.py` | committed | yes |
| `untracked.py` | not in git, not ignored | **yes** |
| `ignored.py` | matched by `.gitignore` | **no** |

So "tracked by git" actually means "not excluded by `.gitignore`". Untracked
files are scanned. It has nothing to do with whether a remote exists or whether
anything was pushed.

### The part to be careful about

The ignored file was skipped **silently**. It did not appear in the run's
skipped list, and nothing in the output said a file had been excluded. With no
git repository present at all, the same directory scanned 3 files and produced
3 findings; inside a git repository it scanned 2 and produced 2. The missing
finding announced itself nowhere.

The consequence: **an over-broad `.gitignore` pattern creates a silent blind
spot in the scanner.** An unanchored pattern such as `data/` matches nested
directories too, so a `site/data/` or `app/data/` full of real source is
excluded from both git and the scan, without warning.

Anchor gitignore patterns for build output and volumes with a leading slash,
`/data/`, `/dist/`, so they match only at the repository root. Then confirm what
was actually scanned:

```sh
semgrep scan --config=p/python --metrics=off --json . \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['paths'])"
```

Checking the file count is the cheap version of this check. If it is lower than
you expect, something is being excluded.

## Why the two runs can still disagree

| Cause | What to do |
|---|---|
| Uncommitted local changes | CI scans the pushed branch, not your disk. Commit and push. |
| Registry rules changed between runs | Pin the image, as the workflow does. Rules are fetched at scan time, so they can move. |
| Different `--config` flags | Keep the local command and the workflow in step. Both are in the README. |
| A file is gitignored | It is invisible to CI entirely, since CI only ever sees what git holds. |

That last row is the important one. Locally an untracked file is still scanned,
so a finding can appear on your machine and never in CI. In CI, if it is not in
git, it does not exist.
