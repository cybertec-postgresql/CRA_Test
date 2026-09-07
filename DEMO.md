# Run the gate test yourself

A runbook for showing the two gates live, in about twenty minutes. Every
command is safe to copy. Read the "say" lines aloud if you like; they are
the point of each step. GATE_TEST.md is the record of the last full run.

## Before the demo, once

1. Docker is running on the laptop (`docker info` prints without error). The
   three scanners run as containers; nothing else is installed.
2. A fresh clone with the hook switched on:

   ```sh
   cd ~/Desktop
   git clone git@github.com:cybertec-postgresql/CRA_Test.git CRA_Test
   cd CRA_Test
   sh scripts/install-hooks.sh
   ```

   The hook lives in the repository at `scripts/hooks/pre-push`. The
   installer only tells git to look there: `git config core.hooksPath` should
   now print `scripts/hooks`.
3. Pull the images once so the first run is not a download:

   ```sh
   docker pull ghcr.io/gitleaks/gitleaks:v8.30.1
   docker pull ghcr.io/google/osv-scanner:v2.5.1
   docker pull semgrep/semgrep:1.175.0
   ```
4. Agree who is Dev B. They need the Write role and must not be the person
   pushing.

## Part 1, Gate 1 on the laptop

Say: every change is checked on the developer's own computer before it can be
uploaded.

1. A branch with three planted problems:

   ```sh
   git checkout main && git pull
   git checkout -b demo/gate-test-$(date +%Y%m%d)
   printf 'requests==2.31.0\n' >> requirements.txt
   python3 -c "import secrets,string; a=string.ascii_uppercase+'234567'; k='AKIA'+''.join(secrets.choice(a) for _ in range(16)); open('app/config.py','a').write(f'\nAWS_ACCESS_KEY_ID = \"{k}\"\n')"
   printf 'import requests\n\n\ndef fetch(url):\n    return requests.get(url, verify=False, timeout=5).content\n' > app/upstream.py
   git add -A && git commit -m "Demo: three planted problems"
   ```

   The second command writes a made up key in the AWS format straight into
   the file without showing it on screen. Do not use the AWS documentation
   example key; the scanner allowlists it and the demo would fail to fail.

2. Try to upload:

   ```sh
   git push -u origin HEAD
   ```

   Say: watch the three sections, then the summary. Expected:

   ```
   Gate 1 summary
     secrets   gitleaks     FAIL
     packages  osv-scanner  FAIL
     code      semgrep      FAIL
   Push refused. Nothing has left this computer.
   ```

   Prove it: `git ls-remote --heads origin | grep demo/gate-test` prints
   nothing. The branch never left the laptop.

3. Say: a developer can skip the hook. Show it, because that is what Gate 2 is
   for:

   ```sh
   git push --no-verify -u origin HEAD
   ```

## Part 2, Gate 2 on GitHub

Say: the same three checks, run by GitHub, and nobody can switch them off.

4. Open the pull request from the link git just printed. Within a minute the
   three checks turn red. Point at:
   - the merge button, disabled;
   - the comment "CRA triage" with one row per finding, score and priority;
   - Issues: five new ones, `[P3]` and `[P2]` in the title, labels
     `cra-triage` and the priority, assigned to the developer.

   Say: five issues for three problems because one old package carries three
   CVEs, and the rule is one issue per CVE.

## Part 3, the fix

Say: nothing is closed by hand. Fix the code and the record follows.

5. Fix all three, then rewrite the commit so the key leaves the history too:

   ```sh
   sed -i 's/^requests==2.31.0$/requests==2.33.0/' requirements.txt
   sed -i '/^AWS_ACCESS_KEY_ID = "AKIA/d' app/config.py
   sed -i 's/verify=False/verify=True/' app/upstream.py
   git add -A && git commit --amend -m "Demo: fixed"
   git push --force-with-lease
   ```

   Say: a committed secret is exposed even after the line is deleted, so the
   commit itself is replaced. In real life the credential is rotated first.

   This push runs Gate 1 again and it passes: three PASS, "Clean. Pushing."

6. Back on the pull request: the checks go green, the triage comment says
   "No findings on this pull request head", and the five issues are closed
   by the bot with a comment saying why.

7. Dev B reviews and approves. Say: the author cannot approve, and any new
   push would dismiss this approval. The merge button enables. Merge.

## Afterwards

- Delete the demo branch on GitHub if the merge did not.
- The closed issues stay. They are the record: what was found, how bad, who
  owned it, when it was fixed.
- If the branch is behind `main` the merge button asks for an update first;
  `git rebase origin/main && git push --force-with-lease` does it and runs
  Gate 1 once more.

## If something does not go to plan

| Symptom | Cause | Do |
|---|---|---|
| Gate 1 prints nothing and the push succeeds | hook not installed in this clone | `sh scripts/install-hooks.sh`, push again |
| `docker: permission denied` or `Cannot connect to the Docker daemon` | Docker not running or user not in the docker group | start Docker; push again |
| secrets PASS on the planted commit | the key matched an allowlist | generate the key with the command in step 1, never type one by hand |
| `secret-scan` still red after the fix | the key is still in a commit on the branch | `git log -p -S AKIA` to find it; amend or squash so it is gone; force push |
| merge box says the branch is out of date | `main` moved | rebase as above |
