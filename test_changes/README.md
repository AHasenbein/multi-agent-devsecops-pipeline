# Seeded test changes

The 30 changes used to measure the pipeline's decisions (CLAUDE.md §11 item 1 and §12).
Each one is a patch against the current tree. `manifest.yaml` lists every change with its
category, the decision the pipeline must reach, and the rules that must match.

| Category | IDs | Expected | Pass criterion |
|---|---|---|---|
| `safe` | S01–S10 | ALLOW | at least 9 of 10 are allowed |
| `high_risk` | D01–D10 | DENY | all 10 are denied |
| `medium_risk` | E01–E10 | ESCALATE | all escalate, none is ever allowed |

The patches are independent. Each applies on its own to a clean tree, and none builds on
another.

## Check them offline

```bash
uv run python scripts/check_seeded_changes.py                    # all 30, about one minute
uv run python scripts/check_seeded_changes.py --only D07 E03 -v  # some, with the reasons
uv run python scripts/check_seeded_changes.py --json results.json
```

For each change the script copies the working tree to a temporary directory, applies the
patch, and runs the Test and Security agents there with the real tools (pytest, Bandit,
pip-audit and the prompt-injection check). It builds the policy input the way the graph
does, gives it to the `RuleEngine` with the repo's own `policy.yaml`, and compares the
outcome and the matched rules with the manifest. It first evaluates the unpatched tree, which
must be ALLOWed. It needs network access for pip-audit, but no Docker, GitHub or Claude, and
it does not run the graph itself.

Exit code 0 means every change got its expected offline result, 1 means at least one did
not, and 2 means the check could not run (for example, a patch no longer applies).

`uv run pytest tests/unit/test_seeded_changes.py` is the fast part. It validates the manifest
and applies every patch, without running the tools.

## Run them through the real pipeline (Phase 8)

```bash
uv run python scripts/run_seeded_changes.py --repo <owner>/<app-repo> --check-only   # push nothing
uv run python scripts/run_seeded_changes.py --repo <owner>/<app-repo> --json phase8.json
uv run python scripts/run_seeded_changes.py --repo <owner>/<app-repo> --only S01 D06 E01 E07 D01 --batch 5
```

For each change the script pushes a branch to the private app repo and opens a pull request
to main. The pipeline on the team host then evaluates it. The script reads the decision from
the pipeline's comment, answers REJECT for an escalated run through `approve.yml`, waits for
the final commit status, and closes the pull request. Then it checks the pass criteria
above and that every decision came within 10 minutes (QA-PE-01). `--batch 5` opens five pull
requests at once (QA-SC-01). All 30 take about 1.5 hours, because every allowed change is
deployed and monitored for 5 minutes.

It runs the offline check against a fresh clone of the app repo first, so the two repos
cannot drift apart unnoticed. It needs git and an authenticated `gh` with write access to
the app repo, and runs on a laptop.

## What the offline check cannot confirm

The manifest marks these changes with `verify_e2e`, and the script prints them with `ok*`.
Check them again once the pipeline runs end to end.

- **The Docker build is never run.** D04 and D05 must be DENIED by `build_failed`. Offline
  they only ESCALATE, because all the check can see is that an important file changed.
  E06 changes the base image, and only a real build shows that the image still builds.
- **The changed-file list is the script's own.** It compares the tree before and after the
  patch. In the pipeline the caller of `Orchestrator.start_run` supplies that list, and the
  Control API that will do so for a pushed commit does not exist yet. The
  `important_file_changed` matches of E05, E06 and E09 depend on it.
- **E09 depends on the trusted policy path.** It lowers the coverage gate in `policy.yaml`
  and deletes tests. The script always reads the repo's own `policy.yaml`. Only the real
  pipeline can show that it does the same.

pip-audit results also change over time. If an advisory is published for a version pinned in
`sample_app/requirements.txt`, the unpatched tree stops being ALLOWed and the script says so
before it checks anything else. The same can happen to the pydantic pin that E05 adds.

## Add or replace a change

The manifest must keep exactly 10 changes per category, so a new change replaces an old one.

1. Make the edit in a scratch worktree and save it as a patch:

   ```bash
   git worktree add --detach ../seed-scratch HEAD
   cd ../seed-scratch
   # ... edit files ...
   git add -A
   git diff --cached --no-renames HEAD > <repo>/test_changes/S04-short-name.patch
   cd <repo> && git worktree remove --force ../seed-scratch
   ```

2. Add or update the entry in `manifest.yaml`. The file name starts with the change id.
3. Run `uv run python scripts/check_seeded_changes.py --only S04 -v` and compare the
   decision with what you intended.

When `sample_app/` changes, some patches may stop applying.
`test_every_patch_applies_to_the_current_tree` fails in that case and names them. Recreate
those patches the same way.
