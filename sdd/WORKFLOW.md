# navigator-session SDD Workflow

## Overview

This document defines the **Spec-Driven Development (SDD)** methodology for navigator-session, driven through Claude Code slash commands with multi-agent task distribution.

The key idea: specifications are the Single Source of Truth (SSOT). Agents consume spec documents and produce **Task Artifacts** — discrete, self-contained files in `sdd/tasks/active/` that can be independently picked up and executed by agents in parallel.

---

## The SDD Lifecycle

```
                                 ┌─ /sdd-fromjira → jira-issue → brainstorm ────┐
                                 │                                                 │
                                 ├─ /sdd-proposal → discuss → brainstorm ──────────┤
                                 │                                                 │
                                 ├─ /sdd-spec → scaffold spec ─────────────────────┤
[Human] ────────────────────────┤                                           Feature Spec → [Planner] Tasks → [Executors] Code → [Reviewer] Validation
                                 │                                                 ↑              ↑                                       |
                                 ├─ /sdd-tojira → jira-issue ──────────────────────┘              └────────── Feedback Loop ──────────────┘
                                 │                                                                                                        |
                                 └────────── /sdd-task → decomposes spec into tasks ──────────────────────────────────────────────────────┘
```

### Phase 0 — Feature Proposal *(optional)*
Start here when the idea is not yet well-defined. Use `/sdd-proposal` to discuss
a feature in non-technical language. The agent walks through motivation, scope,
and impact with you, producing `sdd/proposals/<feature>.proposal.md`.

The proposal can then automatically scaffold a formal spec (Phase 1).

### Phase 1 — Feature Specification
Start here when you already know what you want to build. Use `/sdd-spec` to scaffold
`sdd/specs/<feature>.spec.md`, or accept one auto-generated from `/sdd-proposal`.

### Phase 2 — Task Generation (Claude Code Planner Agent)
Run `/sdd-task <spec-file>` to decompose the spec into Task Artifacts.

Each task is written to `sdd/tasks/active/TASK-<id>-<slug>.md`.
The **per-spec index** at `sdd/tasks/index/<feature-slug>.json` is created
or updated with task metadata (FEAT-145).

Tasks are designed to be:
- **Atomic** — completable independently
- **Bounded** — clear scope, no ambiguity
- **Testable** — every task includes its own test criteria
- **Assignable** — formatted so any Claude Code agent can start immediately

### Phase 3 — Task Execution (Claude Code Executor Agents)
Each executor agent picks up a task file, typically via `/sdd-start TASK-<NNN>`,
which resolves the task, ensures the feature worktree, and implements it in place.

Tasks declare their dependencies, so agents know what must be done first.

### Phase 4 — Validation (Claude Code Reviewer Agent)
After execution, tasks move to `sdd/tasks/completed/`.
A reviewer agent (`/sdd-codereview`) validates against the Test Specification.

---

## Task Artifact Format

Every task file (`sdd/tasks/active/TASK-<NNN>-<slug>.md`) follows this structure:

```markdown
# TASK-<NNN>: <Title>

**Feature**: <parent feature name>
**Spec**: sdd/specs/<feature>.spec.md
**Status**: [ ] pending | [ ] in-progress | [x] done
**Priority**: high | medium | low
**Depends-on**: TASK-<X>, TASK-<Y>   (or "none")
**Assigned-to**: (agent session ID or "unassigned")

## Context
Brief explanation of why this task exists and how it fits the feature.

## Scope
Exactly what this task must implement. Be precise.

## Files to Create/Modify
- `navigator_session/path/to/file.py` — description
- `tests/path/to/test_file.py` — unit tests

## Implementation Notes
Technical guidance for the agent: patterns to follow, existing code to reference,
gotchas, constraints.

## Reference Code
Existing patterns in the codebase the agent should follow:
- See `navigator_session/storages/abstract.py` for the `AbstractStorage` pattern
- See `navigator_session/session.py` for the `SessionHandler` dispatch pattern

## Acceptance Criteria
- [ ] Criterion 1
- [ ] Criterion 2
- [ ] All tests pass: `pytest tests/path/ -v`

## Test Specification
```python
# Minimal test scaffold the agent must make pass
def test_feature_does_x():
    ...

def test_feature_handles_edge_case():
    ...
```

## Output
When complete, the agent must:
1. Move this file to `sdd/tasks/completed/`
2. Update the per-spec index at `sdd/tasks/index/<feature-slug>.json` status to "done"
3. Add a brief completion note below

### Completion Note
(Agent fills this in when done)
```

---

## Git Configuration (FEAT-187)

navigator-session uses two long-lived branches:

- **`main`** — tagged releases only. Hotfixes land here via PR;
  no feature work ever bases on `main`.
- **`dev`** — integration branch for all feature work. Default base
  for `type: feature` flows.

> ⚠️ **Repo-state note**: as of this scaffolding, navigator-session does not
> yet have a `dev` branch — only `main` exists. The migrated commands
> (`/sdd-brainstorm`, `/sdd-spec`) hard-default `type: feature` to
> `base_branch: dev` and refuse `base_branch: main` for features. Create a
> `dev` integration branch before running a feature-flow SDD command, or
> have the commands/rules updated to a `main`-only branch model — whichever
> this repo's maintainers prefer.

---

## Flow Types (FEAT-145, refined by FEAT-187)

Every brainstorm/proposal/spec declares its flow type via YAML frontmatter
at the top of the document:

```yaml
---
type: feature        # one of: feature | hotfix
base_branch: dev     # for feature: dev or a parent feature branch; for hotfix: must be "main"
---
```

| Type      | base_branch         | When to use                                                  |
|-----------|---------------------|--------------------------------------------------------------|
| `feature` | `dev` (default)     | Most work. Lands on `dev` via `/sdd-done`.                   |
| `feature` | `<other-branch>`    | Sub-features extending another feature branch.               |
| `hotfix`  | `main` (required)   | Production hotfixes. Land on `main` via manual PR.           |

Features MUST NOT base on `main`. `/sdd-done` enforces: hotfixes are NEVER
auto-pushed or auto-PR'd to `main`. The user opens the PR manually; afterwards,
run `/sdd-done <FEAT-ID> --sync-down` to propagate the change back into `dev`.

### Recommended Branch Protection

`main` should require PRs, passing CI status checks, and signed commits.
Configure via GitHub repo settings — not declaratively in this repo.

---

## Per-Spec Index Schema (`sdd/tasks/index/<feature-slug>.json`, FEAT-145)

Each per-spec index file contains a header describing the feature plus
the `tasks[]` array for that feature only. Two parallel features touch
disjoint files and never collide on merge.

```json
{
  "feature": "feature-slug",
  "feature_id": "FEAT-NNN",
  "spec": "sdd/specs/feature-slug.spec.md",
  "type": "feature",
  "base_branch": "dev",
  "created_at": "ISO-8601",
  "completed_at": null,
  "tasks": [
    {
      "id": "TASK-001",
      "slug": "abstract-storage-interface",
      "title": "Define the AbstractStorage backend interface",
      "feature_id": "FEAT-NNN",
      "feature": "feature-slug",
      "status": "done",
      "priority": "high",
      "depends_on": [],
      "assigned_to": null,
      "started_at": null,
      "completed_at": "ISO-8601",
      "file": "sdd/tasks/completed/TASK-001-abstract-storage-interface.md"
    }
  ]
}
```

Tasks orphaned by a migration (no resolvable `feature`) live in
`sdd/tasks/index/_orphans.json` with the same schema and `feature: "_orphans"`.
`/sdd-status` surfaces them in a dedicated panel; `/sdd-next` skips them.

---

## TASK/FEAT ID Allocation (FEAT-387)

`TASK-<NNN>` and `FEAT-<NNN>` numbers are meant to be allocated by a tiny,
git-native compare-and-swap ledger, not by scanning existing files for the
highest number and incrementing — that scan-and-increment approach has no
lock and no re-check against `origin/<base_branch>` immediately before
committing, so two `/sdd-task`/`/sdd-spec` runs racing each other can
silently allocate the same number to two different features.

The already-migrated commands (`/sdd-task`, `/sdd-spec`) call this ledger via:

- **`sdd/tasks/.id_ledger.json`** — the ledger itself: a single, git-tracked
  JSON file holding `next_task_id` and `next_feature_id`.
- **`scripts/sdd/id_ledger.py`** — the `IdLedger` model plus
  `load_ledger`/`save_ledger` and `bootstrap_ledger()`.
- **`scripts/sdd/reserve_ids.py`** — the allocator `/sdd-task` and
  `/sdd-spec` call instead of hand-computing a number.
- **`scripts/sdd/check_id_collisions.py`** — an independent, read-only
  defense-in-depth backstop scanning `sdd/tasks/index/*.json`,
  `sdd/tasks/active/*.md`, and `sdd/tasks/completed/*.md`.

> ⚠️ **Not yet ported to this repo.** `scripts/sdd/` (the ledger, the
> allocator, `ensure_worktree.py`, `close_task.sh`, and friends) was
> excluded from the initial SDD migration into navigator-session. Until
> those scripts exist here, `/sdd-task` and `/sdd-spec` cannot actually
> reserve IDs or create worktrees — only the document-authoring phases
> (`/sdd-brainstorm`, `/sdd-proposal`) are fully usable today. Port
> `scripts/sdd/` from a sibling repo (e.g. `notify` or `navigator-auth`)
> when you're ready to run the full pipeline.

Also not yet wired into CI here: a `lint-and-registry` job running
`check_id_collisions.py` against `scripts/sdd/.collision_baseline.json`,
as this repo's `.github/workflows/` only has a release-publish workflow
today.

---

## Parallelism Rules

Claude Code agents can work in parallel when tasks have no shared dependencies:

```
TASK-001 (base interface)
    ├── TASK-002 (redis-storage)   ← parallel after 001
    ├── TASK-003 (cookie-storage)  ← parallel after 001
    └── TASK-004 (vault-storage)   ← parallel after 001
            └── TASK-005 (session-handler-wiring) ← waits for 002, 003, 004
```

A Claude Code agent should **never start a task** if its `depends_on` tasks
are not in `sdd/tasks/completed/`.

---

## Commands Reference

The SDD workflow here is Claude Code only — no Codex or Antigravity agent
definitions have been migrated into this repo:

| Command | Description |
|---|---|
| `/sdd-proposal` | Research a Jira issue, inline request, or notes file before writing a spec |
| `/sdd-brainstorm` | Explore a feature idea, compare options, and write a brainstorm document |
| `/sdd-spec` | Scaffold a formal Feature Specification from exploration or direct request |
| `/sdd-task <spec.md>` | Decompose an approved spec into atomic task files and a per-spec index |
| `/sdd-start <task>` | Implement and close one task inside the feature worktree |
| `/sdd-done <feat>` | Verify, push, open or describe PR, and clean up the worktree |
| `/sdd-codereview <task>` | Code review a completed task with adversarial cross-checks |
| `/sdd-explain <target>` | Code-grounded architectural map or deep implementation trace |
| `/sdd-status` | Show task index status board across all per-spec indexes |
| `/sdd-next` | Suggest next unblocked tasks to assign |
| `/sdd-fromjira` | Bootstrap an SDD brainstorm from a Jira ticket |
| `/sdd-tojira` | Export an SDD specification to a Jira Story and subtasks |
| `/sdd-insight` | Analyze collaboration transcripts and repo-level SDD process adherence |

---

## Quality Rules for Agents

1. **Never modify files outside the task scope** — respect boundaries
2. **Follow existing patterns** — reference code mentioned in the task
3. **Write tests first** — TDD approach per task
4. **Update the index** — always update the per-spec index on completion
5. **Small commits** — one task = one logical commit
6. **Ask via the spec** — if unclear, note the ambiguity in the completion note
   and let the Planner agent refine the spec for the next iteration
