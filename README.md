You’re thinking in the right direction (local, “closest-to-the-code” docs). The trick in a huge monorepo is **progressive disclosure**: give agents a *map* + *rules* up front, and then only load the *one or two* local context shards that matter for the slice of code they’re touching—rather than trying to pre-load the entire tree.

Below is a practical system that scales without overflowing context, and it fits well with how OpenCode and other agents discover `AGENTS.md`. ([Agents][1])

---

## Don’t document every file—document boundaries and “entry points”

For agents, the highest ROI context is usually:

* **Module boundaries**: what this folder owns / does *not* own
* **Entry points**: “start reading here” files (e.g., `main.ts`, `index.ts`, `app/`, `src/server.ts`, `routes.ts`, `handler.go`)
* **Public APIs**: exports, interfaces, endpoints
* **Invariants & gotchas**: constraints that must not be violated
* **How to validate**: tests, linters, dev commands

If you try to create a markdown file for *every* folder/file, you’ll:

* drown in maintenance
* tempt agents to load too much at once
* still miss the “how to navigate” intent

So: **write context only at architectural seams**, and let code search + reading do the rest.

---

## A scalable 3-layer context architecture

### Layer 1: Root “map + rules” (small and stable)

Keep `AGENTS.md` at repo root short—like an agent README—covering:

* repo purpose and top-level structure
* global build/test commands
* cross-cutting conventions
* where deeper docs live (links/paths)
* a strict policy: “do not load everything; load on demand”

This is aligned with the intent of `AGENTS.md` as an agent-focused README. ([Agents][1])

**In OpenCode:** `AGENTS.md` is the rules/instructions file and `/init` can generate a starter one by scanning the repo. ([OpenCode][2])

---

### Layer 2: Per-domain `AGENTS.md` at major seams (only where it matters)

Add `AGENTS.md` files **only** at “big boundaries”, e.g.:

* `packages/payments/AGENTS.md`
* `services/identity/AGENTS.md`
* `infra/AGENTS.md`
* `mobile/AGENTS.md`

Each one should be *short*, focusing on:

* what this domain is responsible for
* entry points
* dependency rules (what it may import/call)
* “when editing X, update Y”
* how to run tests for that area

**OpenCode discovery behavior matters here:** it looks for local rule files by traversing up from the current directory, and the first match wins for local rules. ([OpenCode][2])
That’s useful: it naturally keeps context scoped to “where you are working”.

---

### Layer 3: Deeper docs are *referenced*, not auto-loaded

Put bulky details in separate markdowns (not shoved into every prompt):

* `docs/architecture/*.md`
* `docs/adr/*.md`
* `docs/guidelines/*.md`
* `.agents/` (or `.opencode/skills/`, see below)

Then teach the agent to **lazy load** them only when needed.

OpenCode explicitly supports two patterns for this:

1. **Use `opencode.json` “instructions”** for a *small* set of always-relevant docs (engineering standards, repo map, etc.). OpenCode combines these instruction files with `AGENTS.md`. ([OpenCode][2])
2. **Or** keep references in `AGENTS.md` and instruct the agent to read them *on a need-to-know basis* (OpenCode docs even give an explicit “do NOT preemptively load all references” pattern). ([OpenCode][2])

---

## How to avoid context overflow in practice

### 1) Keep “always loaded” context tiny

A good rule of thumb:

* Root `AGENTS.md`: **~50–200 lines**
* Domain `AGENTS.md`: **~50–150 lines**
* Anything longer becomes a “reference doc” and should be loaded only when needed

This forces discipline: your context stays high-signal.

---

### 2) Use `opencode.json` for *global* invariants, not for per-package dumps

OpenCode lets you include extra instruction files via `opencode.json` and even glob them. ([OpenCode][2])
But in a huge monorepo, **avoid globs that include dozens/hundreds of files** (e.g., `packages/*/AGENTS.md`) unless you are certain they’re tiny and you’ve tested context size.

A safer pattern:

* `opencode.json` includes only:

  * `docs/repo-map.md`
  * `docs/engineering-standards.md`
  * `docs/testing.md`

Then **local** `AGENTS.md` handles the subtree rules.

Example (minimal):

```json
{
  "$schema": "https://opencode.ai/config.json",
  "instructions": [
    "docs/repo-map.md",
    "docs/engineering-standards.md",
    "docs/testing.md"
  ]
}
```

This way, no matter which local `AGENTS.md` wins, the global invariants still show up via combined instructions. ([OpenCode][2])

---

### 3) Write a “Repo Map” that is intentionally shallow

Create `docs/repo-map.md` that answers only:

* What are the big packages/services?
* What is each one for (1–2 lines)?
* Where do you start reading?
* Who owns it / where are the docs?
* What are the key runtime boundaries?

This gives agents a compass without pulling in the world.

---

### 4) Adopt “lazy loading” as an explicit rule

Put this in your root `AGENTS.md`:

* “Search first, then read only the minimal files needed”
* “Only load referenced docs when directly relevant”
* “Prefer entry points + public interfaces”
* “Summarize findings before editing”

OpenCode’s own docs recommend teaching the agent not to load all referenced files preemptively. ([OpenCode][2])

---

## Use Agent Skills for heavy, reusable knowledge (best way to prevent overflow)

If you want agents to have **deep guidance** (architecture walkthroughs, release process, testing philosophy, “how to debug prod locally”, etc.) without bloating every task, use **Agent Skills**.

In OpenCode:

* Skills live in `.opencode/skills/<name>/SKILL.md` (project) or `~/.config/opencode/skills/<name>/SKILL.md` (global). ([OpenCode][3])
* They’re **loaded on-demand** via the native `skill` tool: agents can see what skills exist and only pull full contents when needed. ([OpenCode][3])

This is almost tailor-made for your problem: keep the baseline context slim, and let agents “equip” the right skill when working in a domain.

**Example skills that pay off in monorepos:**

* `repo-navigation` — how to find entry points, how to trace flows, how to pick minimal files
* `testing-strategy` — how to run tests by area, when to add integration tests, fixtures rules
* `api-conventions` — error shape, logging, auth patterns, versioning rules
* `frontend-architecture` — state mgmt, routing, component conventions

---

## A concrete template you can copy

### Root `AGENTS.md` (keep it short)

```md
# Monorepo agent guide

## Goal
Help agents make correct, minimal, verifiable changes without loading the entire repo.

## Repo map
- See: docs/repo-map.md (high-level map and entrypoints)

## Setup / verify
- Install: <...>
- Build: <...>
- Test: <...>
- Lint: <...>

## How to navigate (CRITICAL)
- Do NOT try to load the whole repo.
- Start from the relevant domain entrypoint + public interfaces.
- Use search to locate symbols before reading files.
- Only load referenced docs when relevant to the task.

## Where domain rules live
- packages/<domain>/AGENTS.md describes local invariants & tests.
- services/<svc>/AGENTS.md describes runtime behavior & APIs.
```

### Domain `packages/foo/AGENTS.md`

```md
# packages/foo

## Purpose
<1–2 lines>

## Owns / Does not own
- Owns: <...>
- Does not own: <...>

## Entry points
- src/index.ts
- src/server.ts

## Key flows
- <short bullets>

## Invariants / gotchas
- <short bullets>

## How to test
- unit: <cmd>
- integration: <cmd>
```

---

## A workflow that keeps the agent inside a “context budget”

When you ask an agent to work:

1. **Tell it the scope** (paths or package name)
2. Require it to:

   * identify likely entry points
   * read only those + immediate neighbors
   * summarize its understanding
3. Only then implement changes + run targeted tests

This single habit prevents “context explosion” more than any doc structure.

---

## Key takeaway

Your “markdown next to each folder” idea is good **if** you treat those files as **on-demand shards**, not as something that gets loaded wholesale.

For OpenCode specifically, the strongest combo is:

* Root `AGENTS.md` = short global rules + navigation policy ([OpenCode][2])
* Domain `AGENTS.md` only at major seams (keeps scope tight)
* `opencode.json` `instructions` = a few always-relevant docs (repo map, standards) ([OpenCode][2])
* **Agent Skills** for deep/reusable guidance loaded on-demand ([OpenCode][3])

If you want, I can propose a “minimal set” of where to place domain `AGENTS.md` files in a typical monorepo (and what to put in each) based on your top-level folder structure—just paste your repo’s top 2–3 directory levels (sanitized if needed).

[1]: https://agents.md/ "AGENTS.md"
[2]: https://opencode.ai/docs/rules/ "Rules | OpenCode"
[3]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"

Here’s a **minimal, scalable placement plan** you can apply even before you paste your real tree. I’ll give you:

1. the **smallest set of “context shards”** that covers 90% of navigation needs
2. **exactly what to put in each shard** (templates)
3. two wiring options for **OpenCode**, depending on whether you want **one root `AGENTS.md`** or **multiple**

One important OpenCode-specific nuance: OpenCode picks the **first matching local rules file** by traversing **up** from your current directory; it does **not** merge multiple local `AGENTS.md` files in the same run. Also, any files listed in `opencode.json` under `instructions` get **combined** with your `AGENTS.md`. ([OpenCode][1])

---

## The minimal set of “context shards” to add

### Place shards at *boundaries*, not everywhere

Only add context files at directories that represent a boundary like:

* a deployable/runtime unit (app/service)
* a separately-built artifact (package/library)
* infra/CI boundaries
* a major “domain” that owns business logic

### Recommended minimum placements (typical monorepo)

You almost always want these **6–9** shard locations:

1. **Repo root**

* `/AGENTS.md` (agent rules + navigation policy)
* `/docs/repo-map.md` (a shallow map; 1–2 lines per major area)

2. **Each deployable “thing”**

* `apps/<app>/CONTEXT.md` or `apps/<app>/AGENTS.md`
* `services/<svc>/CONTEXT.md` or `services/<svc>/AGENTS.md`
* `cmd/<binary>/CONTEXT.md` (Go-style)
* `deploy/<env>/CONTEXT.md` (if env-specific behavior is real)

3. **Each major shared library “platform”**

* `packages/<lib>/CONTEXT.md` (or `libs/<lib>/...`)
  Only do this for big / frequently-touched libs. Don’t do it for tiny helpers.

4. **Infrastructure**

* `infra/CONTEXT.md` (or `infrastructure/…`)
* optionally `.github/CONTEXT.md` (CI workflows and release rules)

5. **Tooling / scripts**

* `scripts/CONTEXT.md` or `tools/CONTEXT.md`
  (especially if scripts mutate code, generate files, or publish artifacts)

6. **Cross-cutting “standards”**

* `docs/engineering-standards.md`
* `docs/testing.md`
* `docs/architecture.md` (or ADR index)

Then load those standards **globally** via `opencode.json` instructions. ([OpenCode][1])

---

## The best wiring for OpenCode: pick one of these two options

### Option A (recommended): **One** `AGENTS.md` + many `CONTEXT.md` shards

This avoids OpenCode’s “nearest `AGENTS.md` wins” behavior and keeps your root policy always active. ([OpenCode][1])

**Files:**

* `/AGENTS.md` (root)
* `*/CONTEXT.md` at boundaries (apps/services/packages/infra)

**Root `AGENTS.md` includes a rule like:**

* “When working inside a boundary directory, read the nearest `CONTEXT.md` for that boundary, but only if relevant.”

This matches OpenCode’s own guidance style for “manual external loading” + lazy loading. ([OpenCode][1])

---

### Option B: multiple `AGENTS.md` (only if you *really* want local overrides)

If you put `AGENTS.md` inside `apps/web/`, OpenCode will load *that* as the local rules and **not** the root `AGENTS.md` as local rules for that session. ([OpenCode][1])

So if you choose this option, do this:

* Put your “always-on” rules in a separate doc (e.g. `docs/agent-global.md`)
* Load it via `opencode.json` → `"instructions": [...]`
* Then each local `AGENTS.md` can stay short and focused

OpenCode explicitly supports “custom instruction files” via `opencode.json`, and combines those instruction files with `AGENTS.md`. ([OpenCode][1])

---

## What to put in each shard (copy/paste templates)

### 1) Root `/AGENTS.md` (keep it short; the “compass”)

```md
# Agent Guide (Monorepo)

## Critical navigation rules
- Do NOT load the whole repo.
- Start from an entry point + public interfaces, then expand outward only as needed.
- Prefer reading: (1) boundary CONTEXT.md, (2) entrypoint files, (3) public APIs, (4) tests.

## Where context lives
- Shallow map: docs/repo-map.md
- Boundary context: look for nearest CONTEXT.md in the area you are editing.
- Deep standards: docs/engineering-standards.md, docs/testing.md, docs/architecture.md
  - Load only when relevant to the task.

## How to validate changes
- Always run the narrowest relevant test command for the area changed.
- If a boundary has a test command in CONTEXT.md, use that first.
```

Why: `AGENTS.md` is meant to be a predictable “README for agents.” ([Agents][2])

---

### 2) `docs/repo-map.md` (shallow map: 1–2 lines each)

```md
# Repo Map (Shallow)

## apps/
- apps/web: Customer-facing web UI. Entry: apps/web/src/main.tsx
- apps/admin: Admin console. Entry: apps/admin/src/main.tsx

## services/
- services/api: Public HTTP API. Entry: services/api/src/server.ts
- services/worker: Async jobs. Entry: services/worker/src/worker.ts

## packages/
- packages/core: Shared domain primitives (types, validation, business rules).
- packages/ui: Shared UI components for apps/*.

## infra/
- Terraform/Pulumi/CDK/etc. Used to provision cloud resources.
```

---

### 3) Boundary `CONTEXT.md` for an app/service (deployable unit)

Put this in `apps/<name>/CONTEXT.md` or `services/<name>/CONTEXT.md`:

```md
# <boundary name>

## Purpose (2 lines max)
What this app/service does and for whom.

## Entry points
- Runtime entry: <path>
- Routing: <path>
- Config: <path>

## Depends on
- Internal deps: packages/core, packages/<...>
- External deps: <db>, <queue>, <third-party API>

## Owns / does not own
- Owns: <things this boundary is responsible for>
- Does not own: <things to avoid changing here>

## Key flows (bullets)
- Request -> auth -> handler -> persistence
- Job -> dedupe -> process -> emit event

## Invariants / gotchas
- <example: "All writes must go through RepositoryX">
- <example: "Timezone handling must be UTC only">

## How to test (copy-paste commands)
- Unit: <cmd>
- Integration: <cmd>
- Local run: <cmd>
```

This keeps context high-signal: entry points + invariants + how to validate.

---

### 4) Boundary `CONTEXT.md` for a shared library (package)

`packages/<lib>/CONTEXT.md`:

```md
# packages/<lib>

## Purpose
What capabilities this library provides.

## Public API surface
- Main exports: <path>
- Key types/interfaces: <path>

## Dependency rules
- May import: <allowed>
- Must not import: <forbidden> (to prevent cycles)

## Common usage
- Example import paths / patterns

## Change checklist
- If you change X, update Y
- Versioning / changelog rules (if any)

## Tests
- <cmd>
```

---

### 5) Infra shard `infra/CONTEXT.md`

```md
# infra/

## What lives here
IaC for <cloud>, environments <dev/stage/prod>

## Entry points
- <main stack file>
- <modules folder>

## Safety rules
- Never apply to prod from local unless explicit.
- Where secrets live (and where they must NOT live)

## Validation
- <fmt/lint cmd>
- <plan cmd>
```

---

### 6) Tooling shard `scripts/CONTEXT.md`

```md
# scripts/

## What scripts are safe to run
- Safe/read-only: <...>
- Mutating/generating: <...>

## Common workflows
- Generate clients: <cmd>
- Update snapshots: <cmd>

## Gotchas
- Requires env vars: <...>
- Writes files to: <...>
```

---

## Keeping the context from overflowing: the “budget rule”

Use a strict writing constraint:

* **Root AGENTS.md**: 100–200 lines max
* **Any CONTEXT.md shard**: 60–150 lines max
* **If it’s longer** → move details into `docs/...` and reference it (lazy-load)

OpenCode even shows a pattern for “manual external loading” and explicitly tells agents **not** to preemptively load all referenced docs. ([OpenCode][1])

---

## For deep knowledge, prefer Skills over stuffing docs everywhere

When you have content that’s important but bulky (release process, debugging playbook, migrations, “how we do auth”, etc.), put it in an **OpenCode Agent Skill** instead of bloating repo-wide context.

OpenCode looks for skills in `.opencode/skills/<name>/SKILL.md` (and also global locations), and skills are loaded **on-demand** via the `skill` tool. ([OpenCode][3])

Suggested skills for monorepos:

* `repo-navigation` (how to trace flows, find entry points)
* `testing-strategy` (what to run and when)
* `architecture-overview` (deep system mental model)
* `release-process` (tags, changelog, CI gates)

---

## A small but important security note

Some tools treat `AGENTS.md` as **instructions**, not “just docs.” That means changes to these files should be reviewed like code changes (especially in public repos / PRs). ([prompt.security][4])

---

## If you paste your top-level tree, I’ll tailor the exact placements

If you paste just the first 2–3 directory levels (redact names if needed), I’ll respond with:

* the **exact directories** that should get `CONTEXT.md` vs none
* a **one-page repo-map** draft that matches your layout
* the **minimal `opencode.json` instructions list** for your repo

[1]: https://opencode.ai/docs/rules/ "Rules | OpenCode"
[2]: https://agents.md/?utm_source=chatgpt.com "AGENTS.md"
[3]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[4]: https://prompt.security/blog/when-your-repo-starts-talking-agents-md-and-agent-goal-hijack-in-vs-code-chat "VS Code AGENTS.MD: Hidden Agent Instructions and Data Risk"

Below is a **mock monorepo** (TypeScript + Node) showing:

* **where to put the context files** (`AGENTS.md`, boundary `CONTEXT.md`, small global docs)
* **what to write in each**
* an **`opencode.jsonc`** that creates an **`explore` agent** whose job is *to figure out which files matter and what depends on what*, while staying **read‑only**.

OpenCode details referenced here (agents, rules, instructions, tools, skills) are from the OpenCode docs. ([OpenCode][1])

---

## 1) Mock monorepo layout

```txt
acme-commerce/
  opencode.jsonc
  AGENTS.md

  docs/
    repo-map.md
    dependency-rules.md
    testing.md
    architecture.md

  prompts/
    explore-agent.txt

  .opencode/
    skills/
      repo-navigation/
        SKILL.md
      dependency-mapping/
        SKILL.md

  apps/
    web/
      CONTEXT.md
      src/
        app.tsx
        routes.ts
        pages/checkout.tsx
    admin/
      CONTEXT.md
      src/
        app.tsx

  services/
    api/
      CONTEXT.md
      src/
        server.ts
        routes/
          checkout.ts
          users.ts
        domain/
          checkoutService.ts
    worker/
      CONTEXT.md
      src/
        worker.ts
        jobs/
          sendReceipt.ts

  packages/
    core/
      CONTEXT.md
      src/
        money.ts
        checkout.ts
        user.ts
    db/
      CONTEXT.md
      src/
        prisma.ts
        checkoutRepo.ts
    ui/
      CONTEXT.md
      src/
        Button.tsx
        CheckoutForm.tsx

  infra/
    CONTEXT.md
    terraform/
      main.tf

  scripts/
    CONTEXT.md
    gen-openapi.ts

  package.json
  pnpm-workspace.yaml
  tsconfig.base.json
```

The key is: **few global docs**, and **boundary `CONTEXT.md` only at big seams** (apps/services/packages/infra/scripts).

---

## 2) Root `AGENTS.md` (policy + how context is structured)

> File: `acme-commerce/AGENTS.md`

```md
# Acme Commerce Monorepo – Agent Instructions

## Prime directive
- Do NOT load the whole repo.
- Use progressive disclosure:
  1) docs/repo-map.md (shallow map)
  2) docs/dependency-rules.md (allowed dependencies)
  3) nearest CONTEXT.md for the boundary you are editing
  4) entrypoint files + public APIs + tests

## Context shards (where to look)
- apps/*/CONTEXT.md: app-specific entry points, UI flows, test commands
- services/*/CONTEXT.md: runtime entry points, endpoints/jobs, invariants
- packages/*/CONTEXT.md: public APIs, layering rules, change checklist
- infra/CONTEXT.md: IaC entry points + safety rules
- scripts/CONTEXT.md: safe vs mutating scripts, how to run

## How to explore safely
Use the @explore agent first when you are unsure:
- It must output:
  - Working set: the minimal files/dirs to read/edit
  - Dependency notes: what layers/packages are affected
  - Test commands: the narrowest checks to run
- It must NOT edit code.

## Coding standards (high signal only)
- Keep module boundaries intact (see docs/dependency-rules.md).
- Prefer changing packages/* over duplicating logic in apps/services.
- When you change public API in packages/*, update affected services/apps.

## When in doubt
- Ask for a precise target (service/app/package) if the request is ambiguous.
```

Why this works with OpenCode: it keeps the “always-loaded” rules tiny, and pushes detail into boundary files + optional skills. OpenCode supports `AGENTS.md` as project rules, and recommends keeping rules modular via `instructions` too. ([OpenCode][1])

---

## 3) Shallow repo map (1–2 lines per area)

> File: `docs/repo-map.md`

```md
# Repo Map (shallow)

## apps/
- apps/web: Customer storefront (React). Entry: apps/web/src/app.tsx
- apps/admin: Internal admin portal. Entry: apps/admin/src/app.tsx

## services/
- services/api: Public HTTP API (Fastify/Express style). Entry: services/api/src/server.ts
- services/worker: Background job processor. Entry: services/worker/src/worker.ts

## packages/
- packages/core: Domain types + pure business rules (no IO).
- packages/db: Database access layer (Prisma adapters/repos).
- packages/ui: Shared UI components for apps/*.

## infra/
- Terraform for cloud resources. Entry: infra/terraform/main.tf

## scripts/
- Build/dev utility scripts (some mutate files).
```

Keep this short enough that it’s safe to always load.

---

## 4) Dependency rules (the “layering contract”)

> File: `docs/dependency-rules.md`

```md
# Dependency rules (must follow)

## Layering
- apps/* can depend on: packages/core, packages/ui (and call services/api via HTTP).
- services/* can depend on: packages/core, packages/db.
- packages/ui can depend on: packages/core.
- packages/db can depend on: packages/core.
- packages/core must be pure: NO imports from packages/db or packages/ui.

## Forbidden
- services/* must NOT import apps/*.
- packages/* must NOT import apps/* or services/*.
- packages/core must NOT import database, network, filesystem.

## Change impact heuristics
- If you change packages/core:
  - likely impacts services/api, services/worker, and apps/* types.
- If you change packages/db:
  - impacts services/* only (apps should never touch db directly).
- If you change packages/ui:
  - impacts apps/* only.

## “Start reading here” per domain
- Checkout flow:
  - apps/web/src/pages/checkout.tsx
  - packages/ui/src/CheckoutForm.tsx
  - services/api/src/routes/checkout.ts
  - services/api/src/domain/checkoutService.ts
  - packages/core/src/checkout.ts
  - packages/db/src/checkoutRepo.ts
```

This one doc is incredibly effective for “which files should I touch?” decisions.

---

## 5) Testing doc (only commands; no essays)

> File: `docs/testing.md`

```md
# Testing & verification

## Root (common)
- Install: pnpm install
- Typecheck: pnpm -w typecheck
- Lint: pnpm -w lint
- All unit tests: pnpm -w test

## Targeted
- Web app: pnpm --filter @acme/web test
- API service: pnpm --filter @acme/api test
- Worker: pnpm --filter @acme/worker test
- Core package: pnpm --filter @acme/core test
```

---

## 6) Boundary context examples (the “closest shard wins”)

### 6.1 `services/api/CONTEXT.md`

```md
# services/api

## Purpose
HTTP API for checkout + user identity. Owns request validation and orchestration.

## Entry points
- Server bootstrap: src/server.ts
- Routes registry: src/routes/*.ts

## Depends on
- packages/core (domain rules/types)
- packages/db (repositories)

## Owns / does not own
- Owns: API request/response shapes, auth middleware, orchestration logic.
- Does not own: pure domain rules (packages/core), DB schema details (packages/db).

## Key flows
- Checkout:
  src/routes/checkout.ts -> src/domain/checkoutService.ts -> packages/core -> packages/db

## Invariants / gotchas
- Domain rules live in packages/core. API layer should not re-encode business logic.
- All writes go through packages/db repos (no raw SQL here).

## Tests
- Unit: pnpm --filter @acme/api test
- Contract (if present): pnpm --filter @acme/api test:contract
```

### 6.2 `apps/web/CONTEXT.md`

```md
# apps/web

## Purpose
Customer storefront UI.

## Entry points
- App: src/app.tsx
- Routes: src/routes.ts
- Checkout page: src/pages/checkout.tsx

## Depends on
- packages/ui, packages/core

## Invariants
- No direct DB access (ever).
- API calls go via services/api HTTP client wrapper (if present).

## Tests
- pnpm --filter @acme/web test
```

### 6.3 `packages/core/CONTEXT.md`

```md
# packages/core

## Purpose
Pure domain model + business rules. No IO.

## Public API
- checkout rules: src/checkout.ts
- money utilities: src/money.ts
- user model: src/user.ts

## Forbidden imports
- No packages/db
- No packages/ui
- No node fs/net

## Change checklist
- If you change exported types:
  - update services/api DTO mapping
  - update apps/web type usage
- Add/adjust unit tests in this package.

## Tests
- pnpm --filter @acme/core test
```

### 6.4 `packages/db/CONTEXT.md`

```md
# packages/db

## Purpose
DB adapters/repos. Owns Prisma client wiring and persistence logic.

## Entry points
- Prisma client: src/prisma.ts
- Checkout repo: src/checkoutRepo.ts

## Depends on
- packages/core (domain types)

## Invariants
- Return domain types from packages/core (or explicit DTOs), not Prisma models.

## Tests
- pnpm --filter @acme/db test
```

### 6.5 `infra/CONTEXT.md`

```md
# infra

## Purpose
Terraform for cloud resources (db, queues, networking).

## Safety
- Never apply to prod from local by default.
- Secrets must not be committed.

## Entry points
- terraform/main.tf

## Validation
- terraform fmt -recursive
- terraform validate
```

---

## 7) On-demand “Skills” (deep guidance without bloating prompts)

OpenCode skills live at `.opencode/skills/<name>/SKILL.md` and are **loaded on-demand** via the `skill` tool (so they don’t inflate every session). ([OpenCode][2])

### 7.1 Repo navigation skill

> File: `.opencode/skills/repo-navigation/SKILL.md`

```md
---
name: repo-navigation
description: Find entry points, minimal working set, and validation commands in this monorepo
compatibility: opencode
---

## What I do
- Identify the smallest set of files to read for a task (entry points + interfaces + tests).
- Recommend the narrowest commands to validate a change.

## Heuristics
- Prefer boundary CONTEXT.md and docs/dependency-rules.md before scanning code.
- Track imports from apps/services/packages to infer dependency impact.
```

### 7.2 Dependency mapping skill

> File: `.opencode/skills/dependency-mapping/SKILL.md`

```md
---
name: dependency-mapping
description: Build a lightweight dependency graph (imports + runtime calls) and report impact radius
compatibility: opencode
---

## What I do
- Build an adjacency list of package/service deps by scanning imports.
- Explain which layers are impacted by a proposed change.

## Output format
- Direct deps
- Transitive deps (1–2 hops)
- Potentially affected tests/commands
```

---

## 8) `opencode.jsonc`: add an `explore` agent that is read-only and dependency-aware

OpenCode supports `opencode.json` / `opencode.jsonc` with the `$schema` field. ([OpenCode][3])
OpenCode recommends using the `instructions` field to include additional rule/docs files, and **combines instruction files with your `AGENTS.md`**. ([OpenCode][1])
Agents can be configured in `opencode.json` with per-agent `description`, `prompt`, `model`, `tools`, `permission`, and `steps` (iteration limit). ([OpenCode][4])

> File: `opencode.jsonc`

```jsonc
{
  "$schema": "https://opencode.ai/config.json",

  // Keep ALWAYS-LOADED context small.
  "instructions": [
    "docs/repo-map.md",
    "docs/dependency-rules.md",
    "docs/testing.md"
  ],

  // Default permissions (safe-ish defaults).
  // OpenCode permissions can be allow/ask/deny (notably for edit/bash/webfetch). :contentReference[oaicite:6]{index=6}
  "permission": {
    "edit": "ask",
    "bash": "ask",
    "webfetch": "deny",

    // Optional: skill access control by patterns (skills can be allow/ask/deny). :contentReference[oaicite:7]{index=7}
    "skill": {
      "*": "ask",
      "repo-navigation": "allow",
      "dependency-mapping": "allow",
      "experimental-*": "deny"
    }
  },

  // Default tool availability (global). Agent-specific overrides can disable tools. :contentReference[oaicite:8]{index=8}
  "tools": {
    "read": true,
    "list": true,
    "glob": true,
    "grep": true,
    "lsp": true,       // if you enabled the experimental lsp tool in your env
    "bash": true,
    "edit": true,
    "write": true,
    "skill": true,
    "webfetch": false  // keep off globally to avoid accidental browsing
  },

  "agent": {
    "explore": {
      "description": "Read-only repo exploration: identify working set + dependencies + test commands",
      "mode": "all",

      // Deterministic, low-cost exploration
      "temperature": 0.1,

      // Limits how many agentic iterations happen before it must summarize. :contentReference[oaicite:9]{index=9}
      "steps": 8,

      // Prompt file support. :contentReference[oaicite:10]{index=10}
      "prompt": "{file:./prompts/explore-agent.txt}",

      // Hard read-only stance: no edits/writes for this agent. :contentReference[oaicite:11]{index=11}
      "tools": {
        "edit": false,
        "write": false,
        "patch": false,
        "webfetch": false,

        "read": true,
        "list": true,
        "glob": true,
        "grep": true,
        "lsp": true,
        "bash": true,
        "skill": true
      },

      // Ensure edits are denied even if a tool slips through
      "permission": {
        "edit": "deny",
        "webfetch": "deny",

        // Allow only a small “safe” bash set; everything else asks.
        // Command pattern rules with wildcards are supported. :contentReference[oaicite:12]{index=12}
        "bash": {
          "*": "ask",
          "git status*": "allow",
          "git diff*": "allow",
          "git log*": "allow",
          "pnpm -w*": "allow"
        },

        "skill": {
          "*": "deny",
          "repo-navigation": "allow",
          "dependency-mapping": "allow"
        }
      }
    }
  }
}
```

### Why this config helps with “which files should I touch?”

* The `instructions` files are *small and global*, so the agent always has the repo map + dependency contract + test commands. ([OpenCode][1])
* The `@explore` agent is **forced read-only** (`tools.edit=false`, `permission.edit=deny`), so it can’t blow your repo up while “learning.” ([OpenCode][4])
* It’s set up to use **search/list/grep/lsp** to build a minimal working set and dependency notes, rather than reading everything.

---

## 9) The explore agent prompt (what it must output)

> File: `prompts/explore-agent.txt`

```txt
You are the Explore Agent for a large monorepo.

MISSION:
1) Identify the MINIMAL working set of files/directories relevant to the user’s request.
2) Explain dependencies and impact radius using docs/dependency-rules.md and actual imports.
3) Recommend the narrowest test commands from docs/testing.md or boundary CONTEXT.md.
4) You MUST NOT edit code.

PROCESS (progressive disclosure):
- First: consult docs/repo-map.md and docs/dependency-rules.md (already in context).
- Then: find the most relevant boundary (apps/*, services/*, packages/*, infra/*, scripts/*).
- Read ONLY the nearest CONTEXT.md for that boundary.
- Use grep/glob to find entrypoints and import chains.
- If still unclear, use lsp (if available) to locate references/definitions.
- Stop once you can name a working set. Do not keep scanning.

OUTPUT FORMAT (required):
## Working set
- Files to read (max 10)
- Files likely to edit (max 10)
- Files to avoid (if any)

## Dependency notes
- Direct dependencies
- Transitive dependencies (1–2 hops)
- Boundary/layer rules that constrain the change

## Validation
- Exact commands to run (minimal first)

## Open questions
- Only if essential (max 3)
```

---

## 10) Example: how this behaves in practice

If you ask:

> “Add a `phoneNumber` to checkout and store it”

`@explore` should return something like:

* **Working set**

  * `apps/web/src/pages/checkout.tsx`
  * `packages/ui/src/CheckoutForm.tsx`
  * `services/api/src/routes/checkout.ts`
  * `services/api/src/domain/checkoutService.ts`
  * `packages/core/src/checkout.ts`
  * `packages/db/src/checkoutRepo.ts`
* **Dependency notes**

  * You must add field in `packages/core` first (pure type/rules), then map through API, then store via `packages/db`
  * Apps must not touch DB directly (per dependency rules)
* **Validation**

  * `pnpm --filter @acme/core test`
  * `pnpm --filter @acme/api test`
  * `pnpm --filter @acme/web test`

…and it should *not* edit anything.

---

If you want, paste (sanitized) **your repo’s top-level tree** (2–3 levels), and I’ll produce the same package-by-package placement plan and draft **real** `repo-map.md` + `dependency-rules.md` that matches your exact boundaries.

[1]: https://opencode.ai/docs/rules/ "Rules | OpenCode"
[2]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[3]: https://opencode.ai/docs/config/ "Config | OpenCode"
[4]: https://opencode.ai/docs/agents/ "Agents | OpenCode"


Below is a **step-by-step guide** you can apply to any huge monorepo to make an OpenCode agent reliably:

* **navigate** without overflowing context,
* **pick the correct files** to analyze,
* **explain what each file/folder does**, and
* set you up for the next steps: **bug finding → commits → PRs → auto-docs → auto-CR**.

This is built around OpenCode’s primitives: `AGENTS.md` rules, `opencode.json` instructions + permissions, optional local rules, and on-demand Skills. ([opencode.ai][1])

---

## Step 0 — Decide your “context strategy” (the core idea)

Use **progressive disclosure**:

1. **Small always-loaded compass** (root rules + shallow repo map)
2. **Boundary context shards** (only at big seams: apps/services/packages/infra/scripts)
3. **Deep knowledge as on-demand Skills** (loaded only when needed)

This prevents context overflow while still making agents effective.

---

## Step 1 — Add a tiny root `AGENTS.md` (navigation policy)

Create `/AGENTS.md` at repo root. Keep it short (100–200 lines). It should say:

* “don’t load the whole repo”
* where context lives (`docs/repo-map.md`, `docs/dependency-rules.md`, nearest `CONTEXT.md`)
* required exploration output format (working set, deps, tests)
* “read-only explore first; edit later”

OpenCode uses `AGENTS.md` as project rules and even has `/init` to generate a starter. ([opencode.ai][1])

**Template (minimal):**

```md
# Agent Guide (Monorepo)

## Critical navigation rules
- Do NOT load the whole repo.
- Start with docs/repo-map.md and docs/dependency-rules.md.
- Then read only the nearest boundary CONTEXT.md relevant to the task.
- Expand outward from entry points and public APIs only as needed.

## Required outputs when exploring
- Working set (files to read / likely edit)
- Dependency notes (direct + 1–2 hop transitive)
- Validation commands (minimal first)

## Safety
- Use @explore for read-only analysis when uncertain.
```

---

## Step 2 — Create 2–3 small global docs (always-loaded, high signal)

Put these under `docs/`:

1. `docs/repo-map.md`

   * 1–2 lines per top-level area (apps/services/packages/infra/scripts)
   * list key entry points

2. `docs/dependency-rules.md`

   * layering rules (who may import whom)
   * “start reading here” for common flows

3. `docs/testing.md`

   * only commands (root + per boundary)

These are “the compass.” They should be short enough to always include.

---

## Step 3 — Add boundary `CONTEXT.md` shards only at big seams

Instead of “a markdown next to every folder,” add `CONTEXT.md` only in places that represent a **boundary**:

* `apps/<app>/CONTEXT.md`
* `services/<svc>/CONTEXT.md`
* `packages/<pkg>/CONTEXT.md` (only for major pkgs)
* `infra/CONTEXT.md`
* `scripts/CONTEXT.md`

Each `CONTEXT.md` should contain:

* purpose (2 lines)
* entry points (start files)
* dependencies (allowed + important)
* “owns / does not own”
* invariants / gotchas
* test commands

Keep each one short (60–150 lines). Anything longer becomes a doc or a skill.

---

## Step 4 — Put deeper guidance into Skills (so it doesn’t bloat context)

Create `.opencode/skills/<name>/SKILL.md` for things you want agents to reuse but not always load:

* `repo-navigation`
* `dependency-mapping`
* `testing-strategy`
* `bug-hunting-playbook` (later)

OpenCode Skills are discovered and loaded **on-demand** via the `skill` tool, which is ideal for huge repos. ([opencode.ai][2])

---

## Step 5 — Wire global docs into OpenCode with `opencode.json`

Use `instructions` in `opencode.json` to always load your small global docs alongside `AGENTS.md`. OpenCode combines these instruction files with the agent context. ([opencode.ai][1])

**Example `opencode.jsonc`:**

```jsonc
{
  "$schema": "https://opencode.ai/config.json",

  "instructions": [
    "docs/repo-map.md",
    "docs/dependency-rules.md",
    "docs/testing.md"
  ],

  "permission": {
    "read": "allow",
    "edit": "ask",
    "bash": "ask",
    "webfetch": "deny"
  }
}
```

Permissions exist to require approval (“ask”), allow, or deny actions. ([opencode.ai][3])
Also note: file modification tools (`edit`, `write`, `patch`, etc.) are governed by the `edit` permission. ([opencode.ai][4])

---

## Step 6 — Create a dedicated read-only `explore` agent

Make an agent whose *only job* is:

* identify the minimal working set
* map dependencies
* explain what each part does
* recommend the narrowest validation commands

…and **cannot edit files**.

OpenCode agents can be configured (including permissions) in config. ([opencode.ai][5])

**Example agent config:**

```jsonc
{
  "agent": {
    "explore": {
      "description": "Read-only exploration: working set + dependencies + explanation",
      "prompt": "{file:./prompts/explore-agent.txt}",
      "steps": 8,
      "permission": {
        "edit": "deny",
        "webfetch": "deny",
        "bash": "ask"
      }
    }
  }
}
```

(Keep `bash` as ask until you trust it; later you can whitelist safe patterns like `git status*`, `pnpm -w*`.)

---

## Step 7 — Write the `explore-agent` prompt (output contract)

Create `prompts/explore-agent.txt`:

**Must follow progressive disclosure:**

1. read `docs/repo-map.md` + `docs/dependency-rules.md` (already loaded)
2. locate relevant boundary and read nearest `CONTEXT.md`
3. find entry points + import chains with search
4. stop early once minimal working set is clear

**Required output format:**

* Working set (read/edit candidates)
* Dependencies (direct + 1–2 hop)
* Explanation (what each key file does in the flow)
* Validation commands

This output contract is what later enables bug hunting, PRs, doc updates, and CR.

---

## Step 8 — Standard operating procedure for every task

When you give a task to OpenCode, enforce a two-phase flow:

### Phase A: Explore (read-only)

Run `@explore` first.

It returns:

* **Working set** (≤10 files to read, ≤10 likely to edit)
* **Dependency notes**
* **Flow explanation** (input → processing → output)
* **Minimal validation** commands

### Phase B: Build/Fix (edits allowed)

Only after Phase A, switch to your “build/fix” agent/mode and allow edits.

This single discipline is what keeps context under control and reduces wrong-file edits.

---

## Step 9 — Turn exploration outputs into “explain each file/folder” reports

Make the explore agent produce a consistent report section per boundary:

* **Role of folder**
* **Entry points**
* **Public APIs**
* **Key flows**
* **Important invariants**
* **Dependency constraints**
* **Tests**

Over time, you can auto-append these summaries back into the boundary `CONTEXT.md` (in Phase B), creating self-healing documentation.

---

## Step 10 — Extend toward bugs, commits, PRs, auto-docs, auto-CR

Once navigation is solid:

1. Add a `bug-hunting` skill: patterns, sinks/sources, threat model.
2. Add a `change` agent:

   * `permission.edit=ask` initially, later allow with guardrails
3. Add a `pr` agent:

   * writes changelog/summary
   * ensures tests run
4. Add “doc update rules”:

   * if touching entry points/public APIs, update nearest `CONTEXT.md`

When you get there, also consider tightening permissions and command whitelists, since real-world reports show permission edge cases can happen in agent tools. (Not a blocker—just something to be aware of operationally.) ([opencode.ai][3])

---

## The minimal file checklist (copy/paste)

**You create:**

* `/AGENTS.md`
* `/opencode.jsonc`
* `/docs/repo-map.md`
* `/docs/dependency-rules.md`
* `/docs/testing.md`
* `/prompts/explore-agent.txt`
* Boundary shards:

  * `apps/*/CONTEXT.md`
  * `services/*/CONTEXT.md`
  * `packages/*/CONTEXT.md` (major only)
  * `infra/CONTEXT.md`
  * `scripts/CONTEXT.md`
* Optional:

  * `.opencode/skills/repo-navigation/SKILL.md`
  * `.opencode/skills/dependency-mapping/SKILL.md` ([opencode.ai][2])

---

If you paste your repo’s **top 2–3 directory levels**, I’ll turn this into a concrete plan for *your* tree: exactly where the boundary shards should go, and draft the initial `repo-map.md` + `dependency-rules.md` tailored to your layout.

[1]: https://opencode.ai/docs/rules/?utm_source=chatgpt.com "Rules"
[2]: https://opencode.ai/docs/skills/?utm_source=chatgpt.com "Agent Skills"
[3]: https://opencode.ai/docs/permissions/?utm_source=chatgpt.com "Permissions"
[4]: https://opencode.ai/docs/tools/?utm_source=chatgpt.com "Tools"
[5]: https://opencode.ai/docs/agents/?utm_source=chatgpt.com "Agents"


Below is a **complete “OpenCode navigation kit”** for the **xnu** repo, written as if you were adding files *into* `apple-oss-distributions/xnu`. It’s designed so an OpenCode agent can:

* navigate a huge tree without context overflow,
* pick the **right working set** of files,
* explain what it read (folder + file roles + dependencies),
* and set you up for later phases: **bug hunting → commits → PRs → auto docs → auto CR**.

I’m using the repo’s own top-level structure and build entry points from the upstream README (dirs + make targets/flags). ([GitHub][1])
I’m also aligning with OpenCode’s rules/instructions pattern (`AGENTS.md`, `opencode.json` instructions, permissions, agents). ([opencode.ai][2])

---

## 0) What exists in xnu (important boundaries)

Top-level boundaries in this repo include: `bsd`, `osfmk`, `iokit`, `libkern`, `libsa`, `libsyscall`, `libkdd`, `makedefs`, `pexpert`, `security`, `tools`, plus `config`, `SETUP`, `EXTERNAL_HEADERS`, `tests`, `san`, `doc`. ([GitHub][1])
Build flow is driven by `make` with `SDKROOT`, `ARCH_CONFIGS`, `KERNEL_CONFIGS`, etc. ([GitHub][1])

---

## 1) Proposed added file tree (everything you asked for)

```txt
xnu/
  AGENTS.md
  opencode.jsonc

  docs/
    repo-map.md
    dependency-rules.md
    testing.md
    report-format.md
    xnu-build-notes.md

  prompts/
    explore-agent.txt
    explain-folder.txt

  .opencode/
    skills/
      repo-navigation/
        SKILL.md
      dependency-mapping/
        SKILL.md
      xnu-architecture/
        SKILL.md
      xnu-bug-hunting/
        SKILL.md

  # boundary shards (small, one per major boundary)
  bsd/CONTEXT.md
  osfmk/CONTEXT.md
  iokit/CONTEXT.md
  libkern/CONTEXT.md
  pexpert/CONTEXT.md
  security/CONTEXT.md
  makedefs/CONTEXT.md
  tools/CONTEXT.md
  tests/CONTEXT.md
  config/CONTEXT.md
  EXTERNAL_HEADERS/CONTEXT.md
  SETUP/CONTEXT.md
  san/CONTEXT.md
  libsa/CONTEXT.md
  libsyscall/CONTEXT.md
  libkdd/CONTEXT.md
  doc/CONTEXT.md
```

This keeps context **sharded** at repo-defined boundaries, matching how xnu itself describes its tree. ([GitHub][1])

---

## 2) Root rules: `AGENTS.md`

> **File:** `AGENTS.md`

```md
# OpenCode Agent Guide — xnu (Darwin kernel)

## Prime directive (context budget)
- Do NOT load the whole repo.
- Always use progressive disclosure:
  1) docs/repo-map.md (shallow compass)
  2) docs/dependency-rules.md (layering + “start here”)
  3) nearest <boundary>/CONTEXT.md (only for the boundary you’re touching)
  4) then: entry points + public headers + call sites relevant to the task

## Default workflow
When a user asks anything non-trivial:
1) Run @explore (read-only). Produce: working set + dependencies + explanation plan.
2) Only after that, proceed with edits/patches (separate agent or same agent with edit permission).

## What counts as a boundary
Top-level directories like: bsd/, osfmk/, iokit/, libkern/, pexpert/, security/, makedefs/, tools/, tests/.
Also “meta boundaries”: config/, EXTERNAL_HEADERS/, SETUP/, san/, doc/.

## Must-follow safety rules
- @explore MUST NOT edit files.
- Prefer minimal file reads: entry points + the narrowest set that explains the flow.
- Never “summarize the whole kernel.” Focus on the user’s slice (subsystem/flow).

## Output standard (required)
When explaining anything, use docs/report-format.md:
- Scope + assumptions
- Working set (≤10 read, ≤10 likely edit)
- Dependency notes (direct + 1–2 hop)
- Flow walkthrough (step-by-step)
- Risks / bug hypotheses (if asked)
- Validation steps (commands or static checks)
```

OpenCode treats `AGENTS.md` as project rules; you can generate a starter via `/init` and commit it. ([opencode.ai][2])

---

## 3) OpenCode config: `opencode.jsonc`

> **File:** `opencode.jsonc`

```jsonc
{
  "$schema": "https://opencode.ai/config.json",

  // Keep always-loaded context small and stable.
  "instructions": [
    "docs/repo-map.md",
    "docs/dependency-rules.md",
    "docs/testing.md",
    "docs/report-format.md"
  ],

  // Safe defaults.
  "permission": {
    "edit": "ask",
    "bash": "ask",
    "webfetch": "deny",
    "skill": {
      "*": "ask",
      "repo-navigation": "allow",
      "dependency-mapping": "allow",
      "xnu-architecture": "allow",
      "xnu-bug-hunting": "ask"
    }
  },

  "agent": {
    "explore": {
      "description": "Read-only explorer: determine working set, dependencies, and explain the slice of xnu relevant to the request",
      "steps": 10,
      "temperature": 0.1,
      "prompt": "{file:./prompts/explore-agent.txt}",
      "permission": {
        "edit": "deny",
        "webfetch": "deny",
        "bash": "ask",
        "skill": {
          "*": "deny",
          "repo-navigation": "allow",
          "dependency-mapping": "allow",
          "xnu-architecture": "allow"
        }
      }
    }
  }
}
```

This uses OpenCode’s “rules + instruction files” approach and config-driven agents. ([opencode.ai][2])

---

## 4) Always-loaded docs

### 4.1 `docs/repo-map.md` (shallow compass)

```md
# xnu repo map (shallow)

This is a *navigation compass* for agents. Do not expand beyond the task scope.

## Major subsystems (top-level boundaries)
- osfmk/: Mach kernel subsystems (threads, VM, IPC, scheduling).
- bsd/: BSD layer (processes, VFS, sockets, syscalls).
- iokit/: I/O Kit (driver model glue, kernel-side I/O abstractions).
- libkern/: C++ / kernel runtime support used by IOKit and kernel code.
- pexpert/: platform expert (platform/CPU/interrupt/boot interfaces).
- security/: MAC framework interfaces and implementation.
- makedefs/: top-level build rules/defines.

## Supporting / meta boundaries
- config/: exported API/configurations for arch/platform.
- EXTERNAL_HEADERS/: headers sourced from other projects to avoid build cycles.
- SETUP/: tooling for configuring/versioning/kext symbol management.
- libsa/: kernel bootstrap/startup support.
- libsyscall/: syscall library interface for user space.
- libkdd/: user library for parsing kernel data.
- san/: sanitizer-related kernel support.
- tools/: utilities for testing/debugging/profiling kernel.
- tests/: kernel tests.
- doc/: documentation.

## Build entry (high-level)
- Root Makefile + makedefs define build behavior.
- Core build interface uses make variables: SDKROOT, ARCH_CONFIGS, KERNEL_CONFIGS.
```

The directory descriptions are directly aligned with xnu’s own README “Source Tree” section. ([GitHub][1])

---

### 4.2 `docs/dependency-rules.md` (layering + “start here”)

```md
# xnu dependency rules (practical, agent-oriented)

These are heuristics to keep exploration bounded; they aren’t strict compile rules.

## Layering mental model (simplified)
- osfmk/ (Mach core) <-> bsd/ (POSIX/BSD personality)
- iokit/ + libkern/ provide driver/runtime support
- pexpert/ is the platform boundary (boot/interrupts/platform hooks)
- security/ provides MAC policy interfaces used across subsystems
- makedefs/ drives build composition

## Allowed exploration pattern
When following a flow:
1) Find entry point (syscall / trap / kext / boot / VM fault / socket op).
2) Stay within the owning subsystem as long as possible.
3) Only cross boundaries when you hit a well-known interface:
   - syscall interface (bsd <-> osfmk + libsyscall)
   - MAC hooks (security/)
   - IOKit class interfaces (iokit/libkern)
   - platform expert calls (pexpert/)
   - exported headers/config (config/ and EXTERNAL_HEADERS/)

## “Start here” pointers by question type
- Syscall / user->kernel boundary: bsd/ + libsyscall/ (then hop as needed)
- Scheduling/threads/IPC/VM internals: osfmk/
- Driver model / kext interaction: iokit/ + libkern/
- Boot/platform/interrupts: pexpert/ + libsa/
- Mandatory Access Control / policy checks: security/

## Stop conditions (to avoid repo-wide reads)
- Once you can name:
  - the entry point,
  - the key call chain (1–2 hops across boundaries),
  - the main data structures involved,
  - and the likely files to change,
  STOP and summarize.
```

---

### 4.3 `docs/testing.md` (commands + tactics)

```md
# Testing & verification (xnu)

## Build interface (from upstream README)
- Build syntax:
  make SDKROOT=<sdkroot> ARCH_CONFIGS=<arch> KERNEL_CONFIGS=<variant>
- Examples:
  make SDKROOT=macosx.internal
  make SDKROOT=macosx.internal ARCH_CONFIGS=X86_64 KERNEL_CONFIGS=DEVELOPMENT
- Install to DSTROOT:
  make install_kernels DSTROOT=/tmp/xnu-dst
- Useful build toggles:
  MAKEJOBS=-jN, BUILD_LTO=0, VERBOSE=YES, LOGCOLORS=y, BUILD_CODE_COVERAGE=1

## Non-build validation (agent-friendly)
- Prefer:
  - grep-based call chain confirmation
  - header/API consistency checks
  - local unit tests under tests/ (when present)
```

Those `make` variables and targets are explicitly documented in the repo’s README. ([GitHub][1])

---

### 4.4 `docs/report-format.md` (how the agent must explain)

```md
# Explanation report format (required)

## 1) Scope
- What subsystem(s) are in scope and why
- What is explicitly out of scope

## 2) Working set
### Files to read (≤10)
- <path> — why
### Files likely to edit (≤10)
- <path> — why

## 3) Dependency notes
- Direct dependencies (subsystems/files)
- Transitive dependencies (1–2 hops)
- Interfaces crossed (syscall/MAC/IOKit/pexpert/exported headers)

## 4) Step-by-step flow
Numbered steps:
1) entry point (user/kernel boundary or internal trigger)
2) dispatch/routing
3) core logic
4) state mutation
5) output/return path

Each step must include:
- function(s) / file(s)
- state/data structure
- “what is happening” in one sentence

## 5) Risks / bug hypotheses (optional unless requested)
- Suspected class (UAF/race/OOB/logic error)
- What invariants would need to break

## 6) Validation plan
- Minimal static checks (search/compile flags)
- Build/test commands if applicable
```

---

### 4.5 `docs/xnu-build-notes.md` (optional deep link; not always loaded)

```md
# xnu build notes (reference)

This doc is optional; only load if the user asked about building/running kernels.

Highlights:
- KERNEL_CONFIGS: debug/development/release/profile
- ARCH_CONFIGS: X86_64 / ARM64 etc (per your environment)
- install_kernels + DSTROOT for staged installs
- kernelcache testing workflows are described upstream
```

(Upstream README contains extensive kernelcache notes; only load when asked.) ([GitHub][1])

---

## 5) Prompts

### 5.1 `prompts/explore-agent.txt` (the core behavior)

```txt
You are the Explore Agent for the xnu monorepo. You are read-only.

MISSION
1) Identify the minimal working set of files for the user request.
2) Explain dependencies across xnu subsystems (direct + 1–2 hop).
3) Produce a step-by-step flow explanation using docs/report-format.md.
4) Do NOT edit code.

PROGRESSIVE DISCLOSURE (mandatory)
- Start with docs/repo-map.md and docs/dependency-rules.md.
- Decide the primary boundary (bsd/osfmk/iokit/libkern/pexpert/security/makedefs/etc).
- Read ONLY that boundary’s CONTEXT.md first.
- Then locate entry point(s) and call chain using search.
- Stop once you can fill the report format with confidence.

OUTPUT
Use docs/report-format.md exactly.

COMMON FLOWS (hints)
- Syscall path: bsd + libsyscall (+ osfmk as needed)
- VM/scheduler/IPC path: osfmk
- Driver path: iokit + libkern
- Boot/platform: pexpert + libsa
- MAC checks: security
```

### 5.2 `prompts/explain-folder.txt` (for “explain this directory” requests)

```txt
Task: Explain what this folder does and how it fits into xnu.

Rules:
- First read the folder’s CONTEXT.md.
- Then read no more than 5 additional files:
  - 1–2 representative headers
  - 1–2 representative .c/.cpp files
  - 1 build/config file if relevant
- Output: a short explanation + the working set + a “start reading here” list.
```

---

## 6) Skills (on-demand deep knowledge)

OpenCode Skills are ideal for huge repos because they can be loaded when needed (rather than always in context). ([opencode.ai][2])

### 6.1 `.opencode/skills/repo-navigation/SKILL.md`

```md
---
name: repo-navigation
description: Progressive disclosure navigation in huge repos; working-set selection; avoid context overflow
compatibility: opencode
---

## Heuristics
- Prefer boundary CONTEXT.md + shallow map before reading code.
- Identify an entry point, then expand outward in 1–2 hop rings.
- Stop when you can name:
  - entry point
  - key call chain
  - key data structures
  - likely edit files

## Working set rubric
- 1 boundary CONTEXT.md
- 1 routing/dispatch file
- 1–3 core logic files
- 1–2 type/header files
- 1 test or build rule file (only if needed)
```

### 6.2 `.opencode/skills/dependency-mapping/SKILL.md`

```md
---
name: dependency-mapping
description: Build a small dependency explanation (subsystems + files) and impact radius for a proposed change
compatibility: opencode
---

## Output contract
- Direct deps (imports/includes/calls)
- Transitive deps (1–2 hops)
- Interfaces crossed: syscall / MAC / IOKit / pexpert / exported headers

## Method
- Use include graphs and call sites.
- Prefer known boundary crossings over brute-force reading.
```

### 6.3 `.opencode/skills/xnu-architecture/SKILL.md`

```md
---
name: xnu-architecture
description: Practical mental model for xnu boundaries and common cross-subsystem interfaces
compatibility: opencode
---

## xnu in one page (agent-oriented)
- osfmk: Mach core (threads, VM, IPC, scheduling)
- bsd: POSIX/BSD layer (process, VFS, sockets, syscalls)
- iokit + libkern: driver/runtime model and C++ support
- pexpert + libsa: platform/boot boundary and low-level startup glue
- security: MAC framework interfaces
- makedefs: build system rules and composition

## Typical boundary crossings
- syscall: libsyscall -> bsd -> (sometimes) osfmk
- MAC hooks: bsd/osfmk/iokit -> security
- driver: iokit <-> libkern; platform glue via pexpert
```

These boundary summaries reflect the repo’s own “Source Tree” descriptions. ([GitHub][1])

### 6.4 `.opencode/skills/xnu-bug-hunting/SKILL.md` (kept “ask” by default)

```md
---
name: xnu-bug-hunting
description: Bug-finding workflow template (race/UAF/OOB/logic) tailored for kernel subsystems
compatibility: opencode
---

## Only use when requested (or when the user is explicitly doing security work)

## Workflow
1) Define entry point + attacker model (local user? unprivileged? kernel extension?)
2) Trace data lifetimes (alloc/free, refcount, locks)
3) Identify invariants (must-hold conditions)
4) Look for:
   - lock ordering breaks / missing locks
   - refcount underflow/overflow
   - stale pointers / missing retain/release
   - size/length trust issues across boundaries
5) Produce a step-by-step exploitability hypothesis (if asked)

## Reporting
Always output in docs/report-format.md with a “Bug hypotheses” section.
```

---

## 7) Boundary `CONTEXT.md` shards (xnu-specific, small)

Each one is intentionally short and points to “start here” rather than exhaustively documenting the subtree.

### 7.1 `osfmk/CONTEXT.md`

```md
# osfmk/ — Mach core

## Purpose
Mach kernel subsystems: threads, scheduling, IPC, VM, low-level kernel primitives.

## Common “start here” questions
- threads/scheduling -> look for scheduler and thread structures in this subtree
- VM faults/memory -> VM subsystem files here
- IPC -> Mach message/ports code here

## Interfaces crossed
- to bsd/: syscall/personality integration points
- to pexpert/: platform hooks
- to security/: MAC hooks (when present)

## Invariants
- Concurrency rules matter; always identify lock/refcount ownership before proposing changes.
```

### 7.2 `bsd/CONTEXT.md`

```md
# bsd/ — BSD personality

## Purpose
POSIX/BSD layer: processes, syscalls, VFS, sockets, networking, Unix abstractions.

## “Start here”
- syscall-related request: find syscall dispatch and the specific syscall implementation in bsd/
- file system/VFS: VFS layer here
- sockets/network: socket layer here

## Interfaces crossed
- to libsyscall/: user-visible syscall interface library
- to osfmk/: Mach primitives used underneath
- to security/: MAC hooks
```

### 7.3 `iokit/CONTEXT.md`

```md
# iokit/ — I/O Kit glue

## Purpose
Kernel I/O Kit subsystem: driver model integration and I/O abstractions.

## Depends on
- libkern/ for C++ kernel runtime support

## Interfaces crossed
- to pexpert/ for platform specifics
- to security/ for policy hooks (when relevant)

## Invariants
- Object lifetime and concurrency are central; track retains/releases and locking.
```

### 7.4 `libkern/CONTEXT.md`

```md
# libkern/ — C++ kernel runtime support

## Purpose
C++ support code used heavily by IOKit and kernel components.

## Typical use
- core container/types, runtime utilities for kernel C++ code

## Invariants
- Be careful with allocation/lifetime patterns; many bugs are ownership-related.
```

### 7.5 `pexpert/CONTEXT.md`

```md
# pexpert/ — Platform expert

## Purpose
Platform-specific kernel code: interrupts, atomics, platform hooks, boot-time interfaces.

## Interfaces crossed
- used by osfmk/ and iokit/ for platform glue

## Invariants
- Architecture/platform assumptions are critical; avoid “portable” refactors without strong evidence.
```

### 7.6 `security/CONTEXT.md`

```md
# security/ — MAC framework

## Purpose
Mandatory Access Control policy interfaces and related implementations.

## Interfaces crossed
- called from bsd/osfmk/iokit at policy enforcement points

## Invariants
- Changes can have system-wide security semantics; always explain the policy impact.
```

### 7.7 `makedefs/CONTEXT.md`

```md
# makedefs/ — Build rules

## Purpose
Top-level build rules/defines for kernel build.

## “Start here”
- If the question is “how is this built/which components are included”, start here + root Makefile.

## Notes
- xnu build interface is make-driven and uses SDKROOT/ARCH_CONFIGS/KERNEL_CONFIGS. (See docs/testing.md)
```

### 7.8 `config/CONTEXT.md`

```md
# config/ — exported APIs and configurations

## Purpose
Configurations for exported APIs for supported architecture/platform.

## When to read this
- Header visibility/export issues
- “Why is this symbol/header available/unavailable for X?”
```

### 7.9 `EXTERNAL_HEADERS/CONTEXT.md`

```md
# EXTERNAL_HEADERS/ — imported headers to avoid build cycles

## Purpose
Headers sourced from other projects to avoid dependency cycles when building.

## When to touch
- Rarely. Prefer updating from upstream source projects rather than local edits.

## Risks
- Getting out of sync can cause build/ABI surprises.
```

That purpose is stated in the upstream README. ([GitHub][1])

### 7.10 `SETUP/CONTEXT.md`

```md
# SETUP/ — setup tooling

## Purpose
Tools for configuring the kernel, versioning, and kext symbol management.

## When relevant
- versioning questions
- kext symbol/manifest management questions
```

This aligns with the upstream README description. ([GitHub][1])

### 7.11 `tools/CONTEXT.md`

```md
# tools/ — kernel utilities

## Purpose
Utilities for testing/debugging/profiling kernel.

## When to read
- User asks about tracing/debug/profiling workflows
- A test harness/tool is referenced by build docs
```

### 7.12 `tests/CONTEXT.md`

```md
# tests/ — kernel tests

## Purpose
Test suites for xnu kernel behaviors.

## Agent rule
- Prefer targeted tests here before suggesting full rebuild cycles.
- When changing behavior, identify or add the narrowest relevant test.
```

### 7.13 The remaining small boundaries

(Keep these tiny; they’re “when asked” context.)

`san/CONTEXT.md`

```md
# san/ — sanitizer support
Purpose: sanitizer-related kernel support.
Read when the issue relates to sanitizer instrumentation or sanitizer-specific build/runtime behavior.
```

`libsa/CONTEXT.md`

```md
# libsa/ — bootstrap/startup support
Purpose: kernel bootstrap/startup support code.
Read when investigating boot-time flow and early initialization.
```

`libsyscall/CONTEXT.md`

```md
# libsyscall/ — syscall interface library
Purpose: syscall library interface for user space programs.
Read when tracing user->kernel syscall ABI/dispatch.
```

`libkdd/CONTEXT.md`

```md
# libkdd/ — kernel data parsing library
Purpose: user library for parsing kernel data (e.g., chunked data).
Read when tooling consumes kernel-exported diagnostics/data formats.
```

`doc/CONTEXT.md`

```md
# doc/ — documentation
Purpose: build and architecture documentation.
Agent rule: only load docs relevant to the user’s exact question.
```

These all match the upstream README’s “Source Tree” descriptions. ([GitHub][1])

---

## 8) How an OpenCode agent should use this (the operational playbook)

**When the user asks anything like “explain subsystem X / trace flow Y / where is Z implemented?”**

1. Load global compass (auto via `opencode.jsonc`):
   `docs/repo-map.md`, `docs/dependency-rules.md`, `docs/testing.md`, `docs/report-format.md`.

2. Run `@explore` (read-only):

   * choose the **primary boundary** (e.g., `bsd/` for syscalls, `osfmk/` for VM)
   * read only that boundary’s `CONTEXT.md`
   * identify entry point(s), then **read ≤10 files total**
   * output the report format with:

     * working set
     * dependency notes
     * step-by-step flow

3. Only then move to “edit” phase for bugfix/PR (you’ll add that later).

---

If you want, tell me a concrete example question (e.g., “trace open() syscall path” or “where are MAC hooks enforced for file ops?”) and I’ll show what the **@explore report output** would look like using this exact kit.

[1]: https://github.com/apple-oss-distributions/xnu "GitHub - apple-oss-distributions/xnu"
[2]: https://opencode.ai/docs/rules/?utm_source=chatgpt.com "Rules"


You already have the **navigation kit**. To move from “explain” → “fix a bug safely,” you mainly need to add:

1. **a second agent** (`fix`) that’s allowed to edit, but only after exploration
2. a **bug-fix workflow contract** (what it must output + when it may change files)
3. **permissions / guardrails** (edit is “ask” + safe bash allowlist)
4. **a patch discipline** (small diffs, compile/test hooks, update local CONTEXT/docs)
5. optional: a **bug-triage skill** that turns your bug description into hypotheses + a working set

Below is exactly what to add/modify in the existing setting.

---

## 1) Add a `@fix` agent (separate from `@explore`)

Keep `@explore` read-only. Add `@fix` for changes.

### Modify `opencode.jsonc`

Add this under `"agent"` alongside `explore`:

```jsonc
{
  "agent": {
    "fix": {
      "description": "Bug-fix agent: uses @explore output, edits minimal files, validates, updates docs",
      "steps": 18,
      "temperature": 0.1,
      "prompt": "{file:./prompts/fix-agent.txt}",
      "permission": {
        "edit": "ask",
        "webfetch": "deny",
        "bash": {
          "*": "ask",
          "git status*": "allow",
          "git diff*": "allow",
          "git log*": "allow",
          "git grep*": "allow",
          "make -n*": "allow",
          "make SDKROOT=*": "ask",
          "make install_kernels*": "ask"
        },
        "skill": {
          "*": "ask",
          "repo-navigation": "allow",
          "dependency-mapping": "allow",
          "xnu-architecture": "allow",
          "xnu-bug-hunting": "allow"
        }
      }
    }
  }
}
```

Why:

* `edit: ask` forces an approval step before modifications (good for kernel code).
* `bash` allowlist avoids the agent running dangerous commands silently.
* `webfetch: deny` keeps it deterministic and prevents “random internet fixes.”

OpenCode permissions and agent configuration are designed for this exact kind of separation.  (see note below)

> I didn’t browse in this thread yet, and for OpenCode spec accuracy it’s worth verifying the latest docs before you implement. If you want, I can web-check the exact schema fields for agent permissions and bash allowlists in current OpenCode.

(If you prefer, you can keep `bash` entirely `ask` at first.)

---

## 2) Add `prompts/fix-agent.txt` (the bug-fix contract)

> **New file:** `prompts/fix-agent.txt`

```txt
You are the Fix Agent for xnu.

NON-NEGOTIABLE WORKFLOW
1) You MUST run @explore first unless the user has already provided an @explore report for this same bug.
2) You MUST propose a patch plan and get approval (edit permission is ask) before editing.
3) Make the smallest possible change that fixes the bug.
4) After editing: validate using the narrowest commands from docs/testing.md and boundary CONTEXT.md.

PROGRESSIVE DISCLOSURE
- Use docs/repo-map.md and docs/dependency-rules.md.
- Read only the boundary CONTEXT.md for the edited area.
- Keep the working set small; do not “refactor.”

REQUIRED OUTPUT SECTIONS
## Bug statement (restated)
## Hypotheses
- H1, H2, H3 with evidence to confirm/deny
## Working set
- Files to read
- Files to edit
## Fix plan
- Exact change and why it is correct
- Risks and regression areas
## Patch
- Provide diff summary and rationale
## Validation
- Minimal checks / build targets
## Documentation updates
- Update nearest CONTEXT.md if public behavior/invariants changed
```

This ensures the agent doesn’t jump straight to edits and doesn’t expand scope.

---

## 3) Update root `AGENTS.md` to enforce “explore → fix”

Add a “Bug fixing” section.

> **Modify** `AGENTS.md`:

```md
## Bug fixing workflow (mandatory)
- Use @explore first to produce a working set + dependency notes + flow walkthrough.
- Then use @fix to implement the smallest patch possible.
- @fix must:
  - restate bug + hypotheses
  - change minimal files
  - run minimal validation
  - update nearest CONTEXT.md if invariants/public behavior changed
```

---

## 4) Add two docs: `docs/bugfix-playbook.md` + `docs/patch-quality.md`

These are not always loaded; reference them from `AGENTS.md` and let the agent load only when needed.

### `docs/bugfix-playbook.md`

```md
# Bugfix playbook (xnu)

## Triage
1) Classify bug: crash/panic, race, UAF, OOB, deadlock, logic error, ABI mismatch.
2) Identify boundary: bsd/osfmk/iokit/libkern/pexpert/security.
3) Identify entry point: syscall / message / interrupt / kext / timer / workloop.

## Confirmation steps (lightweight first)
- Find call sites and invariants in headers/comments.
- Identify locking + lifetime model (retain/release/refcount).
- Identify data structures and ownership.

## Patch discipline
- Minimal change; avoid refactors.
- Add assertions only if safe in configs.
- Prefer fixing root cause over masking symptoms.
```

### `docs/patch-quality.md`

```md
# Patch quality checklist

- Minimal diff
- Correct locking / lifetime
- No new boundary violations (see docs/dependency-rules.md)
- Comments explain invariants (if changed)
- Tests/build steps recommended
- Update local CONTEXT.md if behavior/invariants changed
```

If you want them always loaded, add them to `opencode.jsonc` instructions—but usually they’re better as optional references.

---

## 5) Add a small “bug intake template” prompt (optional but powerful)

This helps convert your description into structured inputs.

> **New file:** `prompts/bug-intake.txt`

```txt
Ask for missing details only if essential.
Otherwise, infer and proceed.

Extract:
- Symptom: what happens
- Trigger: what action/load
- Environment: arch/config if known
- Location hints: files/functions/log lines provided
- Expected vs actual
- Repro steps (if any)
- Safety: can we run builds? (assume no unless user said yes)
```

Then in `AGENTS.md`, tell the agent: “if bug report is vague, run bug-intake extraction first.”

---

## 6) Expand `xnu-bug-hunting` skill into “triage + working set selection”

You already have `xnu-bug-hunting`. Add a section that maps common symptoms to likely boundaries and “first files to look at,” without being too specific.

Example additions:

* panic in VM → `osfmk/vm/*`
* syscall issue → `bsd/kern/*` + `bsd/sys/*` + `libsyscall/*`
* IOKit lifetime crash → `iokit/*` + `libkern/*`

This dramatically speeds “navigate to right location from description.”

---

## 7) Add a “doc auto-update rule” (tiny but important)

When `@fix` touches anything that changes invariants, require it to update the nearest `CONTEXT.md` *in the same patch*.

In `prompts/fix-agent.txt` (already included) + reinforce in `docs/patch-quality.md`.

That’s what gets you to “auto documenting” as a natural byproduct of fixing.

---

## What you do NOT need yet

* PR automation / commit hooks (later)
* fully building xnu in CI (later)
* exhaustive dependency graph indexing (overkill)

---

## Minimal change summary (copy/paste checklist)

**Modify**

* `opencode.jsonc` → add `@fix` agent (edit ask + bash allowlist)
* `AGENTS.md` → enforce explore→fix workflow

**Add**

* `prompts/fix-agent.txt`
* (optional) `prompts/bug-intake.txt`
* `docs/bugfix-playbook.md`
* `docs/patch-quality.md`
* (optional) expand `.opencode/skills/xnu-bug-hunting/SKILL.md`

---

If you paste an example bug description (panic log snippet or “this syscall returns wrong errno under X”), I can show the exact **@explore output** and then the **@fix plan** using this upgraded setup.


------------------------------->
++++++++++++++++++++++++++++++++

Below is a “security-audit starter kit” for **opencode** that’s tuned for vulnerability research *without* turning your agents into auto-exploit generators. It’s built around: **least privilege**, **repeatable dataflow analysis**, and **high-signal writeups**.

I’m going to cover:

1. How opencode discovers config + folder structure
2. A recommended repo layout
3. A hardened `opencode.jsonc` for vuln research
4. Concrete Markdown files for **agents**, **commands**, and **skills**
5. (Optional) a small custom tool example

---

## How opencode loads config + folders

### Config files (JSON / JSONC)

* opencode supports **JSON or JSONC** (`opencode.json` or `opencode.jsonc`). ([OpenCode][1])
* Config sources are **merged** (not replaced), in this precedence order: remote → global → env override → project → `.opencode` directories → inline env. ([OpenCode][1])
* Typical locations:

  * Global: `~/.config/opencode/opencode.json` ([OpenCode][1])
  * Project: `opencode.json` in repo root ([OpenCode][1])

### The `.opencode/` folder structure

opencode expects “plural” subfolders (singular is supported for backwards compat): `agents/`, `commands/`, `skills/`, `tools/`, etc. ([OpenCode][1])

* **Agents** (Markdown): `.opencode/agents/` (or global `~/.config/opencode/agents/`) ([OpenCode][2])
* **Commands** (Markdown): `.opencode/commands/` (or global `~/.config/opencode/commands/`) ([OpenCode][3])
* **Skills** (`SKILL.md` in named folders): `.opencode/skills/<name>/SKILL.md` ([OpenCode][4])
* **Custom tools** (TS/JS): `.opencode/tools/` (or global `~/.config/opencode/tools/`) ([OpenCode][5])
* **Project rules**: `AGENTS.md` in repo root (or global `~/.config/opencode/AGENTS.md`). ([OpenCode][6])

---

## Design goals for vuln-research agents

**What you want:** find *reachable* bug paths, and document “how an attacker gets there” at the dataflow + state level.

**What you don’t want by default:** auto-writing exploit payloads or weaponized PoCs.

So the ideal setup is:

* **Default agent = read-only audit lead**
* **Bash is “ask” by default**, with a whitelist for common read-only commands
* **Edits are denied globally**, except a dedicated “findings” directory
* **Web fetch is denied by default** (avoid accidental code/context leakage); enable it only in a dedicated “deps/cve” agent if needed
* Specialized subagents:

  * recon/attack surface
  * dataflow/taint tracing
  * authz logic
  * deps/config review
  * writeup/reporting

---

## Recommended repo layout

```text
repo-root/
  opencode.jsonc
  AGENTS.md

  .opencode/
    agents/
      vuln.md
      vuln-recon.md
      vuln-dataflow.md
      vuln-authz.md
      vuln-deps.md
      vuln-writer.md

    commands/
      sec-surface.md
      sec-taint.md
      sec-authz.md
      sec-deps.md
      sec-report.md

    skills/
      audit-playbook/SKILL.md
      attack-surface-map/SKILL.md
      taint-trace/SKILL.md
      authz-audit/SKILL.md
      dependency-audit/SKILL.md
      finding-writeup/SKILL.md

  docs/
    security/
      findings/
        TEMPLATE.md
```

Notes:

* Putting `docs/security/findings/` under version control gives you a canonical place for audit output.
* Skills are loaded “on-demand” via the `skill` tool (agents see the list and load only when needed). ([OpenCode][4])

---

## 1) `opencode.jsonc` tuned for vulnerability research

This config makes **audit mode the default**, keeps it **safe by default**, and still lets you do real work (grep, lsp navigation, limited bash).

```jsonc
// opencode.jsonc
{
  "$schema": "https://opencode.ai/config.json",

  // Vulnerability research often includes sensitive context—disable sharing.
  "share": "disabled",

  // Start sessions in our primary security agent (defined in .opencode/agents/vuln.md).
  "default_agent": "vuln",

  // Keep big/noisy directories out of the file watcher.
  "watcher": {
    "ignore": [
      ".git/**",
      "node_modules/**",
      "dist/**",
      "build/**",
      "target/**",
      "vendor/**",
      ".venv/**",
      "__pycache__/**"
    ]
  },

  // Permissions are the real “security boundary”.
  // allow  — run without approval
  // ask    — prompt for approval
  // deny   — block
  "permission": {
    "*": "ask",

    // Safe read/navigation tools
    "read": "allow",
    "list": "allow",
    "glob": "allow",
    "grep": "allow",
    "lsp": "allow",

    // Use todo tools for tracking audit plan + open questions
    "todoread": "allow",
    "todowrite": "allow",

    // Skills are helpful, but you can restrict them by pattern if needed.
    "skill": "allow",

    // Editing is denied everywhere except the findings directory.
    // (Note: write/patch are controlled by edit permission.)
    "edit": {
      "*": "deny",
      "docs/security/findings/**": "allow"
    },

    // Avoid accidental outbound context leakage. Enable only in a dedicated agent if needed.
    "webfetch": "deny",

    // Bash is powerful; keep it gated.
    // Allow common read-only commands automatically; ask for everything else.
    "bash": {
      "*": "ask",

      "git status*": "allow",
      "git diff*": "allow",
      "git log*": "allow",
      "git show*": "allow",

      "rg *": "allow",
      "grep *": "allow",
      "find *": "allow",
      "ls*": "allow",
      "cat *": "allow",
      "head *": "allow",
      "tail *": "allow",
      "sed -n*": "allow"
    }
  },

  // Optional: keep built-in Build from accidentally becoming “dangerous” during audits.
  "agent": {
    "build": {
      "permission": {
        "edit": "ask",
        "bash": "ask",
        "webfetch": "deny"
      }
    }
  }
}
```

Why this is “ideal” for vuln research:

* You can still do **fast static analysis** (`grep`, `glob`, `lsp`, `read`).
* You can still run **safe bash** (ripgrep, git read-only).
* You can **write reports** but not mutate code.
* You reduce risk of accidental data exfil (share + webfetch disabled). ([OpenCode][1])

(Sharing config + default agent rules are documented in the config schema.) ([OpenCode][1])

---

## 2) `AGENTS.md` – project rules for security auditing

`AGENTS.md` is included in model context and is the best place to define “how we do audits in this repo.” ([OpenCode][6])

```md
<!-- AGENTS.md -->
# Security Audit Rules (opencode)

This repository may contain security-sensitive defects.
Use opencode audit agents only on codebases you are authorized to review.

## Goals
- Map attack surface: identify all external inputs and trust boundaries.
- Trace untrusted dataflow: source → transforms/validators → sinks.
- Identify missing/incorrect authorization checks across flows.
- Produce actionable findings with evidence and fixes.
- Do NOT generate weaponized exploit payloads or instructions.

## Output rules
When reporting a potential vulnerability, always include:
1. **Title**
2. **Impact** (what could happen if abused)
3. **Reachability** (how attacker-controlled input reaches the bug, at a conceptual level)
4. **Evidence** (file paths + line ranges + call chain or references)
5. **Preconditions** (auth required? specific roles? feature flags? config?)
6. **Fix recommendation** (minimal change; defense-in-depth)
7. **Regression test idea** (unit/integration/fuzz suggestion)

## Where to write findings
- Write Markdown findings to: `docs/security/findings/`
- Follow the template: `docs/security/findings/TEMPLATE.md`

## Allowed execution
- Prefer static analysis first.
- Only run local tests/tools that are safe and repo-scoped.
- Avoid network calls unless explicitly requested by the user.

## Repo notes (fill in)
- Primary language(s):
- Frameworks:
- Entry points:
- Auth model:
- Build/test commands:
```

---

## 3) Agents (Markdown) for vulnerability research

Agents can be defined as markdown files in `.opencode/agents/`. ([OpenCode][2])
Each file name becomes the agent name (e.g. `vuln.md` => `@vuln`). ([OpenCode][2])

### `.opencode/agents/vuln.md` (primary orchestrator)

```md
---
description: Primary vulnerability research agent. Orchestrates recon, dataflow tracing, authz review, deps/config review, and produces high-signal findings without writing exploit code.
mode: primary
temperature: 0.1
steps: 40

permission:
  # Only allow spawning the dedicated vuln-* subagents.
  task:
    "*": deny
    "vuln-*": allow

  # Keep outbound fetch blocked by default.
  webfetch: deny

---

You are a vulnerability research lead for a codebase.

Operating principles:
- Prioritize *reachable* issues: show how untrusted input can plausibly reach the bug.
- Be specific: file paths, symbols, call chains, and “source → sink” flow narratives.
- Do not generate weaponized exploit payloads or step-by-step instructions to attack real systems.
  If asked for exploitation, provide a defensive reproduction strategy (unit test / safe harness) instead.

Workflow:
1) Load `audit-playbook` skill and create a short audit plan.
2) Delegate:
   - @vuln-recon: enumerate entry points + trust boundaries.
   - @vuln-dataflow: trace source→sink flows for top-risk areas.
   - @vuln-authz: check authn/authz boundaries and IDOR-style patterns.
   - @vuln-deps: review dependencies + configs that change exposure.
3) Synthesize findings:
   - Rank by reachability + impact.
   - For each, include evidence and a minimal fix.
4) If user asks for a report file, delegate to @vuln-writer.
```

### `.opencode/agents/vuln-recon.md`

```md
---
description: Attack-surface mapper. Finds externally reachable entry points, trust boundaries, and risky parsers/handlers. Read-only.
mode: subagent
temperature: 0.1
steps: 30

permission:
  edit: deny
  webfetch: deny
---

You map attack surface.

Output format:
- Entry points (HTTP routes, RPC handlers, message consumers, CLI args, file parsers)
- Trust boundaries (where data crosses from untrusted → trusted)
- Data stores and secrets usage
- High-risk components (auth, deserialization, templating, shelling out, dynamic eval)

Rules:
- Use code evidence (paths + line ranges).
- Prefer breadth first; then highlight top 5 risky flows to investigate.
```

### `.opencode/agents/vuln-dataflow.md`

```md
---
description: Dataflow / taint-tracing specialist. Traces attacker-controlled sources to sensitive sinks and identifies missing validation/sanitization. Read-only.
mode: subagent
temperature: 0.1
steps: 35

permission:
  edit: deny
  webfetch: deny
---

You do source→sink analysis.

Method:
- Identify attacker-controlled sources (request params, headers, body, files, env, IPC, messages).
- Identify sensitive sinks (SQL/ORM raw queries, filesystem paths, template rendering, command execution, SSRF-style fetches, deserialization).
- Trace flow across functions/modules; note validators/normalizers and where they fail.

Deliverables for each suspected issue:
- Source → transforms → sink narrative
- Preconditions (auth/roles/config/state)
- Why existing validation is insufficient
- Fix options (least invasive first)
- Safe reproduction idea (unit test / integration test harness), not an exploit payload
```

### `.opencode/agents/vuln-authz.md`

```md
---
description: Authorization logic auditor. Looks for IDOR, missing ownership checks, confused deputy, multi-tenant boundary breaks, privilege escalation paths. Read-only.
mode: subagent
temperature: 0.1
steps: 30

permission:
  edit: deny
  webfetch: deny
---

You audit authorization flows and invariants.

Look for:
- “lookup by ID” without verifying tenant/ownership
- Role checks applied inconsistently across endpoints
- Admin-only actions reachable through alternate routes
- Mixed authn contexts (service tokens vs user sessions)
- Cache/queue consumers missing auth context

Output:
- Candidate issue list with evidence (paths + call sites)
- For top issues: describe the broken invariant and the minimal fix pattern
```

### `.opencode/agents/vuln-deps.md`

```md
---
description: Dependency/config exposure auditor. Finds risky configurations and known-vulnerable dependency surfaces. Minimal bash allowed; no code edits.
mode: subagent
temperature: 0.1
steps: 25

permission:
  edit: deny
  # Keep webfetch blocked; enable per-run only if the user explicitly wants online CVE lookup.
  webfetch: deny
---

You audit dependencies and security-relevant configuration.

Focus:
- Dependency manifests + lockfiles
- Dangerous defaults (debug flags, permissive CORS, weak auth settings)
- Use of outdated crypto / serialization libs
- Build/deploy configs that widen attack surface (public admin endpoints, dev middleware)

Output:
- Top dependency/config risks with file locations
- Concrete mitigation actions (version bump, config hardening)
- If you need to run a local command (e.g., listing dependencies), ask first.
```

### `.opencode/agents/vuln-writer.md`

```md
---
description: Writes security findings into docs/security/findings using the repo template. No bash. Allowed to write only in findings folder (global permission already enforces this).
mode: subagent
temperature: 0.1
steps: 20

permission:
  bash: deny
  webfetch: deny
---

You are a security report writer.

When asked to write a finding:
- Use `docs/security/findings/TEMPLATE.md` structure.
- Create a new file named: `docs/security/findings/YYYY-MM-DD-<short-slug>.md`
- Include: impact, reachability narrative (conceptual), evidence, preconditions, fix, regression test.

Do not include weaponized exploit payloads or real-world attack instructions.
```

---

## 4) Skills (SKILL.md) for reusable vuln-research behavior

Skills live in `.opencode/skills/<name>/SKILL.md`. ([OpenCode][4])
They must have YAML frontmatter with required fields and a name that matches the folder name. ([OpenCode][4])

### `.opencode/skills/audit-playbook/SKILL.md`

```md
---
name: audit-playbook
description: A repeatable vulnerability research workflow (recon → dataflow → authz → deps/config → prioritized findings).
compatibility: opencode
---

## What I do
- Provide an audit plan optimized for reachability + impact.
- Define what “good evidence” looks like (paths, line ranges, call chains).
- Provide a consistent finding template and severity heuristics.

## Checklist
- [ ] Identify entry points + trust boundaries
- [ ] Identify sensitive sinks
- [ ] Trace source→sink for top-risk components
- [ ] Validate authz invariants (tenant/ownership/role)
- [ ] Check config/deps that change exposure
- [ ] Write findings with concrete fixes and regression tests
```

### `.opencode/skills/attack-surface-map/SKILL.md`

```md
---
name: attack-surface-map
description: How to systematically enumerate externally reachable entry points and trust boundaries in a repo.
compatibility: opencode
---

## What I do
- Enumerate all likely “inputs” an attacker can influence.
- Categorize entry points: HTTP/RPC, queues, CLIs, file parsers, scheduled jobs, plugins.
- Highlight “hot zones”: auth, deserialization, template rendering, command execution, file paths.

## Output format
- Entry points table: type | location | auth context | notes
- Trust boundaries list
- Top 5 risky flows to investigate next
```

### `.opencode/skills/taint-trace/SKILL.md`

```md
---
name: taint-trace
description: Source→transform→sink tracing for untrusted data flows, including validators/sanitizers and bypass patterns (defensive analysis).
compatibility: opencode
---

## What I do
- Identify sources, sinks, and sanitizers.
- Trace cross-module call chains.
- Summarize reachability and preconditions.

## Deliverable template
- Source:
- Transform(s):
- Sink:
- Preconditions:
- Evidence:
- Fix:
- Regression test idea:
```

### `.opencode/skills/authz-audit/SKILL.md`

```md
---
name: authz-audit
description: Authorization and multi-tenant boundary review checklist (IDOR, confused deputy, privilege escalation).
compatibility: opencode
---

## What I do
- Check for missing ownership/tenant checks on object access.
- Validate consistent role enforcement across routes and background consumers.
- Identify dangerous “admin” toggles and alternate execution paths.

## Evidence to collect
- Where user/tenant identity is derived
- How resource IDs map to owners/tenants
- Where checks are performed (and where they are missing)
```

### `.opencode/skills/dependency-audit/SKILL.md`

```md
---
name: dependency-audit
description: Dependency + configuration security review (manifests, lockfiles, risky defaults, supply-chain exposure).
compatibility: opencode
---

## What I do
- Inventory runtime deps and security-sensitive configs.
- Identify risky libraries/features: unsafe parsing, dynamic execution, weak crypto, debug middleware.
- Recommend mitigations: version upgrades, feature flags, config tightening.

## Output
- Risk list with file references
- Mitigation plan (quick wins → larger refactors)
```

### `.opencode/skills/finding-writeup/SKILL.md`

```md
---
name: finding-writeup
description: Standard security finding writeup format for consistent, high-signal reports with evidence and fixes.
compatibility: opencode
---

## Finding format
1. Title
2. Impact
3. Reachability (conceptual attacker path, no weaponized payloads)
4. Evidence (file/line + call chain)
5. Preconditions
6. Fix (minimal + defense-in-depth)
7. Regression test

## Severity heuristics
- High: reachable + strong impact (auth bypass, sensitive data exposure, code execution)
- Medium: reachable + limited impact or hard preconditions
- Low: defense-in-depth, low reachability, or best-practice issues
```

---

## 5) Commands (Markdown) to run common audit workflows

Commands are Markdown files in `.opencode/commands/` and are invoked as `/name`. ([OpenCode][3])

### `.opencode/commands/sec-surface.md`

```md
---
description: Map attack surface and trust boundaries (entry points, parsers, auth boundaries).
agent: vuln
---

Use @vuln-recon to enumerate:
- All externally reachable entry points
- Trust boundaries and auth contexts
- Top 5 highest-risk flows to investigate next

Output a concise attack-surface map with file path evidence.
```

### `.opencode/commands/sec-taint.md`

```md
---
description: Perform source→sink dataflow tracing for a component or feature.
agent: vuln
---

Use @vuln-dataflow.

Target: $ARGUMENTS

If $ARGUMENTS is empty, pick the most exposed entry point (from prior recon) and trace
untrusted data flows to sensitive sinks.

For each candidate issue: provide a reachability narrative, evidence, preconditions, and fixes.
Do not provide weaponized exploit payloads.
```

### `.opencode/commands/sec-authz.md`

```md
---
description: Audit authorization and multi-tenant boundaries for a target area.
agent: vuln
---

Use @vuln-authz.

Target: $ARGUMENTS

If empty, prioritize areas with object lookups by ID, user/tenant context propagation,
admin actions, and background consumers.

Output: candidate issues + evidence + minimal fix patterns.
```

### `.opencode/commands/sec-deps.md`

```md
---
description: Review dependencies and security-relevant configuration for exposure.
agent: vuln
---

Use @vuln-deps.

Scan manifests/lockfiles and security-critical config files.
List top risks with file evidence and concrete mitigations.
Avoid network calls unless explicitly requested.
```

### `.opencode/commands/sec-report.md`

```md
---
description: Write a finding to docs/security/findings (uses template).
agent: vuln
---

If there is an agreed finding in the current discussion, invoke @vuln-writer to create a report
file in `docs/security/findings/`.

Title / slug: $ARGUMENTS

Ensure the report includes: impact, reachability narrative, evidence, preconditions, fix, regression test.
```

---

## 6) Findings template (so the writer agent has structure)

```md
<!-- docs/security/findings/TEMPLATE.md -->
# <Finding Title>

## Summary
(1–3 sentences)

## Impact
What could happen if abused?

## Reachability (Conceptual)
Describe how attacker-controlled input could reach the vulnerable behavior.
No weaponized payloads; focus on source → sink and preconditions.

## Evidence
- Files/lines:
- Call chain:
- Notes:

## Preconditions
Auth required? Role? Config? Feature flags? Specific state?

## Recommended Fix
Minimal fix first; then defense-in-depth ideas.

## Regression Test
Unit/integration/fuzz strategy suggestion.
```

---

## Optional: a tiny custom tool example (read-only)

If you run SAST tools that output **SARIF** (e.g., from GitHub CodeQL workflows), a little summarizer tool can help you triage quickly.

Custom tools live in `.opencode/tools/` (project) or `~/.config/opencode/tools/` (global). ([OpenCode][5])

```ts
// .opencode/tools/sarif-summary.ts
import { tool } from "@opencode-ai/plugin"
import fs from "node:fs/promises"

export default tool({
  description: "Summarize a SARIF report (top rules, files, and messages). Read-only.",
  args: {
    path: tool.schema.string().describe("Path to SARIF JSON file"),
    max: tool.schema.number().optional().describe("Max results to return (default 50)")
  },
  async execute(args) {
    const max = (args as any).max ?? 50
    const raw = await fs.readFile(args.path, "utf8")
    const sarif = JSON.parse(raw)

    const runs = sarif.runs ?? []
    const out: string[] = []
    let count = 0

    for (const run of runs) {
      const results = run.results ?? []
      for (const r of results) {
        if (count >= max) break
        const msg = r.message?.text ?? "(no message)"
        const loc = r.locations?.[0]?.physicalLocation
        const file = loc?.artifactLocation?.uri ?? "(unknown file)"
        const region = loc?.region
        const line = region?.startLine ?? "?"
        const ruleId = r.ruleId ?? "(no ruleId)"
        out.push(`- [${ruleId}] ${file}:${line} — ${msg}`)
        count++
      }
    }

    return out.length ? out.join("\n") : "No results found."
  }
})
```

If you add any custom tool, remember you can permission-gate it the same way as built-ins (e.g., require `ask`).

---

## How you use this day-to-day

* Start opencode in the repo → it should default to the `vuln` primary agent (because `default_agent` is set). ([OpenCode][1])
* Run:

  * `/sec-surface`
  * `/sec-taint <component-or-feature>`
  * `/sec-authz <area>`
  * `/sec-deps`
  * `/sec-report <title>`

You can also manually call a subagent:

* `@vuln-dataflow trace request param X into file write paths`

---

## One important guardrail

This setup is aimed at **defensive vulnerability research** on code you’re authorized to review. It’s intentionally configured to:

* default to **read-only** investigation
* avoid **auto-exploit** behavior
* keep outbound sharing/fetching off unless you explicitly enable it

If you want, tell me what kind of codebase you typically audit (language/framework + monorepo vs single service). I can tailor the agent prompts (especially the recon + dataflow heuristics) to that ecosystem without changing the overall safety posture.

[1]: https://opencode.ai/docs/config/ "Config | OpenCode"
[2]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[3]: https://opencode.ai/docs/commands/ "Commands | OpenCode"
[4]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[5]: https://opencode.ai/docs/custom-tools/ "Custom Tools | OpenCode"
[6]: https://opencode.ai/docs/rules/ "Rules | OpenCode"

Below are **two concrete opencode “use cases”** you can drop into your setup:

1. **Memory Lifetime Timeline (malloc/free tracking)** → optimized for **Use-After-Free / Double-Free / Leak** triage
2. **Z3 Feasibility (satisfiable bug triggers)** → turns a suspected memory bug path into **constraints**, checks **SAT/UNSAT**, and records the result in the report

This is designed to fit your existing **Flow Walkthrough** report format (S1..Sn + “What is happening” per step), and uses opencode’s native layout: **agents/commands/skills/tools**. ([OpenCode][1])

---

# Add these files

### File tree (additions)

```text
.opencode/
  agents/
    vuln-mem.md
    vuln-smt.md

  commands/
    sec-mem-timeline.md
    sec-mem-z3.md

  skills/
    memory-lifetime-timeline/SKILL.md
    z3-feasibility/SKILL.md

  tools/
    mem_events.py
    mem_events.ts
    z3_smt2.py
    z3_smt2.ts

docs/security/findings/
  TEMPLATE-memory.md
```

Notes:

* Skills **must** be named `SKILL.md` in all caps and include YAML frontmatter with `name` + `description`. ([OpenCode][2])
* Custom tools live in `.opencode/tools/` and are TS/JS wrappers that can invoke Python (or anything). ([OpenCode][3])
* Commands are Markdown files in `.opencode/commands/` with frontmatter. ([OpenCode][4])
* Agents can be Markdown files in `.opencode/agents/` with frontmatter like `mode`, `temperature`, `tools`, and `permission`. ([OpenCode][1])

---

# Use case 1 — Memory Lifetime Timeline (UAF hunting)

## What it produces

**A per-allocation timeline** that looks like this (example shape):

* **Allocation ID**: `A1`
* **Timeline**: `ALLOC → alias → store → FREE → USE ⚠️`
* Every step references:

  * **What is happening**
  * **Evidence** (`path:Lx-Ly`)
  * **Heap state snapshot** (who points to what; live vs freed)

This makes UAF review *very fast*, because you can literally follow the lifetime like a story.

---

## 1A) Agent: `.opencode/agents/vuln-mem.md`

```md
---
description: Memory lifetime auditor. Builds allocation/free/use timelines to find UAF/double-free/leak candidates. Read-only by default.
mode: subagent
temperature: 0.1
steps: 35

tools:
  write: false
  edit: false
  patch: false
  bash: false
  webfetch: false

permission:
  # Allow calling our read-only indexing tool (custom tool).
  mem_events: allow
---

You are a memory lifetime auditor for C/C++-style codebases.

Goal:
- Track allocations, frees, and uses of heap objects and produce a timeline per allocation.
- Identify memory safety hazards: Use-After-Free, Double Free, invalid free, lifetime confusion, and leaks.

Never:
- Provide weaponized exploit payloads or exploitation steps.
- Discuss heap grooming or bypassing mitigations. Stay defensive and diagnostic.

Workflow:
1) Identify allocator/free APIs used (malloc/calloc/realloc/free, new/delete, custom wrappers).
2) Index call sites using the mem_events tool (or grep/lsp if needed).
3) Pick the most reachable/important entry flow and build a Flow Walkthrough (S1..Sn).
4) For each allocation (A1..Ak), build a Timeline:
   - ALLOC event: where created + size expression + initial owner
   - ALIAS/MOVE events: assignments, passing to functions, storing in structs/globals
   - FREE event: where freed + condition guarding it
   - USE events: deref, memcpy/memmove, field access, indexing, printf("%s"), etc.
5) Flag hazard windows:
   - UAF: any USE after FREE on same alloc ID
   - Double free: FREE after FREE
   - Leak: ALLOC without a matching FREE on all paths in scope

Deliverables:
- Memory Objects table (A1..Ak)
- Allocation Timeline table per object
- Annotated hazard window pointing to ⚠️ bug trigger step in the flow
- Evidence references at every step
```

Why this is “opencode-correct”:

* Subagents are supported and invokable with `@...`. ([OpenCode][1])
* Tools can be disabled in agent frontmatter (`tools: write: false`, etc.). ([OpenCode][1])

---

## 1B) Skill: `.opencode/skills/memory-lifetime-timeline/SKILL.md`

````md
---
name: memory-lifetime-timeline
description: Build per-allocation lifetimes (ALLOC/ALIAS/FREE/USE) as step-by-step timelines to detect UAF/double-free/leaks with evidence and “What is happening” at each step.
compatibility: opencode
---

## Concepts

### Allocation IDs
Assign each heap allocation a stable ID:
- A1, A2, A3...
The ID refers to the *heap object instance*, not the pointer variable.

### Event types
Use these canonical events in timelines:
- ALLOC: malloc/calloc/new/realloc returning a new object
- REALLOC: realloc that may move and invalidate old pointer
- ALIAS: another pointer now refers to same allocation (assignment, param passing)
- STORE: pointer stored into struct/global/container
- LOAD: pointer loaded back from struct/global/container
- FREE: free/delete on an alias of the allocation
- NULLIFY: pointer set to NULL (mitigates dangling use for that alias only)
- USE: dereference, indexing, memcpy/memmove, strcmp/strlen, field access, etc.
- ESCAPE: pointer returned or stored externally; lifetime must be tracked across boundary

## Output format

### Memory Objects table (required)
| AllocID | Allocation site | Type/Kind | Size expr | Primary owner | Aliases |
|--------|------------------|----------|----------|--------------|---------|

### Timeline per allocation (required)
| T | Flow step (S#) | Event | Where | What is happening | Heap state after | Evidence |
|---|----------------|-------|-------|------------------|------------------|----------|

Heap state after should include:
- A#: allocated / freed
- alias set: p,q,r → A# (or dangling)
- notes: “p NULL, but q still points to freed A1”

### Mermaid diagram (optional but recommended)
Use a state diagram per allocation:

```mermaid
stateDiagram-v2
  [*] --> Allocated: ALLOC
  Allocated --> Freed: FREE
  Freed --> UseAfterFree: USE ⚠️
````

## UAF identification rule

A UAF exists when:

* There exists an event USE for alloc Ax
* And there exists an earlier FREE for alloc Ax
* And there is no intervening “Ax replaced” (realloc/new assignment) that changes identity
* And the USE is reachable under some conditions (attach to flow and constraints)

## Integration with Flow Walkthrough

In each step S#, include:

* **What is happening**
* **Memory snapshot** (Ax states + aliases)
* Evidence reference

````

Skills require `SKILL.md` + frontmatter and are discoverable in `.opencode/skills/<name>/SKILL.md`. :contentReference[oaicite:7]{index=7}  

---

## 1C) Command: `.opencode/commands/sec-mem-timeline.md`

```md
---
description: Build allocation/free/use timelines and hunt for UAF/double-free in a target area.
agent: vuln
---

Target: $ARGUMENTS

Use @vuln-mem.

Instructions:
1) Load skill `memory-lifetime-timeline`.
2) Index allocations/frees in the target area (use mem_events).
3) Choose the most reachable flow and express it as S1..Sn (Flow Walkthrough).
4) Build a Memory Objects table (A1..Ak).
5) For each Ax, produce a timeline table.
6) Identify hazard windows and mark bug trigger step with ⚠️.

Do not provide exploit payloads. Provide safe reproduction ideas only.
````

Commands are defined via Markdown in `.opencode/commands/` with frontmatter (`description`, `agent`). ([OpenCode][4])

---

## 1D) Custom tool: allocation/free indexer (optional but very useful)

This tool **does not “solve” lifetimes**; it gives your agent a fast index of likely `malloc/free/...` events.

### `.opencode/tools/mem_events.py`

```py
#!/usr/bin/env python3
import argparse
import json
import os
import re
import sys

ALLOC_FUNS_DEFAULT = ["malloc", "calloc", "realloc"]
FREE_FUNS_DEFAULT = ["free"]

ALLOC_RE = re.compile(r"\b(?P<fn>malloc|calloc|realloc)\s*\(")
FREE_RE = re.compile(r"\b(?P<fn>free)\s*\(")

ASSIGN_RE = re.compile(r"(?P<lhs>[A-Za-z_]\w*)\s*=\s*(?:\([^)]+\)\s*)?(?P<fn>malloc|calloc|realloc)\s*\(")
FREE_ARG_RE = re.compile(r"\bfree\s*\(\s*(?P<arg>[^)]+)\)")

def iter_files(root, exts):
  for dirpath, _, filenames in os.walk(root):
    for fn in filenames:
      if any(fn.endswith(ext) for ext in exts):
        yield os.path.join(dirpath, fn)

def scan_file(path, alloc_funs, free_funs, max_events):
  events = []
  with open(path, "r", errors="ignore") as f:
    for i, line in enumerate(f, start=1):
      if len(events) >= max_events:
        break

      # alloc (malloc/calloc/realloc)
      m = ASSIGN_RE.search(line)
      if m and m.group("fn") in alloc_funs:
        events.append({
          "kind": "alloc",
          "fn": m.group("fn"),
          "lhs": m.group("lhs"),
          "file": path,
          "line": i,
          "code": line.strip()
        })
        continue

      m2 = ALLOC_RE.search(line)
      if m2 and m2.group("fn") in alloc_funs:
        events.append({
          "kind": "alloc",
          "fn": m2.group("fn"),
          "lhs": None,
          "file": path,
          "line": i,
          "code": line.strip()
        })
        continue

      # free
      m3 = FREE_ARG_RE.search(line)
      if m3:
        events.append({
          "kind": "free",
          "fn": "free",
          "arg": m3.group("arg").strip(),
          "file": path,
          "line": i,
          "code": line.strip()
        })
        continue

      m4 = FREE_RE.search(line)
      if m4 and m4.group("fn") in free_funs:
        events.append({
          "kind": "free",
          "fn": m4.group("fn"),
          "arg": None,
          "file": path,
          "line": i,
          "code": line.strip()
        })

  return events

def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("path", help="File or directory to scan")
  ap.add_argument("--ext", action="append", default=[".c", ".h", ".cpp", ".hpp"])
  ap.add_argument("--alloc", action="append", default=[])
  ap.add_argument("--free", action="append", default=[])
  ap.add_argument("--max", type=int, default=2000)
  args = ap.parse_args()

  alloc_funs = ALLOC_FUNS_DEFAULT + args.alloc
  free_funs = FREE_FUNS_DEFAULT + args.free

  root = args.path
  all_events = []
  if os.path.isfile(root):
    all_events.extend(scan_file(root, alloc_funs, free_funs, args.max))
  else:
    for fp in iter_files(root, args.ext):
      all_events.extend(scan_file(fp, alloc_funs, free_funs, args.max - len(all_events)))
      if len(all_events) >= args.max:
        break

  print(json.dumps({
    "path": root,
    "alloc_funs": alloc_funs,
    "free_funs": free_funs,
    "events": all_events
  }))

if __name__ == "__main__":
  sys.exit(main())
```

### `.opencode/tools/mem_events.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import path from "path"

export default tool({
  description: "Index malloc/calloc/realloc/free call sites under a path. Returns JSON. (Heuristic, not a full analyzer.)",
  args: {
    path: tool.schema.string().describe("File or directory to scan"),
    max: tool.schema.number().optional().describe("Max events (default 2000)"),
  },

  async execute(args, context) {
    const script = path.join(context.worktree, ".opencode/tools/mem_events.py")
    const max = args.max ?? 2000
    const out = await Bun.$`python3 ${script} ${args.path} --max ${max}`.text()
    return out.trim()
  },
})
```

Custom tools are defined in `.opencode/tools/` and can invoke Python scripts (TS/JS is just the wrapper). ([OpenCode][3])

---

# Use case 2 — Z3 Feasibility for memory bug triggers

## What it produces

A “feasibility appendix” that answers:

* **What conditions must be true** for the FREE to happen?
* **What conditions must be true** for the later USE to happen?
* Are those conditions **SAT** (reachable) or **UNSAT** (dead path)?
* If **SAT**, record **one safe input model** (values) you can use in a regression test harness.

This is the step that turns “this looks like a UAF” into “this is reachable under these constraints”.

---

## 2A) Agent: `.opencode/agents/vuln-smt.md`

```md
---
description: SMT/Z3 feasibility agent. Converts a suspected memory bug flow into constraints and checks SAT/UNSAT (defensive reachability).
mode: subagent
temperature: 0.1
steps: 40

tools:
  write: false
  edit: false
  patch: false
  bash: false
  webfetch: false

permission:
  z3_smt2: ask
---

You are an SMT feasibility analyst for memory-safety findings.

Goal:
- Given a *specific* suspected bug flow (S1..Sn, with a ⚠️ bug trigger step), determine whether the path conditions are satisfiable.

Method:
1) Identify attacker-controlled or environment-controlled variables:
   - sizes, lengths, indices, flags, enum values, counts, pointer-nullness guards, etc.
2) Extract path conditions that must hold to:
   - reach the FREE step
   - reach the USE step after the FREE
3) Write constraints in a small SMT-LIB subset (prefer Int constraints first):
   - declare variables
   - assert constraints
4) Run z3_smt2 tool to check SAT/UNSAT.
5) Interpret the result:
   - SAT: provide one safe model for test harness (not exploit payloads)
   - UNSAT: explain which conditions contradict

Never:
- Provide weaponized exploit steps or heap manipulation advice.
```

Agents can set tool availability and permissions in Markdown frontmatter. ([OpenCode][1])

---

## 2B) Skill: `.opencode/skills/z3-feasibility/SKILL.md`

````md
---
name: z3-feasibility
description: Turn a suspected memory bug flow (FREE then USE) into SMT constraints and use Z3 to check SAT/UNSAT, recording a safe model for regression tests.
compatibility: opencode
---

## What we are solving
We are NOT exploiting anything. We are checking reachability of a bad state.

Bad states of interest:
- UAF: FREE(Ax) occurs and later USE(Ax) occurs
- Double free: FREE(Ax) occurs twice on a reachable path
- OOB: idx >= size or idx < 0 at USE

## Workflow

### Step 1 — Choose the flow
Start from the Flow Walkthrough (S1..Sn).
You must know:
- which step frees Ax
- which later step uses Ax (⚠️)

### Step 2 — Identify symbolic variables
Create a table like:
| Var | Type | Origin | Meaning |
|-----|------|--------|---------|
| n   | Int  | input  | allocation size |
| idx | Int  | input  | index used at deref |
| flag| Bool | input/state | controls free/use |

### Step 3 — Extract constraints
Add only constraints that actually appear in code:
- if statements
- bounds checks
- error checks
- switch cases
- return-early guards

### Step 4 — Write SMT-LIB (minimal subset)
Prefer QF_LIA:
```smt2
(set-logic QF_LIA)
(declare-fun n () Int)
(declare-fun idx () Int)
(declare-fun flag () Bool)

(assert (> n 0))
(assert (< n 64))
(assert (= flag true))
(assert (>= idx 0))
(assert (< idx n))
````

### Step 5 — Interpret SAT/UNSAT safely

* SAT: record one model as “safe test harness inputs”
* UNSAT: document contradictory asserts

## Report formatting (required)

Include a “Feasibility (Z3)” section with:

* Variables table
* SMT-LIB code fence
* Z3 result: SAT/UNSAT
* If SAT: one model (values)
* Explanation tying the model back to flow steps S# (what it enables)

````

---

## 2C) Command: `.opencode/commands/sec-mem-z3.md`

```md
---
description: Check satisfiability of a suspected memory bug path (FREE then USE) using Z3 and record SAT/UNSAT + model.
agent: vuln
---

Target: $ARGUMENTS

Use @vuln-smt.

Instructions:
1) Load skill `z3-feasibility`.
2) Require an explicit flow (S1..Sn) with identified FREE step and ⚠️ USE step.
3) Build SMT constraints from branch conditions along that path.
4) Call z3_smt2 to determine SAT/UNSAT.
5) Produce a short “Feasibility (Z3)” appendix that can be pasted into the finding report.

No exploit payloads; only safe regression test values if SAT.
````

---

## 2D) Custom tool: run Z3 on SMT-LIB constraints

This expects an SMT-LIB file (or string) containing **declarations + asserts**. The tool runs check-sat and prints a model if SAT.

### `.opencode/tools/z3_smt2.py`

```py
#!/usr/bin/env python3
import argparse
import sys

def main():
  ap = argparse.ArgumentParser()
  ap.add_argument("--file", help="Path to SMT2 file with declarations + asserts")
  ap.add_argument("--text", help="Inline SMT2 text with declarations + asserts")
  args = ap.parse_args()

  try:
    from z3 import Solver, parse_smt2_file, parse_smt2_string, sat, unknown
  except Exception as e:
    print("ERROR: z3 module not available. Install with: pip install z3-solver", file=sys.stderr)
    return 2

  s = Solver()

  try:
    if args.file:
      constraints = parse_smt2_file(args.file)
    elif args.text:
      constraints = parse_smt2_string(args.text)
    else:
      print("ERROR: Provide --file or --text", file=sys.stderr)
      return 2
  except Exception as e:
    print(f"ERROR parsing SMT2: {e}", file=sys.stderr)
    return 2

  # constraints is typically a list of BoolRefs
  for c in constraints:
    s.add(c)

  r = s.check()
  if r == sat:
    m = s.model()
    print("sat")
    print(m)
    return 0
  elif str(r) == "unknown":
    print("unknown")
    return 0
  else:
    print("unsat")
    return 0

if __name__ == "__main__":
  sys.exit(main())
```

### `.opencode/tools/z3_smt2.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import path from "path"

export default tool({
  description: "Run Z3 on SMT-LIB constraints (decls+asserts) and return sat/unsat + model. Defensive reachability only.",
  args: {
    file: tool.schema.string().optional().describe("Path to .smt2 file (relative to repo root allowed)"),
    text: tool.schema.string().optional().describe("Inline SMT2 content (decls + asserts)"),
  },

  async execute(args, context) {
    const script = path.join(context.worktree, ".opencode/tools/z3_smt2.py")

    if (!args.file && !args.text) {
      return "ERROR: provide either 'file' or 'text'"
    }

    if (args.file) {
      const abs = path.isAbsolute(args.file) ? args.file : path.join(context.worktree, args.file)
      const out = await Bun.$`python3 ${script} --file ${abs}`.text()
      return out.trim()
    } else {
      // Pass inline text safely via stdin-ish behavior is non-trivial with Bun.$; simplest is arg.
      // Keep this for small constraints. For larger, write to a file in findings folder.
      const out = await Bun.$`python3 ${script} --text ${args.text}`.text()
      return out.trim()
    }
  },
})
```

opencode explicitly supports tools defined in TS/JS that invoke Python scripts, and shows a Python example using `Bun.$`. ([OpenCode][3])

---

# Memory report template (Flow Walkthrough + Memory Timeline + Z3)

Use this for UAF/double-free/OOB findings.

## `docs/security/findings/TEMPLATE-memory.md`

````md
---
id: VR-0000
status: draft
severity: unknown
cwe: unknown
component: unknown
bug_class: memory-safety   # memory-safety | logic | injection | authz | etc
---

# <Finding Title>

## 0) TL;DR
**Impact:** <one sentence>  
**Bug class:** <UAF / double free / OOB read / OOB write>  
**Bug triggers at:** ⚠️ Step [S?](#s)  
**Primary fix:** <one sentence>  

## 1) Scope and Preconditions
- **Attack surface:** <entry point>
- **Attacker:** <unauth/auth/role/etc.>
- **Required conditions:** <flags/state/config>

## 2) Flow at a Glance
**Chain:** [S1](#s1) → [S2](#s2) → … → [Sn](#sn)  
**Bug triggers:** ⚠️ [S?](#s)

```mermaid
flowchart TD
  S1[S1: Entry] --> S2[S2: Parse/Dispatch]
  S2 --> S3[S3: Allocate Ax]
  S3 --> S4[S4: Free Ax]
  S4 --> S5[S5: Use Ax ⚠️]
````

## 3) Flow Table (One Screen Review)

| Step  | Where           | What is happening                                                    | Memory snapshot            | Evidence       |
| ----- | --------------- | -------------------------------------------------------------------- | -------------------------- | -------------- |
| S1    | `<file>::<sym>` | **What is happening:** <…>                                           | (none yet)                 | `<path>:Lx-Ly` |
| S2    | `<file>::<sym>` | **What is happening:** <…>                                           | (none yet)                 | `<path>:Lx-Ly` |
| S3    | `<file>::<sym>` | **What is happening:** Allocates **A1** and stores pointer in `p`.   | `A1=allocated; p→A1`       | `<path>:Lx-Ly` |
| S4    | `<file>::<sym>` | **What is happening:** Frees `p` under condition `<cond>`.           | `A1=freed; p→A1(dangling)` | `<path>:Lx-Ly` |
| S5 ⚠️ | `<file>::<sym>` | **What is happening:** Uses `p` after free (dereference/copy/index). | `A1=freed; USE(A1)`        | `<path>:Lx-Ly` |

## 4) Memory Objects (A1..Ak)

| AllocID | Allocation site | Size expr | Owner                  | Aliases (tracked) |
| ------- | --------------- | --------- | ---------------------- | ----------------- |
| A1      | `<file>:Lx`     | `<expr>`  | `<component/function>` | `p,q,...`         |

## 5) Allocation Timelines

### Allocation A1 timeline

| T  | Flow step | Event | Where           | What is happening                                                      | Heap state after           | Evidence       |
| -- | --------- | ----- | --------------- | ---------------------------------------------------------------------- | -------------------------- | -------------- |
| T1 | S3        | ALLOC | `<file>::<sym>` | **What is happening:** `p = malloc(n)` allocates A1.                   | `A1=allocated; p→A1`       | `<path>:Lx-Ly` |
| T2 | S4        | FREE  | `<file>::<sym>` | **What is happening:** `free(p)` releases A1 but `p` remains non-NULL. | `A1=freed; p→A1(dangling)` | `<path>:Lx-Ly` |
| T3 | S5 ⚠️     | USE   | `<file>::<sym>` | **What is happening:** `p[idx]` dereferences freed A1.                 | `UAF window hit`           | `<path>:Lx-Ly` |

```mermaid
stateDiagram-v2
  [*] --> Allocated: T1 ALLOC(A1)
  Allocated --> Freed: T2 FREE(A1)
  Freed --> UseAfterFree: T3 USE(A1) ⚠️
```

## 6) Feasibility (Z3) (Optional but recommended)

### Variables

| Var  | Type | Origin      | Meaning             |
| ---- | ---- | ----------- | ------------------- |
| n    | Int  | input       | allocation size     |
| idx  | Int  | input       | index used at deref |
| flag | Bool | input/state | controls free path  |

### Constraints (SMT-LIB)

```smt2
(set-logic QF_LIA)
(declare-fun n () Int)
(declare-fun idx () Int)
(declare-fun flag () Bool)

; constraints to reach FREE + USE after it
(assert (> n 0))
(assert (< n 64))
(assert (= flag true))
(assert (>= idx 0))
(assert (< idx n))
```

### Z3 result

* Result: <sat/unsat/unknown>
* Model (if sat): <n=?, idx=?, flag=...>
* Interpretation: <which branch conditions this satisfies and why it enables S4 then S5>

## 7) Root Cause

<one paragraph>

## 8) Fix Recommendation

### Minimal fix

* <e.g., nullify pointers after free + restructure ownership or guard use>

### Defense in depth (optional)

* <e.g., ownership API, RAII, reference counting, clearer contracts>

## 9) Regression Test Idea (Safe)

* <safe harness / unit test / integration test that forces the path and asserts behavior>

````

---

# Recommended tiny AGENTS.md addition (so all agents “know” about these)

If you want your main policy file to explicitly require timelines + Z3 for memory bugs, add this section:

```md
## Memory Safety Extensions (malloc/free timelines + Z3 feasibility)
When auditing C/C++ memory safety issues:
- Build a per-allocation timeline (A1..Ak) with ALLOC/ALIAS/FREE/USE events.
- Integrate memory snapshots into the S1..Sn Flow Walkthrough.
- For suspected UAF/double-free/OOB, attempt a Z3 feasibility check:
  - Extract path constraints
  - Record SAT/UNSAT and (if SAT) one safe model for regression testing
````

`AGENTS.md` is the standard way to feed project instructions to opencode. ([OpenCode][5])

---

# How you actually run the two use cases

### Use case 1 (timeline)

* Run: `/sec-mem-timeline <path/or/component>`
* Output: Allocation tables + timelines + UAF candidates

### Use case 2 (Z3)

* After you have a suspected FREE→USE flow:
* Run: `/sec-mem-z3 <finding or function>`
* Output: SAT/UNSAT + model + interpretation you paste into the finding

---

If you want, I can also provide a **“memory-specific Flow Walkthrough step card”** format (so each S-step always includes a compact heap snapshot), but the template above already enforces it through the Flow Table + timeline sections.

[1]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[2]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[3]: https://opencode.ai/docs/custom-tools/ "Custom Tools | OpenCode"
[4]: https://opencode.ai/docs/commands/?utm_source=chatgpt.com "Commands"
[5]: https://opencode.ai/docs/rules/?utm_source=chatgpt.com "Rules"

You can absolutely build a “memory-safety agent pack” around **(1) lifetime timelines** and **(2) constraint+Z3 feasibility checks**—and keep it *high-signal* by standardizing what a “timeline” looks like and forcing every agent to output the same compact artifact.

Below is a practical, drop-in set of **agents + commands + skills + a Z3 custom tool**, designed around your 2 use cases:

* **Use case A**: “malloc/free timeline for a specific dataflow” → find UAF candidates with minimal noise
* **Use case B**: “scan suspicious memops (memcpy etc), build constrained timeline” → Z3 feasibility check

Everything uses OpenCode’s documented locations and formats for agents, commands, skills, custom tools, and permission rules. ([OpenCode][1])

---

## 0) The core idea: a shared “Timeline Artifact” (so outputs stay small)

To reduce output noise, make every memory agent produce the same **compact timeline artifact**:

### Timeline Artifact (minimal schema)

* **Target**: pointer/ownership object (e.g., `struct foo* p`, or field `ctx->buf`)
* **Events**: ordered list of only memory-lifetime-relevant steps
  `alloc | alias | store | load | free | realloc | memop | deref | return | escape`
* **Guards**: minimal path conditions needed for those events to happen (no full AST dumps)

This standardization is what makes the second phase (“constraints → Z3”) reliable and keeps the LLM from dumping the whole program.

---

## 1) Minimal `opencode.jsonc` updates for this workflow

OpenCode permissions can be defined per tool and can be **glob/pattern-based** (including `task` for subagents, and file-path patterns for `read`/`edit`). ([OpenCode][2])
Custom tools live in `.opencode/tools/` or `~/.config/opencode/tools/`. ([OpenCode][3])

Here’s a config that:

* allows read/grep/glob/lsp,
* blocks edits except artifacts/findings,
* allows invoking only `mem-*` agents,
* keeps webfetch off,
* makes your custom `z3` tool “ask” by default.

```jsonc
// opencode.jsonc
{
  "$schema": "https://opencode.ai/config.json",

  "permission": {
    "*": "ask",

    // Safe/static analysis
    "read": {
      "*": "allow",
      "*.env": "deny",
      "*.env.*": "deny",
      "*.env.example": "allow"
    },
    "grep": "allow",
    "glob": "allow",
    "list": "allow",

    // If you use the LSP tool, it’s permissioned like any other tool.
    "lsp": "allow",

    // Skills are useful for consistent outputs.
    "skill": { "*": "allow" },

    // Subagent launches
    "task": {
      "*": "deny",
      "mem-*": "allow"
    },

    // No outbound
    "webfetch": "deny",

    // No code edits; only allow writing artifacts + findings.
    // edit covers edit/write/patch/multiedit. :contentReference[oaicite:3]{index=3}
    "edit": {
      "*": "deny",
      ".opencode/artifacts/**": "allow",
      "docs/security/findings/**": "allow"
    },

    // Bash is optional; keep it gated.
    "bash": {
      "*": "ask",
      "git *": "allow",
      "rg *": "allow"
    },

    // Custom Z3 tool permission (defined below)
    "z3": "ask"
  }
}
```

Notes:

* Permissions support `task`, `skill`, file-path rules, and more. ([OpenCode][2])
* If you want these agents to use `lsp`, remember it’s an experimental tool that may require enabling via env flags depending on your setup. ([OpenCode][4])

---

## 2) Agents: purpose-built for timeline building + constraint checking

Agents go in `.opencode/agents/` (project) or `~/.config/opencode/agents/` (global). ([OpenCode][1])
Filename = agent name. ([OpenCode][1])

### 2.1 `.opencode/agents/mem-audit.md` (primary orchestrator)

```md
---
description: Memory safety auditor (UAF + heap/stack corruption). Builds compact lifetime timelines and can validate feasibility with Z3.
mode: primary
temperature: 0.1
steps: 40
permission:
  webfetch: deny
  task:
    "*": deny
    "mem-*": allow
---

You are a memory-safety vulnerability research agent. Your job is to find *reachable* memory lifetime and memory corruption issues, while minimizing noise.

Hard rule:
- Do NOT generate weaponized exploit payloads or instructions for attacking real systems.
- You may produce *defensive* reproduction guidance (unit-test harness ideas, fuzz seed shape) and feasibility proofs.

Core workflow:
1) For a suspected target (pointer, buffer, or callsite), produce a compact Timeline Artifact.
2) If asked for feasibility, convert Timeline Artifact → SMT-LIB2 constraints.
3) Use the Z3 tool (via mem-z3-check) to determine sat/unsat and show a minimal model.

Always keep output small:
- Prefer an event list + file:line references.
- Never paste full functions unless specifically needed.

Delegate specialized work to:
- mem-uaf-timeline
- mem-memop-scan
- mem-memop-timeline
- mem-constraints
- mem-z3-check
```

### 2.2 `.opencode/agents/mem-uaf-timeline.md` (use case A)

```md
---
description: Build an allocation/free/use timeline for a specific pointer/dataflow to triage UAF candidates with minimal output.
mode: subagent
temperature: 0.1
steps: 35
permission:
  edit: deny
  webfetch: deny
---

You build a compact UAF timeline.

Inputs (if user provides):
- a pointer symbol (e.g., `p`, `ctx->buf`)
- a type (e.g., `struct foo*`)
- a suspicious use site (file:line or function call)

Method (noise-minimizing):
1) Identify allocator/free wrappers:
   - malloc/calloc/realloc/free
   - new/delete (C++)
   - project-specific wrappers (e.g., xmalloc, foo_alloc/foo_free)
2) Start from the suspected "use" site and slice backwards to the alloc and forwards to frees:
   - Track *aliases only*: assignments, parameter passing, field stores/loads, returns (“escape”).
   - Ignore unrelated locals.
3) Produce a Timeline Artifact with <= 30 events. If more, collapse loops/recursion into a single summarized event.
4) Flag UAF candidates:
   - A free event that dominates a later deref/memop/use event for the same alias-set.
   - Note if concurrency/reentrancy is required (mark as “needs dynamic validation”).

Output (strict):
- ## Timeline Artifact (JSON)
- ## Evidence (event -> file:line)
- ## Guards (minimal conditions)
- ## UAF suspicion verdict (1–3 sentences)
```

### 2.3 `.opencode/agents/mem-memop-scan.md` (use case B: discovery)

```md
---
description: Scan the codebase for memory-corruption-prone operations (memcpy/memmove/strcpy/etc) and rank the most suspicious callsites.
mode: subagent
temperature: 0.1
steps: 25
permission:
  edit: deny
  webfetch: deny
---

You find and rank suspicious memory operations.

Target patterns (include wrappers):
- memcpy, memmove, mempcpy
- strcpy, strncpy, strcat, strncat
- sprintf, vsprintf, snprintf (format risks too)
- read/recv into buffers
- project-specific wrappers around these

Heuristics for "suspicious":
- length argument derived from external input or not obviously bounded
- size computed with int/signed conversions, truncation, or multiplication without overflow checks
- destination buffer is stack array, flexible array member, heap buffer with unclear size, or pointer arithmetic

Output (compact):
- Top 20 callsites as: file:line | function | call | “why suspicious”
- Then a short “next 5 to timeline” list
```

### 2.4 `.opencode/agents/mem-memop-timeline.md` (use case B: timeline + constraints)

```md
---
description: For a specific risky memop callsite (e.g., memcpy), build a compact buffer/length timeline with explicit size/guard constraints.
mode: subagent
temperature: 0.1
steps: 35
permission:
  edit: deny
  webfetch: deny
---

You build a memop-focused timeline + constraints.

Input should identify the callsite:
- file:line OR function name + snippet

Steps:
1) Locate the callsite; extract:
   - dst expression
   - src expression
   - len expression
2) Slice backwards to determine:
   - dst allocation/definition and its size expression
   - any checks that bound len (including early returns)
   - conversions/casts that change signedness/width
3) Produce a Timeline Artifact where the final event is:
   { kind: "memop", op: "memcpy", dst_size_expr: "...", len_expr: "...", ... }

Output:
- ## Timeline Artifact (JSON)
- ## Constraints (human-readable)
  - Define: dst_size, len, and any input-derived vars
  - List: guards that must hold
  - List: bug condition (e.g., len > dst_size)
- ## Recommended Z3 check goal (sat query)
```

### 2.5 `.opencode/agents/mem-constraints.md` (timeline → SMT-LIB2)

```md
---
description: Convert a Timeline Artifact into SMT-LIB2 constraints (small!) to check reachability/trigger feasibility.
mode: subagent
temperature: 0.1
steps: 30
permission:
  edit: deny
  webfetch: deny
---

You translate timeline constraints into SMT-LIB2.

Rules:
- Default to Int arithmetic for a first pass.
- If the bug depends on wraparound/truncation, switch relevant vars to BitVec and state the widths explicitly.
- Keep the SMT2 minimal: only vars appearing in guards or bug condition.

Output:
- ## SMT-LIB2 (copy/paste)
  Must include:
  - (set-option :produce-models true)
  - declarations
  - asserts for guards
  - assert for the bug condition
  - (check-sat)
  - (get-model)

Also output:
- ## Variable mapping
  var -> code expression -> file:line where it comes from
```

### 2.6 `.opencode/agents/mem-z3-check.md` (run solver, interpret safely)

```md
---
description: Run the Z3 custom tool on SMT-LIB2 and interpret sat/unsat into a defensive reproducer plan (no weaponized exploits).
mode: subagent
temperature: 0.1
steps: 15
permission:
  bash: deny
  edit: deny
  webfetch: deny
  z3: allow
---

You run Z3 and interpret results.

Input: SMT-LIB2 in the conversation or referenced via a file.

Process:
1) Call the z3 tool with the SMT2 text.
2) Report status: sat/unsat/unknown.
3) If sat, extract only high-level model assignments (integers/booleans) and explain how they correspond to code variables.
4) Provide *defensive* reproduction guidance:
   - suggest a unit test harness, or a minimized input shape
   - do NOT provide exploit payloads or real-world attack steps
```

---

## 3) Skills: keep agents consistent and “low-noise”

Skills live at `.opencode/skills/<name>/SKILL.md` and require YAML frontmatter with `name` and `description`. ([OpenCode][5])

### 3.1 `.opencode/skills/mem-lifetime-timeline/SKILL.md`

```md
---
name: mem-lifetime-timeline
description: Build compact allocation/free/alias/use timelines for pointer lifetimes to triage UAF with minimal output.
compatibility: opencode
---

## Goal
Produce a **Timeline Artifact** limited to lifetime-relevant events for ONE target pointer/alias set.

## Timeline Artifact schema (JSON)
- target: string
- entry_hint: string (optional)
- events: array of events (<= 30)
- guards: map guard_id -> expression
- notes: short strings

### Event fields
- id: "E1"
- kind: alloc | alias | store | load | free | realloc | deref | memop | return | escape
- ptr: "p" (or "ctx->buf")
- site: "path/file.c:123"
- func: "foo"
- detail: short (allocator/free fn, field name, etc.)
- guard: ["G1","G2"] (optional)

## Noise control rules
- Ignore unrelated locals and helper functions unless they affect ptr lifetime or size.
- Collapse loops into a single summarized event.
- Prefer file:line + 1 sentence over pasted code.
```

### 3.2 `.opencode/skills/mem-memop-triage/SKILL.md`

```md
---
name: mem-memop-triage
description: Identify and rank memory corruption hotspots (memcpy/memmove/strcpy/etc) and extract size/length constraints.
compatibility: opencode
---

## What to search for
- memcpy/memmove/mempcpy
- strcpy/strncpy/strcat/strncat
- sprintf/vsprintf/snprintf
- read/recv into buffers
- project wrappers around these

## Ranking rubric
Higher risk if:
- len is attacker-controlled or not obviously bounded
- dst buffer size is unknown/derived from prior allocations
- casts change signedness/width
- integer multiplication/addition used in size calc without bounds checks

## Deliverable
- top suspicious callsites
- for each: dst expr, len expr, local checks, file:line evidence
```

### 3.3 `.opencode/skills/mem-smt2-modeling/SKILL.md`

```md
---
name: mem-smt2-modeling
description: Translate guard conditions + bug predicates into minimal SMT-LIB2 for Z3 (Int-first, BitVec when needed).
compatibility: opencode
---

## Int-first recipe (fast feasibility)
- declare-const len Int
- declare-const dst_size Int
- assert (>= len 0), (>= dst_size 0)
- assert guards
- assert bug predicate (e.g., (> len dst_size))

## When to use BitVec
Use BitVec when:
- signed/unsigned conversions matter
- truncation (e.g., to 32-bit) matters
- overflow wraparound is part of the bug

## Always include
(set-option :produce-models true)
(check-sat)
(get-model)
```

### 3.4 `.opencode/skills/mem-z3-checking/SKILL.md`

```md
---
name: mem-z3-checking
description: Interpret Z3 sat/unsat results as defensive reachability proofs and convert models into safe reproducer guidance.
compatibility: opencode
---

## Output rules
- sat: show a minimal model (only relevant vars)
- unsat: explain which constraints likely conflict
- unknown: suggest simplifications (drop non-essential guards, Int-first)

## Safety
Do not provide weaponized exploit payloads. Provide unit-test harness guidance instead.
```

---

## 4) Commands: one-liners to drive the workflow

Commands are `.opencode/commands/*.md` and use YAML frontmatter like `description` and optional `agent`. ([OpenCode][6])

### 4.1 `/uaf-timeline`

`.opencode/commands/uaf-timeline.md`

```md
---
description: Build a compact alloc/free/use timeline for a target pointer/dataflow (UAF triage).
agent: mem-uaf-timeline
---

Target: $ARGUMENTS

Build a Timeline Artifact for the target.
Keep to <= 30 events.
Return JSON + evidence + guards + verdict.
```

### 4.2 `/memop-scan`

`.opencode/commands/memop-scan.md`

```md
---
description: Scan and rank suspicious memory ops (memcpy/strcpy/etc).
agent: mem-memop-scan
---

Scan the repo for high-risk memory operations and output the top 20 suspicious callsites.
Then recommend the top 5 to run /memop-timeline on.
```

### 4.3 `/memop-timeline`

`.opencode/commands/memop-timeline.md`

```md
---
description: Build a constraint-aware timeline for a specific memop callsite (e.g. memcpy) suitable for Z3.
agent: mem-memop-timeline
---

Callsite: $ARGUMENTS

Produce:
- Timeline Artifact JSON
- explicit constraints (dst_size, len, guards)
- a suggested Z3 bug predicate to check
```

### 4.4 `/mem-constraints`

`.opencode/commands/mem-constraints.md`

```md
---
description: Convert the most recent Timeline Artifact into SMT-LIB2 constraints.
agent: mem-constraints
---

Using the latest Timeline Artifact in the conversation, emit minimal SMT-LIB2 suitable for Z3.
Prefer Int-first unless wraparound is essential.
```

### 4.5 `/z3-check`

`.opencode/commands/z3-check.md`

```md
---
description: Run Z3 on SMT-LIB2 in the conversation and interpret sat/unsat safely.
agent: mem-z3-check
---

Run Z3 on the SMT-LIB2 provided in the conversation (or referenced via @file).
Return sat/unsat/unknown and a minimal model mapping back to code variables.
```

---

## 5) Custom Z3 tool (so agents can actually run the solver)

Custom tools can be created in `.opencode/tools/` or globally in `~/.config/opencode/tools/`. ([OpenCode][3])
The filename becomes the tool name. ([OpenCode][3])

### `.opencode/tools/z3.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import os from "os"
import path from "path"
import fs from "fs/promises"

export default tool({
  description:
    "Run Z3 on SMT-LIB2 input and return sat/unsat/unknown plus stdout/stderr (for defensive reachability checks).",
  args: {
    smt2: tool.schema.string().describe("SMT-LIB2 text (should include check-sat; get-model optional)."),
    timeout_ms: tool.schema.number().int().positive().optional().describe("Optional Z3 timeout in ms (applied via set-option).")
  },
  async execute(args, context) {
    const z3Path = Bun.which("z3")
    if (!z3Path) {
      return {
        status: "error",
        message:
          "z3 binary not found in PATH. Install Z3, or adjust PATH for the OpenCode runtime."
      }
    }

    const smt2 =
      typeof args.timeout_ms === "number"
        ? `(set-option :timeout ${args.timeout_ms})\n(set-option :produce-models true)\n${args.smt2}`
        : `(set-option :produce-models true)\n${args.smt2}`

    const tmp = path.join(
      os.tmpdir(),
      `opencode-z3-${context.sessionID}-${Date.now()}-${Math.random().toString(16).slice(2)}.smt2`
    )

    await Bun.write(tmp, smt2)

    const proc = Bun.spawn({
      cmd: [z3Path, "-smt2", tmp],
      stdout: "pipe",
      stderr: "pipe"
    })

    const stdout = await new Response(proc.stdout).text()
    const stderr = await new Response(proc.stderr).text()
    const exitCode = await proc.exited

    // Best-effort cleanup
    await fs.unlink(tmp).catch(() => {})

    const out = stdout.trim()
    const firstTok = out.split(/\s+/)[0] || "unknown"

    // Z3 typically prints: sat / unsat / unknown first.
    const status = ["sat", "unsat", "unknown"].includes(firstTok) ? firstTok : "unknown"

    return {
      status,
      exitCode,
      stdout: out,
      stderr: stderr.trim()
    }
  }
})
```

---

## 6) How the 2 use cases look in practice

### Use case A: UAF-focused lifetime timeline

1. `/uaf-timeline ctx->buf`
2. If it shows `free` then later `deref/memop`, run `/mem-constraints`
3. Then `/z3-check` to validate the feasibility of the “free-before-use” + guard conditions (as modeled)

### Use case B: corruption hotspot → constrained timeline → Z3

1. `/memop-scan` (gives top suspicious memcpy/strcpy/etc callsites)
2. `/memop-timeline path/to/file.c:123`
3. `/mem-constraints` (bug predicate might be `len > dst_size` or something more nuanced)
4. `/z3-check` (sat gives you a **defensive** witness model; you turn that into a unit-test harness)

---

## One important realism note

This approach is powerful for **reachability proofs**, but it’s still an approximation:

* aliasing can explode (timeline agent must be strict about alias-set boundaries),
* size computations often depend on opaque helpers,
* concurrency/reentrancy UAFs may require dynamic validation.

That’s fine: your goal is **triage + “is there a satisfiable trigger?”**, not perfect soundness.

---

If you want to push this even further (still keeping outputs compact), the next upgrade is a **single “timeline normalizer” tool** that stores the Timeline Artifact to `.opencode/artifacts/…` and lets subsequent agents reference it by filename instead of copy/pasting. The permission model already supports this path-scoped write pattern. ([OpenCode][2])

[1]: https://opencode.ai/docs/agents/ "Agents | OpenCode"
[2]: https://opencode.ai/docs/permissions/ "Permissions | OpenCode"
[3]: https://opencode.ai/docs/custom-tools/ "Custom Tools | OpenCode"
[4]: https://opencode.ai/docs/tools/ "Tools | OpenCode"
[5]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[6]: https://opencode.ai/docs/commands/ "Commands | OpenCode"

----------------------------------->
+++++++++++++++++++++++++++++++++++++
Below is a complete “starter kit” you can drop into a repo so OpenCode can (1) inventory your large iOS JSON logs, (2) summarize your activity, and (3) flag suspicious patterns — **without** stuffing giant JSON into the model context.

It uses:

* **Agent rules** (`AGENTS.md`) to enforce privacy + a large‑data strategy. ([opencode.ai][1])
* **Skills** (`.opencode/skills/<name>/SKILL.md`) so the agent can load “how to work” on demand. ([opencode.ai][2])
* **Custom tools** (`.opencode/tools/*.ts`) that call **Python scripts** to do the heavy lifting locally, returning small, safe outputs. ([opencode.ai][3])
* Optional **commands** (`.opencode/commands/*.md`) so you can run `/log-inventory`, `/log-index`, etc. ([opencode.ai][4])

> Assumption: you can put your JSON files under a `logs/` folder. Adjust paths if you keep them elsewhere.

---

## 1) Project layout

OpenCode looks for skills at `.opencode/skills/<name>/SKILL.md` (and other compatible locations). ([opencode.ai][2])
Custom tools live in `.opencode/tools/` (or globally in `~/.config/opencode/tools/`). ([opencode.ai][3])
Commands can be defined as markdown files under `.opencode/commands/`. ([opencode.ai][4])
Project config is `opencode.json` at the repo root. ([opencode.ai][5])

Create this structure:

```text
your-log-repo/
├─ opencode.json
├─ AGENTS.md
├─ logs/                              # <-- put your iOS JSON logs here
├─ analysis/                           # <-- generated outputs go here
│  └─ README.md
└─ .opencode/
   ├─ commands/
   │  ├─ log-inventory.md
   │  ├─ log-index.md
   │  ├─ log-summary.md
   │  └─ log-suspicious.md
   ├─ skills/
   │  ├─ ios-log-inventory/SKILL.md
   │  ├─ ios-log-index/SKILL.md
   │  ├─ ios-activity-summary/SKILL.md
   │  └─ ios-suspicious-detector/SKILL.md
   └─ tools/
      ├─ ios_logs.ts
      └─ scripts/
         ├─ json_stream.py
         ├─ inventory_logs.py
         ├─ summarize_logs.py
         ├─ build_index.py
         ├─ query_index.py
         ├─ get_record.py
         └─ suspicious_scan.py
```

---

## 2) Context strategy for “lots of large JSON”

This design avoids context blowups by doing **map/reduce + indexing**:

1. **Inventory**: detect file formats/schemas; write `analysis/manifest.json`
2. **Summarize per file**: write small `analysis/file_summaries/*.json`
3. **Build an index** (SQLite): extract only key fields + record locator (line/index), not full JSON
4. **Query + evidence**: use SQL to pull *only* the slices needed
5. **Suspicious scan**: rules + simple anomaly checks, output a compact findings file

OpenCode also supports automatic session compaction and pruning tool outputs; you should keep that enabled for long analyses. ([opencode.ai][6])

---

## 3) Root config: `opencode.json`

Put this at repo root (project config has highest precedence). ([opencode.ai][5])
This config also enables compaction/pruning. ([opencode.ai][6])

```json
{
  "$schema": "https://opencode.ai/config.json",

  "compaction": {
    "auto": true,
    "prune": true
  },

  "agent": {
    "ios-log-analyst": {
      "description": "Summarize iOS JSON logs and flag suspicious patterns with strong privacy + evidence discipline",
      "mode": "primary",
      "temperature": 0.1,
      "steps": 40,
      "tools": {
        "write": true,
        "read": true,
        "bash": true,
        "edit": true,
        "skill": true,
        "webfetch": false
      },
      "permission": {
        "webfetch": "deny",
        "bash": {
          "*": "ask",
          "ls*": "allow",
          "find*": "allow",
          "rg*": "allow",
          "grep*": "allow",
          "wc*": "allow",
          "head*": "allow",
          "tail*": "allow"
        },
        "edit": "ask"
      }
    }
  },

  "default_agent": "ios-log-analyst"
}
```

Notes:

* Agent config supports low temperature for deterministic analysis and `steps` to cap agentic iterations. ([opencode.ai][7])
* We explicitly disable `webfetch` (privacy) and make arbitrary `bash` require approval.

---

## 4) Rules file: `AGENTS.md`

OpenCode reads `AGENTS.md` as project instructions. ([opencode.ai][1])

```md
# iOS JSON Log Analysis (Local + Privacy-First)

## Goal
You are analyzing large iOS device logs stored as JSON files under `logs/`.
Produce:
1) A human-readable activity summary (what happened, when, what apps/services appear)
2) A suspicious-activity report (flags + supporting evidence + recommended next checks)

## Hard constraints (context + privacy)
- NEVER paste entire log files into chat.
- NEVER read big JSON directly with the `read` tool unless a file is tiny (<200KB).
- Prefer the custom tools:
  - `ios_logs_inventory`
  - `ios_logs_summarize`
  - `ios_logs_build_index`
  - `ios_logs_query`
  - `ios_logs_get_record`
  - `ios_logs_suspicious_scan`
- Always redact obvious PII in outputs (emails, phone numbers, precise GPS, auth tokens, device IDs).
  - If evidence requires a value, hash it or truncate it (e.g., `abcd…wxyz`).

## Large-data workflow (always follow)
1) Inventory -> `analysis/manifest.json`
2) Per-file summaries -> `analysis/file_summaries/`
3) Build SQLite index -> `analysis/index/logs.sqlite`
4) Activity rollup report -> `analysis/activity_summary.md`
5) Suspicious scan report -> `analysis/suspicious_report.md`

## Evidence discipline
- Every suspicious finding must include:
  - timestamp (or "no timestamp found")
  - source file name
  - record locator (line number or array index)
  - a short, redacted snippet
- Don’t claim compromise. Use language like:
  - "flagged for review", "unusual", "needs verification"

## Output contract (files to write)
- `analysis/activity_summary.md`
- `analysis/suspicious_report.md`
- `analysis/suspicious_findings.json` (machine-readable)
```

---

## 5) Skills

Skills are folders with a `SKILL.md` that starts with YAML frontmatter. ([opencode.ai][2])

### 5.1 `.opencode/skills/ios-log-inventory/SKILL.md`

```md
---
name: ios-log-inventory
description: Inventory iOS JSON logs (format, schema hints, samples) and write analysis/manifest.json for downstream work
compatibility: opencode
---

## What I do
- Scan `logs/` for JSON/JSONL/NDJSON files
- Infer format (ndjson vs json array vs json object)
- Capture lightweight schema hints and safe samples (redacted)
- Write `analysis/manifest.json`

## How to use me
1) Call `ios_logs_inventory` with default options.
2) Read `analysis/manifest.json` (it should be small).
3) If some files look huge/unparseable, note them and proceed with the rest.

## Guardrails
- Do not print raw records verbatim. Prefer redacted samples.
- If a file looks like a huge top-level object, recommend converting to NDJSON or extending the parser.

## Outputs
- `analysis/manifest.json`
```

### 5.2 `.opencode/skills/ios-log-index/SKILL.md`

```md
---
name: ios-log-index
description: Build a compact SQLite index from large iOS JSON logs so analysis can be done via small targeted queries
compatibility: opencode
---

## What I do
- Parse all supported log files under `logs/`
- Extract normalized fields: timestamp, event type, app/process, host/ip, severity, short message
- Store *locators* (line/index) instead of full raw JSON to keep the DB small
- Write `analysis/index/logs.sqlite`

## How to use me
1) Run `ios_logs_build_index`.
2) Validate with a quick query:
   - "count rows", "min/max timestamp", "top apps" (using `ios_logs_query`).

## Guardrails
- Index building can be slow; that’s fine. Don’t try to ingest the logs into the LLM context.
- Keep queries limited (default tool limit is small).

## Outputs
- `analysis/index/logs.sqlite`
```

### 5.3 `.opencode/skills/ios-activity-summary/SKILL.md`

```md
---
name: ios-activity-summary
description: Produce a human-readable timeline and activity summary from indexed iOS logs, using evidence-backed rollups
compatibility: opencode
---

## What I do
- Use SQL queries over the index to build a timeline and “what happened” narrative
- Summarize by:
  - day
  - app/process
  - event types/categories
  - network hosts (if present)
- Write `analysis/activity_summary.md`

## How to use me (recommended queries)
Use `ios_logs_query` for rollups like:
- Daily volume:
  SELECT substr(ts,1,10) AS day, count(*) AS n
  FROM events
  WHERE ts IS NOT NULL
  GROUP BY day
  ORDER BY day;

- Top apps/processes:
  SELECT app, count(*) AS n
  FROM events
  WHERE app IS NOT NULL
  GROUP BY app
  ORDER BY n DESC
  LIMIT 30;

- Error/warn concentration:
  SELECT severity, count(*) AS n
  FROM events
  WHERE severity IS NOT NULL
  GROUP BY severity
  ORDER BY n DESC;

## Guardrails
- Keep the narrative conservative and evidence-based.
- Redact PII.
- If timestamps are missing, explicitly say so and summarize by file/app instead.

## Outputs
- `analysis/activity_summary.md`
```

### 5.4 `.opencode/skills/ios-suspicious-detector/SKILL.md`

```md
---
name: ios-suspicious-detector
description: Run a suspicious-pattern scan over indexed iOS logs and produce a prioritized review report with evidence pointers
compatibility: opencode
---

## What I do
- Run a rules + anomaly scan (keyword flags, rare hosts, auth failures, profile/cert/vpn/proxy indicators, jailbreak/instrumentation keywords)
- Emit machine-readable findings and a human report
- Help you triage by severity and recommended next steps

## How to use me
1) Ensure the index exists (run `ios_logs_build_index` if needed).
2) Run `ios_logs_suspicious_scan`.
3) For any high severity finding, pull 3–10 raw examples via `ios_logs_get_record` (keep redacted).

## Guardrails
- This is not definitive malware detection. Phrase as “flagged for review”.
- Always include evidence (timestamp/file/locator/snippet).
- Don’t recommend risky actions. Offer safe verification steps (update iOS, review profiles, check VPN/proxy settings, etc.).

## Outputs
- `analysis/suspicious_findings.json`
- `analysis/suspicious_report.md`
```

---

## 6) Custom tools

Custom tools are defined in `.opencode/tools/` as JS/TS and can invoke scripts in any language (we’ll use Python). ([opencode.ai][3])

### 6.1 `.opencode/tools/ios_logs.ts`

```ts
import { tool } from "@opencode-ai/plugin"
import path from "path"

function scriptPath(context: any, scriptName: string) {
  return path.join(context.worktree, ".opencode", "tools", "scripts", scriptName)
}

async function runPy(context: any, scriptName: string, args: string[]) {
  const script = scriptPath(context, scriptName)
  // Bun.$ handles shell execution; we keep outputs short and structured (JSON).
  const result = await Bun.$`python3 ${script} ${args}`.text()
  return result.trim()
}

export const inventory = tool({
  description:
    "Inventory JSON log files in logs/ and write analysis/manifest.json (format/schema/sample hints; redacted).",
  args: {
    logsDir: tool.schema.string().default("logs").describe("Directory containing JSON logs"),
    out: tool.schema.string().default("analysis/manifest.json").describe("Where to write the manifest JSON"),
    redact: tool.schema.boolean().default(true).describe("Redact PII in samples"),
    maxFiles: tool.schema.number().int().min(1).max(5000).default(2000).describe("Safety cap on number of files scanned"),
    sampleRecords: tool.schema.number().int().min(0).max(20).default(2).describe("Number of sample records per file")
  },
  async execute(args, context) {
    return await runPy(context, "inventory_logs.py", [
      "--logs-dir", args.logsDir,
      "--out", args.out,
      "--redact", args.redact ? "1" : "0",
      "--max-files", String(args.maxFiles),
      "--sample-records", String(args.sampleRecords)
    ])
  }
})

export const summarize = tool({
  description:
    "Create per-file summaries for JSON logs and write to analysis/file_summaries/*.json (small, redacted).",
  args: {
    logsDir: tool.schema.string().default("logs").describe("Directory containing JSON logs"),
    outDir: tool.schema.string().default("analysis/file_summaries").describe("Directory to write per-file summaries"),
    redact: tool.schema.boolean().default(true).describe("Redact PII in examples/counters"),
    maxRecordsPerFile: tool.schema.number().int().min(100).max(5_000_000).default(200_000)
      .describe("Safety cap (stop after N records per file) to keep runtime bounded"),
    topK: tool.schema.number().int().min(5).max(200).default(30).describe("Top-K values to keep in counters")
  },
  async execute(args, context) {
    return await runPy(context, "summarize_logs.py", [
      "--logs-dir", args.logsDir,
      "--out-dir", args.outDir,
      "--redact", args.redact ? "1" : "0",
      "--max-records-per-file", String(args.maxRecordsPerFile),
      "--topk", String(args.topK)
    ])
  }
})

export const build_index = tool({
  description:
    "Build a compact SQLite index (analysis/index/logs.sqlite) from JSON logs, storing locators not full raw JSON.",
  args: {
    logsDir: tool.schema.string().default("logs"),
    out: tool.schema.string().default("analysis/index/logs.sqlite"),
    redact: tool.schema.boolean().default(true).describe("Hash/redact PII-ish values stored in extracted fields"),
    maxRecordsPerFile: tool.schema.number().int().min(100).max(50_000_000).default(5_000_000),
    commitEvery: tool.schema.number().int().min(100).max(100_000).default(5000)
  },
  async execute(args, context) {
    return await runPy(context, "build_index.py", [
      "--logs-dir", args.logsDir,
      "--out", args.out,
      "--redact", args.redact ? "1" : "0",
      "--max-records-per-file", String(args.maxRecordsPerFile),
      "--commit-every", String(args.commitEvery)
    ])
  }
})

export const query = tool({
  description:
    "Run a read-only SQL query against analysis/index/logs.sqlite and return limited rows as JSON.",
  args: {
    db: tool.schema.string().default("analysis/index/logs.sqlite"),
    sql: tool.schema.string().describe("Read-only SQL (must start with SELECT or WITH)"),
    limit: tool.schema.number().int().min(1).max(500).default(50).describe("Row limit safety cap")
  },
  async execute(args, context) {
    return await runPy(context, "query_index.py", [
      "--db", args.db,
      "--sql", args.sql,
      "--limit", String(args.limit)
    ])
  }
})

export const get_record = tool({
  description:
    "Fetch one raw record by locator (line number or array index) from a source file, returning a redacted JSON snippet.",
  args: {
    file: tool.schema.string().describe("Path to the source JSON file (relative to repo root, e.g., logs/foo.json)"),
    locator: tool.schema.string().describe("Locator JSON from the index (e.g., {\"format\":\"ndjson\",\"line\":123})"),
    redact: tool.schema.boolean().default(true),
    maxDepth: tool.schema.number().int().min(1).max(20).default(6),
    maxString: tool.schema.number().int().min(20).max(2000).default(300)
  },
  async execute(args, context) {
    return await runPy(context, "get_record.py", [
      "--file", args.file,
      "--locator", args.locator,
      "--redact", args.redact ? "1" : "0",
      "--max-depth", String(args.maxDepth),
      "--max-string", String(args.maxString)
    ])
  }
})

export const suspicious_scan = tool({
  description:
    "Run heuristic suspicious-pattern detection over the SQLite index and write analysis/suspicious_findings.json + suspicious_report.md.",
  args: {
    db: tool.schema.string().default("analysis/index/logs.sqlite"),
    outJson: tool.schema.string().default("analysis/suspicious_findings.json"),
    outMd: tool.schema.string().default("analysis/suspicious_report.md"),
    maxEvidencePerFinding: tool.schema.number().int().min(1).max(50).default(10)
  },
  async execute(args, context) {
    return await runPy(context, "suspicious_scan.py", [
      "--db", args.db,
      "--out-json", args.outJson,
      "--out-md", args.outMd,
      "--max-evidence", String(args.maxEvidencePerFinding)
    ])
  }
})
```

---

## 7) Python scripts

### 7.1 `.opencode/tools/scripts/json_stream.py`

A lightweight streaming reader for NDJSON and JSON arrays (no external dependencies).

```py
import json
import os
import re
from json import JSONDecoder
from typing import Any, Dict, Iterator, Tuple

def detect_format(path: str, sample_bytes: int = 65536) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext in [".jsonl", ".ndjson"]:
        return "ndjson"

    with open(path, "rb") as f:
        sample = f.read(sample_bytes)

    # Strip UTF-8 BOM if present
    if sample.startswith(b"\xef\xbb\xbf"):
        sample = sample[3:]

    s = sample.lstrip()
    if not s:
        return "unknown"

    first = chr(s[0])
    if first == "[":
        return "json_array"
    if first == "{":
        # Heuristic: ndjson often contains }\n{ near the top.
        if re.search(rb"\}\s*\n\s*\{", sample):
            return "ndjson"
        return "json_object"
    return "unknown"

def iter_ndjson(path: str) -> Iterator[Tuple[Dict[str, Any], Any]]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line_no, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            locator = {"format": "ndjson", "line": line_no}
            yield locator, obj

def iter_json_array(path: str, chunk_size: int = 65536) -> Iterator[Tuple[Dict[str, Any], Any]]:
    decoder = JSONDecoder()

    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        buf = ""
        pos = 0

        # Read until we find the opening '['
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                raise ValueError("Empty or invalid JSON (no '[' found).")
            buf += chunk
            i = buf.find("[")
            if i != -1:
                pos = i + 1
                break

        idx = 0
        while True:
            # Skip whitespace, commas
            while True:
                while pos < len(buf) and buf[pos].isspace():
                    pos += 1
                if pos < len(buf) and buf[pos] == ",":
                    pos += 1
                    continue
                break

            # Need more data
            if pos >= len(buf):
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                buf = buf[pos:] + chunk
                pos = 0
                continue

            if buf[pos] == "]":
                break

            try:
                obj, new_pos = decoder.raw_decode(buf, pos)
            except json.JSONDecodeError:
                chunk = f.read(chunk_size)
                if not chunk:
                    raise
                buf += chunk
                continue

            idx += 1
            locator = {"format": "json_array", "index": idx}
            pos = new_pos
            yield locator, obj

            if pos > 1_000_000:
                buf = buf[pos:]
                pos = 0

def iter_records(path: str) -> Iterator[Tuple[Dict[str, Any], Any]]:
    fmt = detect_format(path)
    if fmt == "ndjson":
        yield from iter_ndjson(path)
        return
    if fmt == "json_array":
        yield from iter_json_array(path)
        return

    # Fallback: load whole JSON object (best-effort)
    with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
        obj = json.load(f)
    locator = {"format": "json_object"}
    yield locator, obj
```

### 7.2 `.opencode/tools/scripts/inventory_logs.py`

```py
import argparse
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from json_stream import detect_format, iter_records

SENSITIVE_KEY_HINTS = (
    "email", "mail", "phone", "tel", "token", "secret", "password", "passcode",
    "auth", "bearer", "cookie", "ssid", "bssid", "imei", "imsi", "udid", "deviceid",
    "latitude", "longitude", "location", "gps", "address"
)

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def redact_value(key: str, value: Any) -> Any:
    lk = key.lower()
    if any(h in lk for h in SENSITIVE_KEY_HINTS):
        return "<REDACTED>"
    if isinstance(value, str) and len(value) > 200:
        return value[:100] + "…<TRUNCATED>…" + value[-40:]
    return value

def redact_obj(obj: Any, max_depth: int = 6, _depth: int = 0) -> Any:
    if _depth >= max_depth:
        return "<MAX_DEPTH>"
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            out[k] = redact_obj(redact_value(k, v), max_depth, _depth + 1)
        return out
    if isinstance(obj, list):
        return [redact_obj(x, max_depth, _depth + 1) for x in obj[:10]]
    return obj

def safe_sample(path: str, sample_records: int, redact: bool) -> Dict[str, Any]:
    samples = []
    sample_keys: List[str] = []
    fmt = detect_format(path)

    try:
        for i, (loc, rec) in enumerate(iter_records(path)):
            if i >= sample_records:
                break
            if isinstance(rec, dict) and not sample_keys:
                sample_keys = list(rec.keys())[:50]
            elif isinstance(rec, list) and rec and isinstance(rec[0], dict) and not sample_keys:
                sample_keys = list(rec[0].keys())[:50]

            samples.append({
                "locator": loc,
                "record": redact_obj(rec) if redact else rec
            })
    except Exception as e:
        return {"format": fmt, "error": str(e), "sample_keys": sample_keys, "samples": samples}

    return {"format": fmt, "sample_keys": sample_keys, "samples": samples}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs-dir", default="logs")
    ap.add_argument("--out", default="analysis/manifest.json")
    ap.add_argument("--redact", default="1")
    ap.add_argument("--max-files", type=int, default=2000)
    ap.add_argument("--sample-records", type=int, default=2)
    args = ap.parse_args()

    redact = args.redact == "1"

    files = []
    n = 0
    for root, _, fnames in os.walk(args.logs_dir):
        for fn in fnames:
            if not fn.lower().endswith((".json", ".jsonl", ".ndjson")):
                continue
            n += 1
            if n > args.max_files:
                break
            p = os.path.join(root, fn)
            st = os.stat(p)
            files.append({
                "path": p.replace("\\", "/"),
                "size_bytes": st.st_size,
                "mtime_utc": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
                **safe_sample(p, args.sample_records, redact)
            })
        if n > args.max_files:
            break

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    manifest = {
        "generated_at": iso_now(),
        "logs_dir": args.logs_dir,
        "file_count": len(files),
        "files": files
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)

    print(json.dumps({"ok": True, "manifest_path": args.out, "files": len(files)}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

### 7.3 `.opencode/tools/scripts/summarize_logs.py`

```py
import argparse
import json
import os
import re
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

from json_stream import iter_records, detect_format

TS_KEYS = [
    "timestamp", "time", "date", "datetime", "created_at", "createdAt",
    "eventTime", "event_time", "ts"
]
MSG_KEYS = ["message", "msg", "log", "error", "err", "details", "description"]
APP_KEYS = ["bundle_id", "bundleId", "app", "application", "process", "processName"]
TYPE_KEYS = ["event", "type", "action", "name", "category", "subsystem"]
HOST_KEYS = ["host", "domain", "hostname", "url", "remoteHost", "dst", "destination"]
IP_KEYS = ["ip", "remote_ip", "remoteIp", "dst_ip", "destination_ip"]
SEV_KEYS = ["level", "severity", "logLevel"]

SENSITIVE_RE = re.compile(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})")
PHONE_RE = re.compile(r"(\+?\d[\d\-\s]{7,}\d)")

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_ts(v: Any) -> Optional[str]:
    try:
        if isinstance(v, (int, float)):
            # heuristic epoch
            if v > 1e12:
                dt = datetime.fromtimestamp(v / 1000.0, tz=timezone.utc)
            elif v > 1e9:
                dt = datetime.fromtimestamp(v, tz=timezone.utc)
            else:
                return None
            return dt.isoformat()
        if isinstance(v, str):
            s = v.strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            # fromisoformat handles many ISO-8601 variants
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return None
    return None

def get_first(record: Dict[str, Any], keys) -> Optional[Any]:
    for k in keys:
        if k in record and record[k] is not None:
            return record[k]
    return None

def redact_str(s: str) -> str:
    s = SENSITIVE_RE.sub("<REDACTED_EMAIL>", s)
    s = PHONE_RE.sub("<REDACTED_PHONE>", s)
    if len(s) > 400:
        return s[:200] + "…<TRUNCATED>…" + s[-80:]
    return s

def summarize_file(path: str, out_dir: str, redact: bool, max_records: int, topk: int) -> Dict[str, Any]:
    fmt = detect_format(path)
    total = 0
    ts_min = None
    ts_max = None

    key_counter = Counter()
    app_counter = Counter()
    type_counter = Counter()
    host_counter = Counter()
    ip_counter = Counter()
    sev_counter = Counter()

    error_like = 0
    sample_msgs = []

    for locator, rec in iter_records(path):
        total += 1
        if total > max_records:
            break
        if not isinstance(rec, dict):
            continue

        for k in rec.keys():
            key_counter[k] += 1

        ts_val = None
        for tk in TS_KEYS:
            if tk in rec:
                ts_val = parse_ts(rec.get(tk))
                if ts_val:
                    break
        if ts_val:
            ts_min = ts_val if ts_min is None or ts_val < ts_min else ts_min
            ts_max = ts_val if ts_max is None or ts_val > ts_max else ts_max

        app = get_first(rec, APP_KEYS)
        if isinstance(app, str) and app:
            app_counter[app] += 1

        et = get_first(rec, TYPE_KEYS)
        if isinstance(et, str) and et:
            type_counter[et] += 1

        host = get_first(rec, HOST_KEYS)
        if isinstance(host, str) and host:
            host_counter[host] += 1

        ip = get_first(rec, IP_KEYS)
        if isinstance(ip, str) and ip:
            ip_counter[ip] += 1

        sev = get_first(rec, SEV_KEYS)
        if isinstance(sev, str) and sev:
            sev_counter[sev] += 1

        msg = get_first(rec, MSG_KEYS)
        if isinstance(msg, str) and msg:
            msg_l = msg.lower()
            if any(w in msg_l for w in ["error", "failed", "unauthorized", "denied", "invalid", "exception"]):
                error_like += 1
                if len(sample_msgs) < 8:
                    sample_msgs.append(redact_str(msg) if redact else msg)

    def top(counter: Counter) -> Dict[str, int]:
        items = counter.most_common(topk)
        if redact:
            # redact keys by truncation for safety
            out = {}
            for k, v in items:
                ks = redact_str(str(k))
                out[ks] = v
            return out
        return {str(k): v for k, v in items}

    summary = {
        "generated_at": iso_now(),
        "path": path.replace("\\", "/"),
        "format": fmt,
        "records_processed": total,
        "timestamp_min_utc": ts_min,
        "timestamp_max_utc": ts_max,
        "top_keys": top(key_counter),
        "top_apps": top(app_counter),
        "top_event_types": top(type_counter),
        "top_hosts": top(host_counter),
        "top_ips": top(ip_counter),
        "top_severities": top(sev_counter),
        "error_like_count": error_like,
        "error_like_samples": sample_msgs
    }

    os.makedirs(out_dir, exist_ok=True)
    base = os.path.basename(path)
    out_path = os.path.join(out_dir, base + ".summary.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    return {"file": path, "summary_path": out_path}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs-dir", default="logs")
    ap.add_argument("--out-dir", default="analysis/file_summaries")
    ap.add_argument("--redact", default="1")
    ap.add_argument("--max-records-per-file", type=int, default=200000)
    ap.add_argument("--topk", type=int, default=30)
    args = ap.parse_args()

    redact = args.redact == "1"

    results = []
    for root, _, fnames in os.walk(args.logs_dir):
        for fn in fnames:
            if not fn.lower().endswith((".json", ".jsonl", ".ndjson")):
                continue
            p = os.path.join(root, fn)
            try:
                results.append(summarize_file(p, args.out_dir, redact, args.max_records_per_file, args.topk))
            except Exception as e:
                results.append({"file": p, "error": str(e)})

    print(json.dumps({"ok": True, "out_dir": args.out_dir, "files": len(results), "results": results[:50]}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

### 7.4 `.opencode/tools/scripts/build_index.py`

```py
import argparse
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from json_stream import iter_records, detect_format

TS_KEYS = [
    "timestamp", "time", "date", "datetime", "created_at", "createdAt",
    "eventTime", "event_time", "ts"
]
MSG_KEYS = ["message", "msg", "log", "error", "err", "details", "description"]
APP_KEYS = ["bundle_id", "bundleId", "app", "application", "process", "processName"]
TYPE_KEYS = ["event", "type", "action", "name", "category", "subsystem"]
HOST_KEYS = ["host", "domain", "hostname", "url", "remoteHost", "dst", "destination"]
IP_KEYS = ["ip", "remote_ip", "remoteIp", "dst_ip", "destination_ip"]
SEV_KEYS = ["level", "severity", "logLevel"]

SENSITIVE_VALUE_RE = re.compile(r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})|(\+?\d[\d\-\s]{7,}\d)")

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def parse_ts(v: Any) -> Optional[str]:
    try:
        if isinstance(v, (int, float)):
            if v > 1e12:
                dt = datetime.fromtimestamp(v / 1000.0, tz=timezone.utc)
            elif v > 1e9:
                dt = datetime.fromtimestamp(v, tz=timezone.utc)
            else:
                return None
            return dt.isoformat()
        if isinstance(v, str):
            s = v.strip()
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return None
    return None

def get_first(record: Dict[str, Any], keys) -> Optional[Any]:
    for k in keys:
        if k in record and record[k] is not None:
            return record[k]
    return None

def safe_str(v: Any, redact: bool, max_len: int = 300) -> Optional[str]:
    if v is None:
        return None
    s = str(v)
    if redact:
        s = SENSITIVE_VALUE_RE.sub("<REDACTED>", s)
    if len(s) > max_len:
        s = s[:max_len] + "…"
    return s

def init_db(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("""
      CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts TEXT,
        source_file TEXT NOT NULL,
        locator TEXT NOT NULL,
        event_type TEXT,
        app TEXT,
        host TEXT,
        ip TEXT,
        severity TEXT,
        message TEXT
      )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_app ON events(app)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_host ON events(host)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity)")
    return conn

def extract_fields(rec: Dict[str, Any], redact: bool) -> Dict[str, Any]:
    ts_val = None
    for tk in TS_KEYS:
        if tk in rec:
            ts_val = parse_ts(rec.get(tk))
            if ts_val:
                break

    event_type = get_first(rec, TYPE_KEYS)
    app = get_first(rec, APP_KEYS)
    host = get_first(rec, HOST_KEYS)
    ip = get_first(rec, IP_KEYS)
    sev = get_first(rec, SEV_KEYS)
    msg = get_first(rec, MSG_KEYS)

    # If URL stored in host, keep as-is (agent can later parse)
    return {
        "ts": safe_str(ts_val, redact, 64),
        "event_type": safe_str(event_type, redact, 120),
        "app": safe_str(app, redact, 200),
        "host": safe_str(host, redact, 200),
        "ip": safe_str(ip, redact, 64),
        "severity": safe_str(sev, redact, 64),
        "message": safe_str(msg, redact, 500)
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs-dir", default="logs")
    ap.add_argument("--out", default="analysis/index/logs.sqlite")
    ap.add_argument("--redact", default="1")
    ap.add_argument("--max-records-per-file", type=int, default=5_000_000)
    ap.add_argument("--commit-every", type=int, default=5000)
    args = ap.parse_args()

    redact = args.redact == "1"
    conn = init_db(args.out)
    cur = conn.cursor()

    total_rows = 0
    files_indexed = 0

    for root, _, fnames in os.walk(args.logs_dir):
        for fn in fnames:
            if not fn.lower().endswith((".json", ".jsonl", ".ndjson")):
                continue
            path = os.path.join(root, fn).replace("\\", "/")
            files_indexed += 1
            batch = []
            n = 0
            try:
                for locator, rec in iter_records(path):
                    n += 1
                    if n > args.max_records_per_file:
                        break
                    if not isinstance(rec, dict):
                        continue
                    fields = extract_fields(rec, redact)
                    batch.append((
                        fields["ts"],
                        path,
                        json.dumps(locator, ensure_ascii=False),
                        fields["event_type"],
                        fields["app"],
                        fields["host"],
                        fields["ip"],
                        fields["severity"],
                        fields["message"]
                    ))
                    if len(batch) >= args.commit_every:
                        cur.executemany("""
                          INSERT INTO events(ts, source_file, locator, event_type, app, host, ip, severity, message)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, batch)
                        conn.commit()
                        total_rows += len(batch)
                        batch = []
                if batch:
                    cur.executemany("""
                      INSERT INTO events(ts, source_file, locator, event_type, app, host, ip, severity, message)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, batch)
                    conn.commit()
                    total_rows += len(batch)
            except Exception as e:
                # continue indexing other files
                pass

    conn.close()
    print(json.dumps({"ok": True, "db": args.out, "files_indexed": files_indexed, "rows": total_rows}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

### 7.5 `.opencode/tools/scripts/query_index.py`

```py
import argparse
import json
import os
import sqlite3

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="analysis/index/logs.sqlite")
    ap.add_argument("--sql", required=True)
    ap.add_argument("--limit", type=int, default=50)
    args = ap.parse_args()

    sql = args.sql.strip().rstrip(";")
    low = sql.lower().lstrip()
    if not (low.startswith("select") or low.startswith("with")):
        raise SystemExit("Only read-only SELECT/WITH queries are allowed.")

    # Force a LIMIT if the user didn't include one
    if " limit " not in low:
        sql = f"{sql} LIMIT {args.limit}"
    else:
        # still cap hard
        sql = f"WITH _q AS ({sql}) SELECT * FROM _q LIMIT {args.limit}"

    db_path = args.db
    if not os.path.exists(db_path):
        raise SystemExit(f"DB not found: {db_path}")

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    rows = cur.execute(sql).fetchall()
    cols = rows[0].keys() if rows else []
    out_rows = [dict(r) for r in rows]
    conn.close()

    print(json.dumps({"ok": True, "columns": list(cols), "rows": out_rows}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

### 7.6 `.opencode/tools/scripts/get_record.py`

```py
import argparse
import json
from typing import Any

from json_stream import iter_records

SENSITIVE_KEYS = (
    "email","mail","phone","tel","token","secret","password","passcode","auth","cookie",
    "latitude","longitude","location","gps","imei","imsi","udid","deviceid"
)

def redact(obj: Any, max_depth: int, max_string: int, _depth: int = 0) -> Any:
    if _depth >= max_depth:
        return "<MAX_DEPTH>"
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if any(h in k.lower() for h in SENSITIVE_KEYS):
                out[k] = "<REDACTED>"
            else:
                out[k] = redact(v, max_depth, max_string, _depth + 1)
        return out
    if isinstance(obj, list):
        return [redact(x, max_depth, max_string, _depth + 1) for x in obj[:20]]
    if isinstance(obj, str):
        if len(obj) > max_string:
            return obj[: max_string] + "…"
        return obj
    return obj

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", required=True)
    ap.add_argument("--locator", required=True)
    ap.add_argument("--redact", default="1")
    ap.add_argument("--max-depth", type=int, default=6)
    ap.add_argument("--max-string", type=int, default=300)
    args = ap.parse_args()

    target = json.loads(args.locator)
    do_redact = args.redact == "1"

    for loc, rec in iter_records(args.file):
        if loc.get("format") != target.get("format"):
            continue
        if loc.get("line") and target.get("line") and loc["line"] == target["line"]:
            out = redact(rec, args.max_depth, args.max_string) if do_redact else rec
            print(json.dumps({"ok": True, "file": args.file, "locator": loc, "record": out}, ensure_ascii=False))
            return
        if loc.get("index") and target.get("index") and loc["index"] == target["index"]:
            out = redact(rec, args.max_depth, args.max_string) if do_redact else rec
            print(json.dumps({"ok": True, "file": args.file, "locator": loc, "record": out}, ensure_ascii=False))
            return

    print(json.dumps({"ok": False, "error": "Record not found", "file": args.file, "locator": target}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

### 7.7 `.opencode/tools/scripts/suspicious_scan.py`

```py
import argparse
import json
import os
import sqlite3
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List

KEYWORD_GROUPS = {
    "profiles_certs_vpn_proxy": [
        "configuration profile", "mdm", "mobile device management",
        "certificate", "root ca", "trusted", "trust store",
        "vpn", "proxy", "pac", "http proxy", "mitm"
    ],
    "auth_failures": [
        "unauthorized", "denied", "authentication failed", "login failed",
        "invalid password", "invalid credential", "passcode", "face id", "touch id"
    ],
    "jailbreak_instrumentation": [
        "jailbreak", "cydia", "substrate", "frida", "cycript", "sshd"
    ],
    "data_exfil_suspicion": [
        "upload", "exfil", "export", "backup", "keychain", "token", "credential"
    ]
}

def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def q(conn, sql: str, params=()):
    cur = conn.cursor()
    return cur.execute(sql, params).fetchall()

def finding(f_id: str, severity: str, ftype: str, title: str, why: str, evidence: List[dict]):
    return {
        "id": f_id,
        "severity": severity,
        "type": ftype,
        "title": title,
        "why_flagged": why,
        "count": len(evidence),
        "evidence": evidence
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="analysis/index/logs.sqlite")
    ap.add_argument("--out-json", default="analysis/suspicious_findings.json")
    ap.add_argument("--out-md", default="analysis/suspicious_report.md")
    ap.add_argument("--max-evidence", type=int, default=10)
    args = ap.parse_args()

    if not os.path.exists(args.db):
        raise SystemExit(f"DB not found: {args.db}")

    conn = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row

    findings = []
    fid = 1

    # 1) Keyword-based flags in message
    for group, kws in KEYWORD_GROUPS.items():
        ors = " OR ".join(["lower(message) LIKE ?" for _ in kws])
        sql = f"""
          SELECT ts, source_file, locator, event_type, app, host, ip, severity, message
          FROM events
          WHERE message IS NOT NULL AND ({ors})
          ORDER BY ts
          LIMIT ?
        """
        params = [f"%{k.lower()}%" for k in kws] + [args.max_evidence]
        rows = q(conn, sql, params)

        if rows:
            evidence = []
            for r in rows:
                evidence.append({
                    "ts": r["ts"],
                    "source_file": r["source_file"],
                    "locator": r["locator"],
                    "event_type": r["event_type"],
                    "app": r["app"],
                    "host": r["host"],
                    "ip": r["ip"],
                    "severity": r["severity"],
                    "message": r["message"]
                })
            sev = "high" if group in ["jailbreak_instrumentation", "profiles_certs_vpn_proxy"] else "medium"
            findings.append(finding(
                f"F{fid:03d}", sev, group,
                f"Keyword hits: {group}",
                f"Matched keywords: {', '.join(kws)}",
                evidence
            ))
            fid += 1

    # 2) Unusually high daily volume (simple anomaly)
    rows = q(conn, """
      SELECT substr(ts,1,10) AS day, count(*) AS n
      FROM events
      WHERE ts IS NOT NULL
      GROUP BY day
      ORDER BY n DESC
      LIMIT 10
    """)
    if rows:
        evidence = [{"day": r["day"], "count": r["n"]} for r in rows]
        findings.append({
            "id": f"F{fid:03d}",
            "severity": "low",
            "type": "volume_spike",
            "title": "Highest-volume days (review for spikes)",
            "why_flagged": "Large spikes in logs can indicate unusual activity or simply noisy subsystems; review context.",
            "count": len(evidence),
            "evidence": evidence
        })
        fid += 1

    # 3) Rare hosts (if host exists)
    rows = q(conn, """
      SELECT host, count(*) AS n
      FROM events
      WHERE host IS NOT NULL AND host != ''
      GROUP BY host
      ORDER BY n ASC
      LIMIT 30
    """)
    if rows:
        evidence = [{"host": r["host"], "count": r["n"]} for r in rows]
        findings.append({
            "id": f"F{fid:03d}",
            "severity": "low",
            "type": "rare_hosts",
            "title": "Rare hosts (low frequency)",
            "why_flagged": "Low-frequency hosts can be normal; prioritize unknown domains or direct IPs.",
            "count": len(evidence),
            "evidence": evidence
        })
        fid += 1

    conn.close()

    out = {
        "generated_at": iso_now(),
        "db": args.db,
        "finding_count": len(findings),
        "findings": findings
    }

    os.makedirs(os.path.dirname(args.out_json) or ".", exist_ok=True)
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    # Human report
    md_lines = []
    md_lines.append("# Suspicious Findings Report (Heuristic)\n")
    md_lines.append(f"- Generated at: {out['generated_at']}\n")
    md_lines.append(f"- Findings: {out['finding_count']}\n")
    md_lines.append("\n## Summary\n")
    if not findings:
        md_lines.append("No heuristic findings were produced. This does not guarantee absence of issues.\n")
    else:
        for fnd in findings:
            md_lines.append(f"### {fnd['id']} — {fnd['severity'].upper()} — {fnd['title']}\n")
            md_lines.append(f"- Type: `{fnd['type']}`\n")
            md_lines.append(f"- Why: {fnd['why_flagged']}\n")
            md_lines.append(f"- Evidence items: {fnd['count']}\n\n")
            md_lines.append("Sample evidence:\n")
            for ev in fnd["evidence"][:min(5, len(fnd["evidence"]))]:
                md_lines.append(f"- `{json.dumps(ev, ensure_ascii=False)}`\n")
            md_lines.append("\n")

    with open(args.out_md, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))

    print(json.dumps({"ok": True, "out_json": args.out_json, "out_md": args.out_md, "findings": len(findings)}, ensure_ascii=False))

if __name__ == "__main__":
    main()
```

---

## 8) Optional: Commands (nice UX)

Commands are markdown files under `.opencode/commands/` with YAML frontmatter; the filename becomes the `/command`. ([opencode.ai][4])

### `.opencode/commands/log-inventory.md`

```md
---
description: Inventory logs and write analysis/manifest.json
agent: ios-log-analyst
---

Load skill `ios-log-inventory`, then:
1) Run `ios_logs_inventory` (defaults are fine).
2) Briefly summarize what files exist, which look biggest, and which formats were detected.
3) Point me to `analysis/manifest.json`.
```

### `.opencode/commands/log-index.md`

```md
---
description: Build SQLite index from logs
agent: ios-log-analyst
---

Load skill `ios-log-index`, then:
1) Run `ios_logs_build_index`.
2) Run quick validation queries:
   - total rows
   - min/max ts
   - top apps
3) Write a short note in analysis/README.md describing what was indexed.
```

### `.opencode/commands/log-summary.md`

```md
---
description: Generate activity summary report
agent: ios-log-analyst
---

Load skills `ios-activity-summary` and `ios-log-index` if needed.
If the index doesn’t exist, build it first.
Then create `analysis/activity_summary.md` with:
- Time range covered
- Top apps/processes, event types
- Any error-heavy periods
- Anything that stands out (with evidence pointers)
```

### `.opencode/commands/log-suspicious.md`

```md
---
description: Run suspicious scan and write suspicious report
agent: ios-log-analyst
---

Load skill `ios-suspicious-detector`.
Ensure the SQLite index exists.
Run `ios_logs_suspicious_scan` and then:
- Summarize the top 3–5 findings
- For each HIGH finding, fetch 1–3 examples via `ios_logs_get_record`
- Write `analysis/suspicious_report.md` and keep it redacted
```

---

## 9) Analysis folder README

### `analysis/README.md`

```md
# Analysis Outputs

This folder is generated by OpenCode tools.

## Key files
- `manifest.json` — inventory of log files (format/schema hints, redacted samples)
- `file_summaries/` — per-file summaries (small JSON)
- `index/logs.sqlite` — compact searchable index (timestamps + key fields + record locators)
- `activity_summary.md` — human report of activity timeline and notable events
- `suspicious_findings.json` — machine-readable findings
- `suspicious_report.md` — human suspicious-pattern report (heuristic)
```

---

## How you use it in practice (minimal)

1. Put logs in `logs/`
2. Run OpenCode in this repo
3. Run commands:

* `/log-inventory`
* `/log-index`
* `/log-summary`
* `/log-suspicious`

---

## What “suspicious” means here

This system flags **review candidates**, not definitive compromise:

* Configuration profile / certificate / VPN / proxy indicators
* Authentication/authorization failure clusters
* Jailbreak/instrumentation keywords
* Unusual spikes in event volume
* Rare hosts/domains (if host data exists)

The report is designed to always include **evidence pointers** (file + locator) so you can verify quickly in raw logs.

---

If you want, I can also add an **optional** “domain reputation” tool (VirusTotal / URLHaus / etc.) behind an explicit permission gate — but I didn’t include it here because it sends observables off-machine and isn’t always desirable for personal device logs.

[1]: https://opencode.ai/docs/rules/ "Rules | OpenCode"
[2]: https://opencode.ai/docs/skills/ "Agent Skills | OpenCode"
[3]: https://opencode.ai/docs/custom-tools/ "Custom Tools | OpenCode"
[4]: https://opencode.ai/docs/commands/ "Commands | OpenCode"
[5]: https://opencode.ai/docs/config/?utm_source=chatgpt.com "Config"
[6]: https://opencode.ai/docs/config/ "Config | OpenCode"
[7]: https://opencode.ai/docs/agents/ "Agents | OpenCode"

It’s basically “LLM as analyst, computer as microscope.”

The LLM is *never* meant to read your giant JSON directly. Instead, it orchestrates a set of local parsing/indexing steps, then asks for small, targeted slices when it needs evidence.

## Big picture methodology

### 1) Inventory (understand what you have)

**Goal:** map the dataset without loading it into context.

* Walk `logs/` and detect each file’s format:

  * **NDJSON/JSONL** (one JSON object per line)
  * **JSON array** (`[ {...}, {...} ]`)
  * **JSON object** (single big `{...}`)
* Take **a couple of samples** per file (redacted) to infer:

  * likely timestamp keys
  * likely “message” field
  * app/process fields
  * host/IP fields
  * event type/severity fields
* Output: `analysis/manifest.json`

Why: before any “analysis,” you need to know *schemas vary* across files and which ones are huge / weird.

### 2) Map/Reduce summaries (compress each file into a small profile)

**Goal:** get high-level understanding with bounded cost.

For each file, stream through up to a cap (e.g., 200k records):

* Count frequency of:

  * keys (schema fingerprint)
  * apps/processes
  * event types
  * hosts / IPs (if present)
  * severity levels
* Extract time range:

  * min/max timestamp found (if any)
* Pull a few **error-like** message examples (redacted)
* Output: `analysis/file_summaries/<file>.summary.json`

Why: this gives the LLM “what’s inside” each file without reading it, and it keeps runtime and outputs bounded even when logs are massive.

### 3) Build a compact searchable index (SQLite)

**Goal:** enable targeted queries like “show me auth failures around 2026-02-01” without scanning everything repeatedly.

* Parse logs again (streaming).
* For each record, extract normalized fields:

  * `ts`, `event_type`, `app`, `host`, `ip`, `severity`, `message`
* Store a **locator** (pointer back to raw data), not the full record:

  * NDJSON → `{format:"ndjson", line:12345}`
  * JSON array → `{format:"json_array", index:777}`
* Output: `analysis/index/logs.sqlite`

Why: the LLM can now ask SQL questions (“top apps per day”, “rare hosts”) and get **tiny result sets**. If a row looks important, it can fetch the single raw record by locator for confirmation.

### 4) Activity summarization (LLM does narrative, DB does math)

**Goal:** a human report of your “timeline / activity” with evidence support.

The LLM uses the index to run rollup queries like:

* daily volume
* top apps/processes
* top event types
* error concentration by day/app
* network destinations (if present)

Then it writes `analysis/activity_summary.md`:

* time range covered
* what apps/services appear
* what changed over time
* noteworthy clusters (with file+locator references)

Why: “summary” should be narrative + interpretation, but grounded in measurable aggregates.

### 5) Suspicious detection (heuristics + anomalies + evidence)

**Goal:** flag “things worth checking,” not claim compromise.

Two main approaches:

**A) Rules / keyword families** (fast, interpretable)
Search `message` and sometimes `event_type` for groups like:

* profiles / MDM / certificates / trust store / VPN / proxy / PAC
* jailbreak / instrumentation indicators (frida, substrate, cydia…)
* auth failures (unauthorized/denied/invalid credential…)
* exfil-ish words (upload/export/keychain/token…)

**B) Lightweight anomaly signals** (contextual)

* unusually high-volume days
* rare hosts/domains
* error spikes by app/process

Each finding includes:

* severity (low/medium/high)
* why it was flagged
* evidence rows (ts, file, locator, short redacted message)

Outputs:

* `analysis/suspicious_findings.json`
* `analysis/suspicious_report.md`

Why: suspicious detection needs traceability. The model must be able to say: “here are 8 concrete records that triggered this.”

### 6) Evidence retrieval on demand (“show me the raw record”)

When the LLM needs to confirm a specific flag, it calls `get_record` with:

* the file path
* the locator (line/index)
  It returns one **redacted** JSON snippet.

Why: you keep privacy + keep context small, but you still can verify reality.

---

## The core principle: “bounded context, reproducible evidence”

This setup enforces:

* **Bounded data into the model:** only summaries, query outputs, and a handful of raw records.
* **Reproducibility:** every claim points back to `source_file + locator`.
* **Safety/privacy:** redact PII by default; web is disabled; raw logs stay local.
* **Scalability:** streaming parsing + SQLite means you can handle multi-GB logs.

---

## What the LLM actually “does”

The LLM is mainly:

* choosing which queries to run
* interpreting the aggregates
* deciding which anomalies matter
* writing readable reports
* pulling a few raw records to validate findings

The “heavy lifting” (parsing, counting, indexing, keyword scan) is deterministic code.

---

If you paste 1–2 example filenames (just the names, not contents), I can show the exact flow the agent would follow and what the first SQL queries would look like for your specific log types.
