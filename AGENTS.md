# CtrlDB Agent Guidance

CtrlDB is a safety-first control plane for self-managed databases on Google
Cloud. A defect can expose a database, destroy data, invalidate a backup, or
mutate the wrong cloud resource. Review changes as production infrastructure
software even when the current implementation is read-only or local-only.

This guidance applies repository-wide. A more specific `AGENTS.md` may add
rules for its subtree, but must not weaken these safety properties.

## Code Review Rules

Review the complete change and the relevant callers, schemas, tests, and
failure paths. Report concrete, actionable defects: identify the triggering
condition, resulting impact, and the safety property that is violated. Do not
spend review findings on formatting or lint issues already enforced by CI.

### Fail closed around state changes

- Flag any mutation that can run without an explicit resource identity, fresh
  discovery, an inspectable plan, risk-appropriate approval, immediate
  pre-execution revalidation, a durable operation record, and post-change
  verification. A read-only command must not acquire mutation capability.
- Missing, ambiguous, stale, contradictory, or unrecognized state must stop the
  operation. Drift, expired authorization, partial execution, or loss of an
  operation lock must never cause CtrlDB to guess, silently downgrade safety,
  or continue with an earlier plan.
- Retries, resume, compensation, and rollback must be idempotent and derived
  from observed state. They must not repeat a destructive step, reuse stale
  authorization, hide a partial failure, or endanger data and replica-set
  quorum when replication is enabled.
- Defaults may improve display or discovery, but must not silently choose the
  project, account, region, zone, identity, database, or resource that a
  state-changing command will affect.

### Protect credentials, access, and recoverability

- Flag secrets or sensitive connection material in manifests, command-line
  arguments, logs, errors, audit records, fixtures, or committed files. CtrlDB
  must use established credential helpers and scoped identities; it must not
  extract, persist, or print raw `gcloud` access tokens.
- External processes must be invoked with structured arguments, bounded
  execution, checked exit status, and sanitized output. Never construct shell
  commands by interpolating resource names, user input, or provider output.
  In the approved adapter packages, import `os/exec` without an alias, call its
  constructors directly rather than storing them in function values, and keep
  executable selection visible to the validated runner boundary.
- Database access must be least-privilege and deny-by-default. Flag any public
  exposure that is not explicit, narrowly scoped, authenticated, encrypted,
  audited, time-bounded, and reliably revocable. Broad CIDRs or indefinite
  grants must require an unmistakably exceptional workflow, never a convenient
  fallback.
- Destructive, migration, backup, and restore paths must preserve a verified
  recovery route and surface rollback limits before execution. Do not weaken
  retention or immutability controls, or delete protected recovery assets,
  outside the explicitly authorized workflow.

### Preserve input integrity and provider portability

- Treat manifests, saved plans, journals, provider responses, and imported
  state as untrusted input. Reject unknown or duplicate fields, malformed or
  trailing data, invalid enum values, missing required values, hash/signature
  mismatches, and values that become ambiguous after normalization.
- Any serialized representation used for comparison, approval, hashing,
  signing, resume, or audit must be canonical and deterministic. A semantic
  change must not retain an earlier approval or integrity result.
- Use documented machine-readable `gcloud` or Google Cloud API output. Flag
  parsing of human-formatted CLI text and assumptions tied to one locale,
  account, project, region, or zone. CtrlDB must support every compatible GCP
  region through discovered capabilities rather than a hard-coded home region.
- Do not commit real project IDs, account names, resource names, addresses,
  credentials, private paths, or production-derived data. Examples and tests
  must use obviously fictional values.

### Demand evidence for safety behavior

- Safety-critical changes need tests for rejection and interruption paths, not
  only successful execution. Cover boundary values, malformed and tampered
  input, drift between plan and apply, permission failures, timeouts, partial
  provider failures, retries, resume, rollback, and post-change verification as
  applicable.
- Tests must demonstrate that validation, approval, or revalidation failures
  cause no mutation. A mock that bypasses the production safety boundary is not
  evidence that the boundary works.
- Flag behavior that contradicts public documentation, JSON Schema, CLI help,
  machine-readable output contracts, or compatibility guarantees. User-facing
  safety promises and executable behavior must change together.
