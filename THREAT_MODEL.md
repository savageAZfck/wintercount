# Threat model

wintercount answers one question verifiably: *which rules governed at
time T?* It assumes events faithfully pin the hash that was in force —
the crate preserves and queries that record.

## What it defends against

- **Retroactive governance claims.** Once marks are painted, "the
  policy at time T" is a query over committed history, not a memory.
- **Rejection laundering.** A policy that failed verification still
  has its hash pinned — `foreign_marks` surfaces events governed by
  bytes that were never accepted.
- **Silent defaults.** `builtin` is explicit — "ran on compiled-in
  defaults" can't be confused with "hash unavailable."

## What it does not defend against

- **A ledger that pins the wrong hash.** If the writer lies at paint
  time, the count faithfully preserves the lie. Provenance integrity
  depends on the writer pinning the actual in-force bytes — anchor the
  count in a hash-chained ledger so post-hoc edits break the chain.
- **Unhashed events.** Events without a pinned hash create gaps in the
  robe — `from_ledger` skips them silently, so coverage is the
  integrator's job.
- **Policy bytes lost.** `foreign_marks` flags hashes the registry
  can't resolve; if the document itself is gone, the mark survives but
  the rules don't. Keep a `PolicySet` archive.

## Design posture

Paint what governed, keep the paint permanent, never fabricate a
missing mark.
