# wintercount specification

Temporal policy provenance.

## Model

- **Policy document** — canonical bytes; identity is `sha256(body)`.
- **Mark** — `(ts, policy_hash, label?)`: an event and the policy in
  force at write time. Painted in order; the robe is append-only.
- **`"builtin"`** — the distinguished hash for compiled-in defaults,
  distinguishing "defaults in force" from "hash unavailable".

## API contract

- `policy_at(ts)` — the hash of the latest mark at or before `ts`;
  `None` if the count starts after `ts`. Marks are assumed painted in
  chronological order (append-only by construction).
- `transitions()` — `(ts, old, new)` wherever the hash changes; the
  first mark yields `(ts, None, hash)`.
- `governed_range(hash)` — `(first_ts, last_ts)` of that hash's marks.
- `census()` — mark count per hash.
- `foreign_marks(set, accept_builtin)` — marks under hashes the
  `PolicySet` doesn't resolve; rejected-but-pinned policies surface
  here.
- `from_ledger(lines)` — parses `data.policy_hash` (Bad Apple format)
  or top-level `policy_hash`; unparseable/hashless lines skipped;
  missing timestamps fall back to line index.

## Invariants

- The hash covers the *exact bytes* in force — including a policy that
  was rejected at load. The record proves which bytes were refused.
- Marks are never rewritten: history is paint on the robe.
- `policy_at` never fabricates — before the first mark, it returns
  `None`.

## Non-goals

- wintercount records provenance; it does not evaluate policy or parse
  policy documents — bytes in, hash out.
- It doesn't verify a ledger's hash chain; pair with
  `sovereign_ledger` for that.
