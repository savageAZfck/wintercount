# wintercount

Temporal policy provenance. Named for the **winter count** — the buffalo robes on which Plains nations painted each year's defining event, a permanent record of what happened and what governed then.

Extracted from Bad Apple's audit ledger, where every line pins `policy_hash` — the SHA-256 of the exact policy bytes in force at write time.

## The question it answers

*"What rules governed this decision?"* — not today's rules, not last week's. The rules in force **at the moment it happened**. Forever.

## How it works

- `policy_hash(bytes)` — SHA-256 of the canonical policy document. Even a *rejected* policy gets its hash pinned, so the record can prove which bytes were refused.
- `WinterCount` — the painted robe: an ordered sequence of marks `(ts, policy_hash)`.
- `policy_at(ts)` — the hash governing at time T.
- `transitions()` — every point where governance changed hands.
- `governed_range(hash)` / `census()` — how long and how much each policy ruled.
- `foreign_marks(known)` — events under a policy that isn't in your registry: rejected, removed, or foreign rules.
- `from_ledger(lines)` — extract the count straight from a Bad Apple-format NDJSON ledger.

## Usage

```rust
use wintercount::{WinterCount, PolicySet, policy_hash};

let mut wc = WinterCount::new();
wc.mark(1_700_000_000, policy_hash(b"allow: read"));
wc.mark(1_700_000_100, policy_hash(b"allow: none"));

assert_eq!(wc.policy_at(1_700_000_050), Some(old_hash));
```

## Why it matters

Governance that can't say which rules were in force when a decision was made is governance that can't be audited. The winter count makes the temporal claim verifiable — the robe keeps the record even after the policy is gone.

## License

MIT
