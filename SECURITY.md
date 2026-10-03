# Security policy

## Reporting

Open a private security advisory on the GitHub repository, or email the
maintainer (see `Cargo.toml` authors).

## Scope

In scope:

- `policy_at` returning a hash that was not actually in force at `ts`
  (ordering bugs in the count).
- Marks being mutated or reordered after painting.
- `foreign_marks` missing marks under unregistered policies.

Out of scope:

- Integrity of the source ledger — wintercount reads marks; anchoring
  them in a hash chain is the writer's/ledger's job.
- Confidentiality of policy documents — `PolicySet` stores the bytes
  it's given; protect them at the filesystem layer.

## Guidance

- Anchor the mark stream in a hash-chained or signed ledger so
  post-hoc repainting is detectable.
- Archive every policy document you pin a hash of — a resolvable
  registry is what turns a hash into evidence.
