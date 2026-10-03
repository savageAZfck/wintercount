//! wintercount — temporal policy provenance.
//!
//! Named for the winter count: the buffalo robes on which Plains
//! nations painted each year's defining event — a permanent record of
//! what happened and what governed then. This crate does the same for
//! governed systems: pin the hash of the policy in force into every
//! event, and "which rules governed this decision" stays answerable
//! forever.
//!
//! Extracted from Bad Apple's audit ledger, where every line's data
//! payload carries `policy_hash` — SHA-256 of the exact policy bytes
//! in force at write time, `"builtin"` when running on compiled-in
//! defaults.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// SHA-256 (hex) of policy bytes — the "policy in force" fingerprint.
pub fn policy_hash(policy_bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(policy_bytes))
}

/// The distinguished hash for "no policy file — compiled-in defaults".
/// Distinguishes "defaults in force" from "hash unavailable".
pub const BUILTIN: &str = "builtin";

/// One mark on the robe: an event and the policy hash in force when it
/// happened.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mark {
    /// Seconds since epoch (or any monotonically ordered timestamp).
    pub ts: u64,
    /// The policy hash pinned at write time, or `"builtin"`.
    pub policy_hash: String,
    /// Optional event label (kind, id) carried for reporting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// A policy document registered so hashes resolve back to bytes.
#[derive(Debug, Clone)]
pub struct PolicyDoc {
    /// SHA-256 hex of `body` — its identity.
    pub hash: String,
    /// The canonical bytes that were in force.
    pub body: Vec<u8>,
    /// Where it came from (path, name) — provenance metadata only.
    pub source: String,
}

/// Registry of known policy documents: hash → bytes, so an auditor can
/// resolve a mark's hash to the actual rules that governed.
#[derive(Default)]
pub struct PolicySet {
    docs: BTreeMap<String, PolicyDoc>,
}

impl PolicySet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a policy document; returns its hash.
    pub fn register(&mut self, body: Vec<u8>, source: &str) -> String {
        let hash = policy_hash(&body);
        self.docs.insert(
            hash.clone(),
            PolicyDoc {
                hash: hash.clone(),
                body,
                source: source.to_string(),
            },
        );
        hash
    }

    /// The document for a hash, if it's a known policy.
    pub fn resolve(&self, hash: &str) -> Option<&PolicyDoc> {
        self.docs.get(hash)
    }

    /// All registered hashes.
    pub fn hashes(&self) -> Vec<&str> {
        self.docs.keys().map(|s| s.as_str()).collect()
    }
}

/// The painted robe: an ordered sequence of marks. Built from any
/// event stream that pins a policy hash per event.
#[derive(Debug, Default, Clone)]
pub struct WinterCount {
    marks: Vec<Mark>,
}

impl WinterCount {
    pub fn new() -> Self {
        Self::default()
    }

    /// Paint a mark.
    pub fn mark(&mut self, ts: u64, policy_hash: impl Into<String>) {
        self.marks.push(Mark {
            ts,
            policy_hash: policy_hash.into(),
            label: None,
        });
    }

    /// Paint a mark with a label.
    pub fn mark_labeled(&mut self, ts: u64, policy_hash: impl Into<String>, label: &str) {
        self.marks.push(Mark {
            ts,
            policy_hash: policy_hash.into(),
            label: Some(label.to_string()),
        });
    }

    /// All marks, in painted order.
    pub fn marks(&self) -> &[Mark] {
        &self.marks
    }

    /// The policy hash in force at `ts`: the hash of the most recent
    /// mark at or before `ts`. `None` when the robe starts after `ts`.
    pub fn policy_at(&self, ts: u64) -> Option<&str> {
        self.marks
            .iter()
            .rev()
            .find(|m| m.ts <= ts)
            .map(|m| m.policy_hash.as_str())
    }

    /// Every point where governance changed: `(ts, old_hash, new_hash)`.
    /// The first mark is included as `(ts, None, hash)` — the founding.
    pub fn transitions(&self) -> Vec<(u64, Option<String>, String)> {
        let mut out = Vec::new();
        let mut prev: Option<&str> = None;
        for m in &self.marks {
            if prev != Some(m.policy_hash.as_str()) {
                out.push((m.ts, prev.map(String::from), m.policy_hash.clone()));
                prev = Some(&m.policy_hash);
            }
        }
        out
    }

    /// The range `[first, last]` of marks governed by `hash`.
    pub fn governed_range(&self, hash: &str) -> Option<(u64, u64)> {
        let mut first = None;
        let mut last = None;
        for m in &self.marks {
            if m.policy_hash == hash {
                if first.is_none() {
                    first = Some(m.ts);
                }
                last = Some(m.ts);
            }
        }
        first.zip(last)
    }

    /// How many marks each policy hash governed.
    pub fn census(&self) -> BTreeMap<String, usize> {
        let mut c = BTreeMap::new();
        for m in &self.marks {
            *c.entry(m.policy_hash.clone()).or_insert(0) += 1;
        }
        c
    }

    /// Marks governed by a hash that is *not* in `known` — events under
    /// an unrecognized policy (e.g. rejected, removed, or foreign
    /// rules). `"builtin"` counts as known iff `accept_builtin`.
    pub fn foreign_marks(&self, known: &PolicySet, accept_builtin: bool) -> Vec<&Mark> {
        self.marks
            .iter()
            .filter(|m| {
                if accept_builtin && m.policy_hash == BUILTIN {
                    return false;
                }
                known.resolve(&m.policy_hash).is_none()
            })
            .collect()
    }
}

/// Extract a winter count from an NDJSON ledger whose lines carry
/// `data.policy_hash` (Bad Apple's format) — or a top-level
/// `policy_hash` field. Lines without a parseable hash are skipped.
/// Timestamps come from `ts`/`timestamp` (numeric epoch seconds) or
/// `data.ts`; lines without timestamps are assigned their line index
/// so ordering is still preserved.
pub fn from_ledger(lines: impl Iterator<Item = String>) -> WinterCount {
    let mut wc = WinterCount::new();
    for (i, line) in lines.enumerate() {
        let Ok(v) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let hash = v["data"]["policy_hash"]
            .as_str()
            .or_else(|| v["policy_hash"].as_str());
        let Some(hash) = hash else { continue };
        let ts = v["ts"]
            .as_u64()
            .or_else(|| v["timestamp"].as_u64())
            .or_else(|| v["data"]["ts"].as_u64())
            .unwrap_or(i as u64);
        let label = v["type"]
            .as_str()
            .or_else(|| v["data"]["type"].as_str());
        match label {
            Some(l) => wc.mark_labeled(ts, hash, l),
            None => wc.mark(ts, hash),
        }
    }
    wc
}
