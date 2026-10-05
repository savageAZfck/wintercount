use wintercount::{from_ledger, policy_hash, PolicySet, WinterCount, BUILTIN};

#[test]
fn policy_hash_is_sha256_of_exact_bytes() {
    let h = policy_hash(b"rules: none");
    assert_eq!(h.len(), 64);
    assert_eq!(h, policy_hash(b"rules: none"));
    assert_ne!(h, policy_hash(b"rules: none "));
}

#[test]
fn policy_at_answers_time_t() {
    let mut wc = WinterCount::new();
    let old = policy_hash(b"allow: read");
    let new = policy_hash(b"allow: none");
    wc.mark(100, &old);
    wc.mark(150, &old);
    wc.mark(200, &new);
    wc.mark(250, &new);

    assert_eq!(wc.policy_at(99), None, "robe starts at 100");
    assert_eq!(wc.policy_at(100), Some(old.as_str()));
    assert_eq!(
        wc.policy_at(175),
        Some(old.as_str()),
        "still old policy at 175"
    );
    assert_eq!(wc.policy_at(200), Some(new.as_str()));
    assert_eq!(wc.policy_at(10_000), Some(new.as_str()));
}

#[test]
fn transitions_record_governance_changes() {
    let mut wc = WinterCount::new();
    wc.mark(100, "a");
    wc.mark(150, "a");
    wc.mark(200, "b");
    wc.mark(250, "builtin");

    let t = wc.transitions();
    assert_eq!(t.len(), 3);
    assert_eq!(t[0], (100, None, "a".to_string()));
    assert_eq!(t[1], (200, Some("a".to_string()), "b".to_string()));
    assert_eq!(t[2], (250, Some("b".to_string()), BUILTIN.to_string()));
}

#[test]
fn governed_range_and_census() {
    let mut wc = WinterCount::new();
    wc.mark(10, "a");
    wc.mark(20, "b");
    wc.mark(30, "a");
    assert_eq!(wc.governed_range("a"), Some((10, 30)));
    assert_eq!(wc.governed_range("zzz"), None);
    let c = wc.census();
    assert_eq!(c["a"], 2);
    assert_eq!(c["b"], 1);
}

#[test]
fn foreign_marks_flag_unknown_policies() {
    let mut known = PolicySet::new();
    let good = known.register(b"allow: read".to_vec(), "policy.yaml");

    let rejected = policy_hash(b"allow: everything"); // bytes were refused, hash still pinned
    let mut wc = WinterCount::new();
    wc.mark(1, &good);
    wc.mark(2, &rejected);
    wc.mark(3, BUILTIN);

    let foreign = wc.foreign_marks(&known, true);
    assert_eq!(foreign.len(), 1);
    assert_eq!(foreign[0].policy_hash, rejected);

    // When builtin isn't accepted, it's foreign too.
    assert_eq!(wc.foreign_marks(&known, false).len(), 2);
}

#[test]
fn ledger_extraction_badapple_format() {
    let ledger = vec![
        r#"{"ts":100,"type":"tool_call","data":{"policy_hash":"aaa","tool":"x"}}"#.to_string(),
        r#"{"ts":200,"type":"tool_call","data":{"policy_hash":"bbb","tool":"y"}}"#.to_string(),
        r#"{"ts":300,"type":"heartbeat","data":{}}"#.to_string(), // no hash — skipped
        r#"{"ts":400,"type":"tool_call","data":{"policy_hash":"bbb","tool":"z"}}"#.to_string(),
    ];
    let wc = from_ledger(ledger.into_iter());
    assert_eq!(wc.marks().len(), 3);
    assert_eq!(wc.policy_at(150), Some("aaa"));
    assert_eq!(wc.policy_at(250), Some("bbb"));
    assert_eq!(wc.marks()[0].label.as_deref(), Some("tool_call"));
}
