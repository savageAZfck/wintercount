use wintercount::{from_ledger, policy_hash, PolicySet};

fn main() {
    // An audit ledger in Bad Apple format — every event pins the hash
    // of the policy bytes in force at write time.
    let v1 = policy_hash(b"allow: read\nrequire_approval: false");
    let v2 = policy_hash(b"allow: read\nrequire_approval: true");
    let ledger = vec![
        format!(
            r#"{{"ts":100,"type":"tool_call","data":{{"policy_hash":"{v1}","tool":"read_file"}}}}"#
        ),
        format!(
            r#"{{"ts":150,"type":"tool_call","data":{{"policy_hash":"{v1}","tool":"write_file"}}}}"#
        ),
        // policy.yaml edited at t=200 — the hash changes from here on.
        format!(r#"{{"ts":200,"type":"policy_reload","data":{{"policy_hash":"{v2}"}}}}"#),
        format!(
            r#"{{"ts":250,"type":"tool_call","data":{{"policy_hash":"{v2}","tool":"write_file"}}}}"#
        ),
    ];

    let wc = from_ledger(ledger.into_iter());

    let mut registry = PolicySet::new();
    registry.register(
        b"allow: read\nrequire_approval: false".to_vec(),
        "policy-v1.yaml",
    );
    registry.register(
        b"allow: read\nrequire_approval: true".to_vec(),
        "policy-v2.yaml",
    );

    println!("the robe:");
    for m in wc.marks() {
        println!(
            "  t={:4}  governed by {}  ({})",
            m.ts,
            &m.policy_hash[..12],
            m.label.as_deref().unwrap_or("-")
        );
    }

    println!("\ntransitions:");
    for (ts, old, new) in wc.transitions() {
        println!(
            "  t={ts}: {} → {}",
            old.as_deref().unwrap_or("founding"),
            &new[..12]
        );
    }

    println!(
        "\nwhat governed at t=175? {}",
        &wc.policy_at(175).unwrap()[..12]
    );
    println!(
        "what governed at t=225? {}",
        &wc.policy_at(225).unwrap()[..12]
    );

    let foreign = wc.foreign_marks(&registry, true);
    println!("\nmarks under unrecognized policy: {}", foreign.len());
}
