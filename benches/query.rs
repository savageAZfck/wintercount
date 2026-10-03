use std::hint::black_box;
use std::time::Instant;
use wintercount::WinterCount;

fn main() {
    let mut wc = WinterCount::new();
    for i in 0..100_000u64 {
        wc.mark(i, format!("hash{:03}", i / 10_000));
    }
    let n = 100_000;
    let t = Instant::now();
    for i in 0..n {
        black_box(wc.policy_at(black_box(i as u64)));
    }
    let e = t.elapsed();
    println!(
        "policy_at over 100k marks: {n} queries in {:?} ({:.0} ns/op)",
        e,
        e.as_nanos() as f64 / n as f64
    );
}
