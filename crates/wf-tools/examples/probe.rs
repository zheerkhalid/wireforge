//! Prints the result of the safe self-test (loopback only, counts only).
//! `cargo run -p wf-tools --example probe`

fn main() {
    let results = wf_tools::selftest();
    let failed = results.iter().filter(|(_, r)| r.is_err()).count();
    for (name, result) in &results {
        match result {
            Ok(summary) => println!("ok    {name}: {summary}"),
            Err(reason) => println!("FAIL  {name}: {reason}"),
        }
    }
    println!("{} checks, {} failed", results.len(), failed);
    if failed > 0 {
        std::process::exit(1);
    }
}
