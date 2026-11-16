//! Runs every collector once and prints counts only (no addresses, names or
//! paths): `cargo run -p wf-traffic --example probe`.

fn main() {
    let mut failed = 0;
    for (name, result) in wf_traffic::selftest() {
        match result {
            Ok(summary) => println!("ok    {name:<12} {summary}"),
            Err(why) => {
                failed += 1;
                println!("FAIL  {name:<12} {why}");
            }
        }
    }
    println!("{failed} collector(s) reported a problem");
}
