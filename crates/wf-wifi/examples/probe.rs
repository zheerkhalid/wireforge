//! Runs every collector once and prints counts only (no names, addresses
//! or keys): `cargo run -p wf-wifi --example probe`.

fn main() {
    for (name, result) in wf_wifi::selftest() {
        match result {
            Ok(summary) => println!("{name:<18} OK   {summary}"),
            Err(reason) => println!("{name:<18} ERR  {reason}"),
        }
    }
}
