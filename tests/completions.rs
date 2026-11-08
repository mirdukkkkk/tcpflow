//! The shell completions in doc/completions/ are generated from the option
//! table in src/cli.rs; they must be regenerated when an option changes.

use std::path::Path;

#[test]
fn completion_files_are_up_to_date() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("doc/completions");
    for (name, content) in tcpflow::completions::all() {
        let file = std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        assert!(
            file == content,
            "doc/completions/{name} is out of date: run `cargo run --example completions`"
        );
    }
}

#[test]
fn every_option_letter_is_in_the_table() {
    // the letters in the synopsis of tcpflow -h
    let usage = tcpflow::cli::usage(0);
    for o in tcpflow::cli::OPTIONS {
        if o.letter != 'h' {
            assert!(
                usage.contains(o.letter),
                "-{} is not in the synopsis",
                o.letter
            );
        }
    }
}
