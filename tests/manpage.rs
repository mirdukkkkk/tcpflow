//! The man page source doc/tcpflow.1.md is written by hand; these checks keep
//! it in step with the option table in src/cli.rs. (CI checks that
//! doc/tcpflow.1 is regenerated from it: doc/manpage.sh --check.)

use tcpflow::cli::{F_FLAGS, OPTIONS, PARAMS, POST_PROCESSORS, VERSION};

fn page() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("doc/tcpflow.1.md");
    std::fs::read_to_string(path).unwrap()
}

/// The terms of the definition lists: the line before each `:   ` line.
fn terms(page: &str) -> Vec<String> {
    let lines: Vec<&str> = page.lines().collect();
    lines
        .windows(2)
        .filter(|w| w[1].trim_start().starts_with(":   "))
        .map(|w| w[0].trim().to_string())
        .collect()
}

#[test]
fn every_option_has_an_entry() {
    let terms = terms(&page());
    for o in OPTIONS {
        let short = format!("**-{}**", o.letter);
        assert!(
            terms.iter().any(|t| t.starts_with(&short)),
            "doc/tcpflow.1.md has no entry for -{}",
            o.letter
        );
        if let Some(long) = o.long {
            let long = format!("**\\--{long}**");
            assert!(
                terms.iter().any(|t| t.contains(&long)),
                "doc/tcpflow.1.md lacks --{}",
                o.long.unwrap()
            );
        }
    }
}

#[test]
fn every_parameter_flag_and_post_processor_is_described() {
    let terms = terms(&page());
    let has = |term: String| terms.iter().any(|t| t.starts_with(&term));
    for p in PARAMS {
        assert!(
            has(format!("**{}=**", p.name)),
            "doc/tcpflow.1.md lacks -S {}",
            p.name
        );
    }
    for (flag, _) in F_FLAGS {
        assert!(
            has(format!("**{flag}**")),
            "doc/tcpflow.1.md lacks -F{flag}"
        );
    }
    for (name, _) in POST_PROCESSORS {
        assert!(
            has(format!("**{name}**")),
            "doc/tcpflow.1.md lacks -e {name}"
        );
    }
}

#[test]
fn the_version_is_current() {
    assert!(
        page().contains(&format!("\nfooter: tcpflow {VERSION}\n")),
        "the footer of doc/tcpflow.1.md does not name version {VERSION}"
    );
}
