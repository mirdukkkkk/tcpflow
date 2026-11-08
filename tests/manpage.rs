//! doc/tcpflow.1 is written by hand; these checks keep it in step with the
//! option table in src/cli.rs.

use tcpflow::cli::{F_FLAGS, OPTIONS, PARAMS, POST_PROCESSORS, VERSION};

fn page() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("doc/tcpflow.1");
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn every_option_has_an_entry() {
    let page = page();
    for o in OPTIONS {
        // an entry starts with .B -x, .BI -x or .BR -x after .TP
        let entry = [".B", ".BI", ".BR"].iter().any(|m| {
            page.contains(&format!(".TP\n{m} \\-{} ", o.letter))
                || page.contains(&format!(".TP\n{m} \\-{}\n", o.letter))
        });
        assert!(entry, "doc/tcpflow.1 has no .TP entry for -{}", o.letter);
        if let Some(long) = o.long {
            let long = long.replace('-', "\\-");
            assert!(
                page.contains(&format!("\\-\\-{long}")),
                "doc/tcpflow.1 lacks --{long}"
            );
        }
    }
}

#[test]
fn every_parameter_flag_and_post_processor_is_described() {
    let page = page();
    for p in PARAMS {
        let name = p.name.replace('-', "\\-");
        assert!(
            page.contains(&format!(".BI {name}= ")),
            "doc/tcpflow.1 lacks -S {}",
            p.name
        );
    }
    for (flag, _) in F_FLAGS {
        assert!(
            page.contains(&format!(".TP\n.B {flag}\n")),
            "doc/tcpflow.1 lacks -F{flag}"
        );
    }
    for (name, _) in POST_PROCESSORS {
        assert!(
            page.contains(&format!(".TP\n.B {name}\n")),
            "doc/tcpflow.1 lacks -e {name}"
        );
    }
}

#[test]
fn the_version_is_current() {
    assert!(
        page().contains(&format!("\"tcpflow {VERSION}\"")),
        "the .TH line of doc/tcpflow.1 does not name version {VERSION}"
    );
}
