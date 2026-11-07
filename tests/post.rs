//! Post-processing on a real capture (SPEC.md 13).

mod common;

use common::*;

const JPEGS: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/captures/http/jpegs.pcap"
);

fn bodies(out: &std::path::Path) -> Vec<(String, u64)> {
    let mut v: Vec<_> = std::fs::read_dir(out)
        .unwrap()
        .map(|e| e.unwrap())
        .filter(|e| e.file_name().to_string_lossy().contains("HTTPBODY"))
        .map(|e| {
            (
                e.file_name().into_string().unwrap(),
                e.metadata().unwrap().len(),
            )
        })
        .collect();
    v.sort();
    v
}

#[test]
fn http_max_body_limits_every_body_file() {
    let dir = scratch("max-body");
    assert!(
        run(&dir, &["-a", "-o", "out", "-r", JPEGS])
            .status
            .success()
    );
    let full = bodies(&dir.join("out"));
    assert!(full.iter().any(|(_, n)| *n > 1000));
    let out = run(
        &dir,
        &[
            "-a",
            "-S",
            "http_max_body=1000",
            "-o",
            "limited",
            "-r",
            JPEGS,
        ],
    );
    assert!(out.status.success());
    let limited = bodies(&dir.join("limited"));
    assert_eq!(limited.len(), full.len());
    for ((name, n), (_, m)) in full.iter().zip(&limited) {
        assert_eq!(*m, (*n).min(1000), "{name}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_body_name_that_is_too_long_does_not_stop_the_run() {
    let dir = scratch("long-body");
    // the flow names fit, the body names (plus "-HTTPBODY-001.jpg") do not
    let template = format!("{}%c", "a".repeat(248));
    let out = run(&dir, &["-a", "-T", &template, "-o", "out", "-r", JPEGS]);
    assert!(out.status.success(), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot create"));
    let report = std::fs::read_to_string(dir.join("out/report.xml")).unwrap();
    assert!(report.contains("<total_flows>"));
    assert!(bodies(&dir.join("out")).is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn extracted_bodies_match_the_expected_files() {
    let dir = scratch("image-bodies");
    let image = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/captures/http/image");
    let pcap = format!("{image}/image.pcapng");
    assert!(
        run(&dir, &["-a", "-o", "out", "-r", &pcap])
            .status
            .success()
    );
    let flow = "127.000.000.001.00080-127.000.000.001.52054";
    for (body, expected) in [("001.html", "body-001.html"), ("002.jpg", "body-002.jpg")] {
        let got = std::fs::read(dir.join(format!("out/{flow}-HTTPBODY-{body}"))).unwrap();
        assert_eq!(
            got,
            std::fs::read(format!("{image}/{expected}")).unwrap(),
            "{body}"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
