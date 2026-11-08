//! HTTP body extraction (SPEC.md 13.2): the first byte picks the options, the
//! rest is the server-to-client flow. Bodies are written to a temporary directory.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use tcpflow::post::{Options, http};

fn flow_path() -> &'static str {
    static DIR: OnceLock<String> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("tcpflow-fuzz-http-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("flow").to_string_lossy().into_owned()
    })
}

fuzz_target!(|data: &[u8]| {
    let Some((&pick, flow)) = data.split_first() else {
        return;
    };
    let opt = Options {
        md5: false,
        http: true,
        decompress: pick & 1 == 0,
        // small limits too, to reach the limit code
        max_body: if pick & 2 == 0 { 1 << 20 } else { u64::from(pick >> 2) },
    };
    let _ = http::scan(flow_path(), flow, flow.len() as u64, &opt);
});
