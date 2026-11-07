//! Post-processing of closed flows (SPEC.md section 13).

pub mod http;
pub mod mime;

use std::fs::File;
use std::io::{self, Read, Seek};

use md5::{Digest, Md5};

use http::BodyRun;

/// Which post-processors run.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub md5: bool,
    pub http: bool,
    /// Decompress gzip and deflate HTTP bodies (`-Z` turns this off).
    pub decompress: bool,
    /// `-S http_max_body`: the largest body file written (SPEC.md 13.2).
    pub max_body: u64,
}

impl Options {
    pub fn any(&self) -> bool {
        self.md5 || self.http
    }
}

/// What the post-processors add to a flow's `<fileobject>`.
#[derive(Debug, Default)]
pub struct Results {
    pub md5: Option<String>,
    /// `Some` if the flow was scanned as HTTP, even if no body was found.
    pub http: Option<Vec<BodyRun>>,
}

pub fn run(opt: &Options, path: &str) -> io::Result<Results> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let mut results = Results::default();
    if len == 0 {
        return Ok(results);
    }
    if opt.md5 {
        let mut md5 = Md5::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match file.read(&mut buf)? {
                0 => break,
                n => md5.update(&buf[..n]),
            }
        }
        results.md5 = Some(md5.finalize().iter().map(|b| format!("{b:02x}")).collect());
        file.rewind()?;
    }
    if opt.http {
        let flow = io::BufReader::with_capacity(64 * 1024, &file);
        results.http = http::scan(path, flow, len, opt)?;
    }
    Ok(results)
}
