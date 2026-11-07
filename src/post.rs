//! Post-processing of closed flows (SPEC.md section 13).

use std::fs::File;
use std::io;

use md5::{Digest, Md5};

use crate::http::{self, BodyRun};

/// Which post-processors run.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub md5: bool,
    pub http: bool,
    /// Decompress gzip and deflate HTTP bodies (`-Z` turns this off).
    pub decompress: bool,
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
    let file = File::open(path)?;
    if file.metadata()?.len() == 0 {
        return Ok(Results::default());
    }
    // SAFETY: the flow file is ours and is not modified while mapped.
    let map = unsafe { memmap2::Mmap::map(&file)? };
    let mut results = Results::default();
    if opt.md5 {
        let digest = Md5::digest(&map[..]);
        results.md5 = Some(digest.iter().map(|b| format!("{b:02x}")).collect());
    }
    if opt.http {
        results.http = http::scan(path, &map, opt.decompress)?;
    }
    Ok(results)
}
