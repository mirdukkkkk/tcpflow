//! HTTP post-processing: extract response bodies from a server-to-client flow
//! (SPEC.md 13.2). Framing follows http-parser 2.7, which 1.x used.

use std::fs::File;
use std::io::{self, Write};

use crate::post::mime;
use crate::sys::privs::output_file;

/// Flows shorter than this are not worth parsing.
const MIN_SIZE: usize = 80;

/// One extracted body, for the report's `<byte_runs>`.
#[derive(Debug, PartialEq, Eq)]
pub struct BodyRun {
    /// Offset of the first body byte in the flow file.
    pub offset: usize,
    pub path: String,
    pub size: u64,
}

/// Extract the bodies of the HTTP responses in `data`, the content of `flow_path`.
/// Returns `None` if the flow is not an HTTP response stream.
pub fn scan(flow_path: &str, data: &[u8], decompress: bool) -> io::Result<Option<Vec<BodyRun>>> {
    if data.len() < MIN_SIZE || !data.starts_with(b"HTTP/1.") {
        return Ok(None);
    }
    let mut runs = Vec::new();
    let mut pos = 0;
    let mut number = 0;
    loop {
        while pos < data.len() && (data[pos] == b'\r' || data[pos] == b'\n') {
            pos += 1;
        }
        if pos >= data.len() {
            break;
        }
        let Some(head) = parse_head(&data[pos..]) else {
            break; // incomplete or malformed headers
        };
        number += 1;
        let framing = match head.framing() {
            Some(f) => f,
            None => break,
        };
        let mut path = format!("{flow_path}-HTTPBODY-{number:03}");
        let ext = mime::extension(head.get("content-type").unwrap_or(""));
        if !ext.is_empty() {
            path.push('.');
            path.push_str(ext);
        }
        let encoded = matches!(head.get("content-encoding"), Some("gzip") | Some("deflate"));
        let mut body = Body::create(&path, encoded && decompress)?;

        let body_start = pos + head.len;
        let (consumed, complete) = feed_body(&data[body_start..], framing, &mut body)?;
        // a body cut short by the end of the capture is still reported
        if let Some(size) = body.finish()? {
            runs.push(BodyRun {
                offset: body_start + body.first_offset.unwrap_or(0),
                path,
                size,
            });
        }
        if !complete || head.upgrade() {
            break;
        }
        pos = body_start + consumed;
    }
    Ok(Some(runs))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Framing {
    None,
    Length(u64),
    Chunked,
    UntilEnd,
}

struct Head {
    len: usize,
    status: u32,
    headers: Vec<(String, String)>,
}

impl Head {
    /// The last value of a header; names are lowercase.
    fn get(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    fn has_token(&self, name: &str, token: &str) -> bool {
        self.headers
            .iter()
            .filter(|(n, _)| n == name)
            .flat_map(|(_, v)| v.split(','))
            .any(|t| t.trim().eq_ignore_ascii_case(token))
    }

    fn upgrade(&self) -> bool {
        self.status == 101
            && self.headers.iter().any(|(n, _)| n == "upgrade")
            && self.has_token("connection", "upgrade")
    }

    /// How the body is delimited, or `None` for a framing error.
    fn framing(&self) -> Option<Framing> {
        let chunked = self
            .get("transfer-encoding")
            .is_some_and(|v| v.trim_end().eq_ignore_ascii_case("chunked"));
        let lengths: Vec<&str> = self
            .headers
            .iter()
            .filter(|(n, _)| n == "content-length")
            .map(|(_, v)| v.trim())
            .collect();
        let length = match lengths.as_slice() {
            [] => None,
            [one] => Some(parse_decimal(one)?),
            _ => return None,
        };
        if chunked && length.is_some() {
            return None;
        }
        if self.upgrade() {
            return Some(Framing::None);
        }
        Some(match (chunked, length) {
            (true, _) => Framing::Chunked,
            (false, Some(0)) => Framing::None,
            (false, Some(n)) => Framing::Length(n),
            (false, None) => {
                if self.status / 100 == 1 || self.status == 204 || self.status == 304 {
                    Framing::None
                } else {
                    Framing::UntilEnd
                }
            }
        })
    }
}

fn parse_decimal(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Split off one line ending in LF (with an optional CR before it).
fn line(data: &[u8]) -> Option<(&[u8], usize)> {
    let lf = data.iter().position(|&b| b == b'\n')?;
    let end = if lf > 0 && data[lf - 1] == b'\r' {
        lf - 1
    } else {
        lf
    };
    Some((&data[..end], lf + 1))
}

fn is_token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Status line and headers. `None` if incomplete or malformed.
fn parse_head(data: &[u8]) -> Option<Head> {
    let (status_line, mut len) = line(data)?;
    let rest = status_line.strip_prefix(b"HTTP/")?;
    let space = rest.iter().position(|&b| b == b' ')?;
    let version = &rest[..space];
    let dot = version.iter().position(|&b| b == b'.')?;
    if dot == 0
        || dot + 1 == version.len()
        || !version[..dot]
            .iter()
            .chain(&version[dot + 1..])
            .all(u8::is_ascii_digit)
    {
        return None;
    }
    let after = &rest[space + 1..];
    let digits = after.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 || digits > 3 || (digits < after.len() && after[digits] != b' ') {
        return None;
    }
    let status: u32 = std::str::from_utf8(&after[..digits]).ok()?.parse().ok()?;

    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let (l, n) = line(&data[len..])?;
        len += n;
        if l.is_empty() {
            break;
        }
        if l[0] == b' ' || l[0] == b'\t' {
            // obsolete line folding: the value continues
            let (_, value) = headers.last_mut()?;
            value.push(' ');
            value.push_str(String::from_utf8_lossy(l).trim_matches([' ', '\t']));
            continue;
        }
        let colon = l.iter().position(|&b| b == b':')?;
        if colon == 0 || !l[..colon].iter().all(|&b| is_token(b)) {
            return None;
        }
        let name = String::from_utf8_lossy(&l[..colon]).to_ascii_lowercase();
        let value = String::from_utf8_lossy(&l[colon + 1..])
            .trim_start_matches([' ', '\t'])
            .to_string();
        headers.push((name, value));
    }
    Some(Head {
        len,
        status,
        headers,
    })
}

/// Feed the body to `body`. Returns the bytes consumed and whether the body is complete.
fn feed_body(data: &[u8], framing: Framing, body: &mut Body) -> io::Result<(usize, bool)> {
    match framing {
        Framing::None => Ok((0, true)),
        Framing::UntilEnd => {
            body.write(0, data)?;
            Ok((data.len(), true))
        }
        Framing::Length(n) => {
            let available = (data.len() as u64).min(n) as usize;
            body.write(0, &data[..available])?;
            Ok((available, available as u64 == n))
        }
        Framing::Chunked => {
            let mut pos = 0;
            loop {
                let Some((size_line, n)) = line(&data[pos..]) else {
                    return Ok((pos, false));
                };
                let hex: Vec<u8> = size_line
                    .iter()
                    .copied()
                    .take_while(|&b| b != b';' && b != b' ' && b != b'\t')
                    .collect();
                let Some(size) = std::str::from_utf8(&hex)
                    .ok()
                    .filter(|s| !s.is_empty())
                    .and_then(|s| u64::from_str_radix(s, 16).ok())
                else {
                    return Ok((pos, false));
                };
                pos += n;
                if size == 0 {
                    // trailers end with an empty line
                    loop {
                        let Some((l, n)) = line(&data[pos..]) else {
                            return Ok((pos, false));
                        };
                        pos += n;
                        if l.is_empty() {
                            return Ok((pos, true));
                        }
                    }
                }
                let available = ((data.len() - pos) as u64).min(size) as usize;
                body.write(pos, &data[pos..pos + available])?;
                pos += available;
                if (available as u64) < size {
                    return Ok((pos, false));
                }
                match line(&data[pos..]) {
                    Some(([], n)) => pos += n,
                    _ => return Ok((pos, false)),
                }
            }
        }
    }
}

/// A body file being written, optionally through a decompressor.
struct Body {
    path: String,
    out: Option<Sink>,
    written: u64,
    /// Offset of the first body byte, relative to the start of the body.
    first_offset: Option<usize>,
}

enum Sink {
    Plain(File),
    Gzip(flate2::write::MultiGzDecoder<Counter<File>>),
    Zlib(flate2::write::ZlibDecoder<Counter<File>>),
    /// Decompression is pending until the first bytes show the format.
    Undecided(File),
    /// Decompression failed; the rest of the body is ignored.
    Failed,
}

impl Body {
    fn create(path: &str, decompress: bool) -> io::Result<Body> {
        let file = output_file()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        Ok(Body {
            path: path.to_string(),
            out: Some(if decompress {
                Sink::Undecided(file)
            } else {
                Sink::Plain(file)
            }),
            written: 0,
            first_offset: None,
        })
    }

    fn write(&mut self, offset: usize, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        self.first_offset.get_or_insert(offset);
        let sink = self.out.take().unwrap();
        self.out = Some(match sink {
            Sink::Plain(mut f) => {
                f.write_all(data)?;
                self.written += data.len() as u64;
                Sink::Plain(f)
            }
            Sink::Undecided(f) => {
                // zlib's auto-detection: gzip magic, otherwise a zlib header
                let counter = Counter { inner: f, count: 0 };
                let decoder = if data.starts_with(&[0x1f, 0x8b]) {
                    Sink::Gzip(flate2::write::MultiGzDecoder::new(counter))
                } else {
                    Sink::Zlib(flate2::write::ZlibDecoder::new(counter))
                };
                self.out = Some(decoder);
                return self.write(offset, data);
            }
            Sink::Gzip(mut d) => match d.write_all(data) {
                Ok(()) => Sink::Gzip(d),
                Err(e) => {
                    let _ = d.flush(); // keep what was decompressed before the error
                    self.decompression_failed(&e, d.get_ref().count)
                }
            },
            Sink::Zlib(mut d) => match d.write_all(data) {
                Ok(()) => Sink::Zlib(d),
                Err(e) => {
                    let _ = d.flush();
                    self.decompression_failed(&e, d.get_ref().count)
                }
            },
            Sink::Failed => Sink::Failed,
        });
        Ok(())
    }

    fn decompression_failed(&mut self, e: &io::Error, written: u64) -> Sink {
        crate::log::debug(3, &format!("{}: decompression failed: {e}", self.path));
        self.written = written;
        Sink::Failed
    }

    /// Close the body file. A body that produced no bytes is removed.
    /// Returns the body size if it is to be reported.
    fn finish(&mut self) -> io::Result<Option<u64>> {
        match self.out.take() {
            // a truncated stream fails to finish: keep what was decompressed
            Some(Sink::Gzip(mut d)) => {
                let _ = d.flush();
                let before = d.get_ref().count;
                self.written = d.finish().map_or(before, |c| c.count);
            }
            Some(Sink::Zlib(mut d)) => {
                let _ = d.flush();
                let before = d.get_ref().count;
                self.written = d.finish().map_or(before, |c| c.count);
            }
            _ => {}
        }
        if self.written == 0 {
            std::fs::remove_file(&self.path)?;
            return Ok(None);
        }
        Ok(Some(self.written))
    }
}

/// A writer that counts the bytes written through it.
struct Counter<W> {
    inner: W,
    count: u64,
}

impl<W: Write> Write for Counter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.count += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Files = Vec<(String, Vec<u8>)>;

    fn scan_bytes(name: &str, data: &[u8]) -> (Option<Vec<BodyRun>>, Files) {
        let dir = std::env::temp_dir().join(format!("tcpflow-http-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let flow = dir.join("flow").to_string_lossy().into_owned();
        let runs = scan(&flow, data, true).unwrap();
        let mut files: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                let name = p.file_name().unwrap().to_string_lossy().into_owned();
                (name, std::fs::read(&p).unwrap())
            })
            .collect();
        files.sort();
        std::fs::remove_dir_all(&dir).unwrap();
        (runs, files)
    }

    #[test]
    fn not_http() {
        let (runs, files) = scan_bytes("nothttp", &[b'x'; 100]);
        assert_eq!(runs, None);
        assert!(files.is_empty());
    }

    #[test]
    fn content_length_and_keep_alive() {
        let data = (
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 5\r\n\r\nhello\
             HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc"
        )
        .as_bytes()
        .to_vec();
        let (runs, files) = scan_bytes("length", &data);
        let runs = runs.unwrap();
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].size, 5);
        assert_eq!(&data[runs[0].offset..runs[0].offset + 5], b"hello");
        assert_eq!(
            files[0],
            ("flow-HTTPBODY-001.html".into(), b"hello".to_vec())
        );
        assert_eq!(files[1], ("flow-HTTPBODY-002".into(), b"abc".to_vec()));
    }

    #[test]
    fn chunked() {
        let data =
            ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Padding: 0123456789\r\n\r\n\
             5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\nTrailer: x\r\n\r\n")
                .as_bytes()
                .to_vec();
        let (runs, files) = scan_bytes("chunked", &data);
        assert_eq!(runs.unwrap()[0].size, 11);
        assert_eq!(files[0].1, b"hello world");
    }

    #[test]
    fn gzip_body_is_decompressed() {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(b"decompressed text").unwrap();
        let body = gz.finish().unwrap();
        let mut data = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\nX-Pad: 0123456789012345\r\n\r\n",
            body.len()
        )
        .into_bytes();
        data.extend_from_slice(&body);
        let (runs, files) = scan_bytes("gzip", &data);
        assert_eq!(runs.unwrap()[0].size, 17);
        assert_eq!(files[0].1, b"decompressed text");
    }

    #[test]
    fn no_body_statuses_and_empty_bodies() {
        let data = ("HTTP/1.1 304 Not Modified\r\nETag: x\r\n\r\n\
             HTTP/1.1 200 OK\r\nContent-Length: 0\r\nX-Pad: 01234567890123456789\r\n\r\n")
            .as_bytes()
            .to_vec();
        let (runs, files) = scan_bytes("nobody", &data);
        assert_eq!(runs.unwrap(), vec![]);
        assert!(files.is_empty(), "empty bodies are removed: {files:?}");
    }

    #[test]
    fn truncated_body_is_reported_with_its_size() {
        let data = (
            "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nX-Pad: 0123456789012345678901234567890\r\n\r\npartial"
        )
        .as_bytes()
        .to_vec();
        let (runs, files) = scan_bytes("truncated", &data);
        assert_eq!(runs.unwrap()[0].size, 7);
        assert_eq!(files[0].1, b"partial");
    }
}
