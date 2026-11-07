//! Opening capture files, with in-process decompression (SPEC.md section 3, D6), and
//! capture devices.

use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::os::fd::IntoRawFd;
use std::thread::JoinHandle;

use pcap::{Active, Capture, Device, Offline};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Compression {
    Gzip,
    Bzip2,
    Xz,
    Lzma,
    Zip,
}

fn compression(path: &str) -> Option<Compression> {
    [
        (".gz", Compression::Gzip),
        (".bz2", Compression::Bzip2),
        (".xz", Compression::Xz),
        (".lzma", Compression::Lzma),
        (".zip", Compression::Zip),
    ]
    .into_iter()
    .find(|(suffix, _)| path.ends_with(suffix))
    .map(|(_, c)| c)
}

pub struct Input {
    pub capture: Capture<Offline>,
    inflater: Option<JoinHandle<io::Result<()>>>,
}

/// Open a capture file. `-` is standard input.
pub fn open(path: &str) -> Result<Input, String> {
    let Some(kind) = compression(path) else {
        let capture = Capture::from_file(path).map_err(|e| format!("{path}: {e}"))?;
        return Ok(Input {
            capture,
            inflater: None,
        });
    };
    let file = File::open(path).map_err(|e| format!("{path}: {e}"))?;
    let (reader, mut writer) = io::pipe().map_err(|e| format!("{path}: {e}"))?;
    let inflater = std::thread::spawn(move || -> io::Result<()> {
        let result = decompress(kind, file, &mut writer);
        match result {
            // libpcap stopped reading early (a stop was requested): not an error
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
            other => other,
        }
    });
    // SAFETY: the descriptor is a fresh pipe end; libpcap takes ownership of it.
    let capture = match unsafe { Capture::from_raw_fd(reader.into_raw_fd()) } {
        Ok(c) => c,
        // the decompressor's own error says more than libpcap's "truncated file"
        Err(e) => {
            return Err(match inflater.join() {
                Ok(Err(cause)) => format!("{path}: decompression failed: {cause}"),
                _ => format!("{path}: {e}"),
            });
        }
    };
    Ok(Input {
        capture,
        inflater: Some(inflater),
    })
}

/// Open a capture device for live capture; `None` is the first device libpcap
/// reports. Returns the device name and the capture.
pub fn live(
    device: Option<&str>,
    promisc: bool,
    timeout_ms: i32,
) -> Result<(String, Capture<Active>), String> {
    let device = match device {
        Some(name) => Device::from(name),
        None => Device::lookup().map_err(|e| e.to_string())?.ok_or(
            "found 0 devices, maybe you don't have permissions, switch to root or equivalent user instead.",
        )?,
    };
    let name = device.name.clone();
    let capture = Capture::from_device(device)
        .and_then(|c| {
            c.snaplen(SNAPLEN)
                .promisc(promisc)
                .timeout(timeout_ms)
                .open()
        })
        .map_err(|e| format!("{name}: {e}"))?;
    Ok((name, capture))
}

/// The largest frame 1.x captures.
const SNAPLEN: i32 = 65536;

fn decompress(kind: Compression, file: File, out: &mut impl Write) -> io::Result<()> {
    let mut input = BufReader::new(file);
    match kind {
        Compression::Gzip => {
            io::copy(&mut flate2::read::MultiGzDecoder::new(input), out)?;
        }
        Compression::Bzip2 => {
            io::copy(&mut bzip2::read::MultiBzDecoder::new(input), out)?;
        }
        Compression::Xz => {
            lzma_rs::xz_decompress(&mut input, out).map_err(io::Error::other)?;
        }
        Compression::Lzma => {
            lzma_rs::lzma_decompress(&mut input, out).map_err(io::Error::other)?;
        }
        Compression::Zip => {
            let mut archive = zip::ZipArchive::new(input.into_inner()).map_err(io::Error::other)?;
            let mut first = archive.by_index(0).map_err(io::Error::other)?;
            io::copy(&mut first as &mut dyn Read, out)?;
        }
    }
    Ok(())
}

impl Input {
    /// Wait for the decompressor. Returns its error, if any.
    pub fn finish(self, path: &str) -> Result<(), String> {
        drop(self.capture); // closes the pipe, so a still-running decompressor ends
        match self.inflater.map(|t| t.join()) {
            None | Some(Ok(Ok(()))) => Ok(()),
            Some(Ok(Err(e))) => Err(format!("{path}: decompression failed: {e}")),
            Some(Err(_)) => Err(format!("{path}: decompression failed")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffixes() {
        assert_eq!(compression("a.pcap.gz"), Some(Compression::Gzip));
        assert_eq!(compression("a.pcap.bz2"), Some(Compression::Bzip2));
        assert_eq!(compression("a.xz"), Some(Compression::Xz));
        assert_eq!(compression("a.lzma"), Some(Compression::Lzma));
        assert_eq!(compression("a.zip"), Some(Compression::Zip));
        assert_eq!(compression("a.pcap"), None);
        assert_eq!(compression("-"), None);
    }
}
