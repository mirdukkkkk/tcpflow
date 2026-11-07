//! Console output for `-c`, `-C` and `-J` (SPEC.md section 9).

use std::io::{self, Write};

use crate::demux::FlowKey;

#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    pub suppress_header: bool,
    pub hex: bool,
    pub strip_nonprint: bool,
    pub no_newline: bool,
    pub color: bool,
    pub json: bool,
}

const BLUE: &[u8] = b"\x1b[0;34m";
const RED: &[u8] = b"\x1b[0;31m";
const RESET: &[u8] = b"\x1b[0m";

/// Print one segment of the flow `key`. `name` is the flow name, `client_to_server`
/// selects the color.
pub fn print(
    out: &mut impl Write,
    opt: &Options,
    key: &FlowKey,
    name: &str,
    client_to_server: bool,
    data: &[u8],
) -> io::Result<()> {
    if opt.color {
        out.write_all(if client_to_server { BLUE } else { RED })?;
    }
    if !opt.suppress_header && !opt.json {
        write!(out, "{name}: ")?;
        if opt.hex {
            out.write_all(b"\n")?;
        }
    }
    if opt.hex {
        hex_dump(out, data)?;
    } else if opt.json {
        json(out, key, data)?;
    } else if opt.strip_nonprint {
        let cleaned: Vec<u8> = data
            .iter()
            .map(|&c| {
                if (0x20..=0x7e).contains(&c) || c == b'\n' || c == b'\r' {
                    c
                } else {
                    b'.'
                }
            })
            .collect();
        out.write_all(&cleaned)?;
    } else {
        out.write_all(data)?;
    }
    if opt.color {
        out.write_all(RESET)?;
    }
    if !opt.no_newline {
        out.write_all(b"\n")?;
    }
    out.flush()
}

/// One JSON object; addresses and ports come from the flow key (SPEC.md 9.3, D4).
fn json(out: &mut impl Write, key: &FlowKey, data: &[u8]) -> io::Result<()> {
    let payload: Vec<String> = data.iter().map(u8::to_string).collect();
    write!(
        out,
        "{{\"src_host\":\"{}\",\"src_port\":{},\"dst_host\":\"{}\",\"dst_port\":{},\"payload\": [{}]}}",
        key.src,
        key.sport,
        key.dst,
        key.dport,
        payload.join(",")
    )
}

/// 32 bytes per line: offset, hex in groups of two bytes, then ASCII (SPEC.md 9.2).
fn hex_dump(out: &mut impl Write, data: &[u8]) -> io::Result<()> {
    let mut widest = 0;
    for (n, chunk) in data.chunks(32).enumerate() {
        let mut line = format!("{:04x}: ", n * 32);
        for (j, b) in chunk.iter().enumerate() {
            line.push_str(&format!("{b:02x}"));
            if j % 2 == 1 {
                line.push(' ');
            }
        }
        widest = widest.max(line.len());
        while line.len() < widest {
            line.push(' ');
        }
        line.push(' ');
        for &b in chunk {
            line.push(if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        line.push('\n');
        out.write_all(line.as_bytes())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(opt: Options, data: &[u8]) -> String {
        let key = FlowKey {
            src: "10.0.0.1".parse().unwrap(),
            dst: "2001:db8::2".parse().unwrap(),
            sport: 40000,
            dport: 80,
        };
        let mut out = Vec::new();
        print(&mut out, &opt, &key, "a-b", true, data).unwrap();
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn plain_and_stripped() {
        assert_eq!(render(Options::default(), b"hi\x01"), "a-b: hi\x01\n");
        let strip = Options {
            strip_nonprint: true,
            suppress_header: true,
            no_newline: true,
            ..Default::default()
        };
        assert_eq!(render(strip, b"hi\x01\r\n"), "hi.\r\n");
    }

    #[test]
    fn hex() {
        let opt = Options {
            hex: true,
            ..Default::default()
        };
        let data: Vec<u8> = (0x41..0x41 + 34).collect();
        let text = render(opt, &data);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[0], "a-b: ");
        assert!(lines[1].starts_with("0000: 4142 4344 "));
        assert!(lines[1].ends_with(" ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"));
        // the short last line is padded to the width of the first
        assert_eq!(lines[2].find(" ab").unwrap(), lines[1].find(" AB").unwrap());
    }

    #[test]
    fn json() {
        let opt = Options {
            json: true,
            ..Default::default()
        };
        assert_eq!(
            render(opt, b"GE\xff"),
            "{\"src_host\":\"10.0.0.1\",\"src_port\":40000,\"dst_host\":\"2001:db8::2\",\"dst_port\":80,\"payload\": [71,69,255]}\n"
        );
    }

    #[test]
    fn color() {
        let opt = Options {
            color: true,
            suppress_header: true,
            ..Default::default()
        };
        assert_eq!(render(opt, b"x"), "\x1b[0;34mx\x1b[0m\n");
    }
}
