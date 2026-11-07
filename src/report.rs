//! The DFXML report, `report.xml` (SPEC.md section 14).

use std::fs::File;
use std::io::{self, BufWriter, Write};
use std::net::IpAddr;

use crate::demux::{Flow, FlowSink, Timestamp};
use crate::naming::iso8601;
use crate::post;

pub struct Report {
    out: BufWriter<File>,
}

pub struct Summary {
    pub total_flows: u64,
    pub total_packets: u64,
    pub max_open_flows: usize,
}

impl Report {
    pub fn create(file: File, command_line: &str, tdelta: i64) -> io::Result<Report> {
        let mut out = BufWriter::new(file);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        write!(
            out,
            "<?xml version='1.0' encoding='UTF-8'?>\n\
             <dfxml xmloutputversion='1.0'>\n\
             \x20 <metadata\n\
             \x20 xmlns='http://afflib.org/tcpflow/'\n\
             \x20 xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'\n\
             \x20 xmlns:dc='http://purl.org/dc/elements/1.1/'>\n\
             \x20   <dc:type>Feature Extraction</dc:type>\n\
             \x20 </metadata>\n\
             \x20 <creator version='1.0'>\n\
             \x20   <program>TCPFLOW</program>\n\
             \x20   <version>{}</version>\n\
             \x20   <execution_environment>\n\
             \x20     <command_line>{}</command_line>\n\
             \x20     <start_time>{}</start_time>\n\
             \x20   </execution_environment>\n\
             \x20 </creator>\n\
             \x20 <configuration>\n\
             \x20   <tdelta>{tdelta}</tdelta>\n\
             \x20 </configuration>\n",
            env!("CARGO_PKG_VERSION"),
            escape(command_line),
            iso8601(now),
        )?;
        out.flush()?;
        Ok(Report { out })
    }

    pub fn finish(mut self, s: &Summary) -> io::Result<()> {
        let (utime, stime, maxrss) = rusage();
        write!(
            self.out,
            "  <summary>\n\
             \x20   <total_flows>{}</total_flows>\n\
             \x20   <total_packets>{}</total_packets>\n\
             \x20   <max_open_flows>{}</max_open_flows>\n\
             \x20 </summary>\n\
             \x20 <rusage>\n\
             \x20   <utime>{utime:.6}</utime>\n\
             \x20   <stime>{stime:.6}</stime>\n\
             \x20   <maxrss>{maxrss}</maxrss>\n\
             \x20 </rusage>\n\
             </dfxml>\n",
            s.total_flows, s.total_packets, s.max_open_flows
        )?;
        self.out.flush()
    }
}

impl FlowSink for Report {
    fn flow_closed(&mut self, f: &Flow, post: &post::Results) -> io::Result<()> {
        let o = &mut self.out;
        writeln!(o, "  <fileobject>")?;
        if let Some(path) = &f.path {
            writeln!(o, "    <filename>{}</filename>", escape(path))?;
        }
        writeln!(o, "    <filesize>{}</filesize>", f.last_byte)?;
        write!(
            o,
            "    <tcpflow startime='{}' endtime='{}'",
            timestamp(f.start),
            timestamp(f.last)
        )?;
        // an all-zero address (e.g. a loopback interface) carries no information
        if let Some(mac) = f.link.mac_dst.filter(|m| *m != [0; 6]) {
            write!(o, " mac_daddr='{}'", mac_text(mac))?;
        }
        if let Some(mac) = f.link.mac_src.filter(|m| *m != [0; 6]) {
            write!(o, " mac_saddr='{}'", mac_text(mac))?;
        }
        let family = match f.key.src {
            IpAddr::V4(_) => libc::AF_INET,
            IpAddr::V6(_) => libc::AF_INET6,
        };
        write!(
            o,
            " family='{family}' src_ipn='{}' dst_ipn='{}' srcport='{}' dstport='{}' packets='{}'",
            f.key.src, f.key.dst, f.key.sport, f.key.dport, f.packets
        )?;
        if f.out_of_order > 0 {
            write!(o, " out_of_order_count='{}'", f.out_of_order)?;
        }
        if f.violations > 0 {
            write!(o, " violations='{}'", f.violations)?;
        }
        write!(o, " len='{}'", f.len)?;
        if f.caplen != f.len {
            write!(o, " caplen='{}'", f.caplen)?;
        }
        writeln!(o, "/>")?;
        if let Some(md5) = &post.md5 {
            writeln!(o, "    <hashdigest type='MD5'>{md5}</hashdigest>")?;
        }
        if let Some(runs) = &post.http {
            writeln!(o, "    <byte_runs>")?;
            for r in runs {
                writeln!(
                    o,
                    "      <byte_run file_offset='{}'><fileobject><filename>{}</filename><filesize>{}</filesize></fileobject></byte_run>",
                    r.offset,
                    escape(&r.path),
                    r.size
                )?;
            }
            writeln!(o, "    </byte_runs>")?;
        }
        writeln!(o, "  </fileobject>")?;
        o.flush()
    }
}

/// ISO 8601 UTC with microseconds, as in 1.6.2: `2008-10-06T17:54:54.796605Z`.
fn timestamp(t: Timestamp) -> String {
    let base = iso8601(t.secs);
    format!("{}.{:06}Z", &base[..base.len() - 1], t.usecs)
}

fn mac_text(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\'' => out.push_str("&apos;"),
            '"' => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
    out
}

fn rusage() -> (f64, f64, i64) {
    // SAFETY: getrusage only writes to the struct we pass.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) } != 0 {
        return (0.0, 0.0, 0);
    }
    let secs = |tv: libc::timeval| tv.tv_sec as f64 + tv.tv_usec as f64 / 1e6;
    (secs(ru.ru_utime), secs(ru.ru_stime), ru.ru_maxrss as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps() {
        let t = Timestamp {
            secs: 1223315694,
            usecs: 796605,
        };
        assert_eq!(timestamp(t), "2008-10-06T17:54:54.796605Z");
    }

    #[test]
    fn escaping() {
        assert_eq!(escape("a<b>&'\""), "a&lt;b&gt;&amp;&apos;&quot;");
    }
}
