//! Flow file name templates (SPEC.md section 7).

use std::fmt::Write;
use std::net::IpAddr;

pub const DEFAULT_TEMPLATE: &str = "%A.%a-%B.%b%V%v%C%c";

/// Everything a template can refer to.
pub struct NameInfo {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub mac_src: Option<[u8; 6]>,
    pub mac_dst: Option<[u8; 6]>,
    pub vlan: Option<u16>,
    /// Flow start time, Unix seconds.
    pub start_secs: i64,
    pub flow_number: u64,
    pub session_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Code {
    SrcAddr,
    SrcPort,
    DstAddr,
    DstPort,
    SrcMac,
    DstMac,
    VlanMark,
    Vlan,
    Iso8601,
    UnixTime,
    CounterIfPositive,
    CounterMarkIfPositive,
    Counter,
    Bin(u64),
    Session,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Token {
    Literal(String),
    Code(Code),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    tokens: Vec<Token>,
}

impl Template {
    pub fn parse(template: &str) -> Result<Template, String> {
        let mut tokens = Vec::new();
        let mut literal = String::new();
        let mut chars = template.chars();
        while let Some(c) = chars.next() {
            if c != '%' {
                literal.push(c);
                continue;
            }
            let code = match chars.next() {
                None => return Err(format!("template '{template}' cannot end with a %")),
                Some('%') => {
                    literal.push('%');
                    continue;
                }
                Some('A') => Code::SrcAddr,
                Some('a') => Code::SrcPort,
                Some('B') => Code::DstAddr,
                Some('b') => Code::DstPort,
                Some('E') => Code::SrcMac,
                Some('e') => Code::DstMac,
                Some('V') => Code::VlanMark,
                Some('v') => Code::Vlan,
                Some('T') => Code::Iso8601,
                Some('t') => Code::UnixTime,
                Some('c') => Code::CounterIfPositive,
                Some('C') => Code::CounterMarkIfPositive,
                Some('#') => Code::Counter,
                Some('N') => Code::Bin(1),
                Some('K') => Code::Bin(1_000),
                Some('M') => Code::Bin(1_000_000),
                Some('G') => Code::Bin(1_000_000_000),
                Some('S') => Code::Session,
                Some(other) => {
                    return Err(format!("template '{template}': unknown code %{other}"));
                }
            };
            if !literal.is_empty() {
                tokens.push(Token::Literal(std::mem::take(&mut literal)));
            }
            tokens.push(Token::Code(code));
        }
        if !literal.is_empty() {
            tokens.push(Token::Literal(literal));
        }
        Ok(Template { tokens })
    }

    /// Expand the template for a flow and a connection counter.
    pub fn expand(&self, f: &NameInfo, counter: u32) -> String {
        let mut s = String::new();
        for token in &self.tokens {
            let code = match token {
                Token::Literal(l) => {
                    s.push_str(l);
                    continue;
                }
                Token::Code(code) => *code,
            };
            match code {
                Code::SrcAddr => push_addr(&mut s, f.src),
                Code::DstAddr => push_addr(&mut s, f.dst),
                Code::SrcPort => write!(s, "{:05}", f.sport).unwrap(),
                Code::DstPort => write!(s, "{:05}", f.dport).unwrap(),
                Code::SrcMac => push_mac(&mut s, f.mac_src),
                Code::DstMac => push_mac(&mut s, f.mac_dst),
                Code::VlanMark => {
                    if f.vlan.is_some() {
                        s.push_str("--");
                    }
                }
                Code::Vlan => {
                    if let Some(v) = f.vlan {
                        write!(s, "{v}").unwrap();
                    }
                }
                Code::Iso8601 => s.push_str(&iso8601(f.start_secs)),
                Code::UnixTime => write!(s, "{}", f.start_secs).unwrap(),
                Code::CounterIfPositive => {
                    if counter > 0 {
                        write!(s, "{counter}").unwrap();
                    }
                }
                Code::CounterMarkIfPositive => {
                    if counter > 0 {
                        s.push('c');
                    }
                }
                Code::Counter => write!(s, "{counter}").unwrap(),
                Code::Bin(div) => write!(s, "{:03}", (f.flow_number / div) % 1000).unwrap(),
                Code::Session => write!(s, "{:020}", f.session_id).unwrap(),
            }
        }
        s
    }

    /// Does the name change with the connection counter? A template without
    /// `%#` or `%c` could never find a free name (SPEC.md D11).
    pub fn uses_counter(&self) -> bool {
        self.tokens.iter().any(|t| {
            matches!(
                t,
                Token::Code(Code::Counter) | Token::Code(Code::CounterIfPositive)
            )
        })
    }
}

/// Apply `-F` flags to a template string (SPEC.md 7.2). Returns the warnings for
/// unknown flags. The output flags `X` and `M` are handled by the caller.
pub fn apply_f_flags(template: &mut String, flags: &str) -> Vec<char> {
    let mut unknown = Vec::new();
    for flag in flags.chars() {
        match flag {
            'c' => *template = counter_always(template),
            't' => template.insert_str(0, "%tT"),
            'T' => template.insert_str(0, "%T"),
            'k' => template.insert_str(0, "%K/"),
            'm' => template.insert_str(0, "%M000-%M999/%M%K/"),
            'g' => template.insert_str(0, "%G000000-%G999999/%G%M000-%G%M999/%G%M%K/"),
            'X' | 'M' => {}
            other => unknown.push(other),
        }
    }
    unknown
}

/// `-Fc`: `%C%c` becomes `c%#` and `%c` becomes `%#`. A literal `%%` stays.
fn counter_always(template: &str) -> String {
    let mut out = String::new();
    let mut rest = template;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let (replacement, n) = if rest.starts_with("%%") {
            ("%%", 2)
        } else if rest.starts_with("%C%c") {
            ("c%#", 4)
        } else if rest.starts_with("%c") {
            ("%#", 2)
        } else {
            ("%", 1)
        };
        out.push_str(replacement);
        rest = &rest[n..];
    }
    out.push_str(rest);
    out
}

/// Does `template` contain the `%c` code (not a literal `%%c`)?
pub fn has_counter_code(template: &str) -> bool {
    let mut rest = template;
    while let Some(i) = rest.find('%') {
        rest = &rest[i..];
        if rest.starts_with("%c") {
            return true;
        }
        rest = &rest[rest.len().min(2)..];
    }
    false
}

fn push_addr(s: &mut String, addr: IpAddr) {
    match addr {
        IpAddr::V4(a) => {
            let o = a.octets();
            write!(s, "{:03}.{:03}.{:03}.{:03}", o[0], o[1], o[2], o[3]).unwrap();
        }
        IpAddr::V6(a) => write!(s, "{a}").unwrap(),
    }
}

fn push_mac(s: &mut String, mac: Option<[u8; 6]>) {
    let m = mac.unwrap_or_default();
    write!(
        s,
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
    .unwrap();
}

/// `YYYY-MM-DDTHH:MM:SSZ` for Unix seconds, in UTC.
pub fn iso8601(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> NameInfo {
        NameInfo {
            src: "128.129.130.131".parse().unwrap(),
            dst: "10.11.12.13".parse().unwrap(),
            sport: 2345,
            dport: 45103,
            mac_src: Some([0, 0x0f, 0xcc, 0xfe, 0xcc, 0xdc]),
            mac_dst: None,
            vlan: None,
            start_secs: 1325542703,
            flow_number: 1_234_567,
            session_id: 42,
        }
    }

    fn expand(template: &str, f: &NameInfo, counter: u32) -> String {
        Template::parse(template).unwrap().expand(f, counter)
    }

    #[test]
    fn default_template() {
        let f = info();
        assert_eq!(
            expand(DEFAULT_TEMPLATE, &f, 0),
            "128.129.130.131.02345-010.011.012.013.45103"
        );
        assert_eq!(
            expand(DEFAULT_TEMPLATE, &f, 5),
            "128.129.130.131.02345-010.011.012.013.45103c5"
        );
        let vlan = NameInfo {
            vlan: Some(3),
            ..info()
        };
        assert_eq!(
            expand(DEFAULT_TEMPLATE, &vlan, 0),
            "128.129.130.131.02345-010.011.012.013.45103--3"
        );
    }

    #[test]
    fn times_bins_macs_session() {
        let f = info();
        assert_eq!(expand("%t|%T", &f, 0), "1325542703|2012-01-02T22:18:23Z");
        assert_eq!(expand("%G.%M.%K.%N", &f, 0), "000.001.234.567");
        assert_eq!(
            expand("%E/%e", &f, 0),
            "00:0f:cc:fe:cc:dc/00:00:00:00:00:00"
        );
        assert_eq!(expand("%S", &f, 0), "00000000000000000042");
        assert_eq!(expand("%#%%", &f, 0), "0%");
    }

    #[test]
    fn ipv6_addresses() {
        let f = NameInfo {
            src: "2001:6f8:102d:0:2d0:9ff:fee3:e8de".parse().unwrap(),
            ..info()
        };
        assert_eq!(expand("%A", &f, 0), "2001:6f8:102d:0:2d0:9ff:fee3:e8de");
    }

    #[test]
    fn invalid_templates() {
        assert!(Template::parse("%A%").is_err());
        assert!(Template::parse("%Q").is_err());
    }

    #[test]
    fn literal_percent_is_not_a_code() {
        let mut t = "%%c-%c-%C%c".to_string();
        apply_f_flags(&mut t, "c");
        assert_eq!(t, "%%c-%#-c%#");
        assert!(!has_counter_code("%%c"));
        assert!(has_counter_code("%%%c"));
        assert!(has_counter_code("x%c"));
    }

    #[test]
    fn f_flags() {
        let mut t = DEFAULT_TEMPLATE.to_string();
        assert!(apply_f_flags(&mut t, "ck").is_empty());
        assert_eq!(t, "%K/%A.%a-%B.%b%V%vc%#");
        assert!(Template::parse(&t).unwrap().uses_counter());
        let mut t = DEFAULT_TEMPLATE.to_string();
        assert_eq!(apply_f_flags(&mut t, "tTz"), vec!['z']);
        assert_eq!(t, "%T%tT%A.%a-%B.%b%V%v%C%c");
    }

    #[test]
    fn dates() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso8601(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso8601(-1), "1969-12-31T23:59:59Z");
    }
}
