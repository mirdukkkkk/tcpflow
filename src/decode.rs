//! Link, IP and TCP decoding (SPEC.md section 4).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Link-layer types from libpcap's `DLT_*` values (SPEC.md 4.1).
pub mod dlt {
    pub const NULL: i32 = 0;
    pub const EN10MB: i32 = 1;
    pub const IEEE802: i32 = 6;
    pub const PPP: i32 = 9;
    pub const RAW_12: i32 = 12; // DLT_RAW on most systems; DLT_LOOP on OpenBSD
    pub const RAW_14: i32 = 14;
    pub const PPP_ETHER: i32 = 51;
    pub const RAW: i32 = 101;
    pub const LOOP: i32 = 108;
    pub const LINUX_SLL: i32 = 113;
}

pub const TH_FIN: u8 = 0x01;
pub const TH_SYN: u8 = 0x02;
pub const TH_RST: u8 = 0x04;
pub const TH_ACK: u8 = 0x10;

const ETHERTYPE_IP: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_8021AD: u16 = 0x88a8;
const ETHERTYPE_QINQ: u16 = 0x9100;
const ETHERTYPE_MPLS: u16 = 0x8847;
const IPPROTO_TCP: u8 = 6;
const IP6_HOPOPTS: u8 = 0;
const IP6_ROUTING: u8 = 43;
const IP6_FRAGMENT: u8 = 44;
const IP6_AH: u8 = 51;
const IP6_DSTOPTS: u8 = 60;

/// What the link layer tells us about a packet besides its IP payload.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LinkInfo {
    pub mac_src: Option<[u8; 6]>,
    pub mac_dst: Option<[u8; 6]>,
    pub vlan: Option<u16>,
}

/// A decoded TCP segment.
#[derive(Debug, PartialEq, Eq)]
pub struct Segment<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

/// The result of decoding one captured frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Decoded<'a> {
    /// A TCP segment with a complete 20-byte header.
    Tcp(Segment<'a>, LinkInfo),
    /// A frame that the link layer hands on as IP, but that is not processed as TCP:
    /// not IP after all, not TCP, a fragment, malformed or truncated (SPEC.md 12).
    UnprocessedIp,
    /// The link layer does not carry IP.
    Other,
}

/// Is this link type supported? (SPEC.md 4.1)
pub fn supported(linktype: i32) -> bool {
    matches!(
        linktype,
        dlt::NULL
            | dlt::EN10MB
            | dlt::IEEE802
            | dlt::PPP
            | dlt::RAW_12
            | dlt::RAW_14
            | dlt::PPP_ETHER
            | dlt::RAW
            | dlt::LOOP
            | dlt::LINUX_SLL
    )
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn be32(b: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

pub fn decode(linktype: i32, frame: &[u8]) -> Decoded<'_> {
    let Some((ip, link)) = strip_link(linktype, frame) else {
        return Decoded::Other;
    };
    match ip_tcp(ip) {
        Some((src, dst, tcp)) => decode_tcp(src, dst, tcp, link),
        None => Decoded::UnprocessedIp,
    }
}

/// Does the link layer hand this frame on as IP? Such frames go to `-w` when they
/// are not processed (SPEC.md 12).
pub fn carries_ip(linktype: i32, frame: &[u8]) -> bool {
    strip_link(linktype, frame).is_some()
}

/// The flow addresses of a TCP packet, for `-K`: only the ports are needed from the
/// TCP header, so a capture with a short snaplen still works (SPEC.md 11).
pub struct Ports {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub sport: u16,
    pub dport: u16,
    pub link: LinkInfo,
}

pub fn decode_ports(linktype: i32, frame: &[u8]) -> Option<Ports> {
    let (ip, link) = strip_link(linktype, frame)?;
    match ip_tcp(ip) {
        Some((src, dst, tcp)) if tcp.len() >= 4 => Some(Ports {
            src,
            dst,
            sport: be16(tcp, 0),
            dport: be16(tcp, 2),
            link,
        }),
        _ => None,
    }
}

/// Remove the link-layer header. Returns the IP bytes, or `None` if the frame does not
/// carry IP.
fn strip_link(linktype: i32, f: &[u8]) -> Option<(&[u8], LinkInfo)> {
    let mut link = LinkInfo::default();
    let ip = match linktype {
        dlt::EN10MB | dlt::IEEE802 => {
            if f.len() < 14 {
                return None;
            }
            link.mac_dst = Some(f[0..6].try_into().unwrap());
            link.mac_src = Some(f[6..12].try_into().unwrap());
            let mut at = 12;
            let mut ethertype = be16(f, at);
            while matches!(
                ethertype,
                ETHERTYPE_VLAN | ETHERTYPE_8021AD | ETHERTYPE_QINQ
            ) {
                if f.len() < at + 6 {
                    return None;
                }
                if link.vlan.is_none() {
                    link.vlan = Some(be16(f, at + 2) & 0x0fff); // D1
                }
                at += 4;
                ethertype = be16(f, at);
            }
            if !matches!(ethertype, ETHERTYPE_IP | ETHERTYPE_IPV6) {
                return None;
            }
            &f[at + 2..]
        }
        dlt::NULL => {
            let family: [u8; 4] = f.get(0..4)?.try_into().unwrap();
            let host = u32::from_ne_bytes(family);
            let swapped = host.swap_bytes();
            // AF_INET is 2 everywhere; AF_INET6 is 10, 24, 28 or 30 (D10).
            let known = |v: u32| matches!(v, 2 | 10 | 24 | 28 | 30);
            if !known(host) && !known(swapped) {
                return None;
            }
            &f[4..]
        }
        dlt::LOOP | dlt::PPP => f.get(4..)?,
        dlt::PPP_ETHER => f.get(8..)?,
        dlt::RAW_12 | dlt::RAW_14 | dlt::RAW => f,
        dlt::LINUX_SLL => {
            if f.len() < 16 {
                return None;
            }
            let mut at = 16;
            if be16(f, 14) == ETHERTYPE_MPLS {
                // skip MPLS labels up to the one with the bottom-of-stack bit
                loop {
                    let label = f.get(at..at + 4)?;
                    at += 4;
                    if label[2] & 1 == 1 {
                        break;
                    }
                }
            }
            &f[at..]
        }
        _ => return None,
    };
    Some((ip, link))
}

/// Source, destination and the TCP bytes (header and data).
type IpTcp<'a> = (IpAddr, IpAddr, &'a [u8]);

/// Find the TCP bytes in an IPv4 or IPv6 packet, selected by the version nibble
/// (SPEC.md 4.2, 4.3). `None` if the packet is not processed as TCP.
fn ip_tcp(ip: &[u8]) -> Option<IpTcp<'_>> {
    if ip.len() < 20 {
        return None;
    }
    match ip[0] >> 4 {
        4 => ip4_tcp(ip),
        6 => ip6_tcp(ip),
        _ => None,
    }
}

fn ip4_tcp(ip: &[u8]) -> Option<IpTcp<'_>> {
    if ip[9] != IPPROTO_TCP || be16(ip, 6) & 0x1fff != 0 {
        return None;
    }
    let mut ip_len = be16(ip, 2) as usize;
    if ip_len == 0 {
        ip_len = ip.len(); // TCP segmentation offload on the capturing host
    }
    let header_len = (ip[0] & 0x0f) as usize * 4;
    if header_len < 20 || header_len > ip_len || header_len > ip.len() {
        return None;
    }
    let end = ip_len.min(ip.len());
    let src = IpAddr::V4(Ipv4Addr::from(be32(ip, 12)));
    let dst = IpAddr::V4(Ipv4Addr::from(be32(ip, 16)));
    Some((src, dst, &ip[header_len..end]))
}

fn ip6_tcp(ip: &[u8]) -> Option<IpTcp<'_>> {
    if ip.len() < 40 {
        return None;
    }
    let mut payload_len = be16(ip, 4) as usize;
    if payload_len == 0 {
        payload_len = ip.len() - 40; // TSO or a jumbogram
    }
    let end = (40 + payload_len).min(ip.len());
    let start = ip6_skip_extensions(&ip[..end], ip[6], 40)?;
    let src: [u8; 16] = ip[8..24].try_into().unwrap();
    let dst: [u8; 16] = ip[24..40].try_into().unwrap();
    Some((
        IpAddr::V6(Ipv6Addr::from(src)),
        IpAddr::V6(Ipv6Addr::from(dst)),
        &ip[start..end],
    ))
}

/// Follow the extension headers from `next` at `at` to TCP; returns where TCP
/// starts (SPEC.md 4.3).
fn ip6_skip_extensions(ip: &[u8], mut next: u8, mut at: usize) -> Option<usize> {
    loop {
        let len = match next {
            IPPROTO_TCP => return Some(at),
            IP6_HOPOPTS | IP6_ROUTING | IP6_DSTOPTS => (*ip.get(at + 1)? as usize + 1) * 8,
            IP6_AH => (*ip.get(at + 1)? as usize + 2) * 4,
            IP6_FRAGMENT => {
                if ip.len() < at + 8 || be16(ip, at + 2) & 0xfff8 != 0 {
                    return None; // not the first fragment
                }
                8
            }
            _ => return None, // ESP, no next header, or not TCP
        };
        if ip.len() < at + len {
            return None;
        }
        next = ip[at];
        at += len;
    }
}

fn decode_tcp<'a>(src: IpAddr, dst: IpAddr, tcp: &'a [u8], link: LinkInfo) -> Decoded<'a> {
    if tcp.len() < 20 {
        return Decoded::UnprocessedIp;
    }
    let header_len = (tcp[12] >> 4) as usize * 4;
    let payload = tcp.get(header_len..).unwrap_or(&[]);
    Decoded::Tcp(
        Segment {
            src,
            dst,
            sport: be16(tcp, 0),
            dport: be16(tcp, 2),
            seq: be32(tcp, 4),
            flags: tcp[13],
            payload,
        },
        link,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(flags: u8, seq: u32, payload: &[u8]) -> Vec<u8> {
        let mut t = vec![0u8; 20];
        t[0..2].copy_from_slice(&40000u16.to_be_bytes());
        t[2..4].copy_from_slice(&80u16.to_be_bytes());
        t[4..8].copy_from_slice(&seq.to_be_bytes());
        t[12] = 5 << 4;
        t[13] = flags;
        t.extend_from_slice(payload);
        t
    }

    fn ip4(tcp: &[u8], ip_len: Option<u16>) -> Vec<u8> {
        let mut ip = vec![0u8; 20];
        ip[0] = 0x45;
        let len = ip_len.unwrap_or(20 + tcp.len() as u16);
        ip[2..4].copy_from_slice(&len.to_be_bytes());
        ip[9] = IPPROTO_TCP;
        ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
        ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
        ip.extend_from_slice(tcp);
        ip
    }

    fn ether(ethertype: &[u8], body: &[u8]) -> Vec<u8> {
        let mut f = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        f.extend_from_slice(ethertype);
        f.extend_from_slice(body);
        f
    }

    fn segment(d: Decoded<'_>) -> (Segment<'_>, LinkInfo) {
        match d {
            Decoded::Tcp(s, l) => (s, l),
            other => panic!("expected TCP, got {other:?}"),
        }
    }

    #[test]
    fn ethernet_ipv4_tcp() {
        let f = ether(&[0x08, 0x00], &ip4(&tcp(TH_ACK, 7, b"hello"), None));
        let (s, l) = segment(decode(dlt::EN10MB, &f));
        assert_eq!(s.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!((s.sport, s.dport, s.seq, s.flags), (40000, 80, 7, TH_ACK));
        assert_eq!(s.payload, b"hello");
        assert_eq!(l.mac_dst, Some([1, 2, 3, 4, 5, 6]));
        assert_eq!(l.mac_src, Some([7, 8, 9, 10, 11, 12]));
        assert_eq!(l.vlan, None);
    }

    #[test]
    fn ethernet_padding_is_not_payload() {
        let mut body = ip4(&tcp(TH_ACK, 1, b""), None);
        body.extend_from_slice(&[0xee; 6]);
        let f = ether(&[0x08, 0x00], &body);
        let (s, _) = segment(decode(dlt::EN10MB, &f));
        assert!(s.payload.is_empty());
    }

    #[test]
    fn vlan_id_without_priority_bits() {
        // TCI 0xa02a: priority 5, VLAN 42 (D1)
        let body = [&[0xa0, 0x2a, 0x08, 0x00][..], &ip4(&tcp(0, 0, b"x"), None)].concat();
        let f = ether(&[0x81, 0x00], &body);
        let (_, l) = segment(decode(dlt::EN10MB, &f));
        assert_eq!(l.vlan, Some(42));
    }

    #[test]
    fn tso_ip_len_zero_uses_captured_length() {
        let f = ip4(&tcp(TH_ACK, 1, &[b'A'; 100]), Some(0));
        let (s, _) = segment(decode(dlt::RAW, &f));
        assert_eq!(s.payload.len(), 100);
    }

    #[test]
    fn ip_len_is_clamped_to_capture() {
        let f = ip4(&tcp(TH_ACK, 1, &[b'A'; 100]), Some(1500));
        let (s, _) = segment(decode(dlt::RAW, &f));
        assert_eq!(s.payload.len(), 100);
    }

    #[test]
    fn fragments_and_non_tcp_are_unprocessed() {
        let mut frag = ip4(&tcp(0, 0, b"x"), None);
        frag[7] = 5; // fragment offset 5
        assert_eq!(decode(dlt::RAW, &frag), Decoded::UnprocessedIp);
        let mut udp = ip4(&tcp(0, 0, b"x"), None);
        udp[9] = 17;
        assert_eq!(decode(dlt::RAW, &udp), Decoded::UnprocessedIp);
    }

    #[test]
    fn short_tcp_header_is_unprocessed() {
        let f = ip4(&[0x9c, 0x40], None);
        assert_eq!(decode(dlt::RAW, &f), Decoded::UnprocessedIp);
        assert!(decode_ports(dlt::RAW, &f).is_none());
        let f = ip4(&[0x9c, 0x40, 0x00, 0x50, 0x00, 0x00], None);
        let p = decode_ports(dlt::RAW, &f).unwrap();
        assert_eq!((p.sport, p.dport), (40000, 80));
    }

    #[test]
    fn bad_header_lengths_are_unprocessed() {
        let mut f = ip4(&tcp(0, 0, b"x"), None);
        f[0] = 0x43; // IHL 3
        assert_eq!(decode(dlt::RAW, &f), Decoded::UnprocessedIp);
        let mut f = ip4(&tcp(0, 0, b"x"), None);
        f[0] = 0x4f; // IHL 15 > ip_len
        f[2..4].copy_from_slice(&40u16.to_be_bytes());
        assert_eq!(decode(dlt::RAW, &f), Decoded::UnprocessedIp);
    }

    #[test]
    fn frames_handed_on_as_ip_are_unprocessed_even_if_not_ip() {
        assert_eq!(decode(dlt::RAW, &[0x45; 10]), Decoded::UnprocessedIp);
        assert_eq!(decode(dlt::RAW, &[0x75; 40]), Decoded::UnprocessedIp);
        let mut arp = vec![0u8; 42];
        arp[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
        assert_eq!(decode(dlt::EN10MB, &arp), Decoded::Other);
        assert!(!carries_ip(dlt::EN10MB, &arp));
    }

    #[test]
    fn tcp_data_offset_beyond_segment_means_no_data() {
        let mut t = tcp(TH_ACK, 1, b"abcd");
        t[12] = 15 << 4;
        let f = ip4(&t, None);
        let (s, _) = segment(decode(dlt::RAW, &f));
        assert!(s.payload.is_empty());
    }

    #[test]
    fn null_family_in_either_byte_order() {
        let body = ip4(&tcp(0, 0, b"x"), None);
        for hdr in [2u32.to_le_bytes(), 2u32.to_be_bytes(), 30u32.to_be_bytes()] {
            let f = [&hdr[..], &body[..]].concat();
            assert!(matches!(decode(dlt::NULL, &f), Decoded::Tcp(..)));
        }
        let f = [&7u32.to_le_bytes()[..], &body[..]].concat();
        assert_eq!(decode(dlt::NULL, &f), Decoded::Other);
    }

    #[test]
    fn ipv6_tcp() {
        let t = tcp(TH_SYN, 99, b"");
        let mut ip = vec![0u8; 40];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&(t.len() as u16).to_be_bytes());
        ip[6] = IPPROTO_TCP;
        ip[23] = 1;
        ip[39] = 2;
        ip.extend_from_slice(&t);
        let (s, _) = segment(decode(dlt::RAW, &ip));
        assert_eq!(s.src, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(s.dst, "::2".parse::<IpAddr>().unwrap());
        assert_eq!(s.seq, 99);
    }

    /// IPv6 to ::2 from ::1 with `ext` (extension headers, from `next`) before TCP.
    fn ip6(next: u8, ext: &[u8], tcp: &[u8]) -> Vec<u8> {
        let mut ip = vec![0u8; 40];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&((ext.len() + tcp.len()) as u16).to_be_bytes());
        ip[6] = next;
        ip[23] = 1;
        ip[39] = 2;
        ip.extend_from_slice(ext);
        ip.extend_from_slice(tcp);
        ip
    }

    /// One extension header: `next`, the length byte, then zeros up to `size` bytes.
    fn ext(next: u8, len: u8, size: usize) -> Vec<u8> {
        let mut h = vec![0u8; size];
        h[0] = next;
        h[1] = len;
        h
    }

    fn payload(d: Decoded<'_>) -> Vec<u8> {
        segment(d).0.payload.to_vec()
    }

    #[test]
    fn ipv6_extension_headers_are_followed() {
        let t = tcp(TH_ACK, 7, b"data");
        let hop = ext(IP6_ROUTING, 0, 8);
        let routing = ext(IP6_DSTOPTS, 2, 24);
        let dst = ext(IP6_AH, 1, 16);
        let ah = ext(IPPROTO_TCP, 2, 16);
        let chain = [hop, routing, dst, ah].concat();
        assert_eq!(
            payload(decode(dlt::RAW, &ip6(IP6_HOPOPTS, &chain, &t))),
            b"data"
        );
        let p = decode_ports(dlt::RAW, &ip6(IP6_HOPOPTS, &chain, &t)).unwrap();
        assert_eq!((p.sport, p.dport), (40000, 80));
    }

    #[test]
    fn ipv6_fragments() {
        let t = tcp(TH_ACK, 7, b"data");
        let frag = |offset_and_flags: u16| {
            let mut h = ext(IPPROTO_TCP, 0, 8);
            h[2..4].copy_from_slice(&offset_and_flags.to_be_bytes());
            h
        };
        // the first fragment (more fragments follow) and an atomic fragment
        for first in [0x0001, 0x0000] {
            let f = ip6(IP6_FRAGMENT, &frag(first), &t);
            assert_eq!(payload(decode(dlt::RAW, &f)), b"data");
        }
        let later = ip6(IP6_FRAGMENT, &frag(185 << 3), &t);
        assert_eq!(decode(dlt::RAW, &later), Decoded::UnprocessedIp);
    }

    #[test]
    fn ipv6_without_tcp_is_unprocessed() {
        let t = tcp(TH_ACK, 7, b"data");
        for (next, chain) in [
            (50, vec![0u8; 8]),           // ESP
            (59, vec![]),                 // no next header
            (IP6_DSTOPTS, ext(17, 0, 8)), // UDP after an option header
            (IP6_DSTOPTS, ext(59, 0, 8)),
        ] {
            let f = ip6(next, &chain, &t);
            assert_eq!(decode(dlt::RAW, &f), Decoded::UnprocessedIp, "{next}");
        }
    }

    #[test]
    fn truncated_ipv6_extension_header_is_unprocessed() {
        // the header claims 24 bytes, but the payload ends after 16
        let f = ip6(IP6_DSTOPTS, &ext(IPPROTO_TCP, 2, 16), &[]);
        assert_eq!(decode(dlt::RAW, &f), Decoded::UnprocessedIp);
        // the header fits the capture but not the payload length
        let mut f = ip6(IP6_DSTOPTS, &ext(IPPROTO_TCP, 2, 24), &tcp(TH_ACK, 7, b""));
        f[4..6].copy_from_slice(&16u16.to_be_bytes());
        assert_eq!(decode(dlt::RAW, &f), Decoded::UnprocessedIp);
        // only the first byte of the header is captured
        let mut f = ip6(IP6_HOPOPTS, &[IPPROTO_TCP], &[]);
        f[4..6].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(decode(dlt::RAW, &f), Decoded::UnprocessedIp);
    }

    #[test]
    fn sll_with_mpls() {
        let mut f = vec![0u8; 16];
        f[14..16].copy_from_slice(&ETHERTYPE_MPLS.to_be_bytes());
        f.extend_from_slice(&[0, 0, 0, 0]); // label, not bottom of stack
        f.extend_from_slice(&[0, 0, 1, 0]); // bottom of stack
        f.extend_from_slice(&ip4(&tcp(0, 0, b"x"), None));
        assert!(matches!(decode(dlt::LINUX_SLL, &f), Decoded::Tcp(..)));
    }
}
