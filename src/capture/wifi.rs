//! 802.11 data frames, bare or behind a radiotap or Prism header (SPEC.md 4.1.1).

const RADIOTAP_TSFT: u32 = 1 << 0;
const RADIOTAP_FLAGS: u32 = 1 << 1;
const RADIOTAP_EXT: u32 = 1 << 31;
const F_FCS: u8 = 0x10;
const F_DATAPAD: u8 = 0x20;
const F_BADFCS: u8 = 0x40;
const PRISM_HEADER_LEN: usize = 144;

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// What the capture header says about the frame.
#[derive(Default)]
struct Radio {
    /// `Some(true)`: the frame ends in an FCS; `None`: not known.
    fcs: Option<bool>,
    pad: bool,
}

/// A radiotap header: its length and the flags field, if present.
fn radiotap(f: &[u8]) -> Option<(usize, Radio)> {
    if f.len() < 8 || f[0] != 0 {
        return None;
    }
    let len = le16(f, 2) as usize;
    if f.len() < len {
        return None;
    }
    let first = le32(f, 4);
    let mut at = 4;
    loop {
        if at + 4 > len {
            return None;
        }
        let present = le32(f, at);
        at += 4;
        if present & RADIOTAP_EXT == 0 {
            break;
        }
    }
    let mut radio = Radio::default();
    if first & RADIOTAP_FLAGS != 0 {
        if first & RADIOTAP_TSFT != 0 {
            at = at.next_multiple_of(8) + 8;
        }
        let flags = *f[..len].get(at)?;
        if flags & F_BADFCS != 0 {
            return None;
        }
        radio.fcs = Some(flags & F_FCS != 0);
        radio.pad = flags & F_DATAPAD != 0;
    }
    Some((len, radio))
}

/// Does the frame end in a valid FCS (CRC-32 of the rest, little-endian)?
fn has_fcs(f: &[u8]) -> bool {
    let Some(n) = f.len().checked_sub(4) else {
        return false;
    };
    let mut crc = flate2::Crc::new();
    crc.update(&f[..n]);
    crc.sum() == le32(f, n)
}

/// The IP packet in a capture of link type `linktype` (105, 119 or 127), or `None`
/// if the frame carries no IP.
pub fn strip(linktype: i32, f: &[u8]) -> Option<&[u8]> {
    let (frame, radio) = match linktype {
        crate::capture::decode::dlt::IEEE802_11_RADIO => {
            let (len, radio) = radiotap(f)?;
            (&f[len..], radio)
        }
        crate::capture::decode::dlt::PRISM_HEADER => (f.get(PRISM_HEADER_LEN..)?, Radio::default()),
        _ => (f, Radio::default()),
    };
    let frame = match radio.fcs {
        Some(true) if !has_fcs(frame) => return None,
        Some(true) => &frame[..frame.len() - 4],
        None if has_fcs(frame) => &frame[..frame.len() - 4],
        _ => frame,
    };
    data(frame, radio.pad)
}

/// The IP packet in an 802.11 data frame with LLC/SNAP.
fn data(f: &[u8], pad: bool) -> Option<&[u8]> {
    if f.len() < 24 {
        return None;
    }
    let (fc, flags) = (f[0], f[1]);
    let (version, kind, subtype) = (fc & 3, (fc >> 2) & 3, fc >> 4);
    // data frames only; subtypes with bit 2 set carry no data (Null, QoS Null, ...)
    if version != 0 || kind != 2 || subtype & 4 != 0 {
        return None;
    }
    if flags & 0x40 != 0 {
        return None; // protected: encrypted
    }
    let mut hdr = 24;
    if flags & 3 == 3 {
        hdr += 6; // to and from DS: a fourth address
    }
    if subtype & 8 != 0 {
        // QoS control; an A-MSDU holds subframes, not one packet
        if *f.get(hdr)? & 0x80 != 0 {
            return None;
        }
        hdr += 2;
        if flags & 0x80 != 0 {
            hdr += 4; // HT control
        }
    }
    if pad {
        hdr = hdr.next_multiple_of(4);
    }
    let llc = f.get(hdr..hdr + 8)?;
    if llc[..3] != [0xaa, 0xaa, 0x03] || !matches!(llc[3..6], [0, 0, 0] | [0, 0, 0xf8]) {
        return None;
    }
    if !matches!(u16::from_be_bytes([llc[6], llc[7]]), 0x0800 | 0x86dd) {
        return None;
    }
    Some(&f[hdr + 8..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::decode::dlt;

    const IP: &[u8] = &[0x45, 1, 2, 3];

    /// An 802.11 data frame of `subtype` with DS `flags`, `extra` header bytes and IP.
    fn frame(subtype: u8, flags: u8, extra: &[u8]) -> Vec<u8> {
        let mut f = vec![subtype << 4 | 0x08, flags];
        f.extend_from_slice(&[0; 22]);
        f.extend_from_slice(extra);
        f.extend_from_slice(&[0xaa, 0xaa, 0x03, 0, 0, 0, 0x08, 0x00]);
        f.extend_from_slice(IP);
        f
    }

    fn with_fcs(mut f: Vec<u8>) -> Vec<u8> {
        let mut crc = flate2::Crc::new();
        crc.update(&f);
        f.extend_from_slice(&crc.sum().to_le_bytes());
        f
    }

    fn radiotap_header(flags: u8) -> Vec<u8> {
        let mut h = vec![0, 0, 18, 0];
        h.extend_from_slice(&(RADIOTAP_TSFT | RADIOTAP_FLAGS).to_le_bytes());
        h.extend_from_slice(&[0; 8]); // TSFT
        h.extend_from_slice(&[flags, 0]); // flags, rate
        h
    }

    #[test]
    fn data_frames_with_and_without_fcs() {
        let f = frame(0, 0, &[]);
        assert_eq!(strip(dlt::IEEE802_11, &f), Some(IP));
        assert_eq!(strip(dlt::IEEE802_11, &with_fcs(f)), Some(IP));
    }

    #[test]
    fn header_lengths() {
        assert_eq!(strip(dlt::IEEE802_11, &frame(0, 3, &[0; 6])), Some(IP));
        assert_eq!(strip(dlt::IEEE802_11, &frame(8, 1, &[0; 2])), Some(IP));
        assert_eq!(strip(dlt::IEEE802_11, &frame(8, 0x83, &[0; 12])), Some(IP));
        // the order bit of a non-QoS frame is no HT control field
        assert_eq!(strip(dlt::IEEE802_11, &frame(0, 0x80, &[])), Some(IP));
    }

    #[test]
    fn frames_without_ip() {
        for f in [
            frame(4, 0, &[]),        // Null
            frame(12, 0, &[0; 2]),   // QoS Null
            frame(8, 0, &[0x80, 0]), // A-MSDU
            frame(0, 0x40, &[]),     // protected
            vec![0x80, 0, 0, 0],     // beacon (management)
        ] {
            assert_eq!(strip(dlt::IEEE802_11, &f), None, "{f:?}");
        }
        let mut arp = frame(0, 0, &[]);
        arp[31] = 0x06;
        assert_eq!(strip(dlt::IEEE802_11, &arp), None);
    }

    #[test]
    fn radiotap_flags() {
        let f = frame(0, 0, &[]);
        let both = |h: Vec<u8>, f: &[u8]| [h, f.to_vec()].concat();
        let fcs = with_fcs(f.clone());
        assert_eq!(
            strip(dlt::IEEE802_11_RADIO, &both(radiotap_header(F_FCS), &fcs)),
            Some(IP)
        );
        assert_eq!(
            strip(dlt::IEEE802_11_RADIO, &both(radiotap_header(0), &f)),
            Some(IP)
        );
        // a frame with a wrong FCS is dropped
        let mut bad = fcs.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(
            strip(dlt::IEEE802_11_RADIO, &both(radiotap_header(F_FCS), &bad)),
            None
        );
        assert_eq!(
            strip(dlt::IEEE802_11_RADIO, &both(radiotap_header(F_BADFCS), &f)),
            None
        );
        // the body of a padded frame starts at a multiple of 4
        let padded = frame(8, 0, &[0, 0, 0, 0]);
        assert_eq!(
            strip(
                dlt::IEEE802_11_RADIO,
                &both(radiotap_header(F_DATAPAD), &padded)
            ),
            Some(IP)
        );
    }

    #[test]
    fn radiotap_without_flags_and_with_extended_bitmaps() {
        let f = frame(0, 0, &[]);
        let mut h = vec![0, 0, 12, 0];
        h.extend_from_slice(&RADIOTAP_EXT.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            strip(dlt::IEEE802_11_RADIO, &[h, with_fcs(f)].concat()),
            Some(IP)
        );
        // a bitmap that claims to go on beyond the header
        let h = [0, 0, 8, 0, 0, 0, 0, 0x80];
        assert_eq!(strip(dlt::IEEE802_11_RADIO, &h), None);
    }

    #[test]
    fn prism() {
        let f = [vec![0; PRISM_HEADER_LEN], frame(0, 0, &[])].concat();
        assert_eq!(strip(dlt::PRISM_HEADER, &f), Some(IP));
        assert_eq!(strip(dlt::PRISM_HEADER, &[0; 100]), None);
    }
}
