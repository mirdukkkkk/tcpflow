//! Packet decoding (SPEC.md 4): the first byte picks the link type, the rest
//! is the frame.
#![no_main]

use libfuzzer_sys::fuzz_target;
use tcpflow::capture::decode::{self, Decoded, dlt};

const LINKTYPES: [i32; 13] = [
    dlt::NULL,
    dlt::EN10MB,
    dlt::IEEE802,
    dlt::PPP,
    dlt::RAW_12,
    dlt::RAW_14,
    dlt::PPP_ETHER,
    dlt::RAW,
    dlt::LOOP,
    dlt::IEEE802_11,
    dlt::LINUX_SLL,
    dlt::PRISM_HEADER,
    dlt::IEEE802_11_RADIO,
];

fuzz_target!(|data: &[u8]| {
    let Some((&pick, frame)) = data.split_first() else {
        return;
    };
    let linktype = LINKTYPES[pick as usize % LINKTYPES.len()];
    if let Decoded::Tcp(seg, _) = decode::decode(linktype, frame) {
        // the payload is part of the frame
        let range = frame.as_ptr_range();
        assert!(range.contains(&seg.payload.as_ptr()) || seg.payload.is_empty());
    }
    let _ = decode::carries_ip(linktype, frame);
    let _ = decode::decode_ports(linktype, frame);
});
