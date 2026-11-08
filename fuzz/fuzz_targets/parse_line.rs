//! Arbitrary bytes as a log line, through every parser: none panics.
//!
//! The first byte picks the syslog program name the transport parser would
//! have set (or none), so the program-gated parsers see the rest; the rest
//! is the message body, decoded lossily as the transport does.

#![no_main]

use libfuzzer_sys::fuzz_target;
use usiem::event::{Origin, RawEvent, Timestamp};
use usiem_parsers::{linux, network, windows};

const PROGRAMS: &[&str] = &[
    "sshd",
    "sshd-session",
    "sudo",
    "kernel",
    "filterlog",
    "dnsmasq",
    "dnsmasq-dhcp",
    "pihole-FTL",
];

fuzz_target!(|data: &[u8]| {
    let Some((&first, body)) = data.split_first() else {
        return;
    };
    let text = String::from_utf8_lossy(body);
    let program = PROGRAMS.get(usize::from(first) % (PROGRAMS.len() + 1));
    let parsers = [
        linux::parse_sshd,
        linux::parse_sudo,
        linux::parse_netfilter,
        network::parse_filterlog,
        network::parse_dnsmasq,
        windows::parse_windows_json,
    ];
    for parse in parsers {
        let mut raw = RawEvent::new(
            text.to_string(),
            Timestamp::from_secs(1),
            Origin::from_hostname("h"),
        );
        if let Some(p) = program {
            raw.insert_field("transport.syslog.process", (*p).to_string());
        }
        let _ = parse(raw);
    }
});
