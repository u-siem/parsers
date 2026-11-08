//! Arbitrary bytes as the members of a Windows event record: the input is
//! spliced into an object that already has an `EventID` and a `Channel`, so
//! most inputs get past the cheap pre-checks and reach the field mapping.

#![no_main]

use libfuzzer_sys::fuzz_target;
use usiem::event::{Origin, RawEvent, Timestamp};
use usiem_parsers::windows::parse_windows_json;

const HEADS: &[&str] = &[
    r#"{"EventID":4624,"Channel":"Security","#,
    r#"{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","#,
    r#"{"EventID":7045,"Channel":"System","#,
    r#"{"#,
];

fuzz_target!(|data: &[u8]| {
    let Some((&first, body)) = data.split_first() else {
        return;
    };
    let head = HEADS[usize::from(first) % HEADS.len()];
    let text = format!("{head}{}", String::from_utf8_lossy(body));
    let raw = RawEvent::new(text, Timestamp::from_secs(1), Origin::from_hostname("h"));
    let _ = parse_windows_json(raw);
});
