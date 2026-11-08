//! Every parser over truncated and garbled versions of real-looking lines:
//! none of them may panic. The lines come from untrusted senders, so a panic
//! here is a remote crash. The fuzz targets in `fuzz/` explore further; this
//! runs on stable with `cargo test`.

use std::panic::{AssertUnwindSafe, catch_unwind};
use usiem::event::{Origin, RawEvent, Timestamp};
use usiem::ingest::parser::result::ParseResult;
use usiem_parsers::{linux, network, windows};

type Parse = fn(RawEvent) -> ParseResult;

const PARSERS: &[Parse] = &[
    linux::parse_sshd,
    linux::parse_sudo,
    linux::parse_netfilter,
    network::parse_filterlog,
    network::parse_dnsmasq,
    windows::parse_windows_json,
];

/// Program names the parsers look for, plus none at all.
const PROGRAMS: &[Option<&str>] = &[
    Some("sshd"),
    Some("sudo"),
    Some("kernel"),
    Some("filterlog"),
    Some("dnsmasq"),
    None,
];

const LINES: &[&str] = &[
    "Accepted publickey for bob from 192.0.2.4 port 51234 ssh2: ED25519 SHA256:abc",
    "Failed password for invalid user admin from 2001:db8::7 port 22 ssh2",
    "Invalid user oracle from 198.51.100.2 port 40112",
    "error: maximum authentication attempts exceeded for root from 198.51.100.2 port 22 ssh2 [preauth]",
    "     bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update ; echo",
    "bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/ls",
    "pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob",
    "[ 8123.456789] [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 SRC=203.0.113.9 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=0 DF PROTO=TCP SPT=51234 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0",
    "nft-accept: IN=br0 OUT=wan0 SRC=10.0.0.5 DST=1.1.1.1 LEN=84 PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1",
    "5,,,1000000103,igb1,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.9,192.168.1.10,51234,22,0,S,1234567,,64240,,mss;sackOK;TS;nop;wscale",
    "9,,,1000000105,igb0,match,block,in,6,0x00,0x00000,57,tcp,6,40,2001:db8::9,2001:db8:1::10,51515,443,0,S,99,,65535,,mss",
    "4,,,1000000103,igb1,match,block,in,4,0x0,,52,1234,0,none,1,icmp,84,198.51.100.3,192.168.1.1,request,4321,1",
    "query[AAAA] Example.COM from 192.168.1.20",
    "forwarded example.com to 1.1.1.1",
    "reply www.example.com is <CNAME>",
    "cached nope.example is NODATA-IPv6",
    "gravity blocked ads.example.net is 0.0.0.0",
    "1234 192.168.1.20/53124 query[A] example.com from 192.168.1.20",
    "Jan  5 10:00:00 dnsmasq[812]: query[A] example.com from 192.168.1.20",
    "3164425723 DHCPDISCOVER(eth0) aa:bb:cc:dd:ee:0f no address available",
    "DHCPACK(eth0) 192.168.1.50 aa:bb:cc:dd:ee:0f laptop",
    r#"{"EventTime":"2026-11-05 10:00:00 +0100","Hostname":"DESKTOP-1","Keywords":"9227830359843504128","EventType":"AUDIT_FAILURE","Severity":"ERROR","EventID":4625,"SourceName":"Microsoft-Windows-Security-Auditing","RecordNumber":123456,"Channel":"Security","TargetUserName":"admin","TargetDomainName":"DESKTOP-1","LogonType":"3","WorkstationName":"KALI","IpAddress":"::ffff:192.168.1.66","IpPort":"4242"}"#,
    r#"{"EventID":4732,"Channel":"Security","MemberName":"-","TargetUserName":"Administrators","SubjectUserName":"alice","SubjectDomainName":"HOME"}"#,
    r#"{"EventID":4688,"Channel":"Security","NewProcessId":"0x1a2b","NewProcessName":"C:\\Windows\\System32\\cmd.exe","ProcessId":"0x10","ParentProcessName":"C:\\Windows\\explorer.exe","CommandLine":"cmd.exe /c whoami"}"#,
    r#"{"EventID":3,"Channel":"Microsoft-Windows-Sysmon/Operational","UtcTime":"2026-11-05 10:00:00.123","ProcessId":4242,"Image":"C:\\x.exe","User":"PC\\bob","Protocol":"tcp","SourceIp":"10.0.0.5","SourcePort":50000,"DestinationIp":"2001:db8::1","DestinationPort":443,"DestinationHostname":"example.com"}"#,
    r#"{"ProviderName":"Service Control Manager","EventID":7045,"Level":4,"TimeCreated":"2026-11-05T10:00:00+00:00","EventRecordID":99,"Channel":"System","Computer":"PC","Keywords":"0x8080000000000000","StringInserts":["Evil","C:\\evil.exe"],"EventData":{"ServiceName":"Evil","Nested":{"a":[1,2,{"b":null}]}}}"#,
];

/// Windows records whose members have types or shapes a shipper might send
/// by mistake, or an attacker on purpose.
const ODD_JSON: &[&str] = &[
    r#"{"EventID":"0x1250","Channel":"Security"}"#,
    r#"{"EventID":"0x","Channel":"Security"}"#,
    r#"{"EventID":"-0x8000000000000000","Channel":"Security"}"#,
    r#"{"EventID":"0xFFFFFFFFFFFFFFFFFFFF","Channel":"Security"}"#,
    r#"{"EventID":4624.5,"Channel":"Security"}"#,
    r#"{"EventID":-1,"Channel":"Security"}"#,
    r#"{"EventID":18446744073709551615,"Channel":"Security"}"#,
    r#"{"EventID":1e400,"Channel":"Security"}"#,
    r##"{"EventID":{"#text":"4624"},"Channel":"Security"}"##,
    r#"{"EventID":[4624],"Channel":"Security"}"#,
    r#"{"EventID":4624,"Channel":4624}"#,
    r#"{"EventID":4624,"Channel":null}"#,
    r#"{"EventID":4624,"Channel":"Security","Keywords":-1}"#,
    r#"{"EventID":4624,"Channel":"Security","Keywords":["Audit Success"]}"#,
    r#"{"EventID":4624,"Channel":"Security","Keywords":"0xZZ"}"#,
    r#"{"EventID":4624,"Channel":"Security","Keywords":1e300}"#,
    r#"{"EventID":4624,"Channel":"Security","EventType":7}"#,
    r#"{"EventID":4624,"Channel":"Security","Level":-9223372036854775808}"#,
    r#"{"EventID":4624,"Channel":"Security","Level":1.5,"Severity":null}"#,
    r#"{"EventID":4624,"Channel":"Security","EventTime":12345,"TimeCreated":{}}"#,
    r#"{"EventID":4624,"Channel":"Security","EventTime":"9999-12-31 23:59:59 +2359"}"#,
    r#"{"EventID":4624,"Channel":"Security","EventTime":"0000-01-01T00:00:00Z"}"#,
    r#"{"EventID":4624,"Channel":"Security","EventTime":"2026-02-30 25:61:61 +9999"}"#,
    r#"{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","UtcTime":"-9999-01-01 00:00:00"}"#,
    r#"{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","UtcTime":"2026-11-05 10:00:00.1234567891234"}"#,
    r#"{"EventID":4624,"Channel":"Security","IpPort":"99999999999999999999","IpAddress":12}"#,
    r#"{"EventID":3,"Channel":"Microsoft-Windows-Sysmon/Operational","SourcePort":-1,"DestinationPort":70000,"Protocol":6}"#,
    r#"{"EventID":4624,"Channel":"Security","TargetUserName":["a"],"SubjectUserName":{"x":1}}"#,
    r#"{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","User":"\\","Image":"\\","ParentImage":"/"}"#,
    r#"{"EventID":4624,"Channel":"Security","EventData":[1,2,3],"StringInserts":{"a":1}}"#,
    r#"{"EventID":4624,"Channel":"Security","EventData":{"":"","IpAddress":"::ffff:"}}"#,
    r#"{"EventID":4624,"Channel":"Security","EventID":"twice","Channel":"Sécurité ✓"}"#,
    r#"{"EventID":4624,"Channel":"\u0000\ud83d\ude00---"}"#,
];

fn raw(text: &str, program: Option<&str>) -> RawEvent {
    let mut raw = RawEvent::new(
        text.to_string(),
        Timestamp::from_secs(1),
        Origin::from_hostname("h"),
    );
    if let Some(p) = program {
        raw.insert_field("transport.syslog.process", p.to_string());
    }
    raw
}

fn run_all(text: &str) {
    for program in PROGRAMS {
        for parse in PARSERS {
            let result = catch_unwind(AssertUnwindSafe(|| parse(raw(text, *program))));
            assert!(result.is_ok(), "panicked on {text:?} (program {program:?})");
        }
    }
}

/// Truncations at every byte (lossily decoded), plus single-character
/// edits at every position and a few whole-line rewrites.
fn variants(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    for i in 0..=bytes.len() {
        out.push(String::from_utf8_lossy(&bytes[..i]).into_owned());
        out.push(String::from_utf8_lossy(&bytes[i..]).into_owned());
    }
    let chars: Vec<char> = line.chars().collect();
    for i in 0..=chars.len() {
        let head: String = chars[..i].iter().collect();
        let tail: String = chars[i..].iter().collect();
        for insert in [
            "é",
            "€",
            "\u{1F600}",
            "\0",
            " ",
            "=",
            ",",
            "\"",
            "\\",
            "[",
            "]",
            "9",
        ] {
            out.push(format!("{head}{insert}{tail}"));
        }
        if i < chars.len() {
            let rest: String = chars[i + 1..].iter().collect();
            out.push(format!("{head}{rest}"));
            out.push(format!("{head}\u{FFFD}{rest}"));
        }
    }
    out.push(line.repeat(3));
    out.push(line.replace(' ', "  "));
    out.push(line.replace(',', ",,"));
    out.push(line.replace(char::is_numeric, "9"));
    out.push(line.replace(char::is_numeric, "99999999999999999999"));
    out.push(line.to_uppercase());
    out.push(line.to_lowercase());
    out
}

#[test]
fn sample_lines_parse() {
    // The unmodified lines must match something, or the garbled ones test
    // nothing.
    for line in LINES {
        let matched = PROGRAMS.iter().any(|program| {
            PARSERS
                .iter()
                .any(|parse| matches!(parse(raw(line, *program)), ParseResult::Success(_)))
        });
        assert!(matched, "no parser matches {line:?}");
    }
}

#[test]
fn garbled_lines_do_not_panic() {
    for line in LINES {
        for variant in variants(line) {
            run_all(&variant);
        }
    }
}

#[test]
fn odd_windows_json_does_not_panic() {
    for line in ODD_JSON {
        run_all(line);
    }
    // Past serde_json's recursion limit.
    let deep = format!(
        r#"{{"EventID":1,"Channel":"Security","x":{}{}}}"#,
        "[".repeat(10_000),
        "]".repeat(10_000)
    );
    run_all(&deep);
}

#[test]
fn long_lines_do_not_panic() {
    let long = "a".repeat(1 << 20);
    run_all(&long);
    run_all(&format!("IN={long} SRC=10.0.0.5 DST=10.0.0.6"));
    run_all(&format!("Failed password for {long} from 10.0.0.5 port 22"));
    run_all(&",".repeat(1 << 16));
    run_all(&format!("dnsmasq[1]: reply {long} is {long}"));
}
