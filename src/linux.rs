//! Content parsers for common Linux daemons: OpenSSH `sshd`, `sudo`, and
//! netfilter (`iptables`/`nftables`/UFW) `LOG` lines from the kernel.
//!
//! They read the message body (`RawEvent::log_text`) after a syslog
//! transport parser has run. `sshd` and `sudo` first check the syslog
//! program name (`transport.syslog.process` or, for RFC 5424,
//! `transport.syslog.app_name`), so for other programs they cost one string
//! comparison. Netfilter lines are recognised by their `IN=`/`SRC=`/`DST=`
//! keys, whatever the program name.
//!
//! Fields follow ECS where it has a name: `event.category`, `event.action`,
//! `event.outcome`, `user.name`, `source.ip`, ...

use regex::Regex;
use std::net::IpAddr;
use std::sync::LazyLock;
use usiem::event::RawEvent;
use usiem::event::field::{FieldValue, Ip};
use usiem::event::fields as f;
use usiem::ingest::parser::{LogParser, result::ParseResult};

/// `event.dataset` of each parser.
pub const SSHD_DATASET: &str = "linux.sshd";
pub const SUDO_DATASET: &str = "linux.sudo";
pub const NETFILTER_DATASET: &str = "linux.netfilter";

/// The syslog program name, without any `[pid]`.
fn program(raw: &RawEvent) -> Option<&str> {
    let value = raw
        .get_field("transport.syslog.process")
        .or_else(|| raw.get_field("transport.syslog.app_name"))?;
    match value {
        FieldValue::Str(s) => Some(s.as_str()),
        _ => None,
    }
}

fn ip_value(text: &str) -> Option<FieldValue> {
    text.parse::<IpAddr>()
        .ok()
        .map(|ip| FieldValue::Ip(Ip::from(ip)))
}

fn port_value(text: &str) -> Option<FieldValue> {
    text.parse::<u16>().ok().map(|p| FieldValue::Int(p.into()))
}

// ---------------------------------------------------------------- sshd

static SSHD_LOGIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(Accepted|Failed) (\S+) for (invalid user )?(.*?) from (\S+) port (\d+)(?: (ssh\d?))?",
    )
    .expect("sshd login regex")
});
static SSHD_INVALID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[Ii]nvalid user (.*?) from (\S+)(?: port (\d+))?").expect("sshd invalid regex")
});
static SSHD_MAX_TRIES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:error: )?maximum authentication attempts exceeded for (invalid user )?(.*?) from (\S+) port (\d+)",
    )
    .expect("sshd max tries regex")
});

/// OpenSSH logins and failed attempts.
///
/// | message | `event.action` | `event.outcome` |
/// |---|---|---|
/// | `Accepted <method> for <user> from <ip> port <n>` | `ssh_login` | `success` |
/// | `Failed <method> for [invalid user ]<user> from ...` | `ssh_login` | `failure` |
/// | `Invalid user <user> from <ip> [port <n>]` | `ssh_invalid_user` | `failure` |
/// | `maximum authentication attempts exceeded for ...` | `ssh_max_attempts` | `failure` |
///
/// `ssh.method` holds the method (`password`, `publickey`, ...), and
/// `user.invalid` is `true` when sshd says the account does not exist.
pub fn parse_sshd(mut raw: RawEvent) -> ParseResult {
    if program(&raw) != Some("sshd") && program(&raw) != Some("sshd-session") {
        return ParseResult::NoMatch(raw);
    }
    let text = raw.log_text.trim();
    let mut out: Vec<(&'static str, FieldValue)> = Vec::with_capacity(9);
    if let Some(c) = SSHD_LOGIN.captures(text) {
        let accepted = &c[1] == "Accepted";
        let Some(ip) = ip_value(&c[5]) else {
            return ParseResult::NoMatch(raw);
        };
        out.push((f::EVENT_ACTION, "ssh_login".into()));
        out.push((
            f::EVENT_OUTCOME,
            if accepted { "success" } else { "failure" }.into(),
        ));
        out.push((f::SSH_METHOD, c[2].to_string().into()));
        out.push((f::USER_NAME, c[4].to_string().into()));
        out.push((f::SOURCE_IP, ip));
        if let Some(port) = port_value(&c[6]) {
            out.push((f::SOURCE_PORT, port));
        }
        if c.get(3).is_some() {
            out.push((f::USER_INVALID, FieldValue::Bool(true)));
        }
    } else if let Some(c) = SSHD_INVALID.captures(text) {
        let Some(ip) = ip_value(&c[2]) else {
            return ParseResult::NoMatch(raw);
        };
        out.push((f::EVENT_ACTION, "ssh_invalid_user".into()));
        out.push((f::EVENT_OUTCOME, "failure".into()));
        out.push((f::USER_NAME, c[1].to_string().into()));
        out.push((f::USER_INVALID, FieldValue::Bool(true)));
        out.push((f::SOURCE_IP, ip));
        if let Some(port) = c.get(3).and_then(|m| port_value(m.as_str())) {
            out.push((f::SOURCE_PORT, port));
        }
    } else if let Some(c) = SSHD_MAX_TRIES.captures(text) {
        let Some(ip) = ip_value(&c[3]) else {
            return ParseResult::NoMatch(raw);
        };
        out.push((f::EVENT_ACTION, "ssh_max_attempts".into()));
        out.push((f::EVENT_OUTCOME, "failure".into()));
        out.push((f::USER_NAME, c[2].to_string().into()));
        out.push((f::SOURCE_IP, ip));
        if let Some(port) = port_value(&c[4]) {
            out.push((f::SOURCE_PORT, port));
        }
        if c.get(1).is_some() {
            out.push((f::USER_INVALID, FieldValue::Bool(true)));
        }
    } else {
        return ParseResult::NoMatch(raw);
    }
    raw.insert_field(f::EVENT_CATEGORY, "authentication");
    raw.insert_field(f::EVENT_DATASET, SSHD_DATASET);
    for (k, v) in out {
        raw.insert_field(k, v);
    }
    ParseResult::Success(raw.into_event())
}

pub fn sshd_parser() -> LogParser {
    LogParser::new(
        "sshd",
        "OpenSSH sshd",
        "Parses OpenSSH logins, failed attempts and invalid users",
        parse_sshd,
    )
}

// ---------------------------------------------------------------- sudo

static SUDO_PAM_FAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^pam_unix\(sudo(?:-i)?:auth\): authentication failure;.*?\bruser=(\S*).*?\buser=(\S+)",
    )
    .expect("sudo pam regex")
});

/// `sudo` command records and authentication failures.
///
/// | message | `event.action` | `event.outcome` |
/// |---|---|---|
/// | `<user> : TTY=... ; PWD=... ; USER=<target> ; COMMAND=...` | `sudo_command` | `success` |
/// | `<user> : <n> incorrect password attempts ; ...` | `sudo_incorrect_password` | `failure` |
/// | `<user> : user NOT in sudoers ; ...` | `sudo_not_in_sudoers` | `failure` |
/// | `pam_unix(sudo:auth): authentication failure; ... user=<u>` | `sudo_auth_failure` | `failure` |
///
/// Commands fill `user.target.name` (`USER=`), `process.working_directory`
/// (`PWD=`) and `process.command_line` (`COMMAND=`).
pub fn parse_sudo(mut raw: RawEvent) -> ParseResult {
    if program(&raw) != Some("sudo") {
        return ParseResult::NoMatch(raw);
    }
    let text = raw.log_text.trim();
    if let Some(c) = SUDO_PAM_FAIL.captures(text) {
        // `ruser` is who ran sudo; `user` the account being authenticated.
        let who = if c[1].is_empty() { &c[2] } else { &c[1] };
        let who = who.to_string();
        raw.insert_field(f::EVENT_CATEGORY, "authentication");
        raw.insert_field(f::EVENT_ACTION, "sudo_auth_failure");
        raw.insert_field(f::EVENT_OUTCOME, "failure");
        raw.insert_field(f::USER_NAME, who);
        raw.insert_field(f::EVENT_DATASET, SUDO_DATASET);
        return ParseResult::Success(raw.into_event());
    }
    // `<user> : [reason ; ]TTY=... ; PWD=... ; USER=... ; COMMAND=...`
    let Some((user, rest)) = text.split_once(" : ") else {
        return ParseResult::NoMatch(raw);
    };
    let user = user.trim();
    if user.is_empty() || user.contains(' ') {
        return ParseResult::NoMatch(raw);
    }
    let mut reason = None;
    let mut target = None;
    let mut pwd = None;
    // COMMAND= is last and may itself contain " ; ".
    let (head, command) = match rest.find("COMMAND=") {
        Some(i) => (&rest[..i], Some(rest[i + "COMMAND=".len()..].trim())),
        None => (rest, None),
    };
    for part in head.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        match part.split_once('=') {
            Some(("USER", v)) => target = Some(v),
            Some(("PWD", v)) => pwd = Some(v),
            Some((key, _)) if key.chars().all(|c| c.is_ascii_uppercase()) => {}
            _ => reason = reason.or(Some(part)),
        }
    }
    if command.is_none() && target.is_none() {
        return ParseResult::NoMatch(raw);
    }
    let (action, outcome) = match reason {
        None => ("sudo_command", "success"),
        Some(r) if r.contains("incorrect password") => ("sudo_incorrect_password", "failure"),
        Some(r) if r.contains("NOT in sudoers") => ("sudo_not_in_sudoers", "failure"),
        Some(r) if r.contains("not allowed") => ("sudo_not_allowed", "failure"),
        Some(_) => ("sudo_command", "failure"),
    };
    let user = user.to_string();
    let target = target.map(str::to_string);
    let pwd = pwd.map(str::to_string);
    let command = command.map(str::to_string);
    let reason = reason.map(str::to_string);
    raw.insert_field(
        f::EVENT_CATEGORY,
        if outcome == "success" {
            "process"
        } else {
            "authentication"
        },
    );
    raw.insert_field(f::EVENT_ACTION, action);
    raw.insert_field(f::EVENT_OUTCOME, outcome);
    raw.insert_field(f::EVENT_DATASET, SUDO_DATASET);
    raw.insert_field(f::USER_NAME, user);
    if let Some(v) = target {
        raw.insert_field(f::USER_TARGET_NAME, v);
    }
    if let Some(v) = pwd {
        raw.insert_field(f::PROCESS_WORKING_DIRECTORY, v);
    }
    if let Some(v) = command {
        raw.insert_field(f::PROCESS_COMMAND_LINE, v);
    }
    if let Some(v) = reason {
        raw.insert_field(f::EVENT_REASON, v);
    }
    ParseResult::Success(raw.into_event())
}

pub fn sudo_parser() -> LogParser {
    LogParser::new(
        "sudo",
        "sudo",
        "Parses sudo command records and authentication failures",
        parse_sudo,
    )
}

// ---------------------------------------------------------------- netfilter

/// Netfilter `LOG` target lines, as written by iptables, nftables and UFW:
///
/// ```text
/// [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=203.0.113.9 DST=192.168.1.10 LEN=60 ...
///     PROTO=TCP SPT=51234 DPT=22 ...
/// ```
///
/// The text before `IN=` is the log prefix, which the admin chose; it goes
/// to `rule.name`. `event.action` is `blocked` when the prefix says
/// block/drop/reject/deny, `allowed` when it says allow/accept, otherwise
/// `logged`. Keys map to `observer.ingress.interface` (`IN`),
/// `observer.egress.interface` (`OUT`), `source.ip`, `destination.ip`,
/// `network.transport` (lower-case `PROTO`), `source.port` and
/// `destination.port`.
pub fn parse_netfilter(mut raw: RawEvent) -> ParseResult {
    let text = raw.log_text.as_str();
    let Some(at) = text.find("IN=") else {
        return ParseResult::NoMatch(raw);
    };
    if at > 0 && !text[..at].ends_with(' ') {
        return ParseResult::NoMatch(raw);
    }
    let prefix = log_prefix(&text[..at]);
    let mut fields: Vec<(&'static str, FieldValue)> = Vec::with_capacity(10);
    let (mut src, mut dst) = (false, false);
    for token in text[at..].split_ascii_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let (name, value) = match key {
            "IN" if !value.is_empty() => (f::OBSERVER_INGRESS_INTERFACE, value.to_string().into()),
            "OUT" if !value.is_empty() => (f::OBSERVER_EGRESS_INTERFACE, value.to_string().into()),
            "SRC" => match ip_value(value) {
                Some(ip) => {
                    src = true;
                    (f::SOURCE_IP, ip)
                }
                None => continue,
            },
            "DST" => match ip_value(value) {
                Some(ip) => {
                    dst = true;
                    (f::DESTINATION_IP, ip)
                }
                None => continue,
            },
            "PROTO" => (f::NETWORK_TRANSPORT, value.to_ascii_lowercase().into()),
            "SPT" => match port_value(value) {
                Some(p) => (f::SOURCE_PORT, p),
                None => continue,
            },
            "DPT" => match port_value(value) {
                Some(p) => (f::DESTINATION_PORT, p),
                None => continue,
            },
            _ => continue,
        };
        fields.push((name, value));
    }
    if !(src && dst) {
        return ParseResult::NoMatch(raw);
    }
    let action = prefix.as_deref().map_or("logged", prefix_action);
    raw.insert_field(f::EVENT_CATEGORY, "network");
    raw.insert_field(f::EVENT_ACTION, action);
    raw.insert_field(f::EVENT_DATASET, NETFILTER_DATASET);
    if let Some(prefix) = prefix {
        raw.insert_field(f::RULE_NAME, prefix);
    }
    for (k, v) in fields {
        raw.insert_field(k, v);
    }
    ParseResult::Success(raw.into_event())
}

/// The admin's log prefix: what precedes `IN=`, minus a kernel uptime
/// stamp (`[12345.678901]`) and surrounding brackets.
fn log_prefix(head: &str) -> Option<String> {
    let mut head = head.trim();
    if let Some(rest) = head.strip_prefix('[')
        && let Some((stamp, after)) = rest.split_once(']')
        && stamp.trim().parse::<f64>().is_ok()
    {
        head = after.trim();
    }
    let head = head.trim_matches(|c: char| c == '[' || c == ']' || c == ':' || c == ' ');
    (!head.is_empty()).then(|| head.to_string())
}

fn prefix_action(prefix: &str) -> &'static str {
    let lower = prefix.to_ascii_lowercase();
    if ["block", "drop", "reject", "deny"]
        .iter()
        .any(|w| lower.contains(w))
    {
        "blocked"
    } else if ["allow", "accept"].iter().any(|w| lower.contains(w)) {
        "allowed"
    } else {
        "logged"
    }
}

pub fn netfilter_parser() -> LogParser {
    LogParser::new(
        "netfilter",
        "Netfilter LOG",
        "Parses iptables/nftables/UFW LOG lines (IN= OUT= SRC= DST= PROTO= SPT= DPT=)",
        parse_netfilter,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use usiem::event::{CoreEvent, Origin, Timestamp};

    fn raw(program: &str, text: &str) -> RawEvent {
        let mut raw = RawEvent::new(text.into(), Timestamp::now(), Origin::from_hostname("h"));
        raw.insert_field("transport.syslog.process", program.to_string());
        raw
    }

    fn ok(result: ParseResult) -> CoreEvent {
        match result {
            ParseResult::Success(e) => e,
            _ => panic!("no match"),
        }
    }

    fn s(e: &CoreEvent, field: &str) -> String {
        e.get_field(field)
            .map(|v| v.to_string())
            .unwrap_or_else(|| panic!("missing {field}"))
    }

    #[test]
    fn sshd_accepted_and_failed() {
        let e = ok(parse_sshd(raw(
            "sshd",
            "Accepted publickey for bob from 192.0.2.4 port 51234 ssh2: ED25519 SHA256:abc",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "ssh_login");
        assert_eq!(s(&e, f::EVENT_OUTCOME), "success");
        assert_eq!(s(&e, f::SSH_METHOD), "publickey");
        assert_eq!(s(&e, f::USER_NAME), "bob");
        assert_eq!(s(&e, f::SOURCE_IP), "192.0.2.4");
        assert!(matches!(e.get_field(f::SOURCE_IP), Some(FieldValue::Ip(_))));
        assert_eq!(s(&e, f::SOURCE_PORT), "51234");
        assert_eq!(s(&e, f::EVENT_DATASET), SSHD_DATASET);

        let e = ok(parse_sshd(raw(
            "sshd",
            "Failed password for invalid user admin from 2001:db8::7 port 22 ssh2",
        )));
        assert_eq!(s(&e, f::EVENT_OUTCOME), "failure");
        assert_eq!(s(&e, f::USER_NAME), "admin");
        assert_eq!(s(&e, f::USER_INVALID), "true");
        assert_eq!(s(&e, f::SOURCE_IP), "2001:db8::7");

        // A user name with spaces is kept whole.
        let e = ok(parse_sshd(raw(
            "sshd",
            "Failed none for invalid user a b from 192.0.2.4 port 22 ssh2",
        )));
        assert_eq!(s(&e, f::USER_NAME), "a b");
    }

    #[test]
    fn sshd_invalid_user_and_max_attempts() {
        let e = ok(parse_sshd(raw(
            "sshd",
            "Invalid user oracle from 198.51.100.2 port 40112",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "ssh_invalid_user");
        assert_eq!(s(&e, f::USER_NAME), "oracle");
        let e = ok(parse_sshd(raw(
            "sshd",
            "error: maximum authentication attempts exceeded for root from 198.51.100.2 port 22 ssh2 [preauth]",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "ssh_max_attempts");
        assert_eq!(s(&e, f::USER_NAME), "root");
    }

    #[test]
    fn sshd_ignores_other_programs_and_lines() {
        let line = "Accepted password for bob from 192.0.2.4 port 22 ssh2";
        assert!(matches!(
            parse_sshd(raw("su", line)),
            ParseResult::NoMatch(_)
        ));
        assert!(matches!(
            parse_sshd(raw("sshd", "Server listening on 0.0.0.0 port 22.")),
            ParseResult::NoMatch(_)
        ));
        // RFC 5424 carries the program as app_name.
        let mut r = RawEvent::new(line.into(), Timestamp::now(), Origin::from_hostname("h"));
        r.insert_field("transport.syslog.app_name", "sshd".to_string());
        assert!(matches!(parse_sshd(r), ParseResult::Success(_)));
    }

    #[test]
    fn sudo_command() {
        let e = ok(parse_sudo(raw(
            "sudo",
            "     bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt update ; echo",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "sudo_command");
        assert_eq!(s(&e, f::EVENT_OUTCOME), "success");
        assert_eq!(s(&e, f::USER_NAME), "bob");
        assert_eq!(s(&e, f::USER_TARGET_NAME), "root");
        assert_eq!(s(&e, f::PROCESS_WORKING_DIRECTORY), "/home/bob");
        assert_eq!(s(&e, f::PROCESS_COMMAND_LINE), "/usr/bin/apt update ; echo");
    }

    #[test]
    fn sudo_failures() {
        let e = ok(parse_sudo(raw(
            "sudo",
            "bob : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/ls",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "sudo_incorrect_password");
        assert_eq!(s(&e, f::EVENT_OUTCOME), "failure");
        assert_eq!(s(&e, f::EVENT_REASON), "3 incorrect password attempts");

        let e = ok(parse_sudo(raw(
            "sudo",
            "eve : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "sudo_not_in_sudoers");
        assert_eq!(s(&e, f::USER_NAME), "eve");

        let e = ok(parse_sudo(raw(
            "sudo",
            "pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob rhost=  user=bob",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "sudo_auth_failure");
        assert_eq!(s(&e, f::USER_NAME), "bob");

        assert!(matches!(
            parse_sudo(raw(
                "sudo",
                "pam_unix(sudo:session): session opened for user root(uid=0) by bob(uid=1000)"
            )),
            ParseResult::NoMatch(_)
        ));
    }

    #[test]
    fn netfilter_ufw_block() {
        let e = ok(parse_netfilter(raw(
            "kernel",
            "[ 8123.456789] [UFW BLOCK] IN=eth0 OUT= MAC=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:08:00 SRC=203.0.113.9 DST=192.168.1.10 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=0 DF PROTO=TCP SPT=51234 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "blocked");
        assert_eq!(s(&e, f::RULE_NAME), "UFW BLOCK");
        assert_eq!(s(&e, f::OBSERVER_INGRESS_INTERFACE), "eth0");
        assert!(e.get_field(f::OBSERVER_EGRESS_INTERFACE).is_none());
        assert_eq!(s(&e, f::SOURCE_IP), "203.0.113.9");
        assert_eq!(s(&e, f::DESTINATION_IP), "192.168.1.10");
        assert_eq!(s(&e, f::NETWORK_TRANSPORT), "tcp");
        assert_eq!(s(&e, f::SOURCE_PORT), "51234");
        assert_eq!(s(&e, f::DESTINATION_PORT), "22");
    }

    #[test]
    fn netfilter_nft_prefix_and_no_prefix() {
        let e = ok(parse_netfilter(raw(
            "kernel",
            "nft-accept: IN=br0 OUT=wan0 SRC=10.0.0.5 DST=1.1.1.1 LEN=84 PROTO=ICMP TYPE=8 CODE=0 ID=1 SEQ=1",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "allowed");
        assert_eq!(s(&e, f::RULE_NAME), "nft-accept");
        assert_eq!(s(&e, f::NETWORK_TRANSPORT), "icmp");
        assert!(e.get_field(f::DESTINATION_PORT).is_none());

        let e = ok(parse_netfilter(raw(
            "kernel",
            "IN=eth0 OUT= SRC=10.0.0.5 DST=10.0.0.1 PROTO=UDP SPT=5353 DPT=5353",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "logged");
        assert!(e.get_field(f::RULE_NAME).is_none());
    }

    #[test]
    fn netfilter_needs_addresses() {
        for text in [
            "systemd: LOGIN=1 SRC=x",
            "foo BIN=1 SRC=10.0.0.1 DST=10.0.0.2",
            "IN=eth0 OUT= PROTO=TCP",
        ] {
            assert!(
                matches!(
                    parse_netfilter(raw("kernel", text)),
                    ParseResult::NoMatch(_)
                ),
                "{text}"
            );
        }
    }
}
