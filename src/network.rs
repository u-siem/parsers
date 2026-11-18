//! Content parsers for network appliances and services: the pfSense /
//! OPNsense packet filter (`filterlog`), dnsmasq, which Pi-hole runs for
//! DNS and DHCP, and the Unbound DNS resolver.
//!
//! Like the Linux parsers they read the message body after a syslog
//! transport parser has run, and check the syslog program name first, so
//! other programs cost one string comparison.
//!
//! Fields follow ECS where it has a name.

use regex::Regex;
use std::net::IpAddr;
use std::sync::LazyLock;
use usiem::event::RawEvent;
use usiem::event::field::{FieldValue, Ip};
use usiem::event::fields as f;
use usiem::ingest::parser::{LogParser, result::ParseResult};

/// `event.dataset` of the events [`parse_filterlog`] produces.
pub const FILTERLOG_DATASET: &str = "pfsense.filterlog";
/// `event.dataset` of the DNS events [`parse_dnsmasq`] produces.
pub const DNSMASQ_DNS_DATASET: &str = "dnsmasq.dns";
/// `event.dataset` of the DHCP events [`parse_dnsmasq`] produces.
pub const DNSMASQ_DHCP_DATASET: &str = "dnsmasq.dhcp";
/// `event.dataset` of the DNS events [`parse_unbound`] produces.
pub const UNBOUND_DNS_DATASET: &str = "unbound.dns";
/// `event.dataset` of the other Unbound lines (service messages, statistics).
pub const UNBOUND_LOG_DATASET: &str = "unbound.log";
/// ECS `event.duration`, in nanoseconds: how long Unbound took to answer.
pub const EVENT_DURATION: &str = "event.duration";
/// The size of Unbound's reply in bytes (no ECS field holds it).
pub const UNBOUND_REPLY_SIZE: &str = "unbound.reply.size";

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

/// `aa:bb:cc:dd:ee:ff` → `AA-BB-CC-DD-EE-FF` (the ECS form); `None` if it
/// isn't six hex pairs separated by `:` or `-`.
///
/// ```
/// use usiem_parsers::network::normalize_mac;
///
/// assert_eq!(normalize_mac("aa:bb:cc:dd:ee:0f").as_deref(), Some("AA-BB-CC-DD-EE-0F"));
/// assert_eq!(normalize_mac("laptop"), None);
/// ```
pub fn normalize_mac(text: &str) -> Option<String> {
    // Six pairs and five separators; anything else is not a MAC, and is not
    // worth splitting.
    if text.len() != 17 {
        return None;
    }
    let parts: Vec<&str> = text.split([':', '-']).collect();
    let valid = parts.len() == 6
        && parts
            .iter()
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()));
    valid.then(|| parts.join("-").to_ascii_uppercase())
}

/// A dnsmasq answer that is a status rather than data: `NXDOMAIN`,
/// `SERVFAIL`, `REFUSED`, `NODATA`, and the `NODATA-IPv4` / `NODATA-IPv6`
/// dnsmasq writes for an empty `A` / `AAAA` answer.
fn is_response_code(answer: &str) -> bool {
    answer.starts_with("NODATA-IPv")
        || answer
            .bytes()
            .all(|c| c.is_ascii_uppercase() || c == b'-' || c.is_ascii_digit())
}

// ---------------------------------------------------------------- filterlog

/// pfSense and OPNsense `filterlog` lines: one CSV record per packet the
/// filter logged.
///
/// ```text
/// 5,,,1000000103,igb1,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.9,192.168.1.10,51234,22,0,S,...
/// ```
///
/// The common prefix is rule number, sub-rule, anchor, tracker, interface,
/// reason, action, direction and IP version; IPv4 and IPv6 records differ
/// after that, and TCP/UDP records end with the ports.
///
/// | column | field |
/// |---|---|
/// | rule number | `rule.id` |
/// | tracker (OPNsense: the rule's label hash) | `rule.uuid` |
/// | interface | `observer.ingress.interface` (direction `in`) or `observer.egress.interface` (`out`) |
/// | reason (`match`, ...) | `event.reason` |
/// | action | `event.action`: `blocked` (block, reject) or `allowed` (pass) |
/// | direction | `network.direction`: `ingress` or `egress` |
/// | protocol | `network.transport` (lower case, e.g. `tcp`, `udp`, `icmp`) |
/// | addresses, ports | `source.ip`, `destination.ip`, `source.port`, `destination.port` |
pub fn parse_filterlog(mut raw: RawEvent) -> ParseResult {
    if program(&raw) != Some("filterlog") {
        return ParseResult::NoMatch(raw);
    }
    let text = raw.log_text.trim();
    let cols: Vec<&str> = text.split(',').collect();
    if cols.len() < 9 {
        return ParseResult::NoMatch(raw);
    }
    // (protocol, source, destination, protocol-specific columns)
    let (proto, src, dst, rest) = match cols[8] {
        "4" if cols.len() >= 20 => (cols[16], cols[18], cols[19], &cols[20..]),
        "6" if cols.len() >= 17 => (cols[12], cols[15], cols[16], &cols[17..]),
        _ => return ParseResult::NoMatch(raw),
    };
    let (Some(src), Some(dst)) = (ip_value(src), ip_value(dst)) else {
        return ParseResult::NoMatch(raw);
    };
    let action = match cols[6] {
        "pass" => "allowed",
        "block" | "reject" => "blocked",
        _ => "logged",
    };
    let mut fields: Vec<(&'static str, FieldValue)> = Vec::with_capacity(12);
    fields.push((f::EVENT_ACTION, action.into()));
    if !cols[0].is_empty() {
        fields.push((f::RULE_ID, cols[0].to_string().into()));
    }
    if !cols[3].is_empty() {
        fields.push((f::RULE_UUID, cols[3].to_string().into()));
    }
    if !cols[5].is_empty() {
        fields.push((f::EVENT_REASON, cols[5].to_string().into()));
    }
    let (direction, interface_field) = match cols[7] {
        "out" => (Some("egress"), f::OBSERVER_EGRESS_INTERFACE),
        "in" => (Some("ingress"), f::OBSERVER_INGRESS_INTERFACE),
        _ => (None, f::OBSERVER_INGRESS_INTERFACE),
    };
    if let Some(direction) = direction {
        fields.push((f::NETWORK_DIRECTION, direction.into()));
    }
    if !cols[4].is_empty() {
        fields.push((interface_field, cols[4].to_string().into()));
    }
    let proto = proto.to_ascii_lowercase();
    if matches!(proto.as_str(), "tcp" | "udp") && rest.len() >= 2 {
        if let Some(port) = port_value(rest[0]) {
            fields.push((f::SOURCE_PORT, port));
        }
        if let Some(port) = port_value(rest[1]) {
            fields.push((f::DESTINATION_PORT, port));
        }
    }
    if !proto.is_empty() {
        fields.push((f::NETWORK_TRANSPORT, proto.into()));
    }
    fields.push((f::SOURCE_IP, src));
    fields.push((f::DESTINATION_IP, dst));
    raw.insert_field(f::EVENT_CATEGORY, "network");
    raw.insert_field(f::EVENT_DATASET, FILTERLOG_DATASET);
    for (k, v) in fields {
        raw.insert_field(k, v);
    }
    ParseResult::Success(raw.into_event())
}

/// [`parse_filterlog`] as a [`LogParser`] named `pfsense_filterlog`, ready
/// to register.
pub fn filterlog_parser() -> LogParser {
    LogParser::new(
        "pfsense_filterlog",
        "pfSense / OPNsense filterlog",
        "Parses pfSense and OPNsense packet filter (filterlog) CSV records",
        parse_filterlog,
    )
}

// ---------------------------------------------------------------- dnsmasq

/// A dnsmasq line inside another line, as when a log file is shipped by a
/// file reader: `Jan 15 10:00:00 dnsmasq[123]: query[A] ...`.
static DNSMASQ_EMBEDDED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d )?(?:dnsmasq(?:-dhcp)?|pihole-FTL)\[\d+\]: (.*)$",
    )
    .expect("dnsmasq embedded regex")
});
/// `log-queries=extra` puts `<serial> <client>/<port> ` first.
static DNSMASQ_EXTRA: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d+ \S+/\d+ (.*)$").expect("dnsmasq extra regex"));
static DNSMASQ_QUERY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^query\[([A-Za-z0-9]+)\] (\S+) from (\S+)$").expect("dnsmasq query regex")
});
static DNSMASQ_FORWARDED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^forwarded (\S+) to (\S+)$").expect("dnsmasq forwarded regex"));
/// `reply x is 1.2.3.4`, `cached x is NXDOMAIN`, `gravity blocked x is 0.0.0.0`,
/// `/etc/hosts x is 1.2.3.4`, ...
static DNSMASQ_ANSWER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^(.+?) (\S+) is (\S+)$").expect("dnsmasq answer regex"));
static DNSMASQ_DHCP: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:\d+ )?(DHCP[A-Z]+)(?:\(([^)]*)\))?(?: (.*))?$").expect("dnsmasq dhcp regex")
});

/// The dnsmasq message, if this is a dnsmasq (or Pi-hole) line.
fn dnsmasq_body(raw: &RawEvent) -> Option<String> {
    let text = raw.log_text.trim();
    let ours = matches!(
        program(raw),
        Some("dnsmasq" | "dnsmasq-dhcp" | "dnsmasq-dns" | "pihole-FTL" | "pihole")
    );
    // Cheap test before the regex: an embedded program name sits near the start.
    let head = text.get(..text.len().min(48)).unwrap_or(text);
    if (head.contains("dnsmasq") || head.contains("pihole-FTL"))
        && let Some(c) = DNSMASQ_EMBEDDED.captures(text)
    {
        return Some(c[1].to_string());
    }
    ours.then(|| text.to_string())
}

/// dnsmasq DNS and DHCP log lines (`log-queries`, `log-dhcp`), as Pi-hole
/// writes them too.
///
/// | message | `event.action` | fields |
/// |---|---|---|
/// | `query[A] example.com from 192.168.1.20` | `dns_query` | `dns.question.name`, `dns.question.type`, `source.ip` |
/// | `forwarded example.com to 1.1.1.1` | `dns_forward` | `dns.question.name`, `destination.ip` |
/// | `reply example.com is 93.184.216.34` | `dns_reply` | `dns.question.name`, `dns.answer.data`, `dns.resolved_ip` |
/// | `cached example.com is NXDOMAIN` | `dns_cached` | `dns.response_code` |
/// | `gravity blocked ads.example is 0.0.0.0` | `dns_blocked` | `rule.name` = `gravity blocked` |
/// | `/etc/hosts nas.lan is 192.168.1.5` | `dns_local` | `event.reason` = the source |
/// | `DHCPACK(eth0) 192.168.1.50 aa:bb:cc:dd:ee:ff laptop` | `dhcp_ack` | `dhcp.type`, `client.ip`, `client.mac`, `client.domain`, `observer.ingress.interface` |
///
/// `log-queries=extra` lines (with a serial and the client's port first)
/// are understood too, and so are dnsmasq lines embedded in another line,
/// as a log file reader ships them.
pub fn parse_dnsmasq(mut raw: RawEvent) -> ParseResult {
    let Some(body) = dnsmasq_body(&raw) else {
        return ParseResult::NoMatch(raw);
    };
    let body = match DNSMASQ_EXTRA.captures(&body) {
        Some(c) => c[1].to_string(),
        None => body,
    };
    let mut fields: Vec<(&'static str, FieldValue)> = Vec::with_capacity(8);
    let dataset;
    if let Some(c) = DNSMASQ_QUERY.captures(&body) {
        dataset = DNSMASQ_DNS_DATASET;
        fields.push((f::EVENT_ACTION, "dns_query".into()));
        fields.push((f::DNS_QUESTION_TYPE, c[1].to_ascii_uppercase().into()));
        fields.push((f::DNS_QUESTION_NAME, c[2].to_ascii_lowercase().into()));
        if let Some(ip) = ip_value(&c[3]) {
            fields.push((f::SOURCE_IP, ip));
        }
    } else if let Some(c) = DNSMASQ_FORWARDED.captures(&body) {
        dataset = DNSMASQ_DNS_DATASET;
        fields.push((f::EVENT_ACTION, "dns_forward".into()));
        fields.push((f::DNS_QUESTION_NAME, c[1].to_ascii_lowercase().into()));
        if let Some(ip) = ip_value(&c[2]) {
            fields.push((f::DESTINATION_IP, ip));
        }
    } else if let Some(c) = DNSMASQ_DHCP.captures(&body) {
        dataset = DNSMASQ_DHCP_DATASET;
        let kind = &c[1];
        let action = format!(
            "dhcp_{}",
            kind.trim_start_matches("DHCP").to_ascii_lowercase()
        );
        fields.push((f::EVENT_ACTION, action.into()));
        fields.push((f::DHCP_TYPE, kind.to_string().into()));
        if let Some(iface) = c.get(2).map(|m| m.as_str()).filter(|s| !s.is_empty()) {
            fields.push((f::OBSERVER_INGRESS_INTERFACE, iface.to_string().into()));
        }
        // `[ip] [mac] [hostname | free text]`
        let rest = c.get(3).map_or("", |m| m.as_str());
        let mut tokens = rest.split_whitespace().peekable();
        if let Some(ip) = tokens.peek().and_then(|t| ip_value(t)) {
            fields.push((f::CLIENT_IP, ip));
            tokens.next();
        }
        if let Some(mac) = tokens.peek().and_then(|t| normalize_mac(t)) {
            fields.push((f::CLIENT_MAC, mac.into()));
            tokens.next();
        }
        let rest: Vec<&str> = tokens.collect();
        match rest.as_slice() {
            [] => {}
            [host] => fields.push((f::CLIENT_DOMAIN, host.to_string().into())),
            words => fields.push((f::EVENT_REASON, words.join(" ").into())),
        }
    } else if let Some(c) = DNSMASQ_ANSWER.captures(&body) {
        dataset = DNSMASQ_DNS_DATASET;
        let what = &c[1];
        let answer = &c[3];
        let lower = what.to_ascii_lowercase();
        let action = if lower == "reply" {
            "dns_reply"
        } else if lower.starts_with("cached") {
            "dns_cached"
        } else if ["block", "denied", "blacklisted", "special domain"]
            .iter()
            .any(|w| lower.contains(w))
        {
            fields.push((f::RULE_NAME, what.to_string().into()));
            "dns_blocked"
        } else {
            fields.push((f::EVENT_REASON, what.to_string().into()));
            "dns_local"
        };
        fields.push((f::EVENT_ACTION, action.into()));
        fields.push((f::DNS_QUESTION_NAME, c[2].to_ascii_lowercase().into()));
        if let Some(ip) = ip_value(answer) {
            fields.push((f::DNS_RESOLVED_IP, ip));
            fields.push((f::DNS_ANSWER_DATA, answer.to_string().into()));
        } else if let Some(kind) = answer.strip_prefix('<').and_then(|a| a.strip_suffix('>')) {
            fields.push((f::DNS_ANSWER_TYPE, kind.to_string().into()));
        } else if is_response_code(answer) {
            fields.push((f::DNS_RESPONSE_CODE, answer.to_string().into()));
        } else {
            fields.push((f::DNS_ANSWER_DATA, answer.to_string().into()));
        }
    } else {
        return ParseResult::NoMatch(raw);
    }
    raw.insert_field(f::EVENT_CATEGORY, "network");
    raw.insert_field(f::EVENT_DATASET, dataset);
    for (k, v) in fields {
        raw.insert_field(k, v);
    }
    ParseResult::Success(raw.into_event())
}

/// [`parse_dnsmasq`] as a [`LogParser`] named `dnsmasq`, ready to register.
pub fn dnsmasq_parser() -> LogParser {
    LogParser::new(
        "dnsmasq",
        "dnsmasq / Pi-hole",
        "Parses dnsmasq and Pi-hole DNS query and DHCP log lines",
        parse_dnsmasq,
    )
}

// ---------------------------------------------------------------- unbound

/// An Unbound line inside another line, as a log file reader ships it:
/// `Jan 15 10:00:00 unbound[123]: [123:0] info: ...`.
static UNBOUND_EMBEDDED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d )?unbound(?:\[\d+\])?: (.*)$")
        .expect("unbound embedded regex")
});
/// `[pid:thread] tag: body`; the tag is a log level, or `query` / `reply`
/// with `log-tag-queryreply`.
static UNBOUND_HEAD: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\[\d+:\d+\] ([a-z]+):(?: (.*))?$").expect("unbound head regex"));
/// `log-servfail`: `SERVFAIL <example.com. A IN>: reason`.
static UNBOUND_SERVFAIL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^SERVFAIL <(\S+) (\S+) (\S+)>: ?(.*)$").expect("unbound servfail regex")
});

/// The Unbound message, if this is an Unbound line.
fn unbound_body(raw: &RawEvent) -> Option<String> {
    let text = raw.log_text.trim();
    let head = text.get(..text.len().min(32)).unwrap_or(text);
    if head.contains("unbound")
        && let Some(c) = UNBOUND_EMBEDDED.captures(text)
    {
        return Some(c[1].to_string());
    }
    (program(raw) == Some("unbound")).then(|| text.to_string())
}

/// A DNS name as Unbound prints it, with the root's dot at the end:
/// `Example.COM.` → `example.com`, `.` → `.`.
fn unbound_name(text: &str) -> Option<String> {
    let name = text.strip_suffix('.')?;
    Some(if name.is_empty() {
        ".".to_string()
    } else {
        name.to_ascii_lowercase()
    })
}

/// A record type or class: `A`, `HTTPS`, `TYPE65`, `IN`, `CLASS3`.
fn is_mnemonic(text: &str) -> bool {
    !text.is_empty() && text.len() <= 16 && text.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// `0.061264` (seconds, as Unbound prints them) → nanoseconds, without a
/// float round trip.
fn seconds_to_nanos(text: &str) -> Option<i64> {
    let (whole, frac) = text.split_once('.').unwrap_or((text, ""));
    let digits = |s: &str| s.bytes().all(|b| b.is_ascii_digit());
    if whole.is_empty() || frac.len() > 9 || !digits(whole) || !digits(frac) {
        return None;
    }
    let whole: i64 = whole.parse().ok()?;
    let frac: i64 = if frac.is_empty() {
        0
    } else {
        format!("{frac:0<9}").parse().ok()?
    };
    whole.checked_mul(1_000_000_000)?.checked_add(frac)
}

/// Unbound zone types that refuse or blank the answer.
fn is_blocking_zone(kind: &str) -> bool {
    matches!(
        kind,
        "deny"
            | "refuse"
            | "always_refuse"
            | "always_nxdomain"
            | "always_nodata"
            | "always_null"
            | "always_deny"
            | "inform_deny"
    )
}

/// Statistics Unbound writes when a thread stops (verbosity 1 and up):
/// `server stats for thread 0: ...`, the recursion time histogram and its
/// rows of numbers.
fn is_statistics(body: &str) -> bool {
    body.starts_with("server stats for thread")
        || body.starts_with("histogram of recursion")
        || body.starts_with("average recursion processing time")
        || body.starts_with("lower(secs) upper(secs)")
        || body.starts_with("[25%]=")
        || (!body.is_empty()
            && body
                .split_whitespace()
                .all(|t| t.bytes().all(|b| b.is_ascii_digit() || b == b'.')))
}

/// The DNS fields of a query or reply body, or `None` if it isn't one.
/// `client name. TYPE CLASS [RCODE seconds cached size]`.
fn unbound_lookup(
    tag: &str,
    tokens: &[&str],
    fields: &mut Vec<(&'static str, FieldValue)>,
) -> bool {
    let (client, name, kind, class, reply) = match (tag, tokens) {
        ("query" | "info", [client, name, kind, class]) => (client, name, kind, class, None),
        ("reply" | "info", [client, name, kind, class, rcode, secs, cached, size]) => {
            (client, name, kind, class, Some((rcode, secs, cached, size)))
        }
        _ => return false,
    };
    let (Some(client), Some(name)) = (ip_value(client), unbound_name(name)) else {
        return false;
    };
    if !is_mnemonic(kind) || !is_mnemonic(class) {
        return false;
    }
    let action = match reply {
        None => "dns_query",
        Some((rcode, secs, cached, size)) => {
            if !is_mnemonic(rcode) {
                return false;
            }
            fields.push((f::DNS_RESPONSE_CODE, rcode.to_ascii_uppercase().into()));
            if let Some(nanos) = seconds_to_nanos(secs) {
                fields.push((EVENT_DURATION, FieldValue::Int(nanos)));
            }
            if let Ok(size) = size.parse::<u32>() {
                fields.push((UNBOUND_REPLY_SIZE, FieldValue::Int(size.into())));
            }
            if *cached == "1" {
                "dns_cached"
            } else {
                "dns_reply"
            }
        }
    };
    fields.push((f::EVENT_ACTION, action.into()));
    fields.push((f::SOURCE_IP, client));
    fields.push((f::DNS_QUESTION_NAME, name.into()));
    fields.push((f::DNS_QUESTION_TYPE, kind.to_ascii_uppercase().into()));
    fields.push((f::DNS_QUESTION_CLASS, class.to_ascii_uppercase().into()));
    true
}

/// `log-local-actions`: `zone. type client@port name. TYPE CLASS`.
fn unbound_local(tokens: &[&str], fields: &mut Vec<(&'static str, FieldValue)>) -> bool {
    let [zone, zone_type, client, name, kind, class] = tokens else {
        return false;
    };
    let Some((ip, port)) = client.rsplit_once('@') else {
        return false;
    };
    let (Some(zone), Some(name), Some(ip)) = (unbound_name(zone), unbound_name(name), ip_value(ip))
    else {
        return false;
    };
    if !is_mnemonic(kind) || !is_mnemonic(class) || zone_type.is_empty() {
        return false;
    }
    let action = if is_blocking_zone(zone_type) {
        "dns_blocked"
    } else {
        "dns_local"
    };
    fields.push((f::EVENT_ACTION, action.into()));
    fields.push((f::RULE_NAME, zone_type.to_string().into()));
    fields.push((f::EVENT_REASON, zone.into()));
    fields.push((f::SOURCE_IP, ip));
    if let Some(port) = port_value(port) {
        fields.push((f::SOURCE_PORT, port));
    }
    fields.push((f::DNS_QUESTION_NAME, name.into()));
    fields.push((f::DNS_QUESTION_TYPE, kind.to_ascii_uppercase().into()));
    fields.push((f::DNS_QUESTION_CLASS, class.to_ascii_uppercase().into()));
    true
}

/// Unbound log lines, as OPNsense and most Linux distributions run it.
///
/// Each message is `[pid:thread] tag: body`, where the tag is the level
/// (`info`, `notice`, `error`, ...), or `query` / `reply` when
/// `log-tag-queryreply` is on.
///
/// | message | `event.action` | fields |
/// |---|---|---|
/// | `query: 192.168.1.20 example.com. A IN` (`log-queries`) | `dns_query` | `source.ip`, `dns.question.name`, `dns.question.type`, `dns.question.class` |
/// | `reply: 192.168.1.20 example.com. A IN NOERROR 0.012 0 61` (`log-replies`) | `dns_reply`, or `dns_cached` from the cache | the same, plus `dns.response_code`, `event.duration` (ns), `unbound.reply.size` |
/// | `info: ads.example. always_nxdomain 192.168.1.20@53000 ads.example. A IN` (`log-local-actions`) | `dns_blocked` for refusing zone types, else `dns_local` | `rule.name` = the zone type, `event.reason` = the zone, `source.ip`, `source.port` |
/// | `error: SERVFAIL <example.com. A IN>: all servers failed` (`log-servfail`) | `dns_reply` | `dns.response_code` = `SERVFAIL`, `event.reason` |
///
/// Without `log-tag-queryreply`, queries and replies carry the `info` tag
/// and are told apart by their shape. The DNS events go to `unbound.dns`.
///
/// Every other Unbound line goes to `unbound.log`, so it isn't counted as
/// unparsed: the statistics Unbound writes when it stops (`statistics`),
/// `service_start`, `service_stop`, and `log` for the rest. All of them
/// carry `log.level`.
pub fn parse_unbound(mut raw: RawEvent) -> ParseResult {
    let Some(body) = unbound_body(&raw) else {
        return ParseResult::NoMatch(raw);
    };
    let (tag, body) = match UNBOUND_HEAD.captures(&body) {
        Some(c) => (
            c[1].to_string(),
            c.get(2).map_or("", |m| m.as_str()).trim().to_string(),
        ),
        None => (String::new(), body),
    };
    let mut fields: Vec<(&'static str, FieldValue)> = Vec::with_capacity(10);
    let tokens: Vec<&str> = body.split_whitespace().collect();
    let dns = if let Some(c) = UNBOUND_SERVFAIL.captures(&body) {
        match unbound_name(&c[1]) {
            Some(name) if is_mnemonic(&c[2]) && is_mnemonic(&c[3]) => {
                fields.push((f::EVENT_ACTION, "dns_reply".into()));
                fields.push((f::DNS_RESPONSE_CODE, "SERVFAIL".into()));
                fields.push((f::DNS_QUESTION_NAME, name.into()));
                fields.push((f::DNS_QUESTION_TYPE, c[2].to_ascii_uppercase().into()));
                fields.push((f::DNS_QUESTION_CLASS, c[3].to_ascii_uppercase().into()));
                if !c[4].is_empty() {
                    fields.push((f::EVENT_REASON, c[4].to_string().into()));
                }
                true
            }
            _ => false,
        }
    } else {
        unbound_lookup(&tag, &tokens, &mut fields)
            || (tag == "info" && unbound_local(&tokens, &mut fields))
    };
    let level = match tag.as_str() {
        "" => None,
        "query" | "reply" => Some("info".to_string()),
        other => Some(other.to_string()),
    };
    if let Some(level) = level {
        raw.insert_field(f::LOG_LEVEL, level);
    }
    if dns {
        raw.insert_field(f::EVENT_CATEGORY, "network");
        raw.insert_field(f::EVENT_DATASET, UNBOUND_DNS_DATASET);
    } else {
        fields.clear();
        let action = if is_statistics(&body) {
            "statistics"
        } else if body.starts_with("start of service") {
            "service_start"
        } else if body.starts_with("service stopped") {
            "service_stop"
        } else {
            "log"
        };
        raw.insert_field(f::EVENT_CATEGORY, "process");
        raw.insert_field(f::EVENT_DATASET, UNBOUND_LOG_DATASET);
        raw.insert_field(f::EVENT_ACTION, action);
    }
    for (k, v) in fields {
        raw.insert_field(k, v);
    }
    ParseResult::Success(raw.into_event())
}

/// [`parse_unbound`] as a [`LogParser`] named `unbound`, ready to register.
pub fn unbound_parser() -> LogParser {
    LogParser::new(
        "unbound",
        "Unbound DNS",
        "Parses Unbound query, reply, local-action and SERVFAIL log lines",
        parse_unbound,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use usiem::event::{CoreEvent, Origin, Timestamp};

    fn raw(program: &str, text: &str) -> RawEvent {
        let mut raw = RawEvent::new(text.into(), Timestamp::now(), Origin::from_hostname("h"));
        if !program.is_empty() {
            raw.insert_field("transport.syslog.process", program.to_string());
        }
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
            .map_or_else(|| panic!("missing {field}"), ToString::to_string)
    }

    #[test]
    fn filterlog_ipv4_tcp_block() {
        let e = ok(parse_filterlog(raw(
            "filterlog",
            "5,,,1000000103,igb1,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.9,192.168.1.10,51234,22,0,S,1234567,,64240,,mss;sackOK;TS;nop;wscale",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "blocked");
        assert_eq!(s(&e, f::RULE_ID), "5");
        assert_eq!(s(&e, f::RULE_UUID), "1000000103");
        assert_eq!(s(&e, f::EVENT_REASON), "match");
        assert_eq!(s(&e, f::NETWORK_DIRECTION), "ingress");
        assert_eq!(s(&e, f::OBSERVER_INGRESS_INTERFACE), "igb1");
        assert_eq!(s(&e, f::NETWORK_TRANSPORT), "tcp");
        assert_eq!(s(&e, f::SOURCE_IP), "203.0.113.9");
        assert!(matches!(e.get_field(f::SOURCE_IP), Some(FieldValue::Ip(_))));
        assert_eq!(s(&e, f::DESTINATION_IP), "192.168.1.10");
        assert_eq!(s(&e, f::SOURCE_PORT), "51234");
        assert_eq!(s(&e, f::DESTINATION_PORT), "22");
        assert_eq!(s(&e, f::EVENT_DATASET), FILTERLOG_DATASET);
    }

    #[test]
    fn filterlog_ipv4_udp_pass_out_and_icmp() {
        let e = ok(parse_filterlog(raw(
            "filterlog",
            "77,,,0b4ec45a3d1a8ac6d2fd2e8e0a9fbe3d,em0,match,pass,out,4,0x0,,64,12345,0,none,17,udp,72,192.168.1.20,1.1.1.1,40000,53,52",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "allowed");
        assert_eq!(s(&e, f::NETWORK_DIRECTION), "egress");
        assert_eq!(s(&e, f::OBSERVER_EGRESS_INTERFACE), "em0");
        assert_eq!(s(&e, f::DESTINATION_PORT), "53");

        let e = ok(parse_filterlog(raw(
            "filterlog",
            "4,,,1000000103,igb1,match,block,in,4,0x0,,52,1234,0,none,1,icmp,84,198.51.100.3,192.168.1.1,request,4321,1",
        )));
        assert_eq!(s(&e, f::NETWORK_TRANSPORT), "icmp");
        assert!(e.get_field(f::SOURCE_PORT).is_none());
    }

    #[test]
    fn filterlog_ipv6_and_rejects() {
        let e = ok(parse_filterlog(raw(
            "filterlog",
            "9,,,1000000105,igb0,match,block,in,6,0x00,0x00000,57,tcp,6,40,2001:db8::9,2001:db8:1::10,51515,443,0,S,99,,65535,,mss",
        )));
        assert_eq!(s(&e, f::SOURCE_IP), "2001:db8::9");
        assert_eq!(s(&e, f::DESTINATION_IP), "2001:db8:1::10");
        assert_eq!(s(&e, f::DESTINATION_PORT), "443");
        assert_eq!(s(&e, f::NETWORK_TRANSPORT), "tcp");

        assert!(matches!(
            parse_filterlog(raw("filterlog", "5,,,1,igb1,match,block,in,4,0x0")),
            ParseResult::NoMatch(_)
        ));
        assert!(matches!(
            parse_filterlog(raw(
                "other",
                "5,,,1000000103,igb1,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,203.0.113.9,192.168.1.10,51234,22,0"
            )),
            ParseResult::NoMatch(_)
        ));
    }

    #[test]
    fn dnsmasq_dns_lines() {
        let e = ok(parse_dnsmasq(raw(
            "dnsmasq",
            "query[AAAA] Example.COM from 192.168.1.20",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_query");
        assert_eq!(s(&e, f::DNS_QUESTION_NAME), "example.com");
        assert_eq!(s(&e, f::DNS_QUESTION_TYPE), "AAAA");
        assert_eq!(s(&e, f::SOURCE_IP), "192.168.1.20");
        assert_eq!(s(&e, f::EVENT_DATASET), DNSMASQ_DNS_DATASET);

        let e = ok(parse_dnsmasq(raw(
            "dnsmasq",
            "forwarded example.com to 1.1.1.1",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_forward");
        assert_eq!(s(&e, f::DESTINATION_IP), "1.1.1.1");

        let e = ok(parse_dnsmasq(raw(
            "dnsmasq",
            "reply example.com is 93.184.216.34",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_reply");
        assert_eq!(s(&e, f::DNS_RESOLVED_IP), "93.184.216.34");

        let e = ok(parse_dnsmasq(raw(
            "dnsmasq",
            "reply www.example.com is <CNAME>",
        )));
        assert_eq!(s(&e, f::DNS_ANSWER_TYPE), "CNAME");

        let e = ok(parse_dnsmasq(raw(
            "dnsmasq",
            "cached nope.example is NXDOMAIN",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_cached");
        assert_eq!(s(&e, f::DNS_RESPONSE_CODE), "NXDOMAIN");

        let e = ok(parse_dnsmasq(raw(
            "pihole-FTL",
            "gravity blocked ads.example.net is 0.0.0.0",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_blocked");
        assert_eq!(s(&e, f::RULE_NAME), "gravity blocked");

        let e = ok(parse_dnsmasq(raw(
            "dnsmasq",
            "/etc/hosts nas.lan is 192.168.1.5",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_local");
        assert_eq!(s(&e, f::EVENT_REASON), "/etc/hosts");
    }

    #[test]
    fn dnsmasq_nodata_is_a_response_code() {
        for code in ["NODATA-IPv4", "NODATA-IPv6", "NODATA", "SERVFAIL"] {
            let e = ok(parse_dnsmasq(raw(
                "dnsmasq",
                &format!("reply nope.example is {code}"),
            )));
            assert_eq!(s(&e, f::DNS_RESPONSE_CODE), code);
            assert!(e.get_field(f::DNS_ANSWER_DATA).is_none());
        }
    }

    #[test]
    fn dnsmasq_extra_and_embedded_lines() {
        let e = ok(parse_dnsmasq(raw(
            "dnsmasq",
            "1234 192.168.1.20/53124 query[A] example.com from 192.168.1.20",
        )));
        assert_eq!(s(&e, f::DNS_QUESTION_NAME), "example.com");

        // Pi-hole's log file shipped by a file reader under another program name.
        let e = ok(parse_dnsmasq(raw(
            "pihole",
            "Jan 15 10:00:00 dnsmasq[812]: query[A] example.com from 192.168.1.20",
        )));
        assert_eq!(s(&e, f::SOURCE_IP), "192.168.1.20");
        let e = ok(parse_dnsmasq(raw(
            "",
            "Jan  5 10:00:00 dnsmasq[812]: query[A] example.com from 192.168.1.20",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_query");

        assert!(matches!(
            parse_dnsmasq(raw("sshd", "query[A] example.com from 192.168.1.20")),
            ParseResult::NoMatch(_)
        ));
        assert!(matches!(
            parse_dnsmasq(raw("dnsmasq", "started, version 2.90 cachesize 10000")),
            ParseResult::NoMatch(_)
        ));
    }

    #[test]
    fn dnsmasq_dhcp_lines() {
        let e = ok(parse_dnsmasq(raw(
            "dnsmasq-dhcp",
            "DHCPACK(eth0) 192.168.1.50 aa:bb:cc:dd:ee:0f laptop",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dhcp_ack");
        assert_eq!(s(&e, f::DHCP_TYPE), "DHCPACK");
        assert_eq!(s(&e, f::OBSERVER_INGRESS_INTERFACE), "eth0");
        assert_eq!(s(&e, f::CLIENT_IP), "192.168.1.50");
        assert_eq!(s(&e, f::CLIENT_MAC), "AA-BB-CC-DD-EE-0F");
        assert_eq!(s(&e, f::CLIENT_DOMAIN), "laptop");
        assert_eq!(s(&e, f::EVENT_DATASET), DNSMASQ_DHCP_DATASET);

        let e = ok(parse_dnsmasq(raw(
            "dnsmasq-dhcp",
            "3164425723 DHCPDISCOVER(eth0) aa:bb:cc:dd:ee:0f no address available",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dhcp_discover");
        assert!(e.get_field(f::CLIENT_IP).is_none());
        assert_eq!(s(&e, f::CLIENT_MAC), "AA-BB-CC-DD-EE-0F");
        assert_eq!(s(&e, f::EVENT_REASON), "no address available");

        let e = ok(parse_dnsmasq(raw(
            "dnsmasq-dhcp",
            "DHCPREQUEST(eth0) 192.168.1.50 aa:bb:cc:dd:ee:0f",
        )));
        assert!(e.get_field(f::CLIENT_DOMAIN).is_none());
    }

    #[test]
    fn unbound_tagged_queries_and_replies() {
        let e = ok(parse_unbound(raw(
            "unbound",
            "[74764:7] query: 192.0.2.20 Www.Example.COM. A IN",
        )));
        assert_eq!(s(&e, f::EVENT_DATASET), UNBOUND_DNS_DATASET);
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_query");
        assert_eq!(s(&e, f::SOURCE_IP), "192.0.2.20");
        assert_eq!(s(&e, f::DNS_QUESTION_NAME), "www.example.com");
        assert_eq!(s(&e, f::DNS_QUESTION_TYPE), "A");
        assert_eq!(s(&e, f::DNS_QUESTION_CLASS), "IN");
        assert_eq!(s(&e, f::LOG_LEVEL), "info");
        assert!(e.get_field(f::DNS_RESPONSE_CODE).is_none());

        let e = ok(parse_unbound(raw(
            "unbound",
            "[74764:7] reply: 192.0.2.20 www.example.com. HTTPS IN NOERROR 0.061264 0 192",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_reply");
        assert_eq!(s(&e, f::DNS_QUESTION_TYPE), "HTTPS");
        assert_eq!(s(&e, f::DNS_RESPONSE_CODE), "NOERROR");
        assert_eq!(
            e.get_field(EVENT_DURATION),
            Some(&FieldValue::Int(61_264_000))
        );
        assert_eq!(e.get_field(UNBOUND_REPLY_SIZE), Some(&FieldValue::Int(192)));

        let e = ok(parse_unbound(raw(
            "unbound",
            "[74764:7] reply: 2001:db8::20 nope.example. AAAA IN NXDOMAIN 0.000000 1 36",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_cached");
        assert_eq!(s(&e, f::DNS_RESPONSE_CODE), "NXDOMAIN");
        assert_eq!(s(&e, f::SOURCE_IP), "2001:db8::20");
        assert_eq!(e.get_field(EVENT_DURATION), Some(&FieldValue::Int(0)));
    }

    #[test]
    fn unbound_untagged_lines_are_told_apart_by_shape() {
        let e = ok(parse_unbound(raw(
            "unbound",
            "[76589:4] info: 192.0.2.30 cdn.example.net. A IN",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_query");
        let e = ok(parse_unbound(raw(
            "unbound",
            "[76589:0] info: 192.0.2.30 b._dns-sd._udp.0.2.0.192.in-addr.arpa. PTR IN NXDOMAIN 0.000000 1 116",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_cached");
        assert_eq!(
            s(&e, f::DNS_QUESTION_NAME),
            "b._dns-sd._udp.0.2.0.192.in-addr.arpa"
        );
        assert_eq!(s(&e, f::DNS_QUESTION_TYPE), "PTR");
        // The root zone.
        let e = ok(parse_unbound(raw(
            "unbound",
            "[1:0] info: 192.0.2.30 . NS IN",
        )));
        assert_eq!(s(&e, f::DNS_QUESTION_NAME), ".");
    }

    #[test]
    fn unbound_local_actions_and_servfail() {
        let e = ok(parse_unbound(raw(
            "unbound",
            "[1:2] info: ads.example. always_nxdomain 192.0.2.40@53211 tracker.ads.example. A IN",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_blocked");
        assert_eq!(s(&e, f::RULE_NAME), "always_nxdomain");
        assert_eq!(s(&e, f::EVENT_REASON), "ads.example");
        assert_eq!(s(&e, f::SOURCE_IP), "192.0.2.40");
        assert_eq!(s(&e, f::SOURCE_PORT), "53211");
        assert_eq!(s(&e, f::DNS_QUESTION_NAME), "tracker.ads.example");

        let e = ok(parse_unbound(raw(
            "unbound",
            "[1:2] info: lan. static 2001:db8::5@40000 nas.lan. AAAA IN",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_local");
        assert_eq!(s(&e, f::SOURCE_IP), "2001:db8::5");

        let e = ok(parse_unbound(raw(
            "unbound",
            "[1:3] error: SERVFAIL <broken.example. A IN>: all the configured stub or forward servers failed, at zone .",
        )));
        assert_eq!(s(&e, f::EVENT_DATASET), UNBOUND_DNS_DATASET);
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_reply");
        assert_eq!(s(&e, f::DNS_RESPONSE_CODE), "SERVFAIL");
        assert_eq!(s(&e, f::DNS_QUESTION_NAME), "broken.example");
        assert_eq!(s(&e, f::LOG_LEVEL), "error");
        assert!(s(&e, f::EVENT_REASON).starts_with("all the configured"));
    }

    #[test]
    fn unbound_service_lines_and_statistics() {
        let cases = [
            (
                "[76589:0] info: server stats for thread 6: requestlist max 0 avg 0 exceeded 0 jostled 0",
                "statistics",
            ),
            (
                "[91739:0] info: server stats for thread 0: 16889 queries, 8545 answers from cache, 8344 recursions, 0 prefetch, 0 rejected by ip ratelimiting",
                "statistics",
            ),
            (
                "[76589:0] info: histogram of recursion processing times",
                "statistics",
            ),
            (
                "[76589:0] info: [25%]=0.036864 median[50%]=0.057344 [75%]=0.090112",
                "statistics",
            ),
            (
                "[76589:0] info: lower(secs) upper(secs) recursions",
                "statistics",
            ),
            ("[76589:0] info:    0.016384    0.032768 9", "statistics"),
            (
                "[76589:0] info: average recursion processing time 0.055285 sec",
                "statistics",
            ),
            (
                "[74764:0] info: start of service (unbound 1.25.1).",
                "service_start",
            ),
            (
                "[76589:0] info: service stopped (unbound 1.25.1).",
                "service_stop",
            ),
            ("[74764:0] notice: init module 0: python", "log"),
            ("something without the usual head", "log"),
        ];
        for (line, action) in cases {
            let e = ok(parse_unbound(raw("unbound", line)));
            assert_eq!(s(&e, f::EVENT_DATASET), UNBOUND_LOG_DATASET, "{line}");
            assert_eq!(s(&e, f::EVENT_ACTION), action, "{line}");
            assert!(e.get_field(f::DNS_QUESTION_NAME).is_none(), "{line}");
        }
        let e = ok(parse_unbound(raw(
            "unbound",
            "[74764:0] notice: init module 0: python",
        )));
        assert_eq!(s(&e, f::LOG_LEVEL), "notice");
    }

    #[test]
    fn unbound_embedded_and_other_programs() {
        let e = ok(parse_unbound(raw(
            "",
            "Nov 18 22:00:00 unbound[812]: [812:1] query: 192.0.2.20 example.com. A IN",
        )));
        assert_eq!(s(&e, f::EVENT_ACTION), "dns_query");
        assert!(matches!(
            parse_unbound(raw("dnsmasq", "[1:0] query: 192.0.2.20 example.com. A IN")),
            ParseResult::NoMatch(_)
        ));
        // A name without the trailing dot is not Unbound's query format.
        let e = ok(parse_unbound(raw(
            "unbound",
            "[1:0] query: 192.0.2.20 example.com A IN",
        )));
        assert_eq!(s(&e, f::EVENT_DATASET), UNBOUND_LOG_DATASET);
    }

    #[test]
    fn unbound_seconds() {
        assert_eq!(seconds_to_nanos("0.061264"), Some(61_264_000));
        assert_eq!(seconds_to_nanos("2"), Some(2_000_000_000));
        assert_eq!(seconds_to_nanos("1.5"), Some(1_500_000_000));
        assert_eq!(seconds_to_nanos("0.0000000001"), None);
        assert_eq!(seconds_to_nanos("-1.0"), None);
        assert_eq!(seconds_to_nanos(".5"), None);
        assert_eq!(seconds_to_nanos("99999999999999999999.0"), None);
    }

    #[test]
    fn macs() {
        assert_eq!(
            normalize_mac("aa:bb:cc:dd:ee:ff").as_deref(),
            Some("AA-BB-CC-DD-EE-FF")
        );
        assert_eq!(
            normalize_mac("AA-BB-CC-DD-EE-FF").as_deref(),
            Some("AA-BB-CC-DD-EE-FF")
        );
        assert_eq!(normalize_mac("laptop"), None);
        assert_eq!(normalize_mac("aa:bb:cc:dd:ee"), None);
    }
}
