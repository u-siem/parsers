//! Windows event log records shipped as JSON, one object per line.
//!
//! Two shapes are understood, both recognised by an `EventID` and a
//! `Channel` key:
//!
//! - **NXLog** (`im_msvistalog` + `to_json()`): envelope keys such as
//!   `EventTime`, `Hostname`, `SourceName`, `EventType`, `RecordNumber`,
//!   with the `EventData` members flattened beside them
//!   (`TargetUserName`, `IpAddress`, ...).
//! - **Fluent Bit** (`winevtlog`): `TimeCreated`, `Computer`,
//!   `ProviderName`, `EventRecordID`, `Keywords`, and the event data as a
//!   positional `StringInserts` array, which becomes
//!   `winlog.event_data.param1`, `param2`, ... (Winlogbeat's names for
//!   unnamed data). Named fields, and the ECS mapping below, need NXLog or a
//!   shipper that sends an `EventData` object.
//!
//! Every event data member is kept as `winlog.event_data.<Name>`. The
//! well-known ones are also mapped to ECS: `user.*`, `source.*`,
//! `process.*`, `destination.*`, `dns.question.name`, `file.path`,
//! `group.name`. `event.code` is the event id, `event.dataset` is
//! `windows.<channel>` (`windows.security`, `windows.sysmon`, ...).
//!
//! The event time comes from Sysmon's `UtcTime`, else `EventTime` /
//! `TimeCreated` when it carries a UTC offset. A time without an offset is
//! not guessed at: the receive time stays.

use serde_json::{Map, Value};
use std::net::IpAddr;
use usiem::event::RawEvent;
use usiem::event::field::{FieldValue, Ip, Timestamp};
use usiem::event::fields as f;
use usiem::ingest::parser::{LogParser, result::ParseResult};

/// `event.dataset` prefix.
pub const WINDOWS_DATASET_PREFIX: &str = "windows.";
const SYSMON_CHANNEL: &str = "Microsoft-Windows-Sysmon/Operational";

/// Keys that describe the record rather than being part of its event data.
const ENVELOPE: &[&str] = &[
    "EventTime",
    "EventReceivedTime",
    "TimeCreated",
    "Hostname",
    "Computer",
    "Keywords",
    "EventType",
    "SeverityValue",
    "Severity",
    "Level",
    "EventID",
    "SourceName",
    "ProviderName",
    "ProviderGuid",
    "Version",
    "Task",
    "OpcodeValue",
    "Opcode",
    "RecordNumber",
    "EventRecordID",
    "ActivityID",
    "RelatedActivityID",
    "ProcessID",
    "ThreadID",
    "Channel",
    "Message",
    "Category",
    "Domain",
    "AccountName",
    "AccountType",
    "UserID",
    "SourceModuleName",
    "SourceModuleType",
    "Qualifiers",
    "StringInserts",
    "EventData",
    "UserData",
];

/// Account management: the subject acts on the target account.
const ACCOUNT_EVENTS: &[i64] = &[4720, 4722, 4723, 4724, 4725, 4726, 4738, 4740, 4767, 4781];
/// Group changes: the target is the group, the member is the account.
const GROUP_EVENTS: &[i64] = &[
    4727, 4728, 4729, 4730, 4731, 4732, 4733, 4734, 4735, 4737, 4754, 4755, 4756, 4757, 4758,
];
const AUTH_EVENTS: &[i64] = &[
    4624, 4625, 4634, 4647, 4648, 4672, 4768, 4769, 4771, 4776, 4778, 4779,
];

/// Short `event.action` names for common events.
fn action_of(channel: &str, id: i64) -> Option<&'static str> {
    if channel == SYSMON_CHANNEL {
        return Some(match id {
            1 => "process-created",
            3 => "network-connection",
            5 => "process-terminated",
            7 => "image-loaded",
            8 => "remote-thread-created",
            10 => "process-accessed",
            11 => "file-created",
            12..=14 => "registry-changed",
            22 => "dns-query",
            23 => "file-deleted",
            _ => return None,
        });
    }
    Some(match (channel, id) {
        ("Security", 1102) | ("System", 104) => "audit-log-cleared",
        ("Security", 4624) => "logged-in",
        ("Security", 4625) => "logon-failed",
        ("Security", 4634 | 4647) => "logged-out",
        ("Security", 4648) => "logged-in-explicit",
        ("Security", 4672) => "logged-in-special",
        ("Security", 4688) => "process-created",
        ("Security", 4697) | ("System", 7045) => "service-installed",
        ("Security", 4698) => "scheduled-task-created",
        ("Security", 4720) => "added-user-account",
        ("Security", 4722) => "enabled-user-account",
        ("Security", 4724) => "reset-password",
        ("Security", 4725) => "disabled-user-account",
        ("Security", 4726) => "deleted-user-account",
        ("Security", 4728 | 4732 | 4756) => "added-member-to-group",
        ("Security", 4729 | 4733 | 4757) => "removed-member-from-group",
        ("Security", 4740) => "locked-out-user-account",
        ("Security", 4768) => "kerberos-authentication-ticket-requested",
        ("Security", 4769) => "kerberos-service-ticket-requested",
        ("Security", 4771) => "kerberos-preauth-failed",
        ("Security", 4776) => "credential-validated",
        _ => return None,
    })
}

fn dataset_of(channel: &str) -> String {
    let short = match channel {
        "Security" => "security".to_string(),
        "System" => "system".to_string(),
        "Application" => "application".to_string(),
        SYSMON_CHANNEL => "sysmon".to_string(),
        "Windows PowerShell" | "Microsoft-Windows-PowerShell/Operational" => {
            "powershell".to_string()
        }
        other => {
            let mut s = String::new();
            for c in other.chars() {
                if c.is_ascii_alphanumeric() {
                    s.push(c.to_ascii_lowercase());
                } else if !s.ends_with('_') && !s.is_empty() {
                    s.push('_');
                }
            }
            s.trim_end_matches('_').to_string()
        }
    };
    format!("{WINDOWS_DATASET_PREFIX}{short}")
}

fn as_text(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// A number, a decimal string or a `0x` hex string (4688's process ids).
fn as_int(value: &Value) -> Option<i64> {
    match value {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => {
            let s = s.trim();
            match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                Some(hex) => i64::from_str_radix(hex, 16).ok(),
                None => s.parse().ok(),
            }
        }
        _ => None,
    }
}

/// A port number as a field, if it is one (0 to 65535).
fn port_of(port: i64) -> Option<FieldValue> {
    u16::try_from(port).ok().map(|p| FieldValue::Int(p.into()))
}

/// Windows writes `-` for "none".
fn present(text: &str) -> Option<&str> {
    let text = text.trim();
    (!text.is_empty() && text != "-").then_some(text)
}

fn ip_of(text: &str) -> Option<FieldValue> {
    let text = present(text)?;
    let text = text.strip_prefix("::ffff:").unwrap_or(text);
    text.parse::<IpAddr>()
        .ok()
        .map(|ip| FieldValue::Ip(Ip::from(ip)))
}

/// The file name of a Windows path.
fn base_name(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// `DOMAIN\user` → (`DOMAIN`, `user`).
fn split_account(text: &str) -> (Option<&str>, &str) {
    match text.split_once('\\') {
        Some((domain, user)) => (present(domain), user),
        None => (None, text),
    }
}

/// RFC 3339, or `YYYY-MM-DD HH:MM:SS[.fff] ±HHMM` / `±HH:MM`; `utc` also
/// accepts a time with no offset, as UTC (Sysmon's `UtcTime`).
fn parse_time(text: &str, utc: bool) -> Option<Timestamp> {
    use time::format_description::FormatItem;
    use time::macros::format_description;
    use time::{OffsetDateTime, PrimitiveDateTime};
    const WITH_OFFSET: &[&[FormatItem<'_>]] = &[
        format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond] [offset_hour sign:mandatory][offset_minute]"
        ),
        format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second] [offset_hour sign:mandatory][offset_minute]"
        ),
        format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond] [offset_hour sign:mandatory]:[offset_minute]"
        ),
        format_description!(
            "[year]-[month]-[day] [hour]:[minute]:[second] [offset_hour sign:mandatory]:[offset_minute]"
        ),
    ];
    const NO_OFFSET: &[&[FormatItem<'_>]] = &[
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second].[subsecond]"),
        format_description!("[year]-[month]-[day] [hour]:[minute]:[second]"),
    ];
    let text = text.trim();
    if let Ok(t) = Timestamp::from_rfc3339(text) {
        return Some(t);
    }
    let nanos = WITH_OFFSET
        .iter()
        .find_map(|fmt| OffsetDateTime::parse(text, fmt).ok())
        .map(OffsetDateTime::unix_timestamp_nanos)
        .or_else(|| {
            utc.then(|| {
                NO_OFFSET
                    .iter()
                    .find_map(|fmt| PrimitiveDateTime::parse(text, fmt).ok())
                    .map(|dt| dt.assume_utc().unix_timestamp_nanos())
            })
            .flatten()
        })?;
    i64::try_from(nanos).ok().map(Timestamp::from_nanos)
}

/// `success` / `failure` from NXLog's `EventType` or the audit keyword bits.
fn outcome_of(map: &Map<String, Value>) -> Option<&'static str> {
    if let Some(kind) = map.get("EventType").and_then(Value::as_str) {
        let kind = kind.to_ascii_uppercase();
        if kind.contains("FAILURE") {
            return Some("failure");
        }
        if kind.contains("SUCCESS") {
            return Some("success");
        }
    }
    let keywords = map.get("Keywords")?;
    if let Some(text) = keywords.as_str() {
        if text.contains("Audit Failure") {
            return Some("failure");
        }
        if text.contains("Audit Success") {
            return Some("success");
        }
    }
    // The audit bits sit at the top, so this needs the full u64 range.
    let bits = match keywords {
        Value::Number(n) => n.as_u64()?,
        Value::String(s) => {
            let s = s.trim();
            match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16).ok()?,
                None => s.parse().ok()?,
            }
        }
        _ => return None,
    };
    if bits & 0x0010_0000_0000_0000 != 0 {
        Some("failure")
    } else if bits & 0x0020_0000_0000_0000 != 0 {
        Some("success")
    } else {
        None
    }
}

fn level_of(value: &Value) -> Option<String> {
    match value {
        Value::String(s) => Some(s.to_ascii_lowercase()),
        Value::Number(n) => Some(
            match n.as_i64()? {
                1 => "critical",
                2 => "error",
                3 => "warning",
                5 => "verbose",
                _ => "information",
            }
            .to_string(),
        ),
        _ => None,
    }
}

/// Windows event log JSON (NXLog or Fluent Bit) → ECS. See the module docs.
pub fn parse_windows_json(mut raw: RawEvent) -> ParseResult {
    let text = raw.log_text.trim();
    // A cheap test first: most JSON lines aren't Windows events.
    if !text.starts_with('{') || !text.contains("\"EventID\"") || !text.contains("\"Channel\"") {
        return ParseResult::NoMatch(raw);
    }
    // Broken JSON is the JSON parser's to report.
    let Ok(Value::Object(map)) = serde_json::from_str::<Value>(text) else {
        return ParseResult::NoMatch(raw);
    };
    let (Some(id), Some(channel)) = (
        map.get("EventID").and_then(as_int),
        map.get("Channel")
            .and_then(Value::as_str)
            .map(str::to_string),
    ) else {
        return ParseResult::NoMatch(raw);
    };

    // Event data: an `EventData` object, the flattened NXLog members, and
    // Fluent Bit's positional inserts.
    let mut data: Vec<(String, Value)> = Vec::new();
    if let Some(Value::Object(members)) = map.get("EventData") {
        data.extend(members.iter().map(|(k, v)| (k.clone(), v.clone())));
    }
    for (key, value) in &map {
        if !ENVELOPE.contains(&key.as_str()) {
            data.push((key.clone(), value.clone()));
        }
    }
    if let Some(Value::Array(inserts)) = map.get("StringInserts") {
        for (i, value) in inserts.iter().enumerate() {
            data.push((format!("param{}", i + 1), value.clone()));
        }
    }
    let get = |name: &str| -> Option<String> {
        data.iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| as_text(v))
    };
    let get_int = |name: &str| -> Option<i64> {
        data.iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| as_int(v))
    };

    let mut out: Vec<(&'static str, FieldValue)> = Vec::with_capacity(24);
    out.push((f::WINLOG_EVENT_ID, FieldValue::Int(id)));
    out.push((f::EVENT_CODE, id.to_string().into()));
    out.push((f::WINLOG_CHANNEL, channel.clone().into()));
    out.push((f::EVENT_DATASET, dataset_of(&channel).into()));
    if let Some(provider) = map
        .get("SourceName")
        .or_else(|| map.get("ProviderName"))
        .and_then(as_text)
    {
        out.push((f::WINLOG_PROVIDER_NAME, provider.clone().into()));
        out.push((f::EVENT_PROVIDER, provider.into()));
    }
    if let Some(computer) = map
        .get("Hostname")
        .or_else(|| map.get("Computer"))
        .and_then(as_text)
    {
        out.push((f::WINLOG_COMPUTER_NAME, computer.clone().into()));
        out.push((f::HOST_NAME, computer.into()));
    }
    if let Some(record) = map
        .get("RecordNumber")
        .or_else(|| map.get("EventRecordID"))
        .and_then(as_int)
    {
        out.push((f::WINLOG_RECORD_ID, FieldValue::Int(record)));
    }
    if let Some(level) = map
        .get("Severity")
        .or_else(|| map.get("Level"))
        .and_then(level_of)
    {
        out.push((f::LOG_LEVEL, level.into()));
    }
    if let Some(message) = map.get("Message").and_then(as_text) {
        out.push((f::MESSAGE, message.into()));
    }
    let sysmon = channel == SYSMON_CHANNEL;
    let security = channel == "Security";
    if let Some(action) = action_of(&channel, id) {
        out.push((f::EVENT_ACTION, action.into()));
    }
    let outcome = match (security, id) {
        (true, 4625 | 4771) => Some("failure"),
        (true, 4624) => Some("success"),
        _ => outcome_of(&map),
    };
    if let Some(outcome) = outcome {
        out.push((f::EVENT_OUTCOME, outcome.into()));
    }
    let category = if sysmon {
        match id {
            1 | 5 | 8 | 10 => Some("process"),
            3 | 22 => Some("network"),
            11 | 23 => Some("file"),
            12..=14 => Some("registry"),
            _ => None,
        }
    } else if security && AUTH_EVENTS.contains(&id) {
        Some("authentication")
    } else if security && (ACCOUNT_EVENTS.contains(&id) || GROUP_EVENTS.contains(&id)) {
        Some("iam")
    } else if security && id == 4688 {
        Some("process")
    } else {
        None
    };
    if let Some(category) = category {
        out.push((f::EVENT_CATEGORY, category.into()));
    }

    // Users.
    let subject = get("SubjectUserName").filter(|s| present(s).is_some());
    let subject_domain = get("SubjectDomainName").filter(|s| present(s).is_some());
    let target = get("TargetUserName").filter(|s| present(s).is_some());
    let target_domain = get("TargetDomainName").filter(|s| present(s).is_some());
    if security && GROUP_EVENTS.contains(&id) {
        if let Some(group) = target {
            out.push((f::GROUP_NAME, group.into()));
        }
        if let Some(member) = get("MemberName").filter(|s| present(s).is_some()) {
            out.push((f::USER_TARGET_NAME, member.into()));
        }
        if let Some(subject) = subject {
            out.push((f::USER_NAME, subject.into()));
        }
        if let Some(domain) = subject_domain {
            out.push((f::USER_DOMAIN, domain.into()));
        }
    } else if security && ACCOUNT_EVENTS.contains(&id) {
        if let Some(subject) = subject {
            out.push((f::USER_NAME, subject.into()));
        }
        if let Some(domain) = subject_domain {
            out.push((f::USER_DOMAIN, domain.into()));
        }
        if let Some(target) = target {
            out.push((f::USER_TARGET_NAME, target.into()));
        }
        if let Some(domain) = target_domain {
            out.push((f::USER_TARGET_DOMAIN, domain.into()));
        }
    } else if let Some(user) = target.clone().or(subject.clone()) {
        let domain = if target.is_some() {
            target_domain
        } else {
            subject_domain
        };
        out.push((f::USER_NAME, user.into()));
        if let Some(domain) = domain {
            out.push((f::USER_DOMAIN, domain.into()));
        }
    } else if let Some(account) = get("User").filter(|s| present(s).is_some()) {
        // Sysmon: `DOMAIN\user`.
        let (domain, user) = split_account(&account);
        out.push((f::USER_NAME, user.to_string().into()));
        if let Some(domain) = domain {
            out.push((f::USER_DOMAIN, domain.to_string().into()));
        }
    }

    // Network.
    if let Some(ip) = get("IpAddress").as_deref().and_then(ip_of) {
        out.push((f::SOURCE_IP, ip));
    }
    if let Some(port) = get_int("IpPort").filter(|p| *p > 0).and_then(port_of) {
        out.push((f::SOURCE_PORT, port));
    }
    if let Some(name) = get("WorkstationName").filter(|s| present(s).is_some()) {
        out.push((f::SOURCE_DOMAIN, name.into()));
    }
    if let Some(kind) = get_int("LogonType") {
        out.push((f::WINLOG_LOGON_TYPE, FieldValue::Int(kind)));
    }
    if let Some(ip) = get("SourceIp").as_deref().and_then(ip_of) {
        out.push((f::SOURCE_IP, ip));
    }
    if let Some(port) = get_int("SourcePort").and_then(port_of) {
        out.push((f::SOURCE_PORT, port));
    }
    if let Some(ip) = get("DestinationIp").as_deref().and_then(ip_of) {
        out.push((f::DESTINATION_IP, ip));
    }
    if let Some(port) = get_int("DestinationPort").and_then(port_of) {
        out.push((f::DESTINATION_PORT, port));
    }
    if let Some(name) = get("DestinationHostname").filter(|s| present(s).is_some()) {
        out.push((f::DESTINATION_DOMAIN, name.into()));
    }
    if sysmon && let Some(proto) = get("Protocol") {
        out.push((f::NETWORK_TRANSPORT, proto.to_ascii_lowercase().into()));
    }
    if let Some(name) = get("QueryName").filter(|s| present(s).is_some()) {
        out.push((f::DNS_QUESTION_NAME, name.to_ascii_lowercase().into()));
    }

    // Processes. 4688 names the new process `NewProcess*` and its creator
    // `Process*`; Sysmon uses `Image`/`ProcessId` and `Parent*`.
    let (exe, pid, parent_pid) = if security && id == 4688 {
        (
            get("NewProcessName"),
            get_int("NewProcessId"),
            get_int("ProcessId"),
        )
    } else {
        (
            get("Image").or_else(|| get("ProcessName")),
            get_int("ProcessId"),
            get_int("ParentProcessId"),
        )
    };
    if let Some(exe) = exe.filter(|s| present(s).is_some()) {
        out.push((f::PROCESS_NAME, base_name(&exe).to_string().into()));
        out.push((f::PROCESS_EXECUTABLE, exe.into()));
    }
    if let Some(pid) = pid {
        out.push((f::PROCESS_PID, FieldValue::Int(pid)));
    }
    if let Some(pid) = parent_pid {
        out.push((f::PROCESS_PARENT_PID, FieldValue::Int(pid)));
    }
    if let Some(line) = get("CommandLine").filter(|s| present(s).is_some()) {
        out.push((f::PROCESS_COMMAND_LINE, line.into()));
    }
    if let Some(dir) = get("CurrentDirectory").filter(|s| present(s).is_some()) {
        out.push((f::PROCESS_WORKING_DIRECTORY, dir.into()));
    }
    if let Some(parent) = get("ParentImage")
        .or_else(|| get("ParentProcessName"))
        .filter(|s| present(s).is_some())
    {
        out.push((
            f::PROCESS_PARENT_NAME,
            base_name(&parent).to_string().into(),
        ));
        out.push((f::PROCESS_PARENT_EXECUTABLE, parent.into()));
    }
    if let Some(line) = get("ParentCommandLine").filter(|s| present(s).is_some()) {
        out.push((f::PROCESS_PARENT_COMMAND_LINE, line.into()));
    }
    if let Some(path) = get("TargetFilename").filter(|s| present(s).is_some()) {
        out.push((f::FILE_PATH, path.into()));
    }

    // Time.
    let time = if sysmon {
        get("UtcTime").and_then(|t| parse_time(&t, true))
    } else {
        None
    }
    .or_else(|| {
        map.get("EventTime")
            .or_else(|| map.get("TimeCreated"))
            .and_then(Value::as_str)
            .and_then(|t| parse_time(t, false))
    });
    if let Some(time) = time {
        raw.original_time = time;
    }

    for (key, value) in data {
        if let Some(value) = FieldValue::from_json(value) {
            raw.insert_field(format!("{}{key}", f::WINLOG_EVENT_DATA_PREFIX), value);
        }
    }
    for (key, value) in out {
        raw.insert_field(key, value);
    }
    ParseResult::Success(raw.into_event())
}

/// [`parse_windows_json`] as a [`LogParser`] named `windows_json`, ready to
/// register.
pub fn windows_json_parser() -> LogParser {
    LogParser::new(
        "windows_json",
        "Windows event log (JSON)",
        "Parses Windows event log records shipped as JSON by NXLog or Fluent Bit",
        parse_windows_json,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use usiem::event::{CoreEvent, Origin};

    fn parse(json: &str) -> CoreEvent {
        let raw = RawEvent::new(
            json.into(),
            Timestamp::from_secs(1),
            Origin::from_hostname("h"),
        );
        match parse_windows_json(raw) {
            ParseResult::Success(e) => e,
            _ => panic!("no match: {json}"),
        }
    }

    fn s(e: &CoreEvent, field: &str) -> String {
        e.get_field(field)
            .map_or_else(|| panic!("missing {field}"), ToString::to_string)
    }

    const NXLOG_4625: &str = r#"{"EventTime":"2026-11-05 10:00:00 +0100","Hostname":"DESKTOP-1.home.lan","Keywords":"9227830359843504128","EventType":"AUDIT_FAILURE","SeverityValue":4,"Severity":"ERROR","EventID":4625,"SourceName":"Microsoft-Windows-Security-Auditing","RecordNumber":123456,"ProcessID":712,"Channel":"Security","Message":"An account failed to log on.","SubjectUserSid":"S-1-0-0","SubjectUserName":"-","SubjectDomainName":"-","TargetUserName":"admin","TargetDomainName":"DESKTOP-1","Status":"0xc000006d","FailureReason":"%%2313","LogonType":"3","WorkstationName":"KALI","IpAddress":"192.168.1.66","IpPort":"0","EventReceivedTime":"2026-11-05 10:00:01","SourceModuleName":"eventlog","SourceModuleType":"im_msvistalog"}"#;

    #[test]
    fn nxlog_failed_logon() {
        let e = parse(NXLOG_4625);
        assert_eq!(s(&e, f::WINLOG_EVENT_ID), "4625");
        assert_eq!(s(&e, f::EVENT_CODE), "4625");
        assert_eq!(s(&e, f::EVENT_DATASET), "windows.security");
        assert_eq!(s(&e, f::EVENT_ACTION), "logon-failed");
        assert_eq!(s(&e, f::EVENT_OUTCOME), "failure");
        assert_eq!(s(&e, f::EVENT_CATEGORY), "authentication");
        assert_eq!(s(&e, f::HOST_NAME), "DESKTOP-1.home.lan");
        assert_eq!(s(&e, f::USER_NAME), "admin");
        assert_eq!(s(&e, f::USER_DOMAIN), "DESKTOP-1");
        assert_eq!(s(&e, f::SOURCE_IP), "192.168.1.66");
        assert!(
            e.get_field(f::SOURCE_PORT).is_none(),
            "port 0 is not a port"
        );
        assert_eq!(s(&e, f::SOURCE_DOMAIN), "KALI");
        assert_eq!(s(&e, f::WINLOG_LOGON_TYPE), "3");
        assert_eq!(s(&e, f::WINLOG_RECORD_ID), "123456");
        assert_eq!(s(&e, f::LOG_LEVEL), "error");
        assert_eq!(s(&e, "winlog.event_data.Status"), "0xc000006d");
        assert!(e.get_field("winlog.event_data.EventReceivedTime").is_none());
        // 10:00 at +01:00 is 09:00 UTC.
        assert_eq!(
            e.original_time(),
            Timestamp::from_rfc3339("2026-11-05T09:00:00Z").unwrap()
        );
    }

    #[test]
    fn nxlog_group_add_and_process_creation() {
        let e = parse(
            r#"{"EventTime":"2026-11-05T10:00:00Z","Hostname":"DC1","EventID":4732,"Channel":"Security","SourceName":"Microsoft-Windows-Security-Auditing","MemberName":"-","MemberSid":"S-1-5-21-1-1001","TargetUserName":"Administrators","TargetDomainName":"Builtin","SubjectUserName":"alice","SubjectDomainName":"HOME"}"#,
        );
        assert_eq!(s(&e, f::EVENT_ACTION), "added-member-to-group");
        assert_eq!(s(&e, f::EVENT_CATEGORY), "iam");
        assert_eq!(s(&e, f::GROUP_NAME), "Administrators");
        assert_eq!(s(&e, f::USER_NAME), "alice");
        assert!(e.get_field(f::USER_TARGET_NAME).is_none());
        assert_eq!(s(&e, "winlog.event_data.MemberSid"), "S-1-5-21-1-1001");

        let e = parse(
            r#"{"EventID":4688,"Channel":"Security","Hostname":"PC","SubjectUserName":"bob","NewProcessId":"0x1a2b","NewProcessName":"C:\\Windows\\System32\\cmd.exe","ProcessId":"0x10","ParentProcessName":"C:\\Windows\\explorer.exe","CommandLine":"cmd.exe /c whoami","TargetUserName":"-"}"#,
        );
        assert_eq!(s(&e, f::EVENT_CATEGORY), "process");
        assert_eq!(s(&e, f::USER_NAME), "bob");
        assert_eq!(s(&e, f::PROCESS_PID), "6699");
        assert_eq!(s(&e, f::PROCESS_PARENT_PID), "16");
        assert_eq!(s(&e, f::PROCESS_NAME), "cmd.exe");
        assert_eq!(s(&e, f::PROCESS_PARENT_NAME), "explorer.exe");
        assert_eq!(s(&e, f::PROCESS_COMMAND_LINE), "cmd.exe /c whoami");
        // No time with an offset: the receive time stays.
        assert_eq!(e.original_time(), Timestamp::from_secs(1));
    }

    #[test]
    fn sysmon_process_and_dns() {
        let e = parse(
            r#"{"EventTime":"2026-11-05 11:00:00","Hostname":"PC","EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","SourceName":"Microsoft-Windows-Sysmon","UtcTime":"2026-11-05 10:00:00.123","ProcessGuid":"{1}","ProcessId":4242,"Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell -enc AAAA","CurrentDirectory":"C:\\Users\\bob\\","User":"PC\\bob","Hashes":"SHA256=ABC","ParentProcessId":100,"ParentImage":"C:\\Windows\\explorer.exe","ParentCommandLine":"C:\\Windows\\Explorer.EXE"}"#,
        );
        assert_eq!(s(&e, f::EVENT_DATASET), "windows.sysmon");
        assert_eq!(s(&e, f::EVENT_ACTION), "process-created");
        assert_eq!(s(&e, f::EVENT_CATEGORY), "process");
        assert_eq!(s(&e, f::PROCESS_NAME), "powershell.exe");
        assert_eq!(s(&e, f::PROCESS_PID), "4242");
        assert_eq!(s(&e, f::PROCESS_PARENT_PID), "100");
        assert_eq!(s(&e, f::PROCESS_COMMAND_LINE), "powershell -enc AAAA");
        assert_eq!(s(&e, f::USER_NAME), "bob");
        assert_eq!(s(&e, f::USER_DOMAIN), "PC");
        assert_eq!(
            e.original_time(),
            Timestamp::from_rfc3339("2026-11-05T10:00:00.123Z").unwrap()
        );

        let e = parse(
            r#"{"EventID":22,"Channel":"Microsoft-Windows-Sysmon/Operational","QueryName":"Evil.Example","Image":"C:\\x.exe"}"#,
        );
        assert_eq!(s(&e, f::DNS_QUESTION_NAME), "evil.example");
        assert_eq!(s(&e, f::EVENT_CATEGORY), "network");
    }

    #[test]
    fn ports_out_of_range_are_dropped() {
        let e = parse(
            r#"{"EventID":3,"Channel":"Microsoft-Windows-Sysmon/Operational","SourceIp":"10.0.0.5","SourcePort":-1,"DestinationIp":"10.0.0.6","DestinationPort":70000}"#,
        );
        assert!(e.get_field(f::SOURCE_PORT).is_none());
        assert!(e.get_field(f::DESTINATION_PORT).is_none());
        let e = parse(r#"{"EventID":4625,"Channel":"Security","IpPort":"65536"}"#);
        assert!(e.get_field(f::SOURCE_PORT).is_none());
        let e = parse(r#"{"EventID":4625,"Channel":"Security","IpPort":"65535"}"#);
        assert_eq!(s(&e, f::SOURCE_PORT), "65535");
    }

    #[test]
    fn fluent_bit_shape() {
        let e = parse(
            r#"{"ProviderName":"Service Control Manager","EventID":7045,"Level":4,"TimeCreated":"2026-11-05 10:00:00 +0000","EventRecordID":99,"Channel":"System","Computer":"PC","Keywords":"0x8080000000000000","Message":"A service was installed","StringInserts":["Evil","C:\\evil.exe","user mode service","demand start","LocalSystem"]}"#,
        );
        assert_eq!(s(&e, f::EVENT_ACTION), "service-installed");
        assert_eq!(s(&e, f::EVENT_PROVIDER), "Service Control Manager");
        assert_eq!(s(&e, f::HOST_NAME), "PC");
        assert_eq!(s(&e, f::LOG_LEVEL), "information");
        assert_eq!(s(&e, f::WINLOG_RECORD_ID), "99");
        assert_eq!(s(&e, "winlog.event_data.param1"), "Evil");
        assert_eq!(s(&e, "winlog.event_data.param2"), "C:\\evil.exe");
        assert!(e.get_field("winlog.event_data.StringInserts").is_none());
        assert_eq!(
            e.original_time(),
            Timestamp::from_rfc3339("2026-11-05T10:00:00Z").unwrap()
        );

        // Audit failure from the keyword bits.
        let e = parse(
            r#"{"EventID":4776,"Channel":"Security","Keywords":"0x8010000000000000","StringInserts":[]}"#,
        );
        assert_eq!(s(&e, f::EVENT_OUTCOME), "failure");
    }

    #[test]
    fn other_json_is_left_alone() {
        for text in [
            r#"{"msg":"hello"}"#,
            r#"{"EventID":1}"#,
            r#"{"EventID":"x","Channel":"Security"}"#,
            r#"{"EventID":4624,"Channel":"Security""#,
            "plain text EventID Channel",
        ] {
            let raw = RawEvent::new(
                text.into(),
                Timestamp::from_secs(1),
                Origin::from_hostname("h"),
            );
            assert!(
                matches!(parse_windows_json(raw), ParseResult::NoMatch(_)),
                "{text}"
            );
        }
    }

    #[test]
    fn dataset_names() {
        assert_eq!(
            dataset_of("Microsoft-Windows-TaskScheduler/Operational"),
            "windows.microsoft_windows_taskscheduler_operational"
        );
        assert_eq!(dataset_of("Windows PowerShell"), "windows.powershell");
    }
}
