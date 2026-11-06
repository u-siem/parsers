# usiem-parsers

Log parsers for [uSIEM](../usiem): content parsers that turn the body of a log line into ECS-style fields. The uSIEM core provides the framework (`LogParser`, `ParserRegistry`, the syslog transport parsers and the field constants); the parsers for particular sources live here.

| Module | Parser | Recognises | Main fields |
|---|---|---|---|
| `linux` | `sshd_parser()` | OpenSSH accepted/failed logins, invalid users | `event.action` (`ssh_login`), `event.outcome`, `user.name`, `user.invalid`, `source.ip`, `source.port`, `ssh.method` |
| `linux` | `sudo_parser()` | sudo commands, authentication failures, users not in sudoers | `event.action`, `event.outcome`, `user.name`, `user.target.name`, `process.command_line`, `process.working_directory` |
| `linux` | `netfilter_parser()` | kernel `LOG` lines from iptables, nftables and UFW | `event.action` (`allowed`/`blocked`), `source.ip`, `destination.ip`, ports, `network.transport` |
| `network` | `filterlog_parser()` | pfSense / OPNsense `filterlog` CSV, IPv4 and IPv6 | `event.action`, `network.direction`, `rule.id`, `rule.uuid`, `observer.ingress.interface`, addresses and ports |
| `network` | `dnsmasq_parser()` | dnsmasq and Pi-hole DNS queries, replies and DHCP, also embedded in another line | `dns.question.name`, `dns.resolved_ip`, `dns.response_code`, `client.ip`, `client.mac`, `client.domain` |
| `windows` | `windows_json_parser()` | Windows event log JSON from NXLog (flattened) or Fluent Bit (`StringInserts`) | `winlog.*`, every EventData member as `winlog.event_data.<Name>`, and the well-known ones mapped to ECS |

`sshd`, `sudo`, `filterlog` and `dnsmasq` check the syslog program name first, so for other programs they cost one string comparison.

## Use

```rust
use usiem::ingest::parser::registry::ParserRegistry;
use usiem_parsers::{linux, network, windows};

let mut registry = ParserRegistry::new();
registry.register(linux::sshd_parser());
registry.register(linux::sudo_parser());
registry.register(network::filterlog_parser());
registry.register(network::dnsmasq_parser());
registry.register(windows::windows_json_parser());
registry.register(linux::netfilter_parser());
```

A Windows record whose time has no UTC offset keeps its receive time; only Sysmon's `UtcTime` is read as UTC.

## Development

`cargo test`, `cargo clippy --all-targets` and `cargo fmt` should be clean. It follows uSIEM's conventions: no `thiserror`/`anyhow`, few dependencies.
