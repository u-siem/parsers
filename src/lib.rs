//! # Log parsers for uSIEM
//!
//! Content parsers that turn the body of a log line into ECS-style fields.
//! The [uSIEM](https://github.com/u-siem/usiem) core provides the framework
//! ([`LogParser`](usiem::ingest::parser::LogParser),
//! [`ParserRegistry`](usiem::ingest::parser::registry::ParserRegistry), the
//! syslog transport parsers and the field constants); the parsers for
//! particular sources live here.
//!
//! Each parser reads the message body after a syslog transport parser has
//! run, or a JSON object received without a syslog header.
//!
//! - [`linux`]: OpenSSH `sshd`, `sudo`, and netfilter (`iptables`,
//!   `nftables`, UFW) `LOG` lines.
//! - [`network`]: the pfSense / OPNsense packet filter (`filterlog`) and
//!   dnsmasq (DNS and DHCP, as Pi-hole runs it).
//! - [`windows`]: Windows event log records as NXLog or Fluent Bit ship
//!   them in JSON.
//!
//! Fields follow ECS where it has a name, using the constants in
//! [`usiem::event::fields`].
//!
//! The input is untrusted: it arrives from the network, and parts of it
//! (user names, DNS names, event data) are chosen by whoever caused the
//! event. A parser never panics on it; a line it does not recognise comes
//! back as [`ParseResult::NoMatch`](usiem::ingest::parser::result::ParseResult::NoMatch)
//! for the next parser.
//!
//! ## Example
//!
//! Register the parsers, then parse an sshd line as a syslog transport
//! parser would hand it over:
//!
//! ```
//! use usiem::event::fields as f;
//! use usiem::event::{Origin, RawEvent, Timestamp};
//! use usiem::ingest::parser::registry::ParserRegistry;
//! use usiem::ingest::parser::result::ParseResult;
//! use usiem_parsers::{linux, network, windows};
//!
//! let mut registry = ParserRegistry::new();
//! registry.register(linux::sshd_parser());
//! registry.register(linux::sudo_parser());
//! registry.register(network::filterlog_parser());
//! registry.register(network::dnsmasq_parser());
//! registry.register(windows::windows_json_parser());
//! // Content-matched, so after the parsers that check the program name.
//! registry.register(linux::netfilter_parser());
//!
//! let mut raw = RawEvent::new(
//!     "Failed password for invalid user admin from 192.0.2.4 port 51234 ssh2".into(),
//!     Timestamp::now(),
//!     Origin::from_hostname("bastion"),
//! );
//! raw.insert_field("transport.syslog.process", "sshd".to_string());
//!
//! let ParseResult::Success(event) = linux::parse_sshd(raw) else {
//!     panic!("not an sshd login");
//! };
//! assert_eq!(event.get_field(f::EVENT_OUTCOME).map(ToString::to_string).as_deref(), Some("failure"));
//! assert_eq!(event.get_field(f::SOURCE_IP).map(ToString::to_string).as_deref(), Some("192.0.2.4"));
//! ```

pub mod linux;
pub mod network;
pub mod windows;
