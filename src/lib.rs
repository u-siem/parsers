//! Log parsers for uSIEM.
//!
//! Each parser is a [`LogParser`](usiem::ingest::parser::LogParser) for a
//! [`ParserRegistry`](usiem::ingest::parser::registry::ParserRegistry). It
//! reads the message body after a syslog transport parser has run, or a
//! JSON object received without a syslog header.
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

pub mod linux;
pub mod network;
pub mod windows;
