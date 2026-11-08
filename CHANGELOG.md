# Changelog

All notable changes to this crate are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/). Release tags are the bare version,
with no prefix (`0.1.0`).

## [Unreleased]

## [0.1.0]

First public release.

### Added

- `linux`: OpenSSH `sshd` logins, failed attempts and invalid users; `sudo`
  commands and authentication failures; netfilter `LOG` lines from
  iptables, nftables and UFW.
- `network`: pfSense / OPNsense `filterlog` CSV records (IPv4 and IPv6);
  dnsmasq and Pi-hole DNS queries, replies and DHCP, also when embedded in
  another line.
- `windows`: Windows event log JSON from NXLog (flattened) or Fluent Bit
  (`StringInserts`), with every event data member kept as
  `winlog.event_data.<Name>` and the well-known ones mapped to ECS.
- Fuzz targets (`fuzz/`) and a stable test over garbled input.

[Unreleased]: https://github.com/u-siem/parsers/compare/0.1.0...HEAD
[0.1.0]: https://github.com/u-siem/parsers/releases/tag/0.1.0
