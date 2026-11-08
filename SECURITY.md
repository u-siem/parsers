# Security policy

These parsers read log lines that arrive from the network, and parts of a
line (user names, DNS names, event data) are chosen by whoever caused the
event. Bugs that let such input crash the parser (panics), use unbounded
memory or CPU, or put attacker-chosen values into fields a detection trusts
(for example a spoofed `source.ip`) are security issues.

## Reporting a vulnerability

Please report privately through
[GitHub security advisories](https://github.com/u-siem/parsers/security/advisories/new),
not in a public issue. Include the version or commit, and if you can, the
log line or a test that reproduces the problem.

You should get an answer within a week. Once a fix is released, the advisory
is published and credited to you unless you prefer otherwise.

## Supported versions

Before 1.0, only the latest release gets fixes.
