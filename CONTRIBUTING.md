# Contributing

Thanks for helping. Issues and pull requests are welcome, and so are sample
log lines a parser gets wrong (with addresses and names replaced by
documentation values such as `192.0.2.4` and `example.com`).

## Before you open a pull request

CI runs all of these; running them first saves a round trip.

```sh
cargo fmt --all --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo deny check                # https://github.com/EmbarkStudios/cargo-deny
```

The minimum supported Rust version is 1.89. CI tests it, along with Linux,
Windows and macOS.

## Working against a local uSIEM checkout

The crate depends on [uSIEM](https://github.com/u-siem/usiem) by git, at a
pinned revision. To build against a checkout next to this one (`../usiem`)
instead, override the git source on the command line:

```sh
cargo test --config "patch.'https://github.com/u-siem/usiem'.usiem.path='../usiem'"
```

That rewrites `Cargo.lock` to point at the path; do not commit the lockfile
it produces (`git checkout Cargo.lock` afterwards). To move to a newer uSIEM,
change `rev` in `Cargo.toml` and `fuzz/Cargo.toml`, then run `cargo update -p
usiem` in both places.

## Parser changes

- Every recognised message shape has a unit test next to the parser, with
  the fields it produces.
- A bug fix comes with a regression test that fails without it.
- Use the field constants in `usiem::event::fields`; ECS names where ECS has
  one.
- Input is untrusted: no `unwrap`, no slicing at indices that are not known
  char boundaries, no unbounded per-line work. `tests/garbled_input.rs` runs
  every parser over damaged versions of its sample lines; add new sample
  lines there too.
- Note user-visible changes under `Unreleased` in `CHANGELOG.md`.

## Fuzzing

The parsers face untrusted input, so they are fuzzed with
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (nightly):

```sh
cargo +nightly fuzz run parse_line      # every parser, any program name
cargo +nightly fuzz run windows_json    # Windows event JSON field mapping
```

CI runs each target daily and on pull requests that touch `src/`. A crash
found by fuzzing belongs in a regular test once fixed.

## Releases

Maintainers release by bumping `version` in `Cargo.toml`, moving the
`Unreleased` changelog entries under the new version, and pushing a tag that
is exactly the version, with no prefix: `git tag 0.2.0 && git push origin 0.2.0`.
The release workflow checks the tag, runs CI and creates the GitHub release.
The crate is not published to crates.io while it depends on uSIEM by git.
