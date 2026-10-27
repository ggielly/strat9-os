# XFS filesystem

Based on the [crisscross-rs](https://github.com/crissdev/crisscross-rs) project (an XFS implementation for Windows). Intended for snapshot support in silos.

**Status: deactivated.** The crate is **excluded from the Cargo workspace** — its
`Cargo.toml` has a missing `strate-fs-abstraction` dependency, so `cargo` will not
resolve it. It is therefore not built, not tested, and produces no rustdoc page
in the published documentation site.

## Blockers

- Must be `#![no_std]`; the upstream project is `std`.
- The `strate-fs-abstraction` path dependency is unresolved.
- No ext4-style integration with the kernel VFS or the `SYS_VOLUME_*` layer.
