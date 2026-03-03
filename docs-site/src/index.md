# Strat9 Docs

This website is generated from:

- **mdBook pages** for architecture and usage guides
- **rustdoc API pages** for ABI and syscall crates

## API reference

- [strat9-abi crate](../api/strat9_abi/index.html)
- [strat9-syscall crate](../api/strat9_syscall/index.html)
- [Rustdoc index](../api/index.html)

## Local generation

```bash
bash tools/scripts/build-docs-site.sh
python3 -m http.server --directory build/docs-site 8000
```
