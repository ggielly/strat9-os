# Publishing

## One-command publication script

At repository root:

```bash
./publish-doc.sh
```

This script:

1. builds docs (`cargo make docs-site`)
2. regenerates ABI changelog auto section from git history
3. commits/pushes current branch changes
4. uploads built website to `ggielly.github.io/strat9-os-docs`

The docs builder publishes:

1. mdBook pages under `docs-site/`
2. rustdoc for all workspace crates (`cargo doc --workspace --no-deps`)
3. a combined static site in `build/docs-site`
