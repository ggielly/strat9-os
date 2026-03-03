# Publishing

## GitHub Pages (recommended)

This repository includes a workflow that publishes this docs site to GitHub Pages.

### One-time setup

Run once from the repository root:

```bash
gh repo edit --enable-pages --pages-source=gh-pages
```

If your GitHub organization/repo policy requires it, set Pages source to **GitHub Actions** in repository settings.

### Trigger publication

- Push to `main`, or
- Run the workflow manually from Actions tab (`workflow_dispatch`)

## One-command publication script

At repository root:

```bash
./publish-doc.sh
```

This script:

1. builds docs (`cargo make docs-site`)
2. commits changes
3. pushes current branch
4. triggers `Publish Docs` workflow with `gh`

The workflow builds:

1. rustdoc for `strat9-abi` and `strat9-syscall`
2. mdBook pages under `docs-site/`
3. A combined site served by Pages
