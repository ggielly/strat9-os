# Publishing

## One-command publication script

At repository root:

```bash
./publish-doc.sh
```

This script:

1. builds the docs site (`cargo make docs-site`)
2. stages `docs-site/`, `tools/scripts/build-docs-site.sh`, `.gitlab-ci.yml`, `publish-doc.sh` and `Makefile.toml`
3. commits and pushes the current branch
4. uploads `build/docs-site/` to the remote vhost over SSH (rsync with `--delete`)

Useful flags: `--no-commit`, `--no-push`, `--no-vhost-upload`, `--all-changes` (stage everything with `git add -A` instead of the fixed path list), and `-m "message"`.

### Deployment target

| Variable | Default |
|----------|---------|
| `VHOST_SSH_ALIAS` | `strat9web` |
| `VHOST_SSH_PORT` | `2223` (forwards to the edge-nginx container on `10.10.10.10:22`; the historical `32222` is closed) |
| `VHOST_REMOTE_PATH` | `/var/www/ram_strat9/api.strat9-os.org/public` |
| `REMOTE_NAME` | `origin` |

OVMF firmware images are never uploaded: the script copies `OVMF_VARS.fd` to a scratch path so the packaged file stays pristine.

## What the builder does

`tools/scripts/build-docs-site.sh` (invoked by `cargo make docs-site`, and the `docs-serve` task serves the result on port 8000):

1. **Refreshes the ABI changelog** — reads `ABI_VERSION_MAJOR` / `ABI_VERSION_MINOR` straight out of `workspace/abi/src/lib.rs`, then regenerates the block between `<!-- AUTO-ABI-CHANGELOG:START -->` and `<!-- AUTO-ABI-CHANGELOG:END -->` in `docs-site/src/abi-changelog.md` from the git history of `workspace/abi`, `workspace/components/syscall` and `workspace/kernel/src/syscall` (last 30 commits).
2. **Refreshes the global changelog** — same technique for `docs-site/src/changelog.md`, from the last 50 commits of any path, plus a total-commit count and the latest tag.
3. **Runs `cargo doc` for every workspace package** in *resilient* mode: each package is documented individually with `--no-deps --document-private-items`, and a failure is logged and stepped over rather than aborting the build. Packages that fail are listed at the end.
4. **Builds the mdBook pages** with `mdbook build docs-site`.
5. **Assembles `build/docs-site/`** — the mdBook output at the root, `target/doc` merged into `api/`, and a `.nojekyll` marker. It then writes a generated `api/index.html` listing every crate that produced documentation.
6. **Checks for broken links** with `tools/scripts/check-links.py --site-dir build/docs-site`. This step is best-effort: a failure prints a warning and the build still succeeds.

## Running the pieces by hand

```bash
bash tools/scripts/build-docs-site.sh                              # full build
python3 -m http.server --directory build/docs-site 8000            # serve locally
python3 tools/scripts/check-links.py --site-dir build/docs-site    # link check only
mdbook serve docs-site                                              # live-reload preview
```

## Notes for contributors

- The two auto-generated blocks are **owned by the build script**. Anything you write between the `AUTO-CHANGELOG` / `AUTO-ABI-CHANGELOG` markers will be overwritten on the next run. Put prose outside them.
- Because the changelog blocks are regenerated from `git log`, running the script produces a diff even when no source changed. That is expected.
- Rustdoc is built per package, so a crate that fails to document is simply missing from the `api/` tree. The `abi-matrix.md` and `index.md` pages link to `api/<crate_with_underscores>/index.html`; a link to a crate that failed to build will show up in the link check.
- `workspace/components/strate-fs-xfs` is excluded from the Cargo workspace and therefore has no API page.
