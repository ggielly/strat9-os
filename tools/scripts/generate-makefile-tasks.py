#!/usr/bin/env python3
"""generate-makefile-tasks.py : Auto-generate Makefile.toml build tasks for workspace components.

Scans workspace/components/ and workspace/components/netutils/ for crates
with binary targets, then generates cargo-make tasks (debug, release, dev-opt).

Usage:
    python3 tools/scripts/generate-makefile-tasks.py [--dry-run]
"""

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
COMPONENTS_DIR = ROOT / "workspace" / "components"
MAKEFILE = ROOT / "Makefile.toml"

SKIP_DIRS = {
    "api", "alloc-freelist", "musl-compat", "strat9-config",
    "strate-bus", "strate-fs-abstraction",
}


def find_binary_crates():
    """Find all crates with binary targets."""
    crates = {}

    for base in [COMPONENTS_DIR, COMPONENTS_DIR / "netutils"]:
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            if not d.is_dir():
                continue
            if d.name in SKIP_DIRS:
                continue

            toml = d / "Cargo.toml"
            if not toml.exists():
                continue

            content = toml.read_text()

            # Check for [[bin]] section
            has_bin = bool(re.search(r'^\[\[bin\]\]', content, re.MULTILINE))

            # Check for src/main.rs (default binary target)
            has_main = (d / "src" / "main.rs").exists()

            if not has_bin and not has_main:
                continue

            # Get binary name
            if has_bin:
                m = re.search(r'\[\[bin\]\]\s*\nname\s*=\s*"([^"]+)"', content)
                bin_name = m.group(1) if m else d.name
            else:
                # Use package name
                m = re.search(r'^name\s*=\s*"([^"]+)"', content, re.MULTILINE)
                bin_name = m.group(1) if m else d.name

            # Cargo path relative to root
            cargo_path = str(d.relative_to(ROOT))

            crates[d.name] = {
                "bin_name": bin_name,
                "cargo_path": cargo_path,
                "has_bin": has_bin,
            }

    return crates


def generate_task(name, description, cwd, profile=""):
    """Generate a Makefile.toml task."""
    profile_args = ""
    if profile:
        profile_args = f'    "--profile",\n    "{profile}",'

    return f'''[tasks.{name}]
description = "{description}"
cwd = "{cwd}"
command = "cargo"
args = [
    "build",
    "--target",
    "x86_64-unknown-none",
{profile_args}
    "-Z",
    "build-std=core,alloc",
    "-Z",
    "build-std-features=compiler-builtins-mem",
]
'''


def main():
    dry_run = "--dry-run" in sys.argv

    crates = find_binary_crates()

    print("=== Discovered binary crates ===")
    for name, info in sorted(crates.items()):
        print(f"  {name} -> {info['bin_name']} ({info['cargo_path']})")
    print()

    # Generate tasks
    # Strip "strate-" prefix from dir name to avoid doubling (e.g. strate-strate-init)
    tasks_to_add = []
    for name, info in sorted(crates.items()):
        dir_name = name
        bin_name = info["bin_name"]
        cargo_path = info["cargo_path"]

        # Derive task name: strip "strate-" if present, then re-add it
        if dir_name.startswith("strate-"):
            task_base = dir_name  # e.g. strate-init, strate-graphical
        else:
            task_base = f"strate-{dir_name}"  # e.g. strate-dhcp-client

        task_debug = task_base
        task_release = f"{task_base}-release"
        task_devopt = f"{task_base}-dev-opt"

        tasks_to_add.append((task_debug, f"Build {bin_name} (debug)", cargo_path, ""))
        tasks_to_add.append((task_release, f"Build {bin_name} (release)", cargo_path, "release"))
        tasks_to_add.append((task_devopt, f"Build {bin_name} (dev-opt)", cargo_path, "dev-opt"))

    # Check which tasks already exist
    makefile_content = MAKEFILE.read_text()
    new_tasks = []
    for task_name, desc, cwd, profile in tasks_to_add:
        if f"[tasks.{task_name}]" not in makefile_content:
            new_tasks.append((task_name, desc, cwd, profile))

    if new_tasks:
        print(f"=== {len(new_tasks)} new tasks to add ===")
        for task_name, desc, cwd, profile in new_tasks:
            print(f"  + {task_name}")

        if not dry_run:
            with open(MAKEFILE, "a") as f:
                for task_name, desc, cwd, profile in new_tasks:
                    f.write("\n")
                    f.write(generate_task(task_name, desc, cwd, profile))
            print(f"  Written to {MAKEFILE}")
    else:
        print("=== No new tasks needed ===")

    print()
    print("=== Done ===")


if __name__ == "__main__":
    main()
