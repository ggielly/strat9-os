#!/usr/bin/env python3
"""Initfs packaging regressions: synthetic files only, no compilation or images."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib
import unittest

REPO = Path(__file__).resolve().parents[3]
LIBRARY = REPO / "tools/scripts/uefi-modules.sh"
MANIFEST = REPO / "tools/uefi-modules.manifest"
BASH = os.environ.get("STRAT9_TEST_BASH") or shutil.which("bash")


def manifest_rows():
    return [line.split() for line in MANIFEST.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]


class InitfsPackagingTests(unittest.TestCase):
    def setUp(self):
        self.scratch_parent = (REPO / "build").resolve()
        self.scratch_parent.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="initfs-test-", dir=self.scratch_parent)
        self.root = Path(self.temp.name).resolve()
        self.release = self.root / "release"
        self.debug = self.root / "debug"
        self.destination = self.root / "initfs"
        for path in (self.release, self.debug, self.destination):
            path.mkdir()

    def tearDown(self):
        # Verify the resolved absolute target before recursive fixture cleanup.
        if self.root.parent != self.scratch_parent or not self.root.name.startswith("initfs-test-"):
            raise RuntimeError("refusing cleanup outside the owned fixture directory")
        self.temp.cleanup()

    def bash(self, body, *args, ok=True):
        if not BASH:
            self.fail("bash is required; set STRAT9_TEST_BASH to its executable")
        child_env = os.environ.copy()
        if os.name == "nt":
            # A non-login Git Bash started from PowerShell needs its coreutils.
            for candidate in [Path(BASH).parent.parent / "usr/bin", Path(BASH).parent]:
                if (candidate / "od.exe").is_file():
                    child_env["PATH"] = str(candidate) + os.pathsep + child_env.get("PATH", "")
                    break
        result = subprocess.run(
            [BASH, "--noprofile", "--norc", "-c",
             'set -euo pipefail; source "$1"; shift; ' + body,
             "initfs-test", str(LIBRARY), *(str(arg) for arg in args)],
            cwd=REPO, env=child_env, text=True, capture_output=True, timeout=20,
        )
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ERROR:", result.stderr)
        return result

    def populate(self, include_tests=False):
        names = [name for group, name, _ in manifest_rows() if group == "base" or include_tests]
        for name in names:
            (self.release / name).write_bytes(b"\x7fELF\x02\x01release:" + name.encode())
        return names

    def validate(self, include_tests=0, manifest=MANIFEST, ok=True):
        return self.bash('strat9_validate_module_sources "$1" "$2" "$3"',
                         self.release, manifest, include_tests, ok=ok)

    def test_release_payloads_are_copied_without_debug_or_unlisted_residue(self):
        names = self.populate()
        for name in names:
            (self.debug / name).write_bytes(b"\x7fELF\x02\x01STALE DEBUG")
        (self.release / "obsolete-executable").write_bytes(b"\x7fELF\x02\x01obsolete")
        self.bash('strat9_validate_module_sources "$1" "$2" 0; strat9_copy_modules "$1" "$3"',
                  self.release, MANIFEST, self.destination)
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), sorted(names))
        for name in names:
            self.assertEqual((self.destination / name).read_bytes(), (self.release / name).read_bytes())

    def test_missing_required_file_fails_before_any_copy(self):
        self.populate()
        (self.release / "web-admin").unlink()
        marker = self.destination / "existing-staging"
        marker.write_bytes(b"preserved")
        result = self.bash(
            'strat9_validate_module_sources "$1" "$2" 0; strat9_copy_modules "$1" "$3"',
            self.release, MANIFEST, self.destination, ok=False)
        self.assertIn("web-admin", result.stderr)
        self.assertEqual(list(self.destination.iterdir()), [marker])
        self.assertEqual(marker.read_bytes(), b"preserved")

    def test_test_modules_are_required_only_when_selected(self):
        self.assertEqual(len(self.populate()), 14)
        self.validate(0)
        result = self.validate(1, ok=False)
        self.assertIn("test_pid", result.stderr)
        names = self.populate(include_tests=True)
        self.assertEqual(len(names), 22)
        self.bash('strat9_validate_module_sources "$1" "$2" 1; strat9_copy_modules "$1" "$3"',
                  self.release, MANIFEST, self.destination)
        self.assertEqual(len(list(self.destination.iterdir())), 22)
        self.validate(2, ok=False)

    def test_empty_wrong_class_or_wrong_endian_modules_fail(self):
        self.populate()
        for payload in [b"", b"not an ELF", b"\x7fELF\x01\x01", b"\x7fELF\x02\x02"]:
            with self.subTest(payload=payload):
                (self.release / "strate-init").write_bytes(payload)
                result = self.validate(ok=False)
                self.assertIn("strate-init", result.stderr)

    def test_manifest_rejects_aliases_paths_missing_init_and_excess_count(self):
        malformed = self.root / "bad.manifest"
        cases = [
            "base strate-init producer\nbase STRATE-INIT producer\n",
            "base strate-init producer\nbase ../escape producer\n",
            "base strate-init producer\nbase café producer\n",
            "base strate-init producer\nbase name. producer\n",
            "unknown strate-init producer\n",
            "base web-admin producer\n",
            "base strate-init\n",
            "base strate-init producer unexpected\n",
            "base strate-init producer\n" + "".join(f"base mod-{i} producer\n" for i in range(64)),
        ]
        for text in cases:
            with self.subTest(manifest=text):
                malformed.write_text(text, encoding="utf-8")
                self.bash('strat9_read_module_manifest "$1" 1', malformed, ok=False)

    def test_full_abi_name_length_is_copied_without_truncation(self):
        self.populate()
        custom = self.root / "long.manifest"
        name = "a" * 63
        custom.write_text(f"base strate-init producer\nbase {name} producer\n")
        (self.release / name).write_bytes(b"\x7fELF\x02\x01long-name")
        self.bash('strat9_validate_module_sources "$1" "$2" 0; strat9_copy_modules "$1" "$3"',
                  self.release, custom, self.destination)
        self.assertTrue((self.destination / name).is_file())
        custom.write_text(f"base strate-init producer\nbase {name}a producer\n")
        self.validate(manifest=custom, ok=False)

    def test_cargo_make_profiles_and_dependencies_match_the_manifest(self):
        with (REPO / "Makefile.toml").open("rb") as source:
            tasks = tomllib.load(source)["tasks"]
        for task_name, kernel_profile, include_tests in [
            ("uefi-image", "debug", "0"),
            ("uefi-image-release", "release", "0"),
            ("selftest-image", "debug", "1"),
        ]:
            task = tasks[task_name]
            self.assertEqual(task["env"]["STRAT9_PROFILE"], kernel_profile)
            self.assertEqual(task["env"]["STRAT9_MODULE_PROFILE"], "release")
            self.assertEqual(task["env"]["STRAT9_INCLUDE_TESTS"], include_tests)
            for group, name, producer in manifest_rows():
                if group == "test" and include_tests == "0":
                    continue
                self.assertIn(producer, task["dependencies"], (task_name, name))
                self.assertIn("--release", tasks[producer]["args"])
                cargo_file = REPO / tasks[producer]["cwd"] / "Cargo.toml"
                with cargo_file.open("rb") as source:
                    package = tomllib.load(source)
                bins = {item["name"] for item in package.get("bin", [])}
                if not bins:
                    bins.add(package["package"]["name"])
                self.assertIn(name, bins, str(cargo_file))


if __name__ == "__main__":
    unittest.main(verbosity=2)
