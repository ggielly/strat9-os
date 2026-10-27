#!/usr/bin/env python3
"""Serial verdict and fake-emulator tests. Never invokes QEMU or Cargo."""
import os
from pathlib import Path
import shlex
import sys
import unittest

from test_uefi_images import FixtureTest, SCRIPTS, module

VERDICT = module("selftest-log")
GOOD = "\n".join([VERDICT.START, "[selftest][strate] PASS", VERDICT.DONE]) + "\n"


def styled(log):
    return "".join("[   42.001234] " + line.replace("PASS", "\x1b[32mPASS\x1b[0m")
                   .replace("FAIL", "\x1b[31mFAIL\x1b[0m") + "\r\n" for line in log.splitlines())


class VerdictTests(unittest.TestCase):
    def test_complete_protocol_requires_controlled_zero_exit(self):
        self.assertTrue(VERDICT.verdict(GOOD, 0, True)[0])
        self.assertTrue(VERDICT.verdict(GOOD.replace("\n", "\r\n"), 0, True)[0])
        for status, controlled in [(1, True), (137, True), (0, False)]:
            with self.subTest(status=status, controlled=controlled):
                self.assertFalse(VERDICT.verdict(GOOD, status, controlled)[0])

    def test_kernel_colors_and_timestamps_keep_success_and_failure_semantics(self):
        self.assertTrue(VERDICT.verdict(styled(GOOD), 0, True)[0])
        self.assertFalse(VERDICT.verdict(styled(GOOD + "[selftest] FAIL\n"), 0, True)[0])
        self.assertFalse(VERDICT.verdict("unrelated " + GOOD, 0, True)[0])

    def test_incomplete_duplicate_out_of_order_and_unexpected_results_fail(self):
        invalid = ["", "[selftest][strate] PASS\n", GOOD.replace(VERDICT.DONE, ""),
                   GOOD.replace(VERDICT.START, ""), GOOD.replace(" PASS", " PAS"),
                   GOOD + GOOD, GOOD.replace("[selftest][strate] PASS", "[selftest][other] PASS"),
                   VERDICT.DONE + "\n" + VERDICT.START + "\n[selftest][strate] PASS\n",
                   "[selftest][strate] PASS\n" + VERDICT.START + "\n" + VERDICT.DONE,
                   GOOD + "[selftest][strate] PASS\n"]
        for log in invalid:
            with self.subTest(log=log):
                self.assertFalse(VERDICT.verdict(log, 0, True)[0])

    def test_explicit_failures_and_legacy_timeouts_fail(self):
        for marker in ["[selftest][strate] FAIL", "[selftest] FAIL: timeout waiting 'test'",
                       "[selftest] timeout waiting 'test'", "[selftest] failed to create task"]:
            with self.subTest(marker=marker):
                self.assertFalse(VERDICT.verdict(GOOD + marker + "\n", 0, True)[0])


FAKE_QEMU = r'''#!/usr/bin/env bash
set -eu
printf '%s\n' "$@" > "$FAKE_TRACE"
serial=''
previous=''
for arg in "$@"; do
    if [[ "$previous" == -serial ]]; then serial="${arg#file:}"; fi
    case "$arg" in
        if=pflash,format=raw,file=*) printf 'changed private variables\n' > "${arg##*file=}" ;;
    esac
    previous="$arg"
done
printf '%s\n' "$FAKE_SERIAL" > "$serial"
if [[ "${FAKE_MODE:-normal}" == early ]]; then exit "${FAKE_STATUS:-0}"; fi
read -r request
printf '%s\n' "$request" > "$FAKE_QUIT"
[[ "$request" == quit ]]
exit "${FAKE_STATUS:-0}"
'''


class HarnessTests(FixtureTest):
    def setUp(self):
        super().setUp()
        directory = self.root / "tools/scripts"
        directory.mkdir(parents=True)
        for name in ["qemu-selftest.sh", "selftest-log.py"]:
            (directory / name).write_text((SCRIPTS / name).read_text(), newline="\n")
        self.script = directory / "qemu-selftest.sh"
        self.bin = self.root / "bin"
        self.bin.mkdir()
        qemu = self.bin / "fake-qemu"
        qemu.write_text(FAKE_QEMU, newline="\n")
        python = self.bin / "python3"
        python.write_text("#!/usr/bin/env bash\nexec " + shlex.quote(Path(sys.executable).as_posix())
                          + ' "$@"\n', newline="\n")
        cargo = self.bin / "cargo"
        cargo.write_text('#!/usr/bin/env bash\nprintf "unexpected build" > "$FAKE_BUILD"\nexit 99\n', newline="\n")
        for path in [qemu, python, cargo]:
            path.chmod(0o755)
        self.code = self.root / "OVMF_CODE.fd"
        self.vars = self.root / "OVMF_VARS.fd"
        self.code.write_bytes(b"synthetic code")
        self.vars.write_bytes(b"untouched template")
        self.image = self.root / "artifact.not-an-iso-extension"
        self.image.write_bytes(b"nonbootable fixture")
        self.env.update(PATH=str(self.bin) + os.pathsep + self.env["PATH"], QEMU=str(qemu),
                        FAKE_SERIAL=GOOD, FAKE_TRACE=str(self.root / "argv.txt"),
                        FAKE_QUIT=str(self.root / "quit.txt"), FAKE_BUILD=str(self.root / "build-called"),
                        OVMF_CODE=str(self.code), OVMF_VARS=str(self.vars))

    def run_harness(self, *args, default_image=True):
        selected = ["--iso", self.image] if default_image else []
        result = self.bash('exec bash "$@"', self.script, "--skip-build", *selected,
                           "--timeout", "2", *args, timeout=15)
        self.assertFalse((self.root / "build-called").exists(), "test attempted a build")
        self.assertFalse(list((self.root / "build").glob(".qemu-selftest.*")))
        self.assertEqual(self.vars.read_bytes(), b"untouched template")
        return result

    def test_iso_uses_ovmf_independently_of_suffix_and_stops_cleanly(self):
        result = self.run_harness()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("RESULT: PASS", result.stdout)
        argv = (self.root / "argv.txt").read_text().splitlines()
        self.assertIn("-cdrom", argv)
        self.assertEqual(sum("if=pflash" in arg for arg in argv), 2)
        self.assertEqual((self.root / "quit.txt").read_text().strip(), "quit")
        self.assertIn(VERDICT.DONE, (self.root / "build/qemu-selftest.log").read_text())

    def test_raw_disk_also_uses_ovmf_and_preserves_input(self):
        result = self.run_harness("--image", self.image, default_image=False)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        argv = (self.root / "argv.txt").read_text().splitlines()
        self.assertNotIn("-cdrom", argv)
        self.assertEqual(sum("if=pflash" in arg for arg in argv), 2)
        self.assertTrue(any("format=raw,snapshot=on" in arg for arg in argv))
        self.assertEqual(self.image.read_bytes(), b"nonbootable fixture")

    def test_bios_requires_explicit_selection(self):
        result = self.run_harness("--firmware", "bios")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("if=pflash", (self.root / "argv.txt").read_text())

    def test_crlf_serial_completion(self):
        self.env["FAKE_SERIAL"] = GOOD.replace("\n", "\r\n")
        result = self.run_harness()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_kernel_styled_serial_completion(self):
        self.env["FAKE_SERIAL"] = styled(GOOD)
        result = self.run_harness()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_early_pass_then_exit_zero_is_incomplete(self):
        self.env.update(FAKE_SERIAL=VERDICT.START + "\n[selftest][strate] PASS", FAKE_MODE="early")
        result = self.run_harness()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertNotIn("RESULT: PASS", result.stdout)

    def test_nonzero_emulator_status_even_after_completion_fails(self):
        self.env["FAKE_STATUS"] = "42"
        result = self.run_harness()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("exit status 42", result.stdout)

    def test_timeout_cleans_up_and_preserves_diagnostics(self):
        self.env["FAKE_SERIAL"] = VERDICT.START
        result = self.run_harness()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("RESULT: TIMEOUT", result.stdout)
        self.assertTrue((self.root / "build/qemu-selftest.log.qemu").exists())

    def test_missing_explicit_artifact_and_missing_default_do_not_build(self):
        for args in [("--image", "missing.img"), ()]:
            with self.subTest(args=args):
                result = self.run_harness(*args, default_image=False)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse((self.root / "argv.txt").exists())

    def test_incomplete_firmware_pair_is_rejected_before_launch(self):
        self.env["OVMF_VARS"] = ""
        result = self.run_harness()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse((self.root / "argv.txt").exists())

    def test_bad_arguments_are_environment_errors(self):
        for args in [("--timeout", "0"), ("--mem", "-1"), ("--smp", "08"),
                     ("--firmware", "automatic"), ("--timeout",), ("--unknown",)]:
            with self.subTest(args=args):
                result = self.run_harness(*args)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse((self.root / "argv.txt").exists())


if __name__ == "__main__":
    unittest.main()
