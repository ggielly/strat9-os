#!/usr/bin/env python3
"""Image geometry and script failure tests. No builds or real image tools run."""
import importlib.util
import io
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import uuid
import zlib

REPO = Path(__file__).resolve().parents[3]
SCRIPTS = REPO / "tools/scripts"
BASH = os.environ.get("STRAT9_TEST_BASH") or shutil.which("bash")


def module(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + ".py"))
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


GEOMETRY = module("validate-uefi-image")
CATALOG = module("validate-uefi-iso-report")
REPORT = ("El Torito boot img :   1  UEFI  y   none  0x0000  0x00      0      123\n"
          "El Torito img path :   1  /efiboot.img\n")


def fat_headers(sectors=131072, hidden=0):
    """Only reserved-sector metadata: deliberately no FAT chains or executable."""
    data = bytearray(7 * 512)
    struct.pack_into("<H", data, 11, 512)
    data[13] = 1
    struct.pack_into("<H", data, 14, 32)
    data[16] = 2
    struct.pack_into("<III", data, 28, hidden, sectors, (sectors + 127) // 128)
    struct.pack_into("<IHH", data, 44, 2, 1, 6)
    data[510:512] = b"\x55\xaa"
    data[6 * 512:7 * 512] = data[:512]
    data[512:516] = b"RRaA"
    data[512 + 484:512 + 488] = b"rrAa"
    data[512 + 508:1024] = b"\0\0\x55\xaa"
    return data


def gpt_headers(total, start, count):
    entries = bytearray(128 * 128)
    entries[:16] = GEOMETRY.ESP_TYPE
    entries[16:32] = uuid.UUID(int=1).bytes_le
    struct.pack_into("<QQ", entries, 32, start, start + count - 1)
    result = {}
    for lba, other, array in [(1, total - 1, 2), (total - 1, 1, total - 33)]:
        header = bytearray(512)
        header[:8] = b"EFI PART"
        struct.pack_into("<II", header, 8, 0x10000, 92)
        struct.pack_into("<QQQQ", header, 24, lba, other, 34, total - 34)
        header[56:72] = uuid.UUID(int=2).bytes_le
        struct.pack_into("<QIII", header, 72, array, 128, 128, zlib.crc32(entries))
        struct.pack_into("<I", header, 16, zlib.crc32(header[:92]))
        result[lba * 512] = header
        result[array * 512] = entries
    mbr = bytearray(512)
    mbr[450] = 0xEE
    struct.pack_into("<II", mbr, 454, 1, total - 1)
    mbr[510:512] = b"\x55\xaa"
    result[0] = mbr
    return result


class FixtureTest(unittest.TestCase):
    def setUp(self):
        self.parent = (REPO / "build").resolve()
        self.parent.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="uefi-test-", dir=self.parent)
        self.root = Path(self.temp.name).resolve()
        self.env = os.environ.copy()
        if os.name == "nt" and BASH:
            self.env["PATH"] = str(Path(BASH).parent.parent / "usr/bin") + os.pathsep + self.env["PATH"]
        self.env["PYTHONDONTWRITEBYTECODE"] = "1"

    def tearDown(self):
        if self.root.parent != self.parent or not self.root.name.startswith("uefi-test-"):
            raise RuntimeError("refusing cleanup outside the owned fixture directory")
        self.temp.cleanup()

    def bash(self, body, *args, timeout=20):
        self.assertTrue(BASH, "set STRAT9_TEST_BASH to a Bash executable")
        return subprocess.run([BASH, "--noprofile", "--norc", "-c", body, "fixture", *map(str, args)],
                              cwd=self.root, env=self.env, capture_output=True, text=True, timeout=timeout)


class GeometryTests(FixtureTest):
    def disk(self):
        # A small sparse metadata fixture, not a usable or bootable filesystem.
        self.sectors, self.start, self.count = 140000, 2048, 131072
        path = self.root / "metadata.bin"
        with path.open("wb") as stream:
            stream.truncate(self.sectors * 512)
            for offset, data in gpt_headers(self.sectors, self.start, self.count).items():
                stream.seek(offset)
                stream.write(data)
            stream.seek(self.start * 512)
            stream.write(fat_headers(self.count, self.start))
        return path

    def validate(self, path):
        GEOMETRY.validate(path, "disk", self.start, self.count)

    def test_matching_gpt_and_bpb_with_backup_crcs(self):
        self.validate(self.disk())

    def test_fat_overrunning_partition_by_one_mib_is_rejected(self):
        path = self.disk()
        with path.open("r+b") as stream:
            stream.seek(self.start * 512)
            stream.write(fat_headers(self.count + 2048, self.start))
        with self.assertRaisesRegex(ValueError, "BPB size"):
            self.validate(path)

    def test_corrupt_primary_backup_and_entry_array_are_rejected(self):
        for offset in [512 + 56, (140000 - 1) * 512 + 56, 2 * 512 + 16,
                       (140000 - 33) * 512 + 16]:
            with self.subTest(offset=offset):
                path = self.disk()
                with path.open("r+b") as stream:
                    stream.seek(offset)
                    stream.write(b"\xff")
                with self.assertRaisesRegex(ValueError, "CRC"):
                    self.validate(path)

    def test_valid_crcs_but_disagreeing_gpt_copies_are_rejected(self):
        path = self.disk()
        alternate = gpt_headers(self.sectors, self.start, self.count - 1)
        with path.open("r+b") as stream:
            for offset, data in alternate.items():
                if offset > (self.sectors - 34) * 512:
                    stream.seek(offset)
                    stream.write(data)
        with self.assertRaisesRegex(ValueError, "disagree"):
            self.validate(path)

    def test_empty_zero_and_truncated_outputs_are_rejected(self):
        for size in [0, 512, 513, 4096]:
            with self.subTest(size=size):
                path = self.root / "bad.bin"
                path.write_bytes(bytes(size))
                with self.assertRaises(ValueError):
                    GEOMETRY.validate(path, "disk")

    def test_fat_reserved_metadata_and_minimum_cluster_count(self):
        GEOMETRY.fat32(io.BytesIO(fat_headers()), 0, 131072, 0)
        for offset, value, expected in [(28, 1, "hidden"), (6 * 512, 1, "backup"),
                                         (512, 0, "FSInfo"), (44, 0, "root cluster")]:
            with self.subTest(offset=offset):
                data = fat_headers()
                data[offset] = value
                with self.assertRaisesRegex(ValueError, expected):
                    GEOMETRY.fat32(io.BytesIO(data), 0, 131072, 0)
        with self.assertRaisesRegex(ValueError, "cluster count"):
            GEOMETRY.fat32(io.BytesIO(fat_headers(65536)), 0, 65536, 0)

    def test_iso_requires_bootable_uefi_entry_and_matching_path(self):
        CATALOG.validate_report(REPORT)
        for invalid in ["", REPORT.replace("UEFI", "BIOS"), REPORT.replace(" y ", " n "),
                        REPORT.replace("efiboot.img", "wrong.img"), REPORT + REPORT,
                        REPORT.splitlines()[0], REPORT.replace("none", "hd")]:
            with self.subTest(report=invalid), self.assertRaises(ValueError):
                CATALOG.validate_report(invalid)


# These Bash functions replace EVERY partitioning, formatting, image-validation
# and ISO command in script orchestration tests. Output files are short text.
# The real Python metadata validators are exercised independently above.
FAKE_PRODUCERS = r'''
command() {
    if [[ "${1-}" == -v && "${2-}" == "${MISSING_TOOL-}" ]]; then return 1; fi
    builtin command "$@"
}
parted() {
    printf '%s\n' "$*" >> "$TRACE"
    [[ "${FAIL_TOOL-}" != parted ]]
}
dd() {
    local arg output=''
    for arg in "$@"; do case "$arg" in of=*) output="${arg#of=}";; esac; done
    printf '%s\n' "$*" >> "$TRACE"
    printf 'synthetic nonbootable fixture\n' > "$output"
    case "$output" in */esp.img|*/efiboot.img) FAKE_FAT="$output";; esac
}
mkfs.fat() { [[ "${FAIL_TOOL-}" != mkfs.fat ]]; }
fsck.fat() { [[ "${FAIL_TOOL-}" != fsck.fat ]]; }
mcopy() {
    [[ "${FAIL_TOOL-}" != mcopy ]] || return 1
    local source="$4" destination="$5"
    case "$source" in
        ::/*) cp -r -- "$FAKE_STORE/${source#::/}" "$destination" ;;
        *) cp -r -- "$source" "$FAKE_STORE/" ;;
    esac
    if [[ "${FAIL_TOOL-}" == readback && "$source" == ::/boot ]]; then
        printf 'corrupt readback\n' > "$destination/boot/kernel.elf"
    fi
}
python3() {
    printf 'validator %s\n' "$*" >> "$TRACE"
    [[ "${FAIL_TOOL-}" != validation ]]
}
xorriso() {
    local prev='' arg output=''
    for arg in "$@"; do
        [[ "$prev" != -o ]] || output="$arg"
        prev="$arg"
    done
    if [[ -n "$output" ]]; then
        printf 'synthetic partial ISO\n' > "$output"
        [[ "${FAIL_TOOL-}" != xorriso ]] || return 7
    elif [[ "$*" == *-report_el_torito* ]]; then
        [[ "${FAIL_TOOL-}" != catalog ]] || return 8
        printf 'synthetic report (validator is mocked in orchestration tests)\n'
    else
        [[ "${FAIL_TOOL-}" != extract ]] || return 9
        cp -- "$FAKE_FAT" "${@: -1}"
    fi
}
mv() {
    if [[ "${FAIL_TOOL-}" == publish && "$*" == *disk.img* ]]; then return 10; fi
    builtin command mv "$@"
}
'''


class ProducerTests(FixtureTest):
    def setUp(self):
        super().setUp()
        self.build = self.root / "build"
        self.build.mkdir()
        self.payload = self.build / "fixture-uefi-root"
        for child in ["efi/boot", "boot/initfs"]:
            (self.payload / child).mkdir(parents=True)
        (self.payload / "efi/boot/BOOTX64.EFI").write_bytes(b"old loader")
        (self.payload / "boot/kernel.elf").write_bytes(b"old kernel")
        (self.payload / "boot/initfs/strate-init").write_bytes(b"\x7fELF\x02\x01old init")
        (self.payload / "boot/initfs/silo.toml").write_bytes(
            (REPO / "workspace/assets/boot/silo.toml").read_bytes())
        (self.payload / "modules.manifest").write_text("base strate-init producer\n")
        (self.payload / "include-tests").write_text("0\n")
        for child, content in [("x86_64-unknown-uefi/debug/strat9-bootloader.efi", b"new loader"),
                               ("x86_64-unknown-none/debug/kernel", b"new kernel"),
                               ("x86_64-unknown-none/release/strate-init", b"\x7fELF\x02\x01new init")]:
            path = self.root / "target" / child
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        self.disk = self.build / "fixture-uefi.img"
        self.iso = self.build / "fixture-uefi.iso"
        self.disk.write_bytes(b"previous disk")
        self.iso.write_bytes(b"previous iso")
        store = self.root / "fake-fat-store"
        store.mkdir()
        self.stubs = self.root / "stubs.sh"
        self.stubs.write_text(FAKE_PRODUCERS, newline="\n")
        self.env.update(STRAT9_IMAGE_BASENAME="fixture", STRAT9_PROFILE="debug",
                        STRAT9_MODULE_PROFILE="release", STRAT9_INCLUDE_TESTS="0",
                        STRAT9_BUILD_DIR="build", STRAT9_MODULE_MANIFEST="build/fixture-uefi-root/modules.manifest",
                        TRACE=str(self.root / "trace.txt"), FAKE_STORE=str(store))

    def run_producer(self, iso=False):
        name = "create-iso-uefi.sh" if iso else "create-uefi-image.sh"
        return self.bash('source "$1"; source "$2"', self.stubs, SCRIPTS / name)

    def assert_preserved(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("created and validated", result.stdout)
        self.assertEqual(self.disk.read_bytes(), b"previous disk")
        self.assertEqual(self.iso.read_bytes(), b"previous iso")
        self.assertEqual((self.payload / "boot/kernel.elf").read_bytes(), b"old kernel")
        self.assertFalse(list(self.build.glob(".uefi-work.*")))

    def test_missing_dependencies_preserve_outputs_before_staging(self):
        for tool in ["parted", "mkfs.fat", "fsck.fat", "mcopy", "python3"]:
            with self.subTest(tool=tool):
                self.env["MISSING_TOOL"] = tool
                result = self.run_producer()
                self.assert_preserved(result)
                self.assertIn(tool, result.stderr)

    def test_disk_failure_paths_and_publication_rollback(self):
        for tool in ["parted", "mkfs.fat", "mcopy", "fsck.fat", "readback", "validation", "publish"]:
            with self.subTest(tool=tool):
                # The fake FAT store is reused: cp must overwrite files, not nest directories.
                self.env["FAIL_TOOL"] = tool
                self.assert_preserved(self.run_producer())

    def test_iso_partial_write_catalog_and_extraction_failures_preserve_output(self):
        for tool in ["xorriso", "catalog", "extract"]:
            with self.subTest(tool=tool):
                self.env["FAIL_TOOL"] = tool
                self.assert_preserved(self.run_producer(iso=True))

    def test_disk_sector_arguments_and_final_publication(self):
        result = self.run_producer()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        trace = (self.root / "trace.txt").read_text()
        self.assertIn("unit s mkpart ESP fat32 2048s 526335s", trace)
        self.assertIn("--esp-start 2048 --esp-sectors 524288", trace)
        self.assertEqual((self.payload / "boot/kernel.elf").read_bytes(), b"new kernel")
        self.assertEqual((self.payload / "boot/initfs/silo.toml").read_bytes(),
                         (REPO / "workspace/assets/boot/silo.toml").read_bytes())
        self.assertNotEqual(self.disk.read_bytes(), b"previous disk")
        self.assertFalse(list(self.build.glob(".uefi-work.*")))

    def test_iso_publication_after_mocked_validations(self):
        result = self.run_producer(iso=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotEqual(self.iso.read_bytes(), b"previous iso")
        self.assertEqual(self.disk.read_bytes(), b"previous disk")
        self.assertFalse(list(self.build.glob(".uefi-work.*")))

    def test_iso_rejects_payload_without_silo_config(self):
        (self.payload / "boot/initfs/silo.toml").unlink()
        result = self.run_producer(iso=True)
        self.assert_preserved(result)
        self.assertIn("silo configuration", result.stderr)


if __name__ == "__main__":
    unittest.main()
