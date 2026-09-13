#!/usr/bin/env python3
"""Validate the kernel orchestrator's serial protocol after QEMU has stopped."""
import argparse
from pathlib import Path
import re
import sys

START = "[selftest] orchestrator start"
DONE = "[selftest] orchestrator done"
# The current orchestrator emits exactly this success result. Other task logs
# are not a stable machine-readable protocol and are not counted as successes.
EXPECTED_PASSES = {"[selftest][strate] PASS"}


def protocol_lines(text):
    # serial.rs uses SGR colors for PASS/FAIL and BootPrefixWriter can prepend
    # "[{:>5}.{:06}] ". Strip only those presentation features, not arbitrary
    # prefixes that could turn an unrelated log message into a result.
    text = re.sub(r"\x1b\[[0-9;]*m", "", text)
    return [re.sub(r"^\[ *[0-9]+\.[0-9]{6}\] ", "", line) for line in text.splitlines()]


def verdict(text, status, controlled_stop):
    lines = protocol_lines(text)
    if status != 0:
        return False, f"QEMU-FAILED (exit status {status})"
    if not controlled_stop:
        return False, "INCOMPLETE (QEMU exited before a controlled stop)"
    if lines.count(START) != 1 or lines.count(DONE) != 1:
        return False, "INCOMPLETE (missing or repeated orchestrator start/done)"
    start, done = lines.index(START), lines.index(DONE)
    if start >= done:
        return False, "INCOMPLETE (orchestrator markers out of order)"
    marked = [line for line in lines if line.startswith("[selftest]")]
    if any(re.search(r"\b(?:FAIL(?:ED)?|timeout|failed)\b", line) for line in marked):
        return False, "FAIL (failure or timeout reported by orchestrator)"
    passes = [line for line in marked if re.search(r"\bPASS\b", line)]
    if len(passes) != len(EXPECTED_PASSES) or set(passes) != EXPECTED_PASSES:
        return False, "INCOMPLETE (missing, duplicate or unexpected PASS results)"
    if any(not start < lines.index(line) < done for line in passes):
        return False, "INCOMPLETE (PASS outside the orchestrator run)"
    return True, f"PASS ({len(passes)} expected result, orchestrator complete, QEMU exit 0)"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--qemu-status", type=int, required=True)
    parser.add_argument("--controlled-stop", action="store_true")
    args = parser.parse_args()
    try:
        passed, message = verdict(args.log.read_text(errors="replace"), args.qemu_status, args.controlled_stop)
    except OSError as error:
        passed, message = False, f"LOG-ERROR ({error})"
    print(f"SELFTEST-HARNESS RESULT: {message}")
    sys.exit(0 if passed else 1)
