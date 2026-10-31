#!/usr/bin/env python3
"""s9dump - small BLE console viewer for strat9 OS (Nordic UART Service).

    pip install bleak
    python s9dump.py                    # scan for a device named S9-DUMP*
    python s9dump.py --address AA:BB:CC:DD:EE:FF
"""
import argparse
import asyncio
import sys
import threading

from s9frame import FrameDecoder, TYPE_DATA, TYPE_DROP, TYPE_HELLO

SVC_UUID = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E"
TX_UUID = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E"
RX_UUID = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E"


def say(msg):
    print(msg, file=sys.stderr, flush=True)


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="strat9 OS BLE console dump client")
    p.add_argument("--name", default="S9-DUMP",
                   help="advertised name prefix (default: S9-DUMP)")
    p.add_argument("--address",
                   help="BLE address/MAC, takes precedence over --name")
    p.add_argument("--log", metavar="FILE", help="append raw DATA bytes to FILE")
    p.add_argument("--no-stdin", action="store_true",
                   help="viewer only, never send keyboard input")
    p.add_argument("--scan-timeout", type=float, default=10.0,
                   help="scan timeout in seconds (default: 10)")
    return p.parse_args(argv)


def render(frames, log, state):
    """Print decoded frames: DATA to stdout, notices to stderr."""
    out = sys.stdout.buffer
    for typ, _seq, payload in frames:
        if typ == TYPE_DATA:
            out.write(payload)
            out.flush()
            if log is not None:
                log.write(payload)
                log.flush()
        elif typ == TYPE_DROP:
            lost = int.from_bytes(payload[:4].ljust(4, b"\x00"), "little")
            say(f"\n[--- lost {lost} bytes ---]")
        elif typ == TYPE_HELLO:
            if not state["hello"]:
                state["hello"] = True
                banner = payload.decode("ascii", "replace").strip()
                say(banner or "[hello] strat9 BLE dump connected")


async def pump(client, queue):
    """Send lines typed on stdin to the RX characteristic."""
    while True:
        line = await queue.get()
        try:
            # The OS RX characteristic expects raw command text, not a frame.
            await client.write_gatt_char(
                RX_UUID, line.encode("utf-8"), response=False)
        except Exception as exc:
            say(f"[warn] write failed: {exc}")


async def session(device, args, queue):
    from bleak import BleakClient

    decoder = FrameDecoder()
    state = {"hello": False}
    log = open(args.log, "ab") if args.log else None

    def on_notify(_char, data):
        frames = decoder.feed_frame(bytes(data))
        for gap in decoder.take_gaps():
            say(f"[--- gap: {gap} frames ---]")
        for typ in decoder.take_unknown():
            say(f"[warn] unknown frame type 0x{typ:02x}")
        render(frames, log, state)

    try:
        async with BleakClient(device, timeout=20.0) as client:
            services = client.services
            for uuid in (SVC_UUID, TX_UUID, RX_UUID):
                if services.get_characteristic(uuid) is None:
                    raise RuntimeError(f"missing characteristic {uuid} on {SVC_UUID}")
            await client.start_notify(TX_UUID, on_notify)
            say(f"[connected] {getattr(device, 'address', device)}")
            sender = asyncio.create_task(pump(client, queue))
            try:
                while client.is_connected:
                    await asyncio.sleep(0.25)
            finally:
                sender.cancel()
            say("[disconnected]")
    finally:
        if log is not None:
            log.close()


async def run(args):
    from bleak import BleakScanner

    queue = asyncio.Queue()
    loop = asyncio.get_running_loop()

    if not args.no_stdin and sys.stdin.isatty():
        def reader():
            for line in sys.stdin:
                loop.call_soon_threadsafe(queue.put_nowait, line.rstrip("\r\n"))

        threading.Thread(target=reader, daemon=True).start()
        say("[stdin] type a line + Enter to send it to the device")

    while True:
        try:
            if args.address:
                target = args.address
            else:
                found = await BleakScanner.discover(
                    timeout=args.scan_timeout, return_adv=True)
                target = next(
                    (dev for dev, adv in found.values()
                     if (dev.name or adv.local_name or "").startswith(args.name)),
                    None)
                if target is None:
                    say(f"[scan] no device whose name starts with {args.name!r}")
                    await asyncio.sleep(1)
                    continue
                say(f"[scan] found {target.name} ({target.address})")
            await session(target, args, queue)
        except Exception as exc:
            say(f"[error] {exc}")
        say("[reconnect in 1s]")
        await asyncio.sleep(1)


def main(argv=None):
    args = parse_args(argv)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        sys.stdout.write("\x1b[0m")
        sys.stdout.flush()
        say("[bye]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
