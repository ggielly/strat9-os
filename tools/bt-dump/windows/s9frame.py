"""Pure framing for the strat9 OS console dump protocol (no BLE dependency).

Frame layout::

    [type u8][seq u32 little-endian][payload...]

There is no length field: one notification carries one frame, so a frame ends
where the next header starts, or at the end of the buffer.  Splitting a
concatenated buffer therefore relies on header detection: a known type byte
followed by a sequence number that continues the previous frame (or, for a
gap, a plausibly larger one).

Types: 0xD0 DATA (raw console text), 0xD1 DROP (u32 LE lost bytes),
0xD2 HELLO (ASCII banner).
"""

TYPE_DATA = 0xD0
TYPE_DROP = 0xD1
TYPE_HELLO = 0xD2
KNOWN_TYPES = (TYPE_DATA, TYPE_DROP, TYPE_HELLO)

HEADER = 5
# A header may be followed by a forward jump in sequence numbers (a gap).
# Anything further away than this is treated as payload noise, not a header.
MAX_GAP = 1 << 16


def _seq_at(buf, i):
    return int.from_bytes(buf[i + 1:i + HEADER], "little")


def _find_header(buf, start, want=None):
    """Return the index of the next plausible header at or after ``start``.

    A header whose sequence number equals ``want`` is preferred; otherwise the
    first known type byte with a plausibly forward sequence number is used.
    """
    best = None
    for k in range(start, len(buf) - HEADER + 1):
        if buf[k] not in KNOWN_TYPES:
            continue
        seq = _seq_at(buf, k)
        if want is not None and seq == want:
            return k
        if best is None:
            if want is None or ((seq - want) & 0xFFFFFFFF) < MAX_GAP:
                best = k
    return best


def decode_frames(buf, expect=None, reports=None):
    """Split ``buf`` into frames.

    Returns ``(frames, leftover)`` where each frame is
    ``(type, seq, payload)`` and ``leftover`` holds a trailing incomplete
    header (fewer than 5 bytes) that the caller should prepend to next data.

    ``expect`` is the sequence number expected for the next frame (used to
    disambiguate headers inside payload text).  Unknown type bytes are skipped
    by dropping one byte at a time; the first byte of each junk run is appended
    to ``reports`` when a list is supplied.
    """
    frames = []
    i, n = 0, len(buf)
    want = expect
    junk = False
    while n - i >= HEADER:
        typ = buf[i]
        if typ not in KNOWN_TYPES:
            if reports is not None and not junk:
                reports.append(typ)
            junk = True
            nxt = _find_header(buf, i + 1, want)
            i = i + 1 if nxt is None else nxt
            continue
        junk = False
        seq = _seq_at(buf, i)
        nxt = _find_header(buf, i + HEADER, (seq + 1) & 0xFFFFFFFF)
        end = n if nxt is None else nxt
        frames.append((typ, seq, bytes(buf[i + HEADER:end])))
        want = (seq + 1) & 0xFFFFFFFF
        i = end
    return frames, bytes(buf[i:])


def encode_text_frame(seq, text):
    """Build a DATA frame for the RX (PC -> OS) channel."""
    if isinstance(text, str):
        text = text.encode("utf-8")
    return bytes([TYPE_DATA]) + (seq & 0xFFFFFFFF).to_bytes(4, "little") + bytes(text)


class FrameDecoder:
    """Incremental decoder with sequence-gap and unknown-type accounting."""

    def __init__(self):
        self._buf = b""
        self.expected = None
        self.gaps = []
        self.unknown = []

    def _accept(self, frame):
        """Record sequence state for one complete frame."""
        typ, seq, _payload = frame
        if self.expected is not None and seq != self.expected:
            missing = (seq - self.expected) & 0xFFFFFFFF
            if missing < 0x80000000:
                self.gaps.append(missing)
        self.expected = (seq + 1) & 0xFFFFFFFF
        return frame

    def feed(self, data):
        """Feed a byte stream that may contain zero or more frames."""
        buf = self._buf + bytes(data)
        frames, self._buf = decode_frames(buf, self.expected, self.unknown)
        return [self._accept(frame) for frame in frames]

    def feed_frame(self, data):
        """Feed exactly one notification payload (the normal BLE path).

        One notification carries exactly one frame, so the whole payload is
        taken as-is.  This avoids mis-splitting console text that happens to
        contain a frame-type byte.
        """
        data = bytes(data)
        if len(data) < HEADER:
            return []
        if data[0] not in KNOWN_TYPES:
            self.unknown.append(data[0])
            return []
        return [self._accept((data[0], _seq_at(data, 0), data[HEADER:]))]

    def take_gaps(self):
        """Return and clear the pending missing-frame counts."""
        gaps, self.gaps = self.gaps, []
        return gaps

    def take_unknown(self):
        """Return and clear the pending unknown frame types."""
        unknown, self.unknown = self.unknown, []
        return unknown
