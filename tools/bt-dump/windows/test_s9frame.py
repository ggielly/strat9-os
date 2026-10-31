"""Unit tests for the pure framing module (no BLE, no bleak)."""

import unittest

from s9frame import (
    FrameDecoder,
    TYPE_DATA,
    TYPE_DROP,
    TYPE_HELLO,
    decode_frames,
    encode_text_frame,
)


def frame(typ, seq, payload=b""):
    return bytes([typ]) + seq.to_bytes(4, "little") + payload


class DecodeTests(unittest.TestCase):
    def test_data_frame(self):
        frames, rest = decode_frames(frame(TYPE_DATA, 0, b"hello\r\n"))
        self.assertEqual(frames, [(TYPE_DATA, 0, b"hello\r\n")])
        self.assertEqual(rest, b"")

    def test_multiple_frames_in_one_buffer(self):
        buf = frame(TYPE_DATA, 0, b"abc") + frame(TYPE_DROP, 1, (12).to_bytes(4, "little"))
        buf += frame(TYPE_DATA, 2, b"def")
        frames, rest = decode_frames(buf)
        self.assertEqual([f[1] for f in frames], [0, 1, 2])
        self.assertEqual(frames[0][2], b"abc")
        self.assertEqual(frames[1][2], (12).to_bytes(4, "little"))
        self.assertEqual(frames[2][2], b"def")
        self.assertEqual(rest, b"")

    def test_partial_frame_then_completion(self):
        decoder = FrameDecoder()
        payload = b"\xd0\x01\x00\x00\x00hello"
        self.assertEqual(decoder.feed(payload[:3]), [])
        self.assertEqual(decoder.feed(payload[3:]), [(TYPE_DATA, 1, b"hello")])

    def test_drop_frame(self):
        frames, _ = decode_frames(frame(TYPE_DROP, 4, (1234).to_bytes(4, "little")))
        self.assertEqual(frames[0][0], TYPE_DROP)
        self.assertEqual(int.from_bytes(frames[0][2], "little"), 1234)

    def test_hello_frame(self):
        frames, _ = decode_frames(frame(TYPE_HELLO, 0, b"S9-DUMP v1\n"))
        self.assertEqual(frames, [(TYPE_HELLO, 0, b"S9-DUMP v1\n")])

    def test_unknown_type_resync(self):
        decoder = FrameDecoder()
        reports = []
        buf = b"\x99" + frame(TYPE_DATA, 3, b"ok")
        frames, rest = decode_frames(buf, None, reports)
        self.assertEqual(reports, [0x99])
        self.assertEqual(frames, [(TYPE_DATA, 3, b"ok")])
        self.assertEqual(rest, b"")
        self.assertEqual(decoder.feed(frame(TYPE_DATA, 0, b"x")), [(TYPE_DATA, 0, b"x")])

    def test_truncated_header_is_leftover(self):
        frames, rest = decode_frames(b"\xd0\x01\x00")
        self.assertEqual(frames, [])
        self.assertEqual(rest, b"\xd0\x01\x00")

    def test_seq_gap_detected(self):
        decoder = FrameDecoder()
        self.assertEqual(len(decoder.feed(frame(TYPE_DATA, 0, b"a"))), 1)
        self.assertEqual(decoder.feed(frame(TYPE_DATA, 5, b"b")), [(TYPE_DATA, 5, b"b")])
        self.assertEqual(decoder.take_gaps(), [4])
        self.assertEqual(decoder.take_gaps(), [])

    def test_seq_wraparound_is_not_a_gap(self):
        decoder = FrameDecoder()
        decoder.feed(frame(TYPE_DATA, 0xFFFFFFFF, b"a"))
        decoder.feed(frame(TYPE_DATA, 0, b"b"))
        self.assertEqual(decoder.take_gaps(), [])

    def test_encode_text_frame(self):
        out = encode_text_frame(7, "ls\n")
        self.assertEqual(out, bytes([TYPE_DATA]) + b"\x07\x00\x00\x00ls\n")
        frames, rest = decode_frames(out)
        self.assertEqual(frames, [(TYPE_DATA, 7, b"ls\n")])
        self.assertEqual(rest, b"")

    def test_feed_frame_keeps_payload_with_header_bytes(self):
        # A console line may contain 0xD0 followed by a plausible sequence
        # number; one notification is one frame, so it must not be split.
        decoder = FrameDecoder()
        payload = b"abc\xd0\x01\x00\x00\x00def"
        frames = decoder.feed_frame(frame(TYPE_DATA, 0, payload))
        self.assertEqual(frames, [(TYPE_DATA, 0, payload)])
        self.assertEqual(decoder.take_gaps(), [])

    def test_feed_frame_empty_hello_and_gap(self):
        decoder = FrameDecoder()
        self.assertEqual(decoder.feed_frame(frame(TYPE_HELLO, 0)), [(TYPE_HELLO, 0, b"")])
        self.assertEqual(decoder.feed_frame(frame(TYPE_DATA, 3, b"x")), [(TYPE_DATA, 3, b"x")])
        self.assertEqual(decoder.take_gaps(), [2])

    def test_feed_frame_rejects_short_and_unknown(self):
        decoder = FrameDecoder()
        self.assertEqual(decoder.feed_frame(b"\xd0\x00"), [])
        self.assertEqual(decoder.feed_frame(b"\x99\x00\x00\x00\x00x"), [])
        self.assertEqual(decoder.take_unknown(), [0x99])


if __name__ == "__main__":
    unittest.main()
