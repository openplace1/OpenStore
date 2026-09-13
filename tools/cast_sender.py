#!/usr/bin/env python3
"""Streams this computer's screen to the Cast Receiver app on an OpenOS device.

    python tools/cast_sender.py <device-ip> [--fps 8] [--rotate] [--test]

The device shows its IP on the receiver's waiting screen. The desktop is
scaled to fit the 240x320 panel (letterboxed; --rotate turns it sideways so a
landscape screen fills more of the panel), converted to RGB565 and sent as
16-row tiles over one TCP connection. Only tiles that changed since the last
frame are sent, so a still desktop costs almost nothing.

Wire format, little-endian:
    'C'  kind(u8)  y(u16)  rows(u16)  reserved(u16)   then 240*rows*2 bytes

Needs Pillow for screen capture (pip install pillow); --test streams a
moving pattern without it.
"""

from __future__ import annotations

import argparse
import math
import socket
import struct
import sys
import time

WIDTH, HEIGHT = 240, 320
TILE_ROWS = 16
PORT = 7777


def to_rgb565(rgb_bytes: bytes) -> bytes:
    """RGB888 bytes -> RGB565 little-endian bytes."""
    out = bytearray(len(rgb_bytes) // 3 * 2)
    j = 0
    for i in range(0, len(rgb_bytes), 3):
        r, g, b = rgb_bytes[i], rgb_bytes[i + 1], rgb_bytes[i + 2]
        v = ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
        out[j] = v & 0xFF
        out[j + 1] = v >> 8
        j += 2
    return bytes(out)


def grab_frame(rotate: bool) -> bytes:
    from PIL import Image, ImageGrab   # noqa: WPS433 (optional dependency)
    shot = ImageGrab.grab()
    if rotate:
        shot = shot.rotate(90, expand=True)
    shot.thumbnail((WIDTH, HEIGHT), Image.LANCZOS)
    canvas = Image.new("RGB", (WIDTH, HEIGHT), (0, 0, 0))
    canvas.paste(shot, ((WIDTH - shot.width) // 2, (HEIGHT - shot.height) // 2))
    return to_rgb565(canvas.tobytes())


def test_frame(t: float) -> bytes:
    """A moving colour field plus a bouncing square; no dependencies."""
    pixels = bytearray(WIDTH * HEIGHT * 2)
    bx = int((math.sin(t * 1.3) * 0.5 + 0.5) * (WIDTH - 60))
    by = int((math.cos(t * 0.9) * 0.5 + 0.5) * (HEIGHT - 60))
    k = 0
    for y in range(HEIGHT):
        for x in range(WIDTH):
            if bx <= x < bx + 60 and by <= y < by + 60:
                v = 0xFFFF
            else:
                r = (x * 31 // WIDTH + int(t * 8)) & 0x1F
                g = (y * 63 // HEIGHT) & 0x3F
                b = 12
                v = (r << 11) | (g << 5) | b
            pixels[k] = v & 0xFF
            pixels[k + 1] = v >> 8
            k += 2
    return bytes(pixels)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", help="device IP shown by Cast Receiver")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--fps", type=float, default=8.0)
    parser.add_argument("--rotate", action="store_true", help="turn the desktop sideways")
    parser.add_argument("--test", action="store_true", help="send a test pattern instead of the screen")
    args = parser.parse_args()

    if not args.test:
        try:
            import PIL  # noqa: F401
        except ImportError:
            sys.exit("Pillow is required for screen capture: pip install pillow "
                     "(or use --test)")

    print(f"connecting to {args.host}:{args.port} ...")
    sock = socket.create_connection((args.host, args.port), timeout=10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    print("connected; streaming (Ctrl+C to stop)")

    previous: bytes | None = None
    row_bytes = WIDTH * 2
    frame_time = 1.0 / max(0.5, args.fps)
    started = time.time()
    sent_tiles = 0
    try:
        while True:
            t0 = time.time()
            frame = test_frame(t0 - started) if args.test else grab_frame(args.rotate)
            for y in range(0, HEIGHT, TILE_ROWS):
                rows = min(TILE_ROWS, HEIGHT - y)
                chunk = frame[y * row_bytes:(y + rows) * row_bytes]
                if previous is not None and previous[y * row_bytes:(y + rows) * row_bytes] == chunk:
                    continue
                sock.sendall(struct.pack("<cBHHH", b"C", 0, y, rows, 0) + chunk)
                sent_tiles += 1
            previous = frame
            elapsed = time.time() - t0
            if elapsed < frame_time:
                time.sleep(frame_time - elapsed)
    except KeyboardInterrupt:
        print(f"\nstopped after {sent_tiles} tiles")
    except (BrokenPipeError, ConnectionResetError):
        print("\nthe device closed the connection")
    finally:
        sock.close()


if __name__ == "__main__":
    main()
