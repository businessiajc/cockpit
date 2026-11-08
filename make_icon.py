"""Genere cockpit.ico : un cadran (jauge) dessine a la main avec des formes vectorielles.

Aucune image externe, aucune bibliotheque : rendu par calcul (4x4 echantillons par pixel).
Usage : uv run python -I make_icon.py [sortie.ico]
"""
import math
import struct
import sys
import zlib

BG = (11, 93, 86)         # vert fonce du Cockpit
FG = (255, 255, 255)
ACCENT = (255, 190, 70)   # aiguille


def _in_round_rect(x, y, m, r):
    x0, y0, x1, y1 = m, m, 1 - m, 1 - m
    cx = min(max(x, x0 + r), x1 - r)
    cy = min(max(y, y0 + r), y1 - r)
    return x0 <= x <= x1 and y0 <= y <= y1 and (x - cx) ** 2 + (y - cy) ** 2 <= r * r


def _dist_seg(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def sample(x, y):
    """Couleur RGBA du point (x, y) dans [0,1]^2."""
    if not _in_round_rect(x, y, 0.04, 0.22):
        return (0, 0, 0, 0)
    c, cy = 0.5, 0.56
    d = math.hypot(x - c, y - cy)
    # arc de jauge : anneau r=0.30, epaisseur 0.07, ouvert vers le bas (de -50 a 230 degres)
    if abs(d - 0.30) <= 0.035:
        ang = math.degrees(math.atan2(-(y - cy), x - c)) % 360
        if not (230 < ang < 310):
            return FG + (255,)
    # graduations aux extremites et au sommet
    for a in (230, 90, -50):
        r = math.radians(a)
        if _dist_seg(x, y, c + 0.22 * math.cos(r), cy - 0.22 * math.sin(r),
                     c + 0.17 * math.cos(r), cy - 0.17 * math.sin(r)) <= 0.018:
            return FG + (255,)
    # aiguille vers le haut a droite
    r = math.radians(58)
    if _dist_seg(x, y, c, cy, c + 0.24 * math.cos(r), cy - 0.24 * math.sin(r)) <= 0.028:
        return ACCENT + (255,)
    if d <= 0.065:
        return FG + (255,)
    return BG + (255,)


def render(size, ss=4):
    px = []
    for j in range(size):
        row = []
        for i in range(size):
            acc = [0, 0, 0, 0]
            for sj in range(ss):
                for si in range(ss):
                    r, g, b, a = sample((i + (si + .5) / ss) / size, (j + (sj + .5) / ss) / size)
                    acc[0] += r * a
                    acc[1] += g * a
                    acc[2] += b * a
                    acc[3] += a
            n = ss * ss
            a = acc[3]
            row.append((round(acc[0] / a), round(acc[1] / a), round(acc[2] / a), round(a / n)) if a else (0, 0, 0, 0))
        px.append(row)
    return px


def png_bytes(px):
    h, w = len(px), len(px[0])
    raw = b"".join(b"\x00" + b"".join(struct.pack("BBBB", *p) for p in row) for row in px)

    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b""))


def bmp_bytes(px):
    """Entree ICO au format DIB 32 bits (BGRA, de bas en haut) + masque AND vide."""
    h, w = len(px), len(px[0])
    hdr = struct.pack("<IiiHHIIiiII", 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
    body = b"".join(b"".join(struct.pack("BBBB", p[2], p[1], p[0], p[3]) for p in row) for row in reversed(px))
    stride = ((w + 31) // 32) * 4
    return hdr + body + b"\x00" * (stride * h)


def build_ico(sizes=(16, 24, 32, 48, 64, 256)):
    entries = []
    for s in sizes:
        px = render(s, 4 if s >= 32 else 8)
        entries.append((s, png_bytes(px) if s >= 256 else bmp_bytes(px)))
    out = struct.pack("<HHH", 0, 1, len(entries))
    off = 6 + 16 * len(entries)
    for s, data in entries:
        out += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(data), off)
        off += len(data)
    return out + b"".join(d for _, d in entries)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "cockpit.ico"
    with open(target, "wb") as f:
        f.write(build_ico())
    print("ecrit", target)
