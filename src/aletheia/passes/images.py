"""Imágenes PNG del pase generadas sin dependencias: la marca de Aletheia (escudo con
tilde) rasterizada con suavizado por supermuestreo. Se calculan una vez y se reutilizan."""

from __future__ import annotations

import math
import struct
import zlib
from functools import lru_cache

ACCENT = (139, 149, 255)  # índigo de la marca (#8b95ff)

# Escudo y tilde en coordenadas de 32×32 (mismo dibujo que el SVG del panel).
_SHIELD: list[tuple[float, float]] = [
    (16, 2),
    (28, 8),
    (28, 16),
    (25.5, 23),
    (16, 30),
    (6.5, 23),
    (4, 16),
    (4, 8),
]
_CHECK = [((10.5, 16.2), (14.3, 20.0)), ((14.3, 20.0), (21.7, 12.0))]


def _png(width: int, height: int, rgba: bytes) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))
        )

    rows = b"".join(b"\x00" + rgba[y * width * 4 : (y + 1) * width * 4] for y in range(height))
    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(rows, 9))
        + chunk(b"IEND", b"")
    )


def _inside(poly: list[tuple[float, float]], x: float, y: float) -> bool:
    inside = False
    j = len(poly) - 1
    for i, (xi, yi) in enumerate(poly):
        xj, yj = poly[j]
        if (yi > y) != (yj > y) and x < (xj - xi) * (y - yi) / (yj - yi) + xi:
            inside = not inside
        j = i
    return inside


def _seg_dist(px: float, py: float, a: tuple[float, float], b: tuple[float, float]) -> float:
    ax, ay = a
    bx, by = b
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def _mark_pixel(x: float, y: float, stroke: float) -> tuple[int, int, int] | None:
    """Color del punto (en coordenadas 32×32): escudo índigo con tilde blanca."""
    if any(_seg_dist(x, y, a, b) <= stroke for a, b in _CHECK):
        return (255, 255, 255)
    if _inside(_SHIELD, x, y):
        return ACCENT
    return None


@lru_cache(maxsize=16)
def mark_png(
    size: int, *, width: int | None = None, background: tuple[int, int, int] | None = None
) -> bytes:
    """Marca cuadrada de ``size`` px; con ``width`` se centra en un lienzo más ancho (logo)."""
    width = width or size
    scale = 32 / size
    samples = 4
    out = bytearray()
    offset = (width - size) / 2
    for py in range(size):
        for px in range(width):
            acc = [0.0, 0.0, 0.0, 0.0]
            for sy in range(samples):
                for sx in range(samples):
                    x = (px - offset + (sx + 0.5) / samples) * scale
                    y = (py + (sy + 0.5) / samples) * scale
                    color = _mark_pixel(x, y, 1.45) if 0 <= x <= 32 else None
                    if color is None and background is not None:
                        color = background
                    if color is not None:
                        acc[0] += color[0]
                        acc[1] += color[1]
                        acc[2] += color[2]
                        acc[3] += 255
            n = samples * samples
            alpha = acc[3] / n
            if alpha:
                k = 255 / acc[3]
                out += bytes(
                    (round(acc[0] * k), round(acc[1] * k), round(acc[2] * k), round(alpha))
                )
            else:
                out += b"\x00\x00\x00\x00"
    return _png(width, size, bytes(out))


def pass_images() -> dict[str, bytes]:
    """Imágenes que requiere un pase genérico: icono (obligatorio) y logo, en 1×/2×/3×."""
    return {
        "icon.png": mark_png(29),
        "icon@2x.png": mark_png(58),
        "icon@3x.png": mark_png(87),
        "logo.png": mark_png(50, width=50),
        "logo@2x.png": mark_png(100, width=100),
    }
