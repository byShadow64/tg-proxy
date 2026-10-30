"""Small, crisp route-inspired icons, drawn locally with no font assets.

``icon_image`` returns an appearance-aware CTkImage. ``icon_bitmap`` provides
the same drawing as a PIL image for native tray/window branding.
"""
from __future__ import annotations

from functools import lru_cache
from typing import Tuple, Union

from PIL import Image, ImageDraw

from ui.ctk_theme import CtkTheme


Color = Union[str, Tuple[str, str]]
_ALIASES = {
    "network": "globe", "route": "connection", "refresh": "restart",
    "arrow_up": "arrow-up", "arrow_right": "arrow-right",
    "arrow_down": "arrow-down", "arrow_left": "arrow-left",
    "up": "arrow-up", "right": "arrow-right", "down": "arrow-down",
    "left": "arrow-left", "log": "logs",
}
ICON_NAMES = (
    "logo", "overview", "activity", "logs", "settings", "server", "restart",
    "arrow-up", "arrow-right", "arrow-down", "arrow-left", "copy", "check",
    "globe", "connection", "link", "shield", "key", "stop", "download",
)


def _color_pair(theme: CtkTheme, color: Color) -> Tuple[str, str]:
    value = getattr(theme, color, color) if isinstance(color, str) else color
    return (value, value) if isinstance(value, str) else tuple(value)


@lru_cache(maxsize=256)
def _draw_icon(name: str, color: str, size: int) -> Image.Image:
    name = _ALIASES.get(name, name)
    if name not in ICON_NAMES:
        raise ValueError(f"Unknown TG Proxy icon: {name}")
    if size < 1:
        raise ValueError("Icon size must be positive")
    scale = size * 4 / 24
    image = Image.new("RGBA", (size * 4, size * 4), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    def box(coords):
        return tuple(round(value * scale) for value in coords)

    def line(points, width=1.7):
        points = [tuple(value * scale for value in point) for point in points]
        stroke = max(1, round(width * scale))
        draw.line(points, fill=color, width=stroke, joint="curve")
        radius = stroke / 2
        for x, y in (points[0], points[-1]):
            draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=color)

    def rect(coords, radius=1.6, width=1.7):
        draw.rounded_rectangle(box(coords), radius=round(radius * scale),
                               outline=color, width=max(1, round(width * scale)))

    def circle(x, y, radius, *, filled=False):
        draw.ellipse(box((x - radius, y - radius, x + radius, y + radius)),
                     fill=color if filled else (0, 0, 0, 0),
                     outline=color, width=max(1, round(1.7 * scale)))

    if name == "logo":
        line(((5, 18), (5, 7), (12, 7), (12, 17), (19, 17), (19, 6)), width=2.5)
        circle(5, 18, 2.7, filled=True)
        circle(19, 6, 2.7, filled=True)
    elif name == "overview":
        for x in (4, 14):
            for y in (4, 14):
                rect((x, y, x + 6, y + 6), radius=1.5)
    elif name == "activity":
        line(((3, 13), (7, 13), (10, 5), (14, 19), (17, 10), (21, 10)))
    elif name == "logs":
        for y in (6, 12, 18):
            circle(4, y, 0.8, filled=True)
            line(((8, y), (20, y)))
    elif name == "settings":
        for x, y in ((6, 8), (12, 16), (18, 10)):
            line(((x, 4), (x, 20)))
            circle(x, y, 2.3)
    elif name == "server":
        for y in (4, 14):
            rect((3.5, y, 20.5, y + 6), radius=2)
            circle(7, y + 3, 0.7, filled=True)
            line(((11, y + 3), (17, y + 3)), width=1.4)
    elif name == "stop":
        draw.rounded_rectangle(box((6, 6, 18, 18)), radius=round(scale), fill=color)
    elif name == "restart":
        draw.arc(box((4, 4, 20, 20)), start=205, end=505,
                 fill=color, width=max(1, round(1.8 * scale)))
        line(((3.5, 4), (3.5, 9.5), (9, 9.5)))
    elif name == "download":
        line(((12, 3.5), (12, 15)))
        line(((7.5, 10.5), (12, 15), (16.5, 10.5)))
        line(((4, 15), (4, 20), (20, 20), (20, 15)))
    elif name.startswith("arrow-"):
        direction = name[6:]
        if direction == "up":
            line(((12, 20), (12, 4)))
            line(((5.5, 10.5), (12, 4), (18.5, 10.5)))
        elif direction == "down":
            line(((12, 4), (12, 20)))
            line(((5.5, 13.5), (12, 20), (18.5, 13.5)))
        elif direction == "right":
            line(((4, 12), (20, 12)))
            line(((13.5, 5.5), (20, 12), (13.5, 18.5)))
        else:
            line(((20, 12), (4, 12)))
            line(((10.5, 5.5), (4, 12), (10.5, 18.5)))
    elif name == "copy":
        line(((6, 15), (4, 15), (4, 4), (15, 4), (15, 6)))
        rect((8, 8, 20, 20), radius=2)
    elif name == "check":
        line(((4.5, 12.5), (9.5, 17.5), (20, 6.5)), width=2)
    elif name == "globe":
        circle(12, 12, 9)
        draw.ellipse(box((8, 3, 16, 21)), outline=color,
                     width=max(1, round(1.5 * scale)))
        line(((3, 12), (21, 12)), width=1.5)
    elif name == "connection":
        line(((5, 6), (18, 6), (18, 18), (6, 18)))
        circle(5, 6, 2.6)
        circle(6, 18, 2.6)
        circle(18, 12, 2.6)
    elif name == "link":
        draw.arc(box((3, 9, 15, 21)), start=45, end=315,
                 fill=color, width=max(1, round(1.8 * scale)))
        draw.arc(box((9, 3, 21, 15)), start=225, end=495,
                 fill=color, width=max(1, round(1.8 * scale)))
        line(((8, 16), (16, 8)))
    elif name == "shield":
        line(((12, 3), (20, 6), (19, 14), (16, 19), (12, 22),
              (8, 19), (5, 14), (4, 6), (12, 3)))
        line(((8.5, 11.5), (11, 14), (15.5, 9.5)), width=1.5)
    elif name == "key":
        circle(8, 8, 4.5)
        line(((11.5, 11.5), (20, 20), (22, 18)))
        line(((16, 16), (18, 14)))
    return image


def _ctk_image(name: str, light: str, dark: str, size: int):
    import customtkinter as ctk

    return ctk.CTkImage(
        light_image=_draw_icon(name, light, size),
        dark_image=_draw_icon(name, dark, size), size=(size, size),
    )


def icon_image(name: str, theme: CtkTheme, size: int = 20, *,
               color: Color = "text_secondary"):
    """Return a CTkImage; ``color`` may name any paired theme token.

    Cache PIL drawings rather than Tk-bound images so separate application
    roots, including native UI tests, never reuse a destroyed Tcl image.
    """
    light, dark = _color_pair(theme, color)
    return _ctk_image(_ALIASES.get(name, name), light, dark, size)


def icon_bitmap(name: str, theme: CtkTheme, size: int = 20, *,
                color: Color = "text_secondary", appearance: str = "light") -> Image.Image:
    """Return a fresh PIL bitmap, suitable for a native tray or window icon."""
    colors = _color_pair(theme, color)
    rendered = _draw_icon(_ALIASES.get(name, name), colors[appearance == "dark"], size)
    return rendered.resize((size, size), Image.Resampling.LANCZOS)


@lru_cache(maxsize=16)
def _app_icon(size: int) -> Image.Image:
    if size < 1:
        raise ValueError("Icon size must be positive")
    canvas = Image.new("RGBA", (size * 4, size * 4), (0, 0, 0, 0))
    draw = ImageDraw.Draw(canvas)
    draw.rounded_rectangle((0, 0, size * 4 - 1, size * 4 - 1),
                           radius=round(size * 0.8), fill="#101A1A")
    symbol = _draw_icon("logo", "#69E4C7", max(1, round(size * 0.74)))
    offset = ((canvas.width - symbol.width) // 2, (canvas.height - symbol.height) // 2)
    canvas.alpha_composite(symbol, offset)
    return canvas.resize((size, size), Image.Resampling.LANCZOS)


def app_icon(size: int = 64) -> Image.Image:
    """Return TG Proxy's graphite/mint route mark for tray and ICO export."""
    return _app_icon(size).copy()
