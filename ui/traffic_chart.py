"""Traffic visualization backed only by observed proxy byte counters."""
from __future__ import annotations

from collections import deque

from PIL import Image, ImageDraw


class TrafficHistory:
    def __init__(self, duration=60.0):
        self.duration = duration
        self.points = deque()
        self._previous = None
        self.rates = (0.0, 0.0)

    def sample(self, uploaded, downloaded, now):
        if self._previous is not None:
            timestamp, old_up, old_down = self._previous
            elapsed = now - timestamp
            if elapsed <= 0:
                return self.rates
            self.rates = (max(0, uploaded - old_up) / elapsed,
                          max(0, downloaded - old_down) / elapsed)
        self._previous = (now, uploaded, downloaded)
        self.points.append((now, *self.rates))
        while self.points and self.points[0][0] < now - self.duration:
            self.points.popleft()
        return self.rates


class TrafficChart:
    def __init__(self, ctk, parent, theme, history):
        self.ctk, self.theme, self.history = ctk, theme, history
        self.frame = ctk.CTkFrame(parent, height=112, fg_color=theme.surface, corner_radius=0)
        self.frame.pack_propagate(False)
        self.label = ctk.CTkLabel(self.frame, text="", height=1, width=1)
        self.label.pack(fill="both", expand=True)
        self._width, self._image = 0, None
        self.frame.bind("<Configure>", self._resize, add="+")

    def _resize(self, event):
        width = max(80, int(event.width / self.frame._get_widget_scaling()))
        if width != self._width:
            self._width = width
            self.refresh()

    @staticmethod
    def _color(token, mode):
        return token[mode] if isinstance(token, (tuple, list)) else token

    def refresh(self):
        if self._width < 1:
            return
        width, height, scale = self._width, 112, 2
        points = tuple(self.history.points)
        ceiling = max(1024.0, max((max(up, down) for _, up, down in points), default=0) * 1.2)

        def render(mode):
            def color(token):
                return self._color(token, mode)
            image = Image.new("RGB", (width * scale, height * scale), color(self.theme.surface))
            draw = ImageDraw.Draw(image)
            left, right, top, bottom = 2 * scale, (width - 2) * scale, 8 * scale, 103 * scale
            for ratio in (0, 0.5, 1):
                y = top + (bottom - top) * ratio
                draw.line((left, y, right, y), fill=color(self.theme.field_border), width=scale)
            if not points:
                return image
            end = points[-1][0]

            def coordinates(series):
                return [(left + max(0, min(1, (stamp - end + self.history.duration)
                                          / self.history.duration)) * (right - left),
                         bottom - min(1, rates[series] / ceiling) * (bottom - top))
                        for stamp, *rates in points]

            down, up = coordinates(1), coordinates(0)
            if len(down) > 1:
                draw.polygon([(down[0][0], bottom), *down, (down[-1][0], bottom)],
                             fill=color(self.theme.accent_soft))
                draw.line(down, fill=color(self.theme.accent), width=2 * scale, joint="curve")
                draw.line(up, fill=color(self.theme.text_muted), width=scale, joint="curve")
            x, y = down[-1]
            radius = 3 * scale
            draw.ellipse((x - radius, y - radius, x + radius, y + radius), fill=color(self.theme.accent))
            return image

        self._image = self.ctk.CTkImage(light_image=render(0), dark_image=render(1), size=(width, height))
        self.label.configure(image=self._image)
