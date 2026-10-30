from __future__ import annotations

import time
from typing import Callable

from proxy import __version__
from proxy.stats import stats
from proxy.utils import human_bytes
from ui.ctk_theme import CtkTheme
from ui.i18n import get_language, t
from ui.icons import icon_image
from ui.branding import brand_image
from ui.log_viewer import LogViewer
from ui.traffic_chart import TrafficChart, TrafficHistory
from ui.update_button import SidebarUpdates
from ui.background_task import BackgroundTask
from ui.connection_diagnostics import ConnectionDiagnostics
from utils.live_logs import live_logs
from utils.helper_config import effective_helper_mode
from utils.connection_diagnostics import make_snapshot


class DashboardView:
    def __init__(self, ctk, root, theme: CtkTheme, config: dict, *,
                 running, on_telegram, on_settings, on_restart,
                 config_path, on_close, log_source=live_logs, on_copy=None, on_update=None,
                 on_stop=None, get_diagnostics_snapshot=None, on_routes=None):
        self.ctk, self.root, self.theme = ctk, root, theme
        self.config, self.running = config, running
        self._on_telegram, self._on_restart = on_telegram, on_restart
        self._on_stop = on_stop
        self._stopping = False
        self._proxy_controls_state = None
        self.stop_task = BackgroundTask(root)
        self.config_path, self.on_close = config_path, on_close
        self.closed = self.logs_visible = False
        self._last_stats_update = 0.0
        self._refresh_id = None
        self._language = get_language()
        self._translated_widgets = []
        self.history = TrafficHistory()
        root.title(t("dashboard.title"))
        root.minsize(860, 640)
        root.resizable(True, True)
        root.configure(fg_color=theme.bg)
        root.attributes("-topmost", False)
        root.grid_rowconfigure(0, weight=1)
        root.grid_columnconfigure(1, weight=1)

        sidebar = ctk.CTkFrame(root, width=190, fg_color=theme.sidebar_bg, corner_radius=0)
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(4, weight=1)
        brand = ctk.CTkFrame(sidebar, fg_color="transparent")
        brand.grid(row=0, column=0, sticky="ew", padx=18, pady=(24, 26))
        ctk.CTkLabel(brand, text="", image=brand_image(), width=48, height=48).pack(
            side="left", padx=(0, 10))
        ctk.CTkLabel(brand, text="TG Proxy", font=(theme.ui_font_family, 18, "bold"),
                     text_color=theme.text_primary).pack(side="left")
        navigation = ctk.CTkFrame(sidebar, fg_color="transparent")
        navigation.grid(row=1, column=0, sticky="ew", padx=12)
        self.overview_button = self._nav(navigation, "dashboard.overview", "overview", self.show_overview)
        self.logs_button = self._nav(navigation, "logs.title", "activity", self.show_logs)
        ctk.CTkFrame(sidebar, height=1, fg_color=theme.field_border, corner_radius=0).grid(
            row=2, column=0, sticky="ew", padx=24, pady=18)
        preferences = ctk.CTkFrame(sidebar, fg_color="transparent")
        preferences.grid(row=3, column=0, sticky="ew", padx=12)
        self.settings_button = self._nav(preferences, "settings.title", "settings", on_settings)
        sidebar_footer = ctk.CTkFrame(sidebar, fg_color="transparent")
        sidebar_footer.grid(row=5, column=0, sticky="ew", padx=24, pady=24)
        self.updates = SidebarUpdates(ctk, sidebar_footer, theme, on_update=on_update)
        self.updates.frame.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(sidebar_footer, text=f"v{__version__}", anchor="w",
                     font=(theme.mono_font_family, 11), text_color=theme.text_muted).pack(fill="x")

        main = ctk.CTkFrame(root, fg_color="transparent", corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew", padx=28, pady=(25, 22))
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)
        header = ctk.CTkFrame(main, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header.grid_columnconfigure(0, weight=1)
        self.page_title = ctk.CTkLabel(
            header, text="", anchor="w", font=(theme.ui_font_family, 25, "bold"),
            text_color=theme.text_primary,
        )
        self.page_title.grid(row=0, column=0, sticky="w")
        self.page_subtitle = ctk.CTkLabel(
            header, text="", anchor="w", font=(theme.ui_font_family, 12),
            text_color=theme.text_secondary,
        )
        self.page_subtitle.grid(row=1, column=0, sticky="w", pady=(3, 0))
        self.status = ctk.CTkLabel(
            header, text="", corner_radius=9, padx=12, height=30,
            font=(theme.ui_font_family, 11, "bold"),
        )
        self.status.grid(row=0, column=1, rowspan=2, sticky="e", padx=(10, 0))
        body = ctk.CTkFrame(main, fg_color="transparent", corner_radius=0)
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)
        self.overview = ctk.CTkScrollableFrame(
            body, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=theme.field_border,
            scrollbar_button_hover_color=theme.text_muted,
        )
        self.overview.grid(row=0, column=0, sticky="nsew")
        self.overview.grid_columnconfigure(0, weight=1)

        hero = self._surface(self.overview)
        hero.grid(row=0, column=0, sticky="ew", pady=(0, 16))
        hero.grid_columnconfigure(0, weight=1)
        intro = ctk.CTkFrame(hero, fg_color="transparent")
        intro.grid(row=0, column=0, sticky="nsew", padx=22, pady=21)
        self._localized(ctk.CTkLabel(
            intro, height=14, anchor="w", font=(theme.ui_font_family, 10, "bold"), text_color=theme.accent,
        ), "dashboard.local_channel").pack(anchor="w")
        self.connection_title = ctk.CTkLabel(
            intro, text="", height=36, anchor="w", font=(theme.ui_font_family, 25, "bold"),
            text_color=theme.text_primary,
        )
        self.connection_title.pack(anchor="w", pady=(9, 3))
        self._localized(ctk.CTkLabel(
            intro, height=24, anchor="w", justify="left", wraplength=310,
            font=(theme.ui_font_family, 12), text_color=theme.text_secondary,
        ), "dashboard.connect_hint").pack(fill="x")
        connection_actions = ctk.CTkFrame(intro, fg_color="transparent")
        connection_actions.pack(anchor="w", pady=(18, 0))
        self.telegram_button = self._localized(ctk.CTkButton(
            connection_actions, height=40, corner_radius=10, font=(theme.ui_font_family, 12, "bold"),
            fg_color=theme.accent, hover_color=theme.accent_hover, text_color=theme.on_accent,
            image=icon_image("arrow-right", theme, 16, color="on_accent"),
            compound="right", command=on_telegram,
        ), "dashboard.connect_telegram")
        self.telegram_button.pack(side="left")
        self.stop_button = ctk.CTkButton(
            connection_actions, text=t("dashboard.stop_proxy"), height=40, width=154,
            corner_radius=10, font=(theme.ui_font_family, 12, "bold"),
            fg_color="transparent", hover_color=theme.surface_alt,
            border_width=1, border_color=theme.field_border,
            text_color=theme.danger, text_color_disabled=theme.text_muted,
            image=icon_image("stop", theme, 15, color="danger"), command=self.stop_proxy,
        )
        self.stop_button.pack(side="left", padx=(10, 0))
        endpoint = ctk.CTkFrame(hero, width=178, fg_color=theme.surface_alt, corner_radius=12)
        endpoint.grid(row=0, column=1, sticky="nsew", padx=(0, 16), pady=16)
        endpoint.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(endpoint, text="", image=icon_image("connection", theme, 24, color="accent"),
                     anchor="w").grid(row=0, column=0, sticky="w", padx=16, pady=(14, 6))
        self.endpoint = ctk.CTkLabel(
            endpoint, text="", width=1, wraplength=145, justify="left", anchor="w",
            font=(theme.mono_font_family, 15, "bold"),
            text_color=theme.text_primary,
        )
        self.endpoint.grid(row=1, column=0, sticky="ew", padx=16)
        self.endpoint_port = ctk.CTkLabel(
            endpoint, text="", anchor="w", font=(theme.mono_font_family, 11),
            text_color=theme.text_secondary,
        )
        self.endpoint_port.grid(row=2, column=0, sticky="w", padx=16, pady=(0, 8))
        self.copy_button = self._localized(ctk.CTkButton(
            endpoint, width=135, height=30, corner_radius=8,
            fg_color="transparent", hover_color=theme.field_border, text_color=theme.text_secondary,
            anchor="w", image=icon_image("copy", theme, 14), font=(theme.ui_font_family, 11),
            command=on_copy or self._copy_link,
        ), "dashboard.copy_link")
        self.copy_button.grid(row=3, column=0, sticky="w", padx=8, pady=(0, 10))

        metrics = self._surface(self.overview)
        metrics.grid(row=1, column=0, sticky="ew", pady=(0, 16))
        self.metrics, self.metric_details = {}, {}
        for index, (name, key) in enumerate((
            ("connections", "dashboard.connections"),
            ("down", "dashboard.downloaded"), ("up", "dashboard.uploaded"),
        )):
            metrics.grid_columnconfigure(index * 2, weight=1, uniform="metric")
            column = ctk.CTkFrame(metrics, fg_color="transparent", width=1)
            column.grid(row=0, column=index * 2, sticky="nsew", padx=20, pady=15)
            self._localized(ctk.CTkLabel(
                column, height=18, anchor="w", font=(theme.ui_font_family, 11), text_color=theme.text_secondary,
            ), key).pack(anchor="w")
            self.metrics[name] = ctk.CTkLabel(
                column, text="0", height=34, anchor="w", font=(theme.ui_font_family, 25, "bold"),
                text_color=theme.text_primary,
            )
            self.metrics[name].pack(anchor="w", pady=(5, 0))
            self.metric_details[name] = ctk.CTkLabel(
                column, text="", height=16, anchor="w", font=(theme.ui_font_family, 10), text_color=theme.text_muted,
            )
            self.metric_details[name].pack(anchor="w")
            if index < 2:
                ctk.CTkFrame(metrics, width=1, height=46, corner_radius=0,
                             fg_color=theme.field_border).grid(row=0, column=index * 2 + 1)

        traffic = self._surface(self.overview)
        traffic.grid(row=2, column=0, sticky="ew", pady=(0, 16))
        traffic_header = ctk.CTkFrame(traffic, fg_color="transparent")
        traffic_header.pack(fill="x", padx=20, pady=(15, 0))
        self._localized(ctk.CTkLabel(
            traffic_header, height=22, font=(theme.ui_font_family, 13, "bold"), text_color=theme.text_primary,
        ), "dashboard.traffic").pack(side="left")
        self.rate_label = ctk.CTkLabel(
            traffic_header, text="", height=22, font=(theme.mono_font_family, 11), text_color=theme.accent,
        )
        self.rate_label.pack(side="right")
        self.chart = TrafficChart(ctk, traffic, theme, self.history)
        self.chart.frame.pack(fill="x", padx=20, pady=(5, 0))
        legend = ctk.CTkFrame(traffic, fg_color="transparent")
        legend.pack(fill="x", padx=20, pady=(0, 14))
        self._localized(ctk.CTkLabel(
            legend, height=16, font=(theme.ui_font_family, 10), text_color=theme.text_muted,
        ), "dashboard.last_minute").pack(side="left")
        self._localized(ctk.CTkLabel(
            legend, height=16, font=(theme.ui_font_family, 10), text_color=theme.accent,
        ), "dashboard.download_legend").pack(side="right")
        self._localized(ctk.CTkLabel(
            legend, height=16, font=(theme.ui_font_family, 10), text_color=theme.text_muted,
        ), "dashboard.upload_legend").pack(side="right", padx=(0, 14))

        self.connection_diagnostics = ConnectionDiagnostics(
            ctk, self.overview, theme,
            get_snapshot=get_diagnostics_snapshot or (lambda: make_snapshot(self.config, running=self.running())),
            running=self.running, on_restart=on_restart,
            on_routes=on_routes or on_settings, on_telegram=on_telegram,
        )
        self.connection_diagnostics.frame.grid(row=3, column=0, sticky="ew", pady=(0, 16))

        routing = ctk.CTkFrame(self.overview, fg_color="transparent")
        routing.grid(row=4, column=0, sticky="ew", pady=(0, 4), padx=2)
        routing.grid_columnconfigure(0, weight=1)
        self.routes = ctk.CTkLabel(
            routing, text="", width=1, anchor="w", justify="left", wraplength=500,
            font=(theme.ui_font_family, 11), text_color=theme.text_secondary,
        )
        self.routes.grid(row=0, column=0, sticky="ew")
        self.restart_button = self._localized(ctk.CTkButton(
            routing, width=140, height=30, corner_radius=8,
            fg_color="transparent", hover_color=theme.surface_alt, text_color=theme.text_secondary,
            image=icon_image("restart", theme, 15), font=(theme.ui_font_family, 11), command=on_restart,
        ), "dashboard.restart")
        self.restart_button.grid(row=0, column=1, padx=(10, 0))
        self.diagnostics = ctk.CTkLabel(
            routing, text="", width=1, anchor="w", justify="left", wraplength=630,
            font=(theme.ui_font_family, 10), text_color=theme.text_muted,
        )
        self.diagnostics.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(7, 0))
        routing.bind("<Configure>", self._fit_footer, add="+")
        self.log_viewer = LogViewer(ctk, body, theme, log_source, self.show_overview,
                                   show_back=False, show_header=False)
        self.log_viewer.frame.grid(row=0, column=0, sticky="nsew")
        self.log_viewer.frame.grid_remove()
        root.protocol("WM_DELETE_WINDOW", self.close)
        # Set the initial size after all scrollable children exist. CTk can
        # pump geometry events while constructing widgets; sizing first can
        # leave the overview's embedded window at the old canvas width.
        root.geometry("1080x760")
        self._page_labels()
        self.refresh()

    def _surface(self, parent):
        return self.ctk.CTkFrame(parent, fg_color=self.theme.surface, corner_radius=15,
                                border_width=1, border_color=self.theme.field_border)

    def _localized(self, widget, key):
        self._translated_widgets.append((widget, key))
        widget.configure(text=t(key))
        return widget

    def _nav(self, parent, key, icon, callback):
        button = self._localized(self.ctk.CTkButton(
            parent, height=42, corner_radius=10, anchor="w", border_spacing=12,
            image=icon_image(icon, self.theme, 18), font=(self.theme.ui_font_family, 12),
            fg_color="transparent", hover_color=self.theme.surface_alt,
            text_color=self.theme.text_secondary, command=callback,
        ), key)
        button.pack(fill="x", pady=3)
        return button

    def _page_labels(self):
        self.page_title.configure(text=t("logs.title" if self.logs_visible else "dashboard.overview"))
        self.page_subtitle.configure(text=t("dashboard.logs_subtitle" if self.logs_visible
                                           else "dashboard.subtitle"))
        for button, active in ((self.overview_button, not self.logs_visible), (self.logs_button, self.logs_visible)):
            button.configure(fg_color=self.theme.accent_soft if active else "transparent",
                             text_color=self.theme.accent if active else self.theme.text_secondary)

    def _fit_footer(self, event):
        width = max(200, int(event.width / self.routes._get_widget_scaling()))
        self.routes.configure(wraplength=max(160, width - 165))
        self.diagnostics.configure(wraplength=width)

    def _copy_link(self):
        from proxy.utils import get_link_host
        host = get_link_host(self.config.get("host", "127.0.0.1"))
        port, secret = self.config.get("port", 1443), self.config.get("secret", "")
        self.root.clipboard_clear()
        self.root.clipboard_append(f"tg://proxy?server={host}&port={port}&secret=dd{secret}")

    def _refresh_language(self):
        language = get_language()
        if language == self._language:
            return
        self._language = language
        self.root.title(t("dashboard.title"))
        for widget, key in self._translated_widgets:
            widget.configure(text=t(key))
        self._page_labels()
        self.updates.refresh()
        self.log_viewer.refresh_language()
        self._last_stats_update = 0.0

    def show_logs(self):
        self.overview.grid_remove()
        self.log_viewer.frame.grid()
        self.logs_visible = True
        self._page_labels()
        self.log_viewer.refresh()

    def show_overview(self):
        self.log_viewer.frame.grid_remove()
        self.overview.grid()
        self.logs_visible = False
        self._page_labels()

    def stop_proxy(self):
        if self.closed or self._stopping or self._on_stop is None or not self.running():
            return
        self._stopping = True
        self._update_proxy_controls()

        def finish():
            self._stopping = False
            self._last_stats_update = 0.0
            self.refresh()

        self.stop_task.start(self._on_stop, lambda result: None, finish)

    def _update_proxy_controls(self):
        alive = self.running()
        state = (alive, self._stopping, get_language())
        if state == self._proxy_controls_state:
            return
        self._proxy_controls_state = state
        self.status.configure(
            text=t("dashboard.stopping" if self._stopping else
                   "dashboard.running" if alive else "dashboard.stopped"),
            fg_color=self.theme.warning_bg if self._stopping else
            self.theme.accent_soft if alive else self.theme.surface_alt,
            text_color=self.theme.warning if self._stopping else
            self.theme.accent if alive else self.theme.text_secondary,
        )
        self.connection_title.configure(text=t("dashboard.ready" if alive else "dashboard.offline"))
        self.telegram_button.configure(
            text=t("dashboard.connect_telegram" if alive else "dashboard.start_proxy"),
            command=self._on_telegram if alive else self._on_restart,
            image=icon_image("arrow-right" if alive else "restart", self.theme, 16, color="on_accent"),
            state="disabled" if self._stopping else "normal",
        )
        self.stop_button.configure(
            text=t("dashboard.stopping" if self._stopping else "dashboard.stop_proxy"),
            state="normal" if alive and self._on_stop is not None and not self._stopping else "disabled",
        )
        self.restart_button.configure(state="disabled" if self._stopping else "normal")

    def refresh(self):
        if self.closed:
            return
        if self._refresh_id is not None:
            self.root.after_cancel(self._refresh_id)
            self._refresh_id = None
        self._refresh_language()
        self.updates.refresh()
        self.connection_diagnostics.refresh()
        self._update_proxy_controls()
        now = time.monotonic()
        if now - self._last_stats_update >= 1:
            self._last_stats_update = now
            self.endpoint.configure(text=str(self.config.get("host", "127.0.0.1")))
            self.endpoint_port.configure(text=t("dashboard.port", port=self.config.get("port", 1443)))
            self.metrics["connections"].configure(text=str(stats.connections_active))
            self.metric_details["connections"].configure(text=t(
                "dashboard.total_connections", count=f"{stats.connections_total:,}".replace(",", " ")))
            for key, amount in (("up", stats.bytes_up), ("down", stats.bytes_down)):
                self.metrics[key].configure(text=human_bytes(amount))
                self.metric_details[key].configure(text=t("dashboard.since_start"))
            up, down = self.history.sample(stats.bytes_up, stats.bytes_down, now)
            self.rate_label.configure(text=t("dashboard.rate", down=human_bytes(down), up=human_bytes(up)))
            self.chart.refresh()
            self.routes.configure(text=t(
                "dashboard.route_counts", helper=stats.connections_helper,
                websocket=stats.connections_ws, cloudflare=stats.connections_cfproxy,
                tcp=stats.connections_tcp_fallback,
            ))
            mode = effective_helper_mode(self.config)
            self.diagnostics.configure(text=t(
                "dashboard.route_mode", mode=t(f"helper.mode.{mode}")) + "\n" + t(
                    "dashboard.config_location", path=self.config_path))
        if self.logs_visible:
            self.log_viewer.refresh()
        self._refresh_id = self.root.after(250, self.refresh)

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.connection_diagnostics.close()
        if self._refresh_id is not None:
            self.root.after_cancel(self._refresh_id)
        try:
            self.root.destroy()
        finally:
            self.on_close()


def build_dashboard(ctk, root, theme: CtkTheme, config: dict, *,
                    running: Callable[[], bool], on_telegram: Callable[[], None],
                    on_settings: Callable[[], None],
                    on_restart: Callable[[], None], config_path: str,
                    on_close: Callable[[], None], log_source=live_logs,
                    on_copy: Callable[[], None] = None,
                    on_update: Callable[[], None] = None,
                    on_stop: Callable[[], None] = None,
                    get_diagnostics_snapshot: Callable = None,
                    on_routes: Callable[[], None] = None) -> DashboardView:
    return DashboardView(
        ctk, root, theme, config, running=running, on_telegram=on_telegram,
        on_settings=on_settings, on_restart=on_restart,
        config_path=config_path, on_close=on_close, log_source=log_source,
        on_copy=on_copy, on_update=on_update, on_stop=on_stop,
        get_diagnostics_snapshot=get_diagnostics_snapshot, on_routes=on_routes,
    )
