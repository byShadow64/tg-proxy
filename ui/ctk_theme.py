from __future__ import annotations

import sys
import tkinter
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Tuple

_tk_variable_del_guard_installed = False
log = logging.getLogger(__name__)


def app_icon_path() -> Path:
    """Resolve the data asset from a PyInstaller bundle or the source tree."""
    bundle = getattr(sys, "_MEIPASS", None)
    base = Path(bundle) if bundle else Path(__file__).resolve().parents[1]
    return base / "icon.ico"


def install_window_icon(root: Any, *, default: bool = False) -> None:
    """Keep TG Proxy's icon after CTk's delayed Windows titlebar setup."""
    if sys.platform != "win32":
        return
    path = app_icon_path()
    if not path.is_file():
        log.warning("Application icon is missing: %s", path)
        return

    def apply_icon():
        try:
            if root.winfo_exists():
                if default:
                    root.iconbitmap(default=str(path))
                else:
                    root.iconbitmap(str(path))
                from utils.windows_identity import install_native_icons
                install_native_icons(root, path)
        except (tkinter.TclError, OSError) as exc:
            log.warning("Could not set application icon (%s)", type(exc).__name__)

    apply_icon()
    # CTkToplevel unconditionally installs its own icon after 200 ms.
    # Apply ours afterwards for every window, not only the hidden app root.
    pending = root.after(300, apply_icon)

    def cancel_pending(event):
        if event.widget is root:
            try:
                root.after_cancel(pending)
            except tkinter.TclError:
                pass

    root.bind("<Destroy>", cancel_pending, add="+")


def install_tkinter_variable_del_guard() -> None:
    global _tk_variable_del_guard_installed
    if _tk_variable_del_guard_installed:
        return
    _orig = tkinter.Variable.__del__

    def _safe_variable_del(self: Any, _orig: Any = _orig) -> None:
        try:
            _orig(self)
        except (RuntimeError, tkinter.TclError):
            pass

    tkinter.Variable.__del__ = _safe_variable_del  # type: ignore[assignment]
    _tk_variable_del_guard_installed = True

CONFIG_DIALOG_SIZE: Tuple[int, int] = (680, 680)
CONFIG_DIALOG_FRAME_PAD: Tuple[int, int] = (28, 24)
FIRST_RUN_SIZE: Tuple[int, int] = (600, 560)
FIRST_RUN_FRAME_PAD: Tuple[int, int] = (32, 28)


@dataclass(frozen=True)
class CtkTheme:
    """TG Proxy's shared light/dark palette. Pairs follow CTk appearance mode."""

    bg: tuple = ("#F4F6F5", "#101A1A")
    surface: tuple = ("#FFFFFF", "#162222")
    surface_alt: tuple = ("#EDF2F0", "#1C2B29")
    sidebar_bg: tuple = ("#E8EEEB", "#0C1515")
    field_bg: tuple = ("#F8FAF9", "#12201F")
    field_border: tuple = ("#D6E1DC", "#2A3D39")
    code_bg: tuple = ("#EBF0ED", "#0D1716")

    accent: tuple = ("#0D7163", "#69E4C7")
    accent_hover: tuple = ("#095D52", "#84EDD5")
    accent_soft: tuple = ("#DCEFE7", "#203D35")
    on_accent: tuple = ("#FFFFFF", "#102D25")
    text_primary: tuple = ("#152B27", "#EDF5F0")
    text_secondary: tuple = ("#536B62", "#A5B9B1")
    text_muted: tuple = ("#5D7268", "#7D958B")

    success: tuple = ("#247C59", "#78D7AD")
    warning: tuple = ("#9C6E1E", "#E8BC6B")
    warning_bg: tuple = ("#FBF1DB", "#372F1E")
    danger: tuple = ("#B5544C", "#EA978D")

    ui_font_family: str = "Sans"
    mono_font_family: str = "Monospace"

    @property
    def tg_blue(self) -> tuple:
        """Compatibility alias for views using the previous palette name."""
        return self.accent

    @property
    def tg_blue_hover(self) -> tuple:
        return self.accent_hover

    @property
    def accent_text(self) -> tuple:
        return self.on_accent


def ctk_theme_for_platform() -> CtkTheme:
    if sys.platform == "win32":
        return CtkTheme(ui_font_family="Segoe UI", mono_font_family="Consolas")
    return CtkTheme()


_APPEARANCE_MODE_MAP = {"auto": "system", "light": "Light", "dark": "Dark"}


def apply_ctk_appearance(ctk: Any, mode: str = "auto") -> None:
    ctk.set_appearance_mode(_APPEARANCE_MODE_MAP.get(mode, "system"))
    _install_widget_theme(ctk, ctk_theme_for_platform())


def _install_widget_theme(ctk: Any, theme: CtkTheme) -> None:
    """Give unstyled CTk widgets the same palette as the custom views."""
    definitions = {
        "CTk": {"fg_color": theme.bg},
        "CTkToplevel": {"fg_color": theme.bg},
        "CTkFrame": {
            "corner_radius": 14, "fg_color": theme.surface,
            "top_fg_color": theme.surface_alt, "border_color": theme.field_border,
        },
        "CTkButton": {
            "corner_radius": 10, "fg_color": theme.accent,
            "hover_color": theme.accent_hover, "text_color": theme.on_accent,
            "border_color": theme.field_border, "text_color_disabled": theme.text_muted,
        },
        "CTkLabel": {"text_color": theme.text_primary},
        "CTkEntry": {
            "corner_radius": 10, "border_width": 1, "fg_color": theme.field_bg,
            "border_color": theme.field_border, "text_color": theme.text_primary,
            "placeholder_text_color": theme.text_muted,
        },
        "CTkCheckBox": {
            "corner_radius": 6, "border_width": 2, "fg_color": theme.accent,
            "hover_color": theme.accent_hover, "border_color": theme.field_border,
            "checkmark_color": theme.on_accent, "text_color": theme.text_primary,
            "text_color_disabled": theme.text_muted,
        },
        "CTkSwitch": {
            "fg_color": theme.field_border, "progress_color": theme.accent,
            "button_color": theme.surface, "button_hover_color": theme.surface_alt,
            "text_color": theme.text_primary, "text_color_disabled": theme.text_muted,
        },
        "CTkRadioButton": {
            "fg_color": theme.accent, "hover_color": theme.accent_hover,
            "border_color": theme.field_border, "text_color": theme.text_primary,
            "text_color_disabled": theme.text_muted,
        },
        "CTkProgressBar": {
            "fg_color": theme.field_border, "progress_color": theme.accent,
            "border_color": theme.field_border,
        },
        "CTkSlider": {
            "fg_color": theme.field_border, "progress_color": theme.accent,
            "button_color": theme.accent, "button_hover_color": theme.accent_hover,
        },
        "CTkOptionMenu": {
            "corner_radius": 10, "fg_color": theme.surface_alt,
            "button_color": theme.surface_alt, "button_hover_color": theme.field_border,
            "text_color": theme.text_primary, "text_color_disabled": theme.text_muted,
        },
        "CTkComboBox": {
            "corner_radius": 10, "border_width": 1, "fg_color": theme.field_bg,
            "border_color": theme.field_border, "button_color": theme.surface_alt,
            "button_hover_color": theme.field_border, "text_color": theme.text_primary,
            "text_color_disabled": theme.text_muted,
        },
        "CTkScrollbar": {
            "button_color": theme.field_border, "button_hover_color": theme.text_muted,
        },
        "CTkSegmentedButton": {
            "corner_radius": 10, "border_width": 3, "fg_color": theme.surface_alt,
            "selected_color": theme.accent_soft, "selected_hover_color": theme.field_border,
            "unselected_color": theme.surface_alt,
            "unselected_hover_color": theme.field_border,
            "text_color": theme.text_primary, "text_color_disabled": theme.text_muted,
        },
        "CTkTextbox": {
            "corner_radius": 12, "border_width": 1, "fg_color": theme.code_bg,
            "border_color": theme.field_border, "text_color": theme.text_primary,
            "scrollbar_button_color": theme.field_border,
            "scrollbar_button_hover_color": theme.text_muted,
        },
        "CTkScrollableFrame": {"label_fg_color": theme.surface_alt},
        "DropdownMenu": {
            "fg_color": theme.surface, "hover_color": theme.accent_soft,
            "text_color": theme.text_primary,
        },
        "CTkFont": {"family": theme.ui_font_family, "size": 13},
    }
    for widget, options in definitions.items():
        ctk.ThemeManager.theme[widget].update(options)

def center_ctk_geometry(root: Any, width: int, height: int) -> None:
    sw = root.winfo_screenwidth()
    sh = root.winfo_screenheight()
    root.geometry(f"{width}x{height}+{(sw - width) // 2}+{(sh - height) // 2}")


class _DialogPresentation:
    """Keep a modeless dialog above its live owner, without global topmost."""

    def __init__(self, window):
        self.window = window
        self.owner = self.pending = self.owner_pending = None
        self.owner_bindings = {}
        window.bind("<Destroy>", self._closed, add="+")

    def _detach_owner(self):
        if self.owner is not None:
            for sequence, binding in self.owner_bindings.items():
                try:
                    self.owner.unbind(sequence, binding)
                except tkinter.TclError:
                    pass
        self.owner, self.owner_bindings = None, {}
        if self.owner_pending is not None:
            try:
                self.window.after_cancel(self.owner_pending)
            except tkinter.TclError:
                pass
            self.owner_pending = None

    def _owner_mapped(self, event):
        if event.widget is self.owner and self.owner_pending is None:
            self.owner_pending = self.window.after(100, self._owner_settled)

    def _owner_settled(self):
        self.owner_pending = None
        try:
            if (self.owner is not None and self.owner.winfo_viewable()
                    and self.window.winfo_exists() and self.window.state() == "withdrawn"):
                # Appearance changes redraw both Windows titlebars. CTk may
                # capture the child's temporarily hidden state while redrawing
                # its owner, then leave it withdrawn after the owner remaps.
                # Restore visibility without stealing focus on a system theme change.
                self.window.deiconify()
        except tkinter.TclError:
            pass

    def _owner_closed(self, event):
        if event.widget is self.owner:
            # The windows are Tk siblings, so closing Overview must not destroy
            # an unsaved settings form. Remove only the WM ownership relation.
            try:
                self.window.transient("")
            except tkinter.TclError:
                pass
            self._detach_owner()

    def _closed(self, event):
        if event.widget is self.window:
            self._detach_owner()
            if self.pending is not None:
                try:
                    self.window.after_cancel(self.pending)
                except tkinter.TclError:
                    pass
                self.pending = None

    def present(self, owner):
        self._detach_owner()
        try:
            if (owner is not None and owner is not self.window
                    and owner.tk is self.window.tk and owner.winfo_exists()
                    and owner.winfo_viewable()):
                self.window.transient(owner)
                self.owner = owner
                self.owner_bindings = {
                    "<Destroy>": owner.bind("<Destroy>", self._owner_closed, add="+"),
                    "<Map>": owner.bind("<Map>", self._owner_mapped, add="+"),
                }
            else:
                # A tray request must work even with Overview hidden/minimized.
                self.window.transient("")
            self.window.deiconify()
            self.window.lift()
            self.window.focus_force()
            if self.pending is not None:
                self.window.after_cancel(self.pending)
            self.pending = self.window.after(100, self._settled)
        except tkinter.TclError:
            self._detach_owner()

    def _settled(self):
        self.pending = None
        try:
            if (self.window.winfo_exists() and self.window.state() == "withdrawn"
                    and (self.owner is None or self.owner.winfo_viewable())):
                # A requested standalone tray dialog can undergo the same CTk
                # titlebar remap as an owned dialog. A missing owner must not
                # leave it hidden; a minimized live owner still stays respected.
                self.window.deiconify()
            if self.window.winfo_exists() and self.window.state() == "normal":
                # CTk's Windows titlebar redraw withdraws/remaps the window and
                # restores the previous focus. Activate after those callbacks,
                # and only once; do not make the dialog permanently topmost.
                self.window.lift()
                self.window.focus_force()
        except tkinter.TclError:
            pass


def present_ctk_dialog(window: Any, *, owner: Any = None) -> None:
    """Call on the Tk thread after constructing a dialog or on a repeat request."""
    presentation = getattr(window, "_tg_dialog_presentation", None)
    if presentation is None:
        presentation = _DialogPresentation(window)
        window._tg_dialog_presentation = presentation
    presentation.present(owner)


def create_ctk_toplevel(
    ctk: Any,
    *,
    title: str,
    width: int,
    height: int,
    theme: CtkTheme,
    topmost: bool = True,
    resizable: bool = False,
    after_create: Optional[Callable[[Any], None]] = None,
) -> Any:
    root = ctk.CTkToplevel()
    install_window_icon(root)

    if sys.platform == "win32":
        def handle_ctrl_shortcut(event: Any) -> Optional[str]:
            shortcuts = {65: ("a", "<<SelectAll>>"), 67: ("c", "<<Copy>>"), 86: ("v", "<<Paste>>")}
            shortcut = shortcuts.get(event.keycode)
            if shortcut and event.keysym.lower() != shortcut[0] and not event.state & 0x20000:
                event.widget.event_generate(shortcut[1])
                return "break"
            return None

        root.bind("<Control-KeyPress>", handle_ctrl_shortcut, add="+")
        
    root.title(title)
    # CTk schedules a Windows titlebar redraw on every resizable() call.
    # Calling it again immediately in a builder can restore a withdrawn state
    # from the first redraw and leave the dialog permanently invisible.
    root.resizable(resizable, resizable)
    center_ctk_geometry(root, width, height)
    root.configure(fg_color=theme.bg)
    if topmost:
        root.attributes("-topmost", True)
    root.lift()
    root.focus_force()
    if after_create:
        _after_id = root.after(300, lambda: after_create(root))
        _orig_destroy = root.destroy

        def _safe_destroy():
            try:
                root.after_cancel(_after_id)
            except Exception:
                pass
            _orig_destroy()

        root.destroy = _safe_destroy
    return root


def main_content_frame(
    ctk: Any,
    root: Any,
    theme: CtkTheme,
    *,
    padx: int,
    pady: int,
) -> Any:
    frame = ctk.CTkFrame(root, fg_color=theme.bg, corner_radius=0)
    frame.pack(fill="both", expand=True, padx=padx, pady=pady)
    return frame
