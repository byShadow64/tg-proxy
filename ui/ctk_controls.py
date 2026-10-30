from __future__ import annotations

from typing import Any
from tkinter import TclError

from ui.ctk_theme import CtkTheme
from ui.ctk_tooltip import attach_tooltip_to_widgets


def _focus_border(widget, theme, border_color):
    def apply_border(color):
        try:
            if widget.winfo_exists():
                widget.configure(border_color=color)
        except TclError:
            pass  # A queued focus callback can outlive the native Entry.

    # Like CTk's own focus handlers, accept calls without an event during native
    # focus/teardown transitions as well as ordinary Tk event bindings.
    widget.bind("<FocusIn>", lambda _event=None: apply_border(theme.accent), add="+")
    widget.bind("<FocusOut>", lambda _event=None: apply_border(border_color), add="+")
    return widget


def create_entry(ctk, parent, theme, *, var=None, width=0, height=42, radius=10, **kw):
    opts = {
        "font": (theme.ui_font_family, 13), "corner_radius": radius,
        "fg_color": theme.field_bg, "border_color": theme.field_border,
        "border_width": 1, "text_color": theme.text_primary,
        "placeholder_text_color": theme.text_muted,
    }
    if var is not None:
        opts["textvariable"] = var
    if width:
        opts["width"] = width
    opts["height"] = height
    opts.update(kw)
    return _focus_border(ctk.CTkEntry(parent, **opts), theme, opts["border_color"])


def create_checkbox(ctk, parent, theme, text, variable):
    return ctk.CTkCheckBox(
        parent, text=text, variable=variable,
        font=(theme.ui_font_family, 13), text_color=theme.text_primary,
        fg_color=theme.accent, hover_color=theme.accent_hover,
        checkmark_color=theme.on_accent, text_color_disabled=theme.text_muted,
        checkbox_width=22, checkbox_height=22, height=28,
        corner_radius=6, border_width=2, border_color=theme.field_border,
    )


def create_label(ctk, parent, theme, text, *, size=12, bold=False, secondary=True, **kw):
    weight = "bold" if bold else "normal"
    options = {
        "text": text, "font": (theme.ui_font_family, size, weight),
        "text_color": theme.text_secondary if secondary else theme.text_primary,
        "anchor": "w",
    }
    options.update(kw)
    return ctk.CTkLabel(parent, **options)


def create_labeled_entry(ctk, parent, theme, label_text, value, *, tip="", width=0, pack_fill=False):
    col = ctk.CTkFrame(parent, fg_color="transparent")
    lbl = create_label(ctk, col, theme, label_text)
    lbl.pack(anchor="w", pady=(0, 6))
    var = ctk.StringVar(master=parent, value=str(value))
    ent = create_entry(ctk, col, theme, var=var, width=width)
    if pack_fill:
        ent.pack(fill="x")
    else:
        ent.pack(anchor="w")
    if tip:
        attach_tooltip_to_widgets([lbl, ent, col], tip)
    return col, var


def create_config_section(
    ctk: Any,
    parent: Any,
    theme: CtkTheme,
    title: str,
    *,
    bottom_spacer: int = 16,
) -> Any:
    wrap = ctk.CTkFrame(parent, fg_color="transparent")
    wrap.pack(fill="x", pady=(0, bottom_spacer))
    create_label(ctk, wrap, theme, title, size=13, secondary=False, bold=True).pack(
        anchor="w", padx=2, pady=(0, 8))
    card = ctk.CTkFrame(
        wrap, fg_color=theme.surface, corner_radius=14,
        border_width=1, border_color=theme.field_border,
    )
    card.pack(fill="x")
    inner = ctk.CTkFrame(card, fg_color="transparent")
    inner.pack(fill="x", padx=16, pady=14)
    return inner


def create_combobox(ctk, parent, theme, *, variable, values, command=None):
    widget = ctk.CTkComboBox(
        parent, values=values, variable=variable, command=command,
        height=42, font=(theme.ui_font_family, 13),
        dropdown_font=(theme.ui_font_family, 13),
        text_color=theme.text_primary, text_color_disabled=theme.text_muted,
        fg_color=theme.field_bg,
        border_width=1, border_color=theme.field_border,
        button_color=theme.surface_alt, button_hover_color=theme.field_border,
        dropdown_fg_color=theme.surface,
        dropdown_text_color=theme.text_primary,
        dropdown_hover_color=theme.accent_soft,
        corner_radius=10, state="readonly",
    )
    return _focus_border(widget, theme, theme.field_border)
