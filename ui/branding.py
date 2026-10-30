"""The author's sidebar badge, shared by source and frozen builds."""
from pathlib import Path

from PIL import Image


def brand_image(size: int = 48):
    import customtkinter as ctk

    # PyInstaller preserves this module's location beside the bundled assets.
    with Image.open(Path(__file__).with_name("assets") / "byshadow64.png") as source:
        image = source.convert("RGBA")
    return ctk.CTkImage(light_image=image, dark_image=image, size=(size, size))
