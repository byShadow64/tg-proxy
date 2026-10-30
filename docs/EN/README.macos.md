# TG Proxy for macOS

The original Flowseal macOS entry point remains in source. This fork currently publishes Windows 10/11 x64 binaries; a fork-specific DMG is not available.

Use a Python build with Tk support. CustomTkinter and PyObjC are installed from the project metadata.

```bash
git clone https://github.com/byShadow64/tg-proxy.git
cd tg-proxy
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/tg-ws-proxy-tray-macos
```

Configure Telegram Desktop with an MTProto proxy at `127.0.0.1:1443` and the secret from settings. See [building from source](BuildFromSource.md).
