# TG Proxy for Linux

This fork publishes a Windows executable and an Ubuntu helper archive. Linux tray/CLI entry points remain available from source; fork-specific `.deb`, `.rpm` and AUR packages are not published.

```bash
git clone https://github.com/byShadow64/tg-proxy.git
cd tg-proxy
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/tg-ws-proxy-tray-linux
```

The GUI needs Tk and AppIndicator/tray support. Use `.venv/bin/tg-ws-proxy` for the console proxy. Configure Telegram Desktop with MTProto at `127.0.0.1:1443` and the secret from settings.

See [source instructions](BuildFromSource.md) and the [Ubuntu helper guide](../RU/Helper.md). The helper is a separate TLS service on TCP/8444.
