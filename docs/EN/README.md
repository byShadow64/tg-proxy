<div align="center">

<img src="../../ui/assets/byshadow64.png" width="104" height="104" alt="">

# TG Proxy

[Русский](../../README.md) · [Documentation](../README.md) · [Changelog](../../CHANGELOG.md)

**A local MTProto proxy for Telegram on Windows and Android.**

It runs on your device, opens Telegram with a connection link and supports an optional Helper server.<br>
You do not need your own server to get started.

</div>

---

- **Windows 10/11 x64:** dashboard, system tray, startup at login and portable mode.
- **Android 8.0+:** a local proxy, background operation and a notification Stop action.
  The Android client is in development.
- Russian and English, light and dark themes, logs and route checks.

## Quick start

1. Start TG Proxy. On Android, tap **Start proxy**.
2. Tap **Open in Telegram**, choose your app and confirm the connection.
   **Copy link** lets you open the link yourself.
3. Keep TG Proxy running while Telegram uses this connection.

> The address `127.0.0.1` belongs to this device. Another phone or computer needs
> its own running copy. Open the current link again after changing the port.
> Disable this proxy in Telegram before stopping TG Proxy.

**[Windows guide](README.windows.md)** · **[Android guide](../../android/README.md)**

## Helper

A Helper provides another route through your server. Leave it disabled if
Telegram works without it.

On Windows, open **Settings → Routes**, enter the IP and select **Connect server**.
On Android, open **Routes**, enter the IP and tap **Connect by IP**. If the server
is not configured, the app offers SSH setup. You need the VPS owner's access
and must confirm the server's SSH host key.

> IP-only connection requires the owner to enable access for registered clients.
> Entering an address does not make an existing private Helper public.

**[Helper guide](../RU/Helper.md)** · **[SSH setup](../SSH_SETUP.md)**

## How it works

Telegram connects to a local MTProto proxy. TG Proxy selects an available route
to Telegram, including WebSocket routes; a Helper provides another option.
TG Proxy is not a system-wide VPN.

If connection fails, check that the proxy is running and Telegram uses the
current link. On Android, see **Help** for background restrictions. A failed
route candidate does not necessarily mean that the whole connection has failed.

## Build and contribute

The desktop source requires Python 3.11+. Android is built separately with
Gradle. The packaged Windows EXE does not require Python.

**[Build Windows](BuildFromSource.md)** ·
**[Build Android](../../android/BUILDING.md)** ·
**[Contributing](CONTRIBUTING.md)**

## Credits and license

Based on [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy).
Android implementation research also included
[amurcanov/tg-ws-proxy-android](https://github.com/amurcanov/tg-ws-proxy-android).
Project development: [byShadow64](https://github.com/byShadow64).
[MIT license](../../LICENSE).
