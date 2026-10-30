# TG Proxy

A local MTProto proxy for Telegram on Windows and Android. TG Proxy runs on your
device and opens Telegram with the connection details. You do not need your own
server to get started; an optional Helper provides another route to Telegram.

**Windows 1.15.3 (in preparation):** Windows 10/11 x64.<br>
**Android 0.1.7-dev (in preparation):** Android 8.0 or newer; still in development.

[Русский](../../README.md) · [Documentation](../README.md) ·
[Report a problem](https://github.com/byShadow64/tg-proxy/issues)

This source tree is being prepared for a new release. See
[project state](../PROJECT_STATE.md) for actual checks and readiness.

## Connect Telegram

1. Start TG Proxy. On Android, tap **Start proxy** in Overview.
2. Tap **Open in Telegram**, choose your app and confirm the proxy connection.
   You can also copy the link.
3. Keep TG Proxy running while Telegram uses it.

The loopback address belongs to this device. Another phone or computer needs
its own running copy. When finished, disable the proxy in Telegram and stop
TG Proxy.

## Windows

A dashboard shows connections, traffic and routes. The app supports the system
tray, startup at login, portable profiles, searchable logs, connection diagnostics
and verified updates with download progress. Russian and English, light and dark
themes are available. The packaged EXE does not require Python.

[Windows guide](README.windows.md) · [Build from source](BuildFromSource.md)

## Android

Start/Stop, a notification Stop action, connection links, Helper by IP, a journal
and a short Help guide. The app can check for updates and download them on
unmetered Wi-Fi. Android requires confirmation before installation. Install the
first updater-enabled APK over 0.1.5 or earlier manually, keeping app data.

This is a development version. Emulator checks do not establish performance on
every physical phone or network.

[Android guide](../../android/README.md) ·
[Android build instructions](../../android/BUILDING.md)

The configured update server operates independently of GitHub visibility.
Update signatures and files are verified; no administrative GitHub token is
embedded in the client.

## Optional Helper

If your connection works without a Helper, leave it disabled. A server whose
owner enabled registered-client access can be connected by entering its IP.
This mode permits all registered TG Proxy installations; an installation key
does not establish a person's identity or ownership of a private server.

SSH setup is an explicit server-owner action with host-key confirmation.
Entering an IP does not make an existing private Helper public.

[Helper guide](../RU/Helper.md) · [SSH setup](../SSH_SETUP.md)

## Troubleshooting and development

Check the running state and current proxy settings in Telegram. Reopen the link
after changing the port. On Android, see Help for background restrictions.
A failed route candidate does not necessarily mean the whole connection failed.

Include the app version, OS/device, network type, Helper state and reproduction
steps in an issue. Remove passwords, tokens and proxy-secret links from logs.

[Contributing](../CONTRIBUTING.md) · [Project state](../PROJECT_STATE.md) ·
[Release process](../PUBLISHER.md)

Based on [Flowseal/tg-ws-proxy](https://github.com/Flowseal/tg-ws-proxy).
Android implementation research also included
[amurcanov/tg-ws-proxy-android](https://github.com/amurcanov/tg-ws-proxy-android).
Client development, UI and Helper work: [byShadow64](https://github.com/byShadow64).
Original attribution is retained.
[MIT license](../../LICENSE).
