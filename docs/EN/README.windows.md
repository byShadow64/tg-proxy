# TG Proxy for Windows

The version in preparation is **1.15.3**, for Windows 10/11 x64. A packaged
`TgWsProxy_windows.exe` runs without a separate Python installation.

## Connect Telegram

1. Start TG Proxy and open its dashboard from the system tray.
2. Choose **Open in Telegram** and confirm the connection. You can also copy
   the current connection link and open it in Telegram.
3. Keep TG Proxy running while Telegram uses this connection.

The local address belongs to this computer. Reopen the current link after changing
the port or secret. Do not share a link containing your proxy secret. Disable this
proxy in Telegram, or select another available proxy, before exiting TG Proxy.

## Settings

The dashboard provides connection status, traffic, logs and route checks. Russian
and English, light/dark themes, startup and tray operation are supported. Settings
open in front of the dashboard. Closing the panel keeps the tray process running;
use the application Exit action to stop it completely.

For manual Telegram setup, select MTProto with `127.0.0.1` and the current port
and secret from TG Proxy. An enrolled Helper can be connected by IP after server
verification. See [Helper](../RU/Helper.md) and [SSH setup](../SSH_SETUP.md).

## Updates and portable mode

The client checks for updates, shows download progress and verifies the file
before installation. A second launch activates the existing panel. Normal updates
retain settings, and failed executable replacement uses rollback.

Use `--portable` or a `TgWsProxy_data` directory beside the executable for portable
mode. Retain that whole directory when moving it. Standard mode uses per-user
application storage.

[Build from source](BuildFromSource.md) · [Project state](../PROJECT_STATE.md).
