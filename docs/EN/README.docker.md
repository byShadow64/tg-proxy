# TG WS Proxy for Docker

## Installation from Source

Enter the commands sequentially, one by one:

```bash
# Clone the repository
git clone https://github.com/byShadow64/tg-proxy.git

# Navigate to the project folder
cd tg-proxy

# Build the image
docker build -t tg-ws-proxy .

# Create and mount a connection secret. Keep this file private.
umask 077
openssl rand -hex 16 > tg-proxy.secret
sudo chown 10001:10001 tg-proxy.secret
sudo chmod 0400 tg-proxy.secret

# Run the container
docker run -d \
  --name tg-ws-proxy \
  --restart=always \
  -p 1443:1443 \
  --mount "type=bind,src=$PWD/tg-proxy.secret,dst=/run/secrets/tg-proxy,readonly" \
  -e TG_WS_PROXY_SECRET_FILE=/run/secrets/tg-proxy \
  tg-ws-proxy:latest
```

Use the contents of the secret file with your public server address in Telegram.
Prefix the hex key with `dd`. Connection details stay out of the startup log.
The image runs as UID/GID 10001. For rootless containers, map the bind mount
owner to this container UID.

## Configuring Parameters

All settings are configured using environment variables when running the container:

| Variable                | Description                      | Default                           |
| ----------------------- | -------------------------------- | --------------------------------- |
| `TG_WS_PROXY_HOST`      | Address for incoming connections | `0.0.0.0`                        |
| `TG_WS_PROXY_PORT`      | Port inside the container        | `1443`                           |
| `TG_WS_PROXY_SECRET_FILE` | Path to a read-only secret file | unset |
| `TG_WS_PROXY_DC_IPS`    | DC number:IP pairs separated by space | `2:149.154.167.220 4:149.154.167.220` |
| `TG_WS_PROXY_CF_WORKER` | Cloudflare Worker domain         | `None`                           |

Existing deployments with `TG_WS_PROXY_SECRET` can continue to start. Move
that value into a mounted secret file to keep it out of the container environment.
Configure only one of these variables.

## Configuring Telegram Desktop

1. Telegram → **Settings** → **Advanced** → **Connection type** → **Proxy**
2. Add proxy:
   - **Type:** MTProto
   - **Server:** `127.0.0.1` (or your custom address)
   - **Port:** `1443` (or your custom port)
   - **Secret:** `dd` followed by the hex key from the mounted file
