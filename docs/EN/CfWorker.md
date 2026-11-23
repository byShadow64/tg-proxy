# Cloudflare Worker

An alternative (completely free, no domain purchase required unlike [CfProxy](./CfProxy.md)) method for proxying.

The proxy restores access to content that previously wouldn't load (reactions, certain stickers). If you are using a non-Premium account with this method and photos/videos still fail to load, leave only `4:149.154.167.220` in the `DC → IP` block.

##

1. **Add the following domains to [zapret](https://github.com/Flowseal/zapret-discord-youtube/) or any other DPI bypass software:**

```
cloudflare.com
cloudflare.dev
workers.dev
```

2. Create an account on [Cloudflare](https://dash.cloudflare.com/) (or log into an existing one)
	* **After creating your account, verify your email using the link sent to your inbox**
3. Select `Compute` → `Workers & Pages` from the left panel
   <img width="250" height="768" alt="image" src="https://github.com/user-attachments/assets/d81e3522-045a-4e65-9c2e-5545b7ad409a" />

4. Click the **`Create application`** button in the top right → `Start with Hello World!` → `Deploy`
   <img width="1406" height="193" alt="image" src="https://github.com/user-attachments/assets/7ac65944-8761-42a6-ab6d-ba5f9080c883" />
   <img width="586" height="379" alt="image" src="https://github.com/user-attachments/assets/ff901439-c2a1-4867-95de-e11b82a37044" />
   <img width="624" height="694" alt="image" src="https://github.com/user-attachments/assets/bb68d49a-166d-42a0-8fe2-bd2b16c0d066" />

5. Click the **`Edit code`** button in the top right, then replace the code on the left with the one [in telegram-worker.mjs](../../worker/telegram-worker.mjs)
    * If the code section fails to load, it means you missed the first step
    <img width="911" height="117" alt="image" src="https://github.com/user-attachments/assets/6bcdf839-d776-47e9-9d18-ba0efdf53244" />
	<img width="1027" height="512" alt="image" src="https://github.com/user-attachments/assets/daf131ed-82d5-40f0-a7eb-daeb598bea40" />


6. Click the **`Deploy`** button in the top right
   <img width="415" height="138" alt="image" src="https://github.com/user-attachments/assets/58d8f83e-d8b5-40cf-a30f-741d7311047b" />

7. Copy the domain from the field on the right and specify it in your **Cloudflare Worker** settings (or via the `--cfproxy-worker-domain` argument)
    * Example domain: `random-symbols-1234.username.workers.dev`
	* **You can specify multiple domains separated by commas (or by repeating the `--cfproxy-worker-domain` argument)**
   <img width="414" height="182" alt="image" src="https://github.com/user-attachments/assets/4fb0b111-8026-4d17-b993-6c70ec37f1f5" />



### Worker code

Use the complete [telegram-worker.mjs](../../worker/telegram-worker.mjs) source.
Both instructions use this one file; replace the previous sample in full.

The Worker accepts binary WebSockets on `/apiws` and connects only to numeric
addresses in Telegram's IP networks on TCP/443. The catalogue matches the desktop
client policy, retaining ordinary DC addresses, DC redirects and IPv6. Arbitrary
addresses and DNS names are rejected. The `binary` subprotocol is negotiated.

Incoming messages are limited to 2 MiB. The TCP upload queue, including its current
write, is limited to 4 MiB and 64 messages, and writes run sequentially. A limit or
connection error closes both endpoints and clears the queue. Telegram connection
setup has a 10-second deadline. Replies are forwarded in chunks of at most 64 KiB.
Application routes and update settings are unchanged.

This is a public Telegram-only relay, not an authenticated private Helper. Anyone
who knows its domain can use it within these constraints. Cloudflare buffers an
incoming message before invoking the handler and manages the outbound WebSocket
queue; platform and plan limits also apply. The Worker API has no documented
outbound drain signal, so bounding the application's queue does not guarantee a
bound on all platform memory. Updating the client does not update an already
deployed Worker; apply the new source in your own Cloudflare dashboard.
