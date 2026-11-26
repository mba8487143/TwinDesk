# Your own relay

TwinDesk connects devices on the same network, over a USB cable, over Bluetooth, or through Tailscale. **Your own relay** adds one more way: a phone or another computer away from your computer's network connects through a small server that you run yourself. It is off until you add one, and nothing is sent anywhere before that.

## What the relay sees

- The relay only joins two connections and copies bytes between them.
- The session inside is TwinDesk's usual one: TLS with your computer's pinned certificate and the pairing's token. The relay can't read it or change it.
- The relay can't tell which devices are talking. The computer is known to it only by an id derived from the certificate.
- It keeps nothing on disk.

## Run it

You need Node 16 or later on a machine that both devices can reach, for example a small cloud server, or a home server with a forwarded port.

```
node relay/twindesk-relay.js --port 47100 --key "choose-a-secret"
```

The key is optional, but use one: only devices given the same key can use your relay. The environment variables `RELAY_PORT`, `RELAY_KEY` and `RELAY_HOST` work too.

Run the relay on another machine, not on the computer itself.

## Add it

1. On the computer, go to **General › Your own relay**.
2. Enter the address (for example `relay.example.com:47100`) and the key, then click **Save**. The row says when the computer is connected to the relay.
3. Connect the phone or the other computer once on the same network. It learns about the relay from the computer.

After that, when the phone or computer can't see the computer on its network, every other connection attempt goes through the relay. Remove the address on the computer and the others forget it at their next connection.

A computer connected through the relay moves the session back to the network on its own once it sees the other computer there again (Windows and Linux), and keeps the relay as a fallback.

## Through the relay between computers

What goes through the relay:

- The session itself: the cursor, keyboard, clipboard, notifications, file transfers and the rest of the session's messages.
- File transfers, over the relay's connection. The faster engine (fx2) and unencrypted transfers (**Encrypt file transfers** off) use other ports and aren't used through the relay, so transfers are always encrypted there.

What doesn't go through it yet:

- **Shared folders** and the **terminal** (`ssh twindesk`): they connect to the other computer's address, which a relay doesn't carry. They say so and wait until the computers are on the same network again. A shared folder's password is never sent to the relay or to an address that may belong to another network.
- **Screen sharing**, audio and the camera: they need a direct network path (WebRTC) for now.
- The separate input lane (UDP): mouse and keyboard go on the session's own connection instead.
- **Multi-device** mode doesn't use the relay.

On the computer that hosts, connections that came through the relay are marked, and nothing is ever sent back to their address (it's the relay's).

## Cost

While an address is set, the computer keeps one idle connection to the relay and sends a ping each minute. A phone or another computer does nothing until it needs the relay; a computer then opens a port on 127.0.0.1 for as long as that session lasts. Without an address, nothing runs.
