# Your own relay

TwinDesk connects devices on the same network, over a USB cable, over Bluetooth, or through Tailscale. **Your own relay** adds one more way: a phone or another computer away from your computer's network connects through a small server that you run yourself. It is off until you add one, and nothing is sent anywhere before that.

## What the relay sees

- The relay only joins two connections and copies bytes between them.
- The session inside is TwinDesk's usual one: TLS with your computer's pinned certificate and the pairing's token. The relay can't read it or change it.
- The relay can't tell which devices are talking. The computer is known to it only by an id derived from the certificate.
- It keeps nothing on disk.

## Run it

Update the relay too when you update TwinDesk: copy the new `relay/twindesk-relay.js` to the server and restart it. This one fixes a bug where, with several connections at once, a connection that was still waiting could be dropped.

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

## Pair with a TwinDesk ID

Two computers that have never been on the same network can pair through the relay, the way AnyDesk connects by ID. Both need the same relay (address and key) in **General › Your own relay**.

1. On the computer to connect to, turn on **Allow pairing through the relay** (off by default). The row shows its **TwinDesk ID**, nine digits such as `123 456 789`.
2. On the other computer, type that ID in **Connect by address** and click **Connect**.
3. Both show the same six-digit code. Compare it (over the phone, for example). Click **Codes match** on one and **Allow** on the other.

What keeps it safe:

- The ID is derived from the computer's certificate. While pairing through the relay is off, the computer isn't registered under it, and a pairing request that comes through the relay anyway is refused before any code or prompt is shown.
- The code compare is the same as on a network: it includes the certificate's fingerprint, so nobody in between (the relay included) can make both sides show the same code.
- The prompt says the request came **through your relay, from outside this network**.
- Failed attempts through the relay count toward their own lockout (five in ten minutes), apart from the ones on this network, so someone failing through the relay can't stop pairing at home.
- Turning pairing through the relay off again doesn't affect computers already paired: they keep connecting through the relay.

A computer paired this way has no network address saved. It always connects through the relay until it's seen on the same network, then it moves there as usual.

A Mac pairs by ID with another Mac, and a Windows or Linux computer with any computer. To connect a Mac to a PC, type the Mac's ID on the PC.

## Attended and unattended access

A paired computer that connects **through the relay** (from outside the network) waits until someone at the computer it connects to allows it, the way AnyDesk asks. On the same network nothing changes, and phones aren't asked.

- The prompt shows who is asking, with **Allow**, **Always allow** and **Deny**.
- **Allow** lets it in for that session. If the session drops, it can come back within five minutes without asking again; after that it asks again.
- **Always allow** makes it unattended: it connects without asking, for example to your own computer at home. Under **Paired**, **Ask again** takes that back.
- **Deny**, or no answer within a minute: the other computer is told, and it doesn't keep trying by itself until someone presses **Connect** there.
- A computer that was just paired through the relay isn't asked again for that first session.

For full remote control without anyone there, also turn on what you want the other computer to use. For example, let it start and switch this screen (Display) and accept its mouse and keyboard.

## Through the relay between computers

What goes through the relay:

- The session itself: the cursor, keyboard, clipboard, notifications, file transfers and the rest of the session's messages.
- File transfers, over the relay's connection. The faster engine (fx2) and unencrypted transfers (**Encrypt file transfers** off) use other ports and aren't used through the relay, so transfers are always encrypted there.
- **Screen sharing, app windows, sound, the microphone and the camera.** These use WebRTC, which normally needs a direct network path. Through the relay both computers use a small TURN server that runs on the computer that hosts, as a phone on a USB cable does: one side reaches it directly, the other through the relay. WebRTC's own encryption (DTLS-SRTP) covers the media end to end, and the TURN login is sent only inside the encrypted session.

What doesn't go through it yet:

- **Shared folders** and the **terminal** (`ssh twindesk`): they connect to the other computer's address, which a relay doesn't carry. They say so and wait until the computers are on the same network again. A shared folder's password is never sent to the relay or to an address that may belong to another network.
- The separate input lane (UDP): mouse and keyboard go on the session's own connection instead.
- **Multi-device** mode doesn't use the relay.

On the computer that hosts, connections that came through the relay are marked, and nothing is ever sent back to their address (it's the relay's).

The relay's connections reach only two places on the computer that hosts: the session's TLS server and the TURN server, told apart by the first byte each client sends. Anything else is closed. The TURN server relays media only between its own allocations, so it can't be used to reach other services on that computer.

Media through the relay travels over TCP, as with a phone on a cable. Expect more delay than on the same network; how much depends on where the relay runs. A phone connected through the relay doesn't use TURN yet, so its screen and camera still need the same network, a cable or Tailscale.

## Cost

While an address is set, the computer keeps one idle connection to the relay and sends a ping each minute, and runs its TURN server (idle until a session through the relay uses it). A phone or another computer does nothing until it needs the relay; a computer then opens a port on 127.0.0.1 for as long as that session lasts. Without an address, nothing runs.
