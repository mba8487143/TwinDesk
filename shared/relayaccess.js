// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// Attended and unattended access through your own relay (shared/relay.js): a paired computer that
// connects through this computer's relay, from outside this network, waits until someone here
// allows it, unless it was set to Always allow (unattended). On this network nothing changes.
//   - The hello waits (hello.wait tells the computer how long), and this computer shows who asks:
//     Allow (this time), Always allow, or Deny.
//   - Allow lasts while that session does and for ONCE_MS after it ends, so a short drop doesn't ask
//     again; then it asks again.
//   - Always allow is kept with the pairing (paired.json relayAccess: 'always') until Ask again here.
//   - Nobody answers within ASK_MS, or Deny: that computer is told and doesn't come back by itself
//     (released) until someone presses Connect there.
//   - One question at a time: another computer asking meanwhile is told this one is busy.
//   - Phones aren't asked (they don't reach the relay's TURN, and connect only when someone there
//     taps Connect).
// The host pairing (mac/pairing.js, windows/ and linux/ hostpair.js) calls ask() from its hello
// handling and closed() when a session ends; the app's UI shows view() and calls respond().
'use strict';

const P = require('./protocol.js');
const Relay = require('./relay.js');

const ASK_MS = 60000; // under the servers' 70 s for a socket that never authenticates
const ONCE_MS = 5 * 60000;
const CHOICES = new Set(['once', 'always', 'deny']);

class RelayAccess {
  // server: send(ctx, msg), fail(ctx, code, message); save(): the pairing's paired.json;
  // changed(): the UI; asked(): a new question (the app brings its window up, as for a pairing);
  // name: this computer's name, for what the other one is told.
  // askMs, onceMs: shorter in tests.
  constructor({ server, save = () => {}, changed = () => {}, asked = () => {}, name = () => 'The other computer', askMs = ASK_MS, onceMs = ONCE_MS }) {
    Object.assign(this, { server, save, changed, asked, name, askMs, onceMs });
    this.asking = null; // {e, ctx, go, timer, since}
    this.once = new Map(); // device id -> until (Infinity while its session is up)
  }

  // Whether this hello goes on now. false: it waits for an answer here (go() runs on Allow), or it
  // was refused already. e: its paired.json entry; phone: it's a phone.
  ask(ctx, e, phone, go) {
    if (phone || !Relay.viaRelay(ctx) || !e) return true;
    if (e.relayAccess === 'always') return true;
    const until = this.once.get(e.id);
    if (until && until > Date.now()) return true;
    if (until) this.once.delete(e.id);
    const a = this.asking;
    if (a && a.e.id === e.id) { // the same computer again (it gave up waiting and retried): this socket waits instead
      a.ctx = ctx;
      a.go = go;
      this._wait(ctx);
      return false;
    }
    if (a) {
      this.server.fail(ctx, P.E.BUSY, `${this.name()} is asking about another computer; try again in a minute`);
      return false;
    }
    this.asking = { e, ctx, go, since: Date.now(), timer: setTimeout(() => this.respond('timeout'), this.askMs) };
    this._wait(ctx);
    this.changed();
    this.asked();
    return false;
  }

  _wait(ctx) {
    this.server.send(ctx, { t: P.T.HELLO_WAIT, ms: this.askMs });
  }

  // What the UI shows while someone waits: {id, name, os} or null.
  view() {
    const a = this.asking;
    return a && { id: a.e.id, name: a.e.name, os: a.e.os || P.OS.WIN, since: a.since };
  }

  // The answer here: 'once' (Allow), 'always' (Always allow), 'deny'; 'timeout' when nobody did.
  respond(choice) {
    const a = this.asking;
    if (!a || !(CHOICES.has(choice) || choice === 'timeout')) return;
    clearTimeout(a.timer);
    this.asking = null;
    this.changed();
    if (choice === 'once' || choice === 'always') {
      if (choice === 'always') {
        a.e.relayAccess = 'always';
        this.save();
      } else this.once.set(a.e.id, Infinity);
      if (a.ctx.ws && a.ctx.ws.readyState === a.ctx.ws.OPEN) a.go();
      return;
    }
    this.server.fail(a.ctx, P.E.RELEASED, choice === 'timeout'
      ? `Nobody allowed it on ${this.name()}. Connect again when someone is there, or ask for Always allow.`
      : `${this.name()} didn’t allow the connection`);
  }

  // A session ended: an Allow for it lasts ONCE_MS more. A waiting socket that went: still asking
  // (the computer may retry), until the answer or the timeout.
  closed(ctx) {
    if (ctx && ctx.deviceId && this.once.get(ctx.deviceId) === Infinity) this.once.set(ctx.deviceId, Date.now() + this.onceMs);
  }

  // Ask again (the pairing's switch here), or forgotten: no more Always allow, nor this session's Allow.
  revoke(e) {
    if (!e) return;
    const had = e.relayAccess === 'always';
    delete e.relayAccess;
    this.once.delete(e.id);
    if (had) this.save();
    if (this.asking && this.asking.e.id === e.id) this.respond('deny');
    this.changed();
  }
}

module.exports = { RelayAccess, ASK_MS, ONCE_MS };
