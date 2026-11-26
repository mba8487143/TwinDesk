// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// Failed pairing attempts per address (hostpair.js): after too many, the host refuses new
// pair.starts from that address for a while, so an attacker on the network can't keep asking.
// Attempts through this computer's own relay count in a bucket of their own (who()).
'use strict';

const MAX = 5;
const WINDOW_MS = 10 * 60 * 1000;

class PairFails {
  constructor() { this.map = new Map(); } // address -> [timestamps within the window]

  fail(address) {
    // 127.0.0.1 is our own Bluetooth/wired pipe, not an attacker on the network.
    if (!address || address === '127.0.0.1') return;
    this.map.set(address, this._live(address, Date.now()).concat(Date.now()));
  }

  locked(address) {
    const list = this._live(address, Date.now());
    if (!list.length) this.map.delete(address);
    return list.length >= MAX;
  }

  clear(address) { this.map.delete(address); }

  // Whom a socket's failures count against: its address, or for one that came through this
  // computer's own relay (shared/relay.js, ws.relayed) the relay's own bucket. Those all share the
  // relay's address: someone failing there can hold back relay pairing, never this network's.
  static who(ctx) {
    if (!ctx) return '';
    return ctx.ws && ctx.ws.relayed === true ? `relay:${ctx.address || ''}` : ctx.address;
  }

  _live(address, now) {
    return (this.map.get(address) || []).filter((t) => now - t < WINDOW_MS);
  }
}

module.exports = { PairFails, MAX, WINDOW_MS };
