// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// Your own relay (General › Your own relay): a server you run (relay/twindesk-relay.js, on any
// machine both can reach) that a phone or computer away from this computer's network connects
// through (a computer: shared/relaypipe.js). Off
// until an address is added; nothing else changes:
//   - The relay only pairs two connections and copies bytes. The session inside is the same TLS
//     with the pinned certificate and the same token as on the local network, so the relay sees
//     neither what's sent nor who the devices are (only an id it can't turn back into one).
//   - The phone tries it only when it can't see this computer on its network, every other attempt
//     (as with Tailscale), and only for a computer that told it about the relay.
//   - The relay's key (if it has one) keeps strangers from using it; it isn't the session's key.
// This computer keeps one idle connection to the relay while an address is set (a ping each
// minute), and opens another for each phone that asks; that one goes straight into the session's
// server (server.https 'connection'), so to the server it's a network connection like any other.
//
// Wire (line-based until spliced, then raw bytes):
//   computer → relay: "TDR1 host <id> <key>\n"         ← "ok\n", later "call <n>\n" per phone, "pong\n"
//   computer → relay: "ping\n" (each minute)
//   computer → relay (new socket): "TDR1 take <id> <n> <key>\n" ← "ok\n", then the phone's bytes
//   phone    → relay: "TDR1 join <id> <key>\n"          ← "ok\n" once the computer took it, "no\n" if absent
//
//   const r = new RelayHost({ server, addr: 'relay.example.com:47100', key, id }); r.start(); r.stop()
//   RelayHost.idOf(certFingerprint) → the id; parseAddr('host:port') → {host, port} | null
'use strict';

const net = require('net');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const P = require('./protocol.js');
const { TurnThread } = require('./turn.js');

const DEFAULT_PORT = 47100;
const PING_MS = 60000;
const DEAD_MS = 150000; // no pong this long: the control connection is gone
const TAKE_MS = 10000;

// "host", "host:port", "[v6]:port" → {host, port}; anything else null.
function parseAddr(s) {
  const v = String(s || '').trim();
  if (!v || v.length > 255 || /[\s/@]/.test(v)) return null;
  let m = /^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$/.exec(v);
  if (!m) m = /^([A-Za-z0-9.-]+)(?::(\d{1,5}))?$/.exec(v);
  if (!m) return null;
  const port = m[2] ? Number(m[2]) : DEFAULT_PORT;
  return port > 0 && port < 65536 ? { host: m[1], port } : null;
}

const cleanKey = (k) => String(k || '').replace(/[^\x21-\x7e]/g, '').slice(0, 128);
// The id a phone asks the relay for: from this computer's certificate, not its name or address.
const idOf = (fp) => crypto.createHash('sha256').update(`twindesk-relay:${String(fp || '')}`).digest('hex').slice(0, 32);

// Reads one "\n"-ended line from a socket, then hands back what came after it.
function readLine(sock, ms, cb) {
  let buf = Buffer.alloc(0);
  let done = false;
  const finish = (err, line, rest) => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    sock.removeListener('data', onData);
    sock.removeListener('error', onErr);
    sock.removeListener('close', onClose);
    cb(err, line, rest);
  };
  const onData = (d) => {
    buf = Buffer.concat([buf, d]);
    const i = buf.indexOf(10);
    if (i >= 0) finish(null, buf.slice(0, i).toString('utf8').trim(), buf.slice(i + 1));
    else if (buf.length > 512) finish(new Error('bad reply'));
  };
  const onErr = (e) => finish(e);
  const onClose = () => finish(new Error('closed'));
  const timer = setTimeout(() => finish(new Error('timed out')), ms);
  sock.on('data', onData);
  sock.on('error', onErr);
  sock.on('close', onClose);
}

class RelayHost extends EventEmitter {
  // server: the session's server (its .https takes the relayed connections).
  // turnPort(): the TURN server's port here (screen, sound, camera through the relay), 0 for none.
  constructor({ server, addr, key = '', id, turnPort = () => 0 }) {
    super();
    this.server = server;
    this.turnPort = turnPort;
    this.to = parseAddr(addr);
    this.key = cleanKey(key) || '-';
    this.id = id;
    this.ctl = null;
    this.state = 'off'; // off | connecting | ready | failed
    this.error = '';
    this.wait = 5000;
    this.timer = null;
    this.running = false;
  }

  get view() { return { state: this.state, error: this.error }; }

  start() {
    if (this.running || !this.to || !this.id) return;
    this.running = true;
    this._connect();
  }

  stop() {
    this.running = false;
    clearTimeout(this.timer);
    clearInterval(this.ping);
    if (this.ctl) this.ctl.destroy();
    this.ctl = null;
    this._set('off');
  }

  _set(state, error = '') {
    if (state === this.state && error === this.error) return;
    this.state = state;
    this.error = error;
    this.emit('state', this.view);
  }

  _retry(err) {
    clearInterval(this.ping);
    this.ctl = null;
    if (!this.running) return;
    this._set('failed', err);
    this.timer = setTimeout(() => this._connect(), this.wait);
    this.wait = Math.min(this.wait * 2, 5 * 60000);
  }

  _connect() {
    if (!this.running) return;
    this._set('connecting');
    const s = net.connect({ host: this.to.host, port: this.to.port });
    this.ctl = s;
    s.setNoDelay(true);
    s.setKeepAlive(true, 30000);
    let failed = false;
    const fail = (e) => { if (failed) return; failed = true; s.destroy(); if (this.ctl === s) this._retry(e); };
    s.once('connect', () => s.write(`TDR1 host ${this.id} ${this.key}\n`));
    readLine(s, 10000, (err, line, rest) => {
      if (err || line !== 'ok') return fail(err ? err.message : line === 'key' ? 'The relay’s key is wrong' : 'Not a TwinDesk relay');
      this.wait = 5000;
      this._set('ready');
      let buf = rest.toString('utf8');
      let last = Date.now();
      this.ping = setInterval(() => {
        if (Date.now() - last > DEAD_MS) return fail('The relay stopped answering');
        s.write('ping\n');
      }, PING_MS);
      const lines = (d) => {
        last = Date.now();
        buf += d.toString('utf8');
        let i;
        while ((i = buf.indexOf('\n')) >= 0) {
          const l = buf.slice(0, i).trim();
          buf = buf.slice(i + 1);
          const m = /^call (\d{1,9})$/.exec(l);
          if (m) this._take(m[1]);
        }
        if (buf.length > 4096) fail('bad reply');
      };
      s.on('data', lines);
      lines(Buffer.alloc(0));
      s.on('error', (e) => fail(e.message));
      s.on('close', () => fail('The relay closed the connection'));
    });
    s.on('error', (e) => fail(e.code === 'ECONNREFUSED' ? 'Nothing answers at that address' : e.code === 'ENOTFOUND' ? 'No such address' : e.message));
  }

  // A phone or computer asked: a connection of its own. What it says first tells where it goes: TLS
  // (a record starts 0x16) to the session's server, STUN (a TURN client's Allocate starts 0x00) to
  // the TURN server, anything else nowhere. Both are spoken first by the side that connects.
  // Marked (isRelayed): its address is the relay's, not the device's, so nothing dials back to it.
  _take(n) {
    const s = net.connect({ host: this.to.host, port: this.to.port });
    s.setNoDelay(true);
    s.tdRelay = true;
    s.once('connect', () => s.write(`TDR1 take ${this.id} ${n} ${this.key}\n`));
    s.on('error', () => s.destroy());
    readLine(s, TAKE_MS, (err, line, rest) => {
      if (err || line !== 'ok' || !this.server || !this.server.https) return s.destroy();
      const route = (first) => {
        clearTimeout(quiet);
        s.pause();
        s.unshift(first);
        if (first[0] === 0x16) {
          mark(s);
          this.server.https.emit('connection', s);
          return this.emit('relayed');
        }
        const port = first[0] <= 0x01 ? this.turnPort() : 0;
        if (!port) return s.destroy();
        const t = net.connect({ host: '127.0.0.1', port });
        t.setNoDelay(true);
        const end = () => { s.destroy(); t.destroy(); };
        t.on('error', end);
        s.on('error', end);
        s.on('close', end);
        t.on('close', end);
        s.pipe(t);
        t.pipe(s);
        this.emit('relayed', 'turn');
      };
      // Nothing said in a while: it goes (the relay already joined it to someone who said nothing).
      const quiet = setTimeout(() => s.destroy(), TAKE_MS);
      if (rest.length) return route(rest);
      s.once('data', route);
      s.once('close', () => clearTimeout(quiet));
    });
  }
}

// The connections the relay handed to this computer's server, by their far end (the relay's address
// and port, the same for all of them): isRelayed() for a socket the server wraps (TLS) as well.
const marked = new Map(); // "address|port" → count open
const keyOf = (s) => `${String(s.remoteAddress || '').replace(/^::ffff:/, '')}|${s.remotePort}`;
function mark(s) {
  const k = keyOf(s);
  marked.set(k, (marked.get(k) || 0) + 1);
  s.once('close', () => {
    const left = (marked.get(k) || 1) - 1;
    if (left > 0) marked.set(k, left); else marked.delete(k);
  });
}
function isRelayed(sock) {
  if (!sock) return false;
  if (sock.tdRelay || (sock._parent && sock._parent.tdRelay)) return true;
  return marked.size > 0 && marked.has(keyOf(sock));
}
// A session through a relay, either side: the server's (its socket came through ours, server.js
// ws.relayed) or a link's (it dialled the other computer's, mac/link.js ctx.via). Its address can't
// be dialled for anything else (shared folders, the terminal).
const viaRelay = (ctx) => !!ctx && (ctx.via === 'relay' || (!!ctx.ws && ctx.ws.relayed === true));

// What the computer tells a device it pairs with (welcome.relay): set by the app (use()).
let current = () => null;
function use(fn) { current = typeof fn === 'function' ? fn : () => null; }
function welcome() {
  const r = current();
  return r && r.addr && r.id ? { addr: r.addr, key: cleanKey(r.key), id: r.id } : undefined;
}

// settings.net.relay as kept: {addr, key, pair} (addr '' = none; pair: Allow pairing through the
// relay, off unless switched on, and never without an address).
function clean(r) {
  const addr = r && parseAddr(r.addr) ? String(r.addr).trim() : '';
  return { addr, key: addr ? cleanKey(r && r.key) : '', pair: !!addr && !!r && r.pair === true };
}

// TwinDesk ID: nine digits a person can read out or type ("123 456 789"), from this computer's
// certificate. Only while Allow pairing through the relay is on does the computer wait on the relay
// under it (idOfCode: a relay id of its own, not the session's idOf(fp)), so a device that has
// never met it can ask to pair: the code compare and Allow here still decide.
const CODE_DIGITS = 9;
function codeOf(fp) {
  const h = crypto.createHash('sha256').update(`twindesk-relay-code:${String(fp || '')}`).digest('hex');
  return (BigInt(`0x${h.slice(0, 16)}`) % 10n ** BigInt(CODE_DIGITS)).toString().padStart(CODE_DIGITS, '0');
}
const idOfCode = (code) => crypto.createHash('sha256').update(`twindesk-relay-pair:${String(code || '')}`).digest('hex').slice(0, 32);
// What a person typed ("123 456 789", "123-456-789", "123456789") → the nine digits, or null.
function parseCode(text) {
  const d = String(text || '').trim().replace(/[\s-]/g, '');
  return new RegExp(`^\\d{${CODE_DIGITS}}$`).test(d) ? d : null;
}
const formatCode = (code) => (code ? `${code.slice(0, 3)} ${code.slice(3, 6)} ${code.slice(6)}` : '');

// Connect by address with what a person typed: null when it isn't a TwinDesk ID (an address, go on
// as before); else what to pair with: {name, relay: {addr, key, id}} through this computer's own
// relay setting (the same relay as the other computer's), or {name, failed} saying what's missing.
function pairTarget(text, setting, selfFp) {
  const code = parseCode(text);
  if (!code) return null;
  const name = `ID ${formatCode(code)}`;
  if (selfFp && codeOf(selfFp) === code) return { name, failed: 'That’s this computer’s own TwinDesk ID.' };
  const r = clean(setting);
  if (!r.addr) return { name, failed: 'To connect with a TwinDesk ID, add the same relay as the other computer first: General › Your own relay.' };
  return { name, code, relay: { addr: r.addr, key: r.key, id: idOfCode(code) } };
}

// The app's one relay: started, changed or stopped from settings.net.relay (each app calls
// apply() on start and when the setting changes; nothing runs while no address is set).
let host = null;
let pairHost = null; // while Allow pairing through the relay is on: waiting under the TwinDesk ID too
// TURN for computers through the relay (shared/turn.js): screen, sound, microphone and camera go
// WebRTC → TCP through the relay → this computer's TURN server, the same way a phone's go through its
// USB cable. Started with the relay, on a port of its own; stopped with it.
let turn = null;
let turnReady = false;
let code = '';
let applied = '';
let appliedServer = null;
function apply({ server, fp, relay, onState = () => {} }) {
  const r = clean(relay);
  const k = JSON.stringify([r, fp]);
  if (k === applied && server === appliedServer) return; // a new server (restarted) takes the relay too
  applied = k;
  appliedServer = server;
  if (host) host.stop();
  if (pairHost) pairHost.stop();
  host = pairHost = null;
  code = '';
  const wantTurn = !!(r.addr && server && fp);
  if (!wantTurn && turn) { turn.stop(); turn = null; turnReady = false; }
  if (wantTurn && !turn) {
    const t = (turn = new TurnThread({ port: 0 }));
    t.start().then(() => { if (turn === t) { turnReady = true; onState(); } }, (e) => {
      console.error(`[relay] TURN: ${e.message}`);
      if (turn === t) turn = null;
    });
  }
  const turnPort = () => (turnReady && turn ? turn.port : 0);
  if (r.addr && server && fp) {
    host = new RelayHost({ server, addr: r.addr, key: r.key, id: idOf(fp), turnPort });
    host.on('state', onState);
    host.start();
    if (r.pair) {
      code = codeOf(fp);
      pairHost = new RelayHost({ server, addr: r.addr, key: r.key, id: idOfCode(code), turnPort });
      pairHost.on('state', onState);
      pairHost.start();
    }
  }
  use(() => (host ? { addr: r.addr, key: r.key, id: idOf(fp) } : null));
}
// Pairing requests that came through the relay are taken only while this is on (pairing.js,
// hostpair.js): with it off they're refused before anything is shown.
const pairingAllowed = () => !!pairHost;

// The RTCConfiguration for a session through our relay, on this side: our TURN server, relayed
// candidates only. Null for any other session (a phone's: it doesn't tunnel TURN yet; one that
// moved to the network: direct again). servers read it as ctx.ice each time (it follows the socket).
function iceFor(ctx) {
  if (!ctx || !ctx.ws || ctx.ws.relayed !== true || P.isPhoneOs(ctx.os) || !turnReady || !turn) return null;
  return turn.ice();
}
// What the other side needs to reach the same TURN server through the relay (welcome {turn}).
function turnFor(ctx) {
  const ice = iceFor(ctx);
  const s = ice && ice.iceServers[0];
  return s ? { username: s.username, credential: s.credential } : null;
}
const view = () => (host ? { ...host.view, addr: host.to ? `${host.to.host}:${host.to.port}` : '', code: formatCode(code) } : { state: 'off', error: '', addr: '', code: '' });

module.exports = { RelayHost, parseAddr, idOf, cleanKey, clean, readLine, use, welcome, apply, view, isRelayed, viaRelay, pairingAllowed, iceFor, turnFor, codeOf, idOfCode, parseCode, formatCode, pairTarget, CODE_DIGITS, DEFAULT_PORT };
