// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// Your own relay, from the side that connects: a computer reaching another computer that isn't on
// its network, through that computer's relay (General › Your own relay, shared/relay.js is the side
// that hosts; android/…/Relay.kt is the same for a phone).
//   - The host tells us its relay in its welcome ({addr, key, id}); link.js keeps it with the host
//     (info() checks it) and, when the host isn't seen on this network, dials every other attempt
//     through it.
//   - open() joins the relay once and, only when the host took that connection, opens a port on
//     127.0.0.1: the session's WSS goes to that port, so the session inside is the usual one (TLS
//     with the host's pinned certificate, the token). The relay only passes bytes on.
//   - Each further connection to the port (fast files, shared/fastfile.js) joins the relay again,
//     so it reaches the host's server as a connection of its own. At most MAX_LIVE at once.
//   - The first joined connection waits FIRST_MS for the session to use it; then it goes.
//   - close(): no new connections (the ones open finish on their own); destroy(): all of them now.
//
//   const pipe = await RelayPipe.open(info(welcome.relay)); // rejects RelayError {code}
//   new WebSocket(`wss://127.0.0.1:${pipe.port}`, …); …; pipe.close()
//   codes: absent (the host isn't on the relay) | key | busy | unreachable | timeout | bad | closed
'use strict';

const net = require('net');
const { parseAddr, cleanKey, readLine } = require('./relay.js');

const CONNECT_MS = 8000;
const JOIN_MS = 20000; // the relay holds a join up to 15 s for the host to take it, then says "no"
const FIRST_MS = 15000;
const MAX_LIVE = 16;
const KEEPALIVE_MS = 30000; // through NATs on the way to the relay: an idle session's TCP stays open
const ID = /^[0-9a-f]{32}$/;

const MESSAGES = {
  absent: '{Name} isn’t on its relay',
  key: 'The relay’s key is wrong',
  busy: 'The relay is busy',
  unreachable: 'Can’t reach the relay',
  timeout: 'The relay didn’t answer',
  bad: 'Not a TwinDesk relay',
  closed: 'Cancelled',
};

class RelayError extends Error {
  constructor(code, detail = '') {
    super(MESSAGES[code] || code);
    this.code = code;
    this.detail = detail;
  }
}

// What a host said in its welcome, checked: {addr, key, id} or null (none, or not one we can use).
function info(r) {
  if (!r || typeof r !== 'object') return null;
  const addr = String(r.addr || '').trim();
  const id = String(r.id || '');
  if (!parseAddr(addr) || !ID.test(id)) return null;
  return { addr, key: cleanKey(r.key), id };
}

// The same relay (a welcome that changes nothing isn't saved again).
const same = (a, b) => (!a && !b) || (!!a && !!b && a.addr === b.addr && a.key === b.key && a.id === b.id);

// A message for the person, with the host's name in it (Windows and Linux fill {Name} themselves).
function message(e, name) {
  const m = e instanceof RelayError ? e.message : MESSAGES.unreachable;
  return name ? m.replace('{Name}', name) : m;
}

// The same while pairing with a TwinDesk ID (Connect by address): what to check is different then.
function pairMessage(e) {
  const code = e instanceof RelayError ? e.code : 'unreachable';
  if (code === 'absent') return 'No computer with that ID is on your relay. Check the ID, and that Allow pairing through the relay is on there.';
  if (code === 'key') return 'Your relay’s key is wrong (General › Your own relay).';
  if (code === 'unreachable' || code === 'timeout') return 'Can’t reach your relay (General › Your own relay).';
  return message(e);
}

// One connection through the relay to the host: resolves the socket (paused, spliced by the caller)
// once the host took it.
function join(r, { connectMs = CONNECT_MS, joinMs = JOIN_MS } = {}) {
  return new Promise((resolve, reject) => {
    const to = parseAddr(r && r.addr);
    if (!to || !r || !ID.test(String(r.id || ''))) return reject(new RelayError('bad'));
    const s = net.connect({ host: to.host, port: to.port });
    s.on('error', () => s.destroy()); // always one listener: an error after the reply never throws
    s.setNoDelay(true);
    let connected = false;
    const timer = setTimeout(() => {
      if (connected) return;
      s.destroy();
      reject(new RelayError('unreachable', 'timed out'));
    }, connectMs);
    s.once('error', (e) => {
      if (connected) return;
      clearTimeout(timer);
      reject(new RelayError('unreachable', e.code || e.message));
    });
    s.once('connect', () => {
      connected = true;
      clearTimeout(timer);
      s.setKeepAlive(true, KEEPALIVE_MS);
      s.write(`TDR1 join ${r.id} ${cleanKey(r.key) || '-'}\n`);
      readLine(s, joinMs, (err, line, rest) => {
        if (!err && line === 'ok') {
          s.pause(); // nothing is lost before the splice: it resumes the socket
          if (rest.length) s.unshift(rest);
          return resolve(s);
        }
        s.destroy();
        if (err) return reject(new RelayError(err.message === 'timed out' ? 'timeout' : 'bad', err.message));
        reject(new RelayError(line === 'no' ? 'absent' : line === 'key' ? 'key' : line === 'busy' ? 'busy' : 'bad', line));
      });
    });
  });
}

class RelayPipe {
  // r: info() of the host's relay. opts: {connectMs, joinMs, firstMs, maxLive} (tests).
  constructor(r, opts = {}) {
    this.r = info(r);
    this.opts = opts;
    this.firstMs = opts.firstMs || FIRST_MS;
    this.server = null;
    this.first = null; // the joined connection kept for the session's own socket
    this.firstTimer = null;
    this.live = new Set(); // spliced pairs [local, relayed]
    this.closed = false;
    this.port = 0;
  }

  static async open(r, opts) {
    const pipe = new RelayPipe(r, opts);
    await pipe._start();
    return pipe;
  }

  async _start() {
    if (!this.r) throw new RelayError('bad');
    const first = await join(this.r, this.opts);
    if (this.closed) { first.destroy(); throw new RelayError('closed'); }
    this._keepFirst(first);
    const server = net.createServer({ pauseOnConnect: true }, (local) => this._accept(local));
    server.maxConnections = this.opts.maxLive || MAX_LIVE;
    this.server = server;
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', () => { server.removeListener('error', reject); resolve(); });
    }).catch((e) => { this.destroy(); throw new RelayError('bad', e.message); });
    server.on('error', () => this.close());
    if (this.closed) { this.destroy(); throw new RelayError('closed'); }
    this.port = server.address().port;
  }

  _keepFirst(s) {
    this.first = s;
    s.once('close', () => { if (this.first === s) this.first = null; });
    clearTimeout(this.firstTimer);
    this.firstTimer = setTimeout(() => {
      if (this.first !== s) return;
      this.first = null;
      s.destroy();
    }, this.firstMs);
  }

  _accept(local) {
    local.on('error', () => local.destroy());
    if (this.closed) return local.destroy();
    local.setNoDelay(true);
    const up = this.first;
    if (up && !up.destroyed) {
      this.first = null;
      clearTimeout(this.firstTimer);
      return this._splice(local, up);
    }
    join(this.r, this.opts).then((s) => {
      if (this.closed || local.destroyed) { s.destroy(); local.destroy(); return; }
      this._splice(local, s);
    }, () => local.destroy());
  }

  _splice(a, b) {
    const pair = [a, b];
    this.live.add(pair);
    const end = () => {
      a.destroy();
      b.destroy();
      this.live.delete(pair);
    };
    for (const s of pair) {
      s.on('close', end);
      s.on('error', end);
    }
    a.pipe(b);
    b.pipe(a);
  }

  // No new connections; the open ones go on until either end closes them.
  close() {
    if (this.closed) return;
    this.closed = true;
    clearTimeout(this.firstTimer);
    if (this.first) this.first.destroy();
    this.first = null;
    if (this.server) this.server.close();
  }

  destroy() {
    this.close();
    for (const [a, b] of this.live) { a.destroy(); b.destroy(); }
    this.live.clear();
  }
}

module.exports = { RelayPipe, RelayError, info, same, join, message, pairMessage, MAX_LIVE, MESSAGES };
