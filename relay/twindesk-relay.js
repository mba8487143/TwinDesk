#!/usr/bin/env node
// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// TwinDesk Relay: run it on a machine your devices can all reach (a small cloud server, a home
// server with a forwarded port), then add its address in TwinDesk on the computer (General › Your
// own relay). A phone or another computer away from the computer's network then connects through
// it (screen, sound and camera too: the computer's TURN rides the same connections).
//
// It pairs connections and copies bytes, nothing more. What goes through is TwinDesk's own TLS
// session (the computer's pinned certificate and the pairing's token), so this relay can't read
// it, change it or tell which devices they are; it never writes anything to disk.
//
//   node twindesk-relay.js [--port 47100] [--key <secret>] [--host 0.0.0.0]
//   (or RELAY_PORT, RELAY_KEY, RELAY_HOST in the environment; the key is best kept there, out of
//   the process list)
// --key: only devices given the same key may use it (set it in TwinDesk with the address). Only
// printable ASCII without spaces counts, as in the apps (shared/relay.js cleanKey).
// --host '::' listens on IPv6 and IPv4 too.
// Node 16 or later; no packages. Wire: shared/relay.js.
//
// Limits: MAX_CONNS connections in all, MAX_PER_IP from one address (a household's devices share
// one), MAX_HOSTS computers, MAX_WAITING joins waiting per computer for JOIN_MS. A call's number
// is random, so only the computer it was sent to can take it. TCP keepalive on every connection:
// one whose far end vanished (a phone's network gone) is closed instead of held for ever.
'use strict';

const net = require('net');
const crypto = require('crypto');

const VERSION = 2; // printed at start: which relay a server runs (the wire stays TDR1)

const arg = (name, env, d) => {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 && process.argv[i + 1] ? process.argv[i + 1] : process.env[env] || d;
};
if (process.argv.includes('--help') || process.argv.includes('-h')) {
  console.log('TwinDesk Relay\n  node twindesk-relay.js [--port 47100] [--key <secret>] [--host 0.0.0.0]\n  Environment: RELAY_PORT, RELAY_KEY, RELAY_HOST');
  process.exit(0);
}
const PORT = Number(arg('port', 'RELAY_PORT', 47100));
const HOST = String(arg('host', 'RELAY_HOST', '0.0.0.0'));
const RAW_KEY = String(arg('key', 'RELAY_KEY', ''));
const KEY = RAW_KEY.replace(/[^\x21-\x7e]/g, '').slice(0, 128); // as the apps send it
const MAX_HOSTS = 1000, MAX_WAITING = 64, JOIN_MS = 15000, IDLE_MS = 180000, MAX_CONNS = 4000, MAX_PER_IP = 256;
const KEEPALIVE_MS = 30000;

if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
  console.error(`TwinDesk Relay: the port must be a number from 1 to 65535 (got "${arg('port', 'RELAY_PORT', 47100)}")`);
  process.exit(2);
}
if (KEY !== RAW_KEY) console.warn('TwinDesk Relay: the key had spaces or other characters the apps leave out (or was longer than 128); using it without them');
if (!KEY) console.warn('TwinDesk Relay: no key set. Anyone who finds this relay can use it: set RELAY_KEY (and the same key in TwinDesk).');

const hosts = new Map(); // id → control socket
const waiting = new Map(); // id → Map(n → joiner socket)
const perIp = new Map(); // address → connections open
let conns = 0;

const same = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const keyOk = (k) => !KEY || same(k, KEY);
const ID = /^[0-9a-f]{32}$/;

function line(sock, cb) {
  let buf = Buffer.alloc(0);
  const timer = setTimeout(() => sock.destroy(), 10000);
  const onData = (d) => {
    buf = Buffer.concat([buf, d]);
    const i = buf.indexOf(10);
    if (i < 0) { if (buf.length > 512) sock.destroy(); return; }
    clearTimeout(timer);
    sock.removeListener('data', onData);
    cb(buf.slice(0, i).toString('utf8').trim(), buf.slice(i + 1));
  };
  sock.on('data', onData);
}

function host(sock, id) {
  const was = hosts.get(id);
  if (was && was !== sock) was.destroy(); // the computer reconnected
  if (!hosts.has(id) && hosts.size >= MAX_HOSTS) return sock.end('full\n');
  hosts.set(id, sock);
  sock.setTimeout(IDLE_MS, () => sock.destroy());
  sock.write('ok\n');
  let buf = '';
  sock.on('data', (d) => {
    buf += d.toString('utf8');
    if (buf.length > 4096) return sock.destroy();
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      if (buf.slice(0, i).trim() === 'ping') sock.write('pong\n');
      buf = buf.slice(i + 1);
    }
  });
  sock.on('close', () => { if (hosts.get(id) === sock) hosts.delete(id); });
}

function join(sock, id, rest) {
  const ctl = hosts.get(id);
  if (!ctl) return sock.end('no\n');
  const list = waiting.get(id) || new Map();
  if (list.size >= MAX_WAITING) return sock.end('busy\n');
  // A random number (the apps take 1 to 9 digits): a guess at another's call almost never hits.
  let n;
  do n = String(crypto.randomInt(1, 1e9)); while (list.has(n));
  sock.pause();
  if (rest.length) sock.unshift(rest);
  list.set(n, sock);
  waiting.set(id, list);
  // Only this list: another join for the id may have started a new one meanwhile (its own waiters).
  const drop = () => { list.delete(n); if (!list.size && waiting.get(id) === list) waiting.delete(id); };
  const timer = setTimeout(() => { drop(); sock.end('no\n'); }, JOIN_MS);
  sock.once('close', () => { clearTimeout(timer); drop(); });
  sock._relayTimer = timer;
  ctl.write(`call ${n}\n`);
}

function take(sock, id, n, rest) {
  const list = waiting.get(id);
  const other = list && list.get(n);
  if (!other) return sock.end('no\n');
  list.delete(n);
  if (!list.size && waiting.get(id) === list) waiting.delete(id);
  clearTimeout(other._relayTimer);
  sock.write('ok\n');
  other.write('ok\n');
  if (rest.length) other.write(rest);
  sock.pipe(other);
  other.pipe(sock);
  other.resume();
  const end = () => { sock.destroy(); other.destroy(); };
  sock.on('close', end);
  other.on('close', end);
  sock.setTimeout(0);
  other.setTimeout(0);
}

const server = net.createServer((sock) => {
  const ip = String(sock.remoteAddress || '').replace(/^::ffff:/, '');
  if (conns >= MAX_CONNS || (perIp.get(ip) || 0) >= MAX_PER_IP) return sock.destroy();
  conns++;
  perIp.set(ip, (perIp.get(ip) || 0) + 1);
  sock.on('close', () => {
    conns--;
    const left = (perIp.get(ip) || 1) - 1;
    if (left > 0) perIp.set(ip, left); else perIp.delete(ip);
  });
  sock.on('error', () => sock.destroy());
  sock.setNoDelay(true);
  sock.setKeepAlive(true, KEEPALIVE_MS);
  sock.setTimeout(20000, () => sock.destroy());
  line(sock, (l, rest) => {
    const p = l.split(' ');
    if (p[0] !== 'TDR1' || !ID.test(p[2] || '')) return sock.destroy();
    if (!keyOk(p[p[1] === 'take' ? 4 : 3] === '-' ? '' : p[p[1] === 'take' ? 4 : 3] || '')) return sock.end('key\n');
    if (p[1] === 'host') return host(sock, p[2]);
    if (p[1] === 'join') return join(sock, p[2], rest);
    if (p[1] === 'take' && /^\d{1,9}$/.test(p[3] || '')) return take(sock, p[2], p[3], rest);
    sock.destroy();
  });
});
server.on('error', (e) => {
  console.error(`TwinDesk Relay: ${e.code === 'EADDRINUSE' ? `port ${PORT} is already in use` : e.code === 'EACCES' ? `not allowed to listen on port ${PORT}` : e.message}`);
  process.exit(1);
});
server.listen(PORT, HOST, () => console.log(`TwinDesk Relay ${VERSION} on ${HOST}:${PORT}${KEY ? ' (with a key)' : ' (no key)'}`));
// A service manager's stop (systemd): close at once; the apps reconnect when it's back.
for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => { server.close(); process.exit(0); });
