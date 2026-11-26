// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// TURN (shared/turn.js) for screen, sound and camera through your own relay (shared/relay.js),
// driven by a small TURN client written here (what a browser does: Allocate with long-term
// credentials, ChannelBind, ChannelData, Send indications):
//   - Two clients relay media to each other through the server's allocations.
//   - Only to the server's own allocations: not to another UDP port on this machine, nor from one.
//   - Port 0: the thread picks one and says which.
//   - Through the relay: one port on the far side takes TLS (to the session's server) and TURN (to the
//     TURN server), told apart by the first byte; anything else goes nowhere. One client reaches the
//     TURN server directly, the other through relay/twindesk-relay.js and a guest's pipe, and they
//     exchange media.
//   - The ICE both sides use: the host's (iceFor, turnFor; none for a phone or a direct session),
//     the guest's through its pipe (relaypipe.js iceThrough), servers' ctx.ice following the socket.
// Run with: node shared/test/turn-relay.js
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const dgram = require('dgram');
const https = require('https');
const crypto = require('crypto');
const { spawn, execFileSync } = require('child_process');
const { Turn, TurnThread } = require('../turn.js');
const R = require('../relay.js');
const RP = require('../relaypipe.js');

const COOKIE = 0x2112a442;
const until = async (cond, what, ms = 8000) => {
  const t = Date.now();
  while (!(await cond())) {
    if (Date.now() - t > ms) throw new Error(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
};
const pad4 = (n) => (n + 3) & ~3;
const attr = (t, v) => { const h = Buffer.alloc(4); h.writeUInt16BE(t, 0); h.writeUInt16BE(v.length, 2); return Buffer.concat([h, v, Buffer.alloc(pad4(v.length) - v.length)]); };
const xorAddr = (ip, port) => {
  const b = Buffer.alloc(8);
  b[1] = 1;
  b.writeUInt16BE(port ^ (COOKIE >>> 16), 2);
  const n = ip.split('.').reduce((a, x) => (a << 8) + Number(x), 0);
  b.writeUInt32BE((n ^ COOKIE) >>> 0, 4);
  return b;
};
const unXor = (b) => { const port = b.readUInt16BE(2) ^ (COOKIE >>> 16); const n = (b.readUInt32BE(4) ^ COOKIE) >>> 0; return { ip: [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'), port }; };

// A TURN client over TCP: what WebRTC does, enough to move bytes.
class Client {
  constructor(port, { username, credential }) {
    this.port = port;
    this.user = username;
    this.pass = credential;
    this.buf = Buffer.alloc(0);
    this.waiting = new Map(); // tid hex -> resolve
    this.received = []; // [{channel|peer, data}]
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.sock = net.connect({ host: '127.0.0.1', port: this.port }, resolve);
      this.sock.on('error', reject);
      this.sock.on('data', (d) => this._data(d));
    });
  }

  _data(d) {
    this.buf = Buffer.concat([this.buf, d]);
    for (;;) {
      if (this.buf.length < 4) return;
      const top = this.buf[0] >> 6;
      const total = top === 0 ? 20 + this.buf.readUInt16BE(2) : pad4(4 + this.buf.readUInt16BE(2));
      if (this.buf.length < total) return;
      const f = this.buf.subarray(0, total);
      this.buf = this.buf.subarray(total);
      if (top === 1) { this.received.push({ channel: f.readUInt16BE(0), data: Buffer.from(f.subarray(4, 4 + f.readUInt16BE(2))) }); continue; }
      const type = f.readUInt16BE(0);
      const attrs = new Map();
      for (let o = 20; o + 4 <= f.length;) { const t = f.readUInt16BE(o); const l = f.readUInt16BE(o + 2); attrs.set(t, f.subarray(o + 4, o + 4 + l)); o += 4 + pad4(l); }
      if (type === 0x0017) { this.received.push({ peer: unXor(attrs.get(0x0012)), data: Buffer.from(attrs.get(0x0013)) }); continue; }
      const w = this.waiting.get(f.subarray(8, 20).toString('hex'));
      if (w) w({ type, attrs });
    }
  }

  // A request, signed once the realm and nonce are known (the 401 dance on the first).
  request(type, attrs) {
    const tid = crypto.randomBytes(12);
    let body = Buffer.concat(attrs);
    if (this.realm) {
      body = Buffer.concat([body, attr(0x0006, Buffer.from(this.user)), attr(0x0014, Buffer.from(this.realm)), attr(0x0015, Buffer.from(this.nonce))]);
      const head = Buffer.alloc(20); head.writeUInt16BE(type, 0); head.writeUInt16BE(body.length + 24, 2); head.writeUInt32BE(COOKIE, 4); tid.copy(head, 8);
      const key = crypto.createHash('md5').update(`${this.user}:${this.realm}:${this.pass}`).digest();
      body = Buffer.concat([body, attr(0x0008, crypto.createHmac('sha1', key).update(Buffer.concat([head, body])).digest())]);
    }
    const head = Buffer.alloc(20); head.writeUInt16BE(type, 0); head.writeUInt16BE(body.length, 2); head.writeUInt32BE(COOKIE, 4); tid.copy(head, 8);
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => reject(new Error(`no answer to 0x${type.toString(16)}`)), 3000);
      this.waiting.set(tid.toString('hex'), (m) => { clearTimeout(t); resolve(m); });
      this.sock.write(Buffer.concat([head, body]));
    });
  }

  async allocate() {
    const want = [attr(0x0019, Buffer.from([17, 0, 0, 0]))];
    let m = await this.request(0x0003, want);
    if (m.type === 0x0113) { // 401: the realm and nonce, then signed
      this.realm = m.attrs.get(0x0014).toString();
      this.nonce = m.attrs.get(0x0015).toString();
      m = await this.request(0x0003, want);
    }
    if (m.type !== 0x0103) throw new Error(`allocate failed 0x${m.type.toString(16)}`);
    this.relayed = unXor(m.attrs.get(0x0016));
    return this.relayed;
  }

  async bind(channel, peer) {
    const m = await this.request(0x0009, [attr(0x000c, Buffer.from([channel >> 8, channel & 255, 0, 0])), attr(0x0012, xorAddr(peer.ip, peer.port))]);
    return m.type === 0x0109 ? 'ok' : `error ${m.attrs.get(0x0009) ? m.attrs.get(0x0009)[2] * 100 + m.attrs.get(0x0009)[3] : '?'}`;
  }

  channelData(channel, data) {
    const h = Buffer.alloc(4); h.writeUInt16BE(channel, 0); h.writeUInt16BE(data.length, 2);
    this.sock.write(Buffer.concat([h, data, Buffer.alloc(pad4(data.length) - data.length)]));
  }

  sendIndication(peer, data) {
    const body = Buffer.concat([attr(0x0012, xorAddr(peer.ip, peer.port)), attr(0x0013, data)]);
    const head = Buffer.alloc(20); head.writeUInt16BE(0x0016, 0); head.writeUInt16BE(body.length, 2); head.writeUInt32BE(COOKIE, 4); crypto.randomBytes(12).copy(head, 8);
    this.sock.write(Buffer.concat([head, body]));
  }

  close() { this.sock.destroy(); }
}

// Two clients on one server (directly, or the second through `port2`) exchange media both ways.
async function exchange(port1, port2, login) {
  const a = new Client(port1, login);
  const b = new Client(port2, login);
  await a.connect();
  await b.connect();
  const ra = await a.allocate();
  const rb = await b.allocate();
  assert.strictEqual(await a.bind(0x4001, rb), 'ok');
  assert.strictEqual(await b.bind(0x4002, ra), 'ok');
  a.channelData(0x4001, Buffer.from('frame from a'));
  b.channelData(0x4002, Buffer.from('frame from b'));
  await until(() => b.received.some((x) => String(x.data) === 'frame from a') && a.received.some((x) => String(x.data) === 'frame from b'), 'media both ways');
  return { a, b, ra, rb };
}

// The TURN thread is unref'd (it never keeps an app from quitting): this keeps the test alive.
const keepAlive = setInterval(() => {}, 1000);

(async () => {
  // ---- the server alone ----
  const turn = new Turn({ port: 0 });
  await turn.start();
  assert.ok(turn.port > 0, 'port 0: a free one, kept');
  assert.strictEqual(turn.ice().iceServers[0].urls, `turn:127.0.0.1:${turn.port}?transport=tcp`);
  const login = { username: turn.username, credential: turn.password };

  const bad = new Client(turn.port, { username: 'td', credential: 'wrong' });
  await bad.connect();
  await assert.rejects(bad.allocate(), /allocate failed/, 'a wrong password gets no allocation');
  bad.close();

  const { a, b, ra } = await exchange(turn.port, turn.port, login);
  // A Send indication works too, to an allocation.
  b.sendIndication(ra, Buffer.from('indication to a'));
  await until(() => a.received.some((x) => String(x.data) === 'indication to a'), 'a send indication');

  // Not to anything else on this machine: a UDP socket that isn't an allocation.
  const stranger = dgram.createSocket('udp4');
  const heard = [];
  stranger.on('message', (m) => heard.push(String(m)));
  await new Promise((r) => stranger.bind(0, '127.0.0.1', r));
  const sp = { ip: '127.0.0.1', port: stranger.address().port };
  assert.strictEqual(await a.bind(0x4003, sp), 'error 403', 'no channel to a port that isn’t an allocation');
  a.sendIndication(sp, Buffer.from('to a stranger'));
  a.sendIndication({ ip: '10.0.0.1', port: 9 }, Buffer.from('off this machine'));
  // … nor from one: what it sends to an allocation doesn't reach the client.
  stranger.send(Buffer.from('from a stranger'), ra.port, '127.0.0.1');
  await new Promise((r) => setTimeout(r, 300));
  assert.deepStrictEqual(heard, [], 'nothing reached the stranger');
  assert.ok(!a.received.some((x) => String(x.data) === 'from a stranger'), 'nothing from the stranger reached the client');
  // Once a client goes, its allocation's port isn't a peer any more.
  b.close();
  await until(() => !turn.relayPorts.has(b.relayed.port), 'the allocation gone with its client');
  a.close();
  stranger.close();
  turn.stop();

  // The thread: port 0 too, and it says which.
  const th = new TurnThread({ port: 0 });
  await th.start();
  assert.ok(th.port > 0, 'the thread’s port');
  assert.strictEqual(th.ice().iceServers[0].urls, `turn:127.0.0.1:${th.port}?transport=tcp`);
  assert.strictEqual(th.ice().iceTransportPolicy, 'relay');
  th.stop();

  // ---- through your own relay ----
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'turn-relay-'));
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=t',
    '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem')], { stdio: 'ignore' });
  const PORT = 43000 + Math.floor(Math.random() * 900);
  const KEY = 'turn-key';
  const ADDR = `127.0.0.1:${PORT}`;
  const relay = spawn(process.execPath, [path.join(__dirname, '../../relay/twindesk-relay.js'), '--port', String(PORT), '--host', '127.0.0.1', '--key', KEY], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((r) => relay.stdout.once('data', r));
  const tlsServer = https.createServer({ key: fs.readFileSync(path.join(dir, 'key.pem')), cert: fs.readFileSync(path.join(dir, 'cert.pem')) }, (req, res) => res.end(R.isRelayed(req.socket) ? 'relayed' : 'direct'));
  await new Promise((r) => tlsServer.listen(0, '127.0.0.1', r));
  const FP = 'AA:BB:CC:TURN';
  try {
    // The host's app: its relay setting applied, which starts the TURN server with it.
    R.apply({ server: { https: tlsServer }, fp: FP, relay: { addr: ADDR, key: KEY } });
    await until(() => R.view().state === 'ready', 'on the relay');
    const relayedCtx = { os: 'win', ws: { relayed: true } };
    await until(() => !!R.iceFor(relayedCtx), 'TURN up with the relay');
    const hostIce = R.iceFor(relayedCtx);
    assert.strictEqual(hostIce.iceTransportPolicy, 'relay');
    assert.match(hostIce.iceServers[0].urls, /^turn:127\.0\.0\.1:\d+\?transport=tcp$/);
    assert.strictEqual(R.iceFor({ os: 'android', ws: { relayed: true } }), null, 'a phone: none (it doesn’t tunnel TURN)');
    assert.strictEqual(R.iceFor({ os: 'win', ws: { relayed: false } }), null, 'a direct session: none');
    assert.strictEqual(R.iceFor(null), null);
    const tlogin = R.turnFor(relayedCtx);
    assert.deepStrictEqual(tlogin, { username: hostIce.iceServers[0].username, credential: hostIce.iceServers[0].credential });
    assert.strictEqual(R.turnFor({ os: 'win', ws: {} }), null, 'no login for a direct session');

    // The guest: its pipe to the host, and its own ICE through it.
    const pipe = await RP.RelayPipe.open({ addr: ADDR, key: KEY, id: R.idOf(FP) });
    const guestIce = RP.iceThrough(pipe, tlogin);
    assert.deepStrictEqual(guestIce, { iceServers: [{ urls: `turn:127.0.0.1:${pipe.port}?transport=tcp`, username: tlogin.username, credential: tlogin.credential }], iceTransportPolicy: 'relay' });
    assert.strictEqual(RP.iceThrough(pipe, null), null, 'no login: none');
    assert.strictEqual(RP.iceThrough(pipe, { username: 'a b', credential: 'x' }), null, 'a login that isn’t one: none');
    assert.strictEqual(RP.iceThrough(null, tlogin), null);
    assert.strictEqual(RP.turnLogin({ username: 'td', credential: 'p' }).username, 'td');
    assert.strictEqual(RP.turnLogin('x'), null);

    // The same port: TLS goes to the session's server (marked relayed)…
    const get = () => new Promise((resolve, reject) => https.get({ host: '127.0.0.1', port: pipe.port, rejectUnauthorized: false, agent: false }, (res) => { let b = ''; res.on('data', (x) => { b += x; }); res.on('end', () => resolve(b)); }).on('error', reject));
    assert.strictEqual(await get(), 'relayed', 'TLS through the pipe: the session’s server, relayed');
    // … TURN to the TURN server: one client here, one through the relay, media both ways.
    const hostPort = Number(/:(\d+)\?/.exec(hostIce.iceServers[0].urls)[1]);
    const x = await exchange(hostPort, pipe.port, tlogin);
    x.a.close();
    x.b.close();
    // Anything else: closed, nothing reaches either server.
    const junk = await new Promise((resolve) => {
      const s = net.connect({ host: '127.0.0.1', port: pipe.port }, () => s.write('GET / HTTP/1.1\r\n\r\n'));
      let got = '';
      s.on('data', (d) => { got += d; });
      s.on('close', () => resolve(got));
      s.on('error', () => {});
    });
    assert.strictEqual(junk, '', 'neither TLS nor STUN: closed');
    pipe.destroy();

    // Relay removed: its TURN goes too.
    R.apply({ server: { https: tlsServer }, fp: FP, relay: { addr: '' } });
    assert.strictEqual(R.iceFor(relayedCtx), null, 'no relay, no TURN');

    // ---- servers: ctx.ice follows the socket; the welcome carries the login only through the relay ----
    R.apply({ server: { https: tlsServer }, fp: FP, relay: { addr: ADDR, key: KEY } });
    await until(() => !!R.iceFor(relayedCtx), 'TURN up again');
    const { EventEmitter } = require('events');
    for (const file of ['../../mac/server.js', '../../windows/server.js', '../../linux/server.js']) {
      const name = file.split('/')[2];
      const { Server } = require(file);
      const s = Object.create(Server.prototype);
      EventEmitter.call(s);
      Object.assign(s, { sockets: new Set(), current: null, fxOn: false });
      const sent = [];
      const ws = { OPEN: 1, readyState: 1, relayed: true, send: (m) => sent.push(JSON.parse(m)) };
      const ctx = { ws, authed: false, address: '203.0.113.5', transport: 'ip' };
      s.sockets.add(ctx);
      s.authenticate(ctx, { deviceId: 'pc', name: 'PC', os: 'win' }, { t: 'welcome', v: 1 });
      await until(() => sent.length === 1, `${name}: welcome`);
      assert.deepStrictEqual(sent[0].turn, R.turnFor(ctx), `${name}: the welcome carries the TURN login through the relay`);
      assert.ok(ctx.ice && ctx.ice.iceTransportPolicy === 'relay', `${name}: ctx.ice: the relay’s TURN`);
      s.send(ctx, { t: 'audio.offer', sdp: 'x' });
      assert.ok(sent[1].ice, `${name}: offers carry it, as for a phone on the cable`);
      ctx.ws = { OPEN: 1, readyState: 1, relayed: false, send: (m) => sent.push(JSON.parse(m)) }; // moved to the network
      assert.strictEqual(ctx.ice, null, `${name}: once on the network, direct again`);
      ctx.ice = 'ignored'; // nothing sets it any more: a write is ignored, never throws
      assert.strictEqual(ctx.ice, null);
      // A session straight on the network: no login, no ICE.
      const sent2 = [];
      const ctx2 = { ws: { OPEN: 1, readyState: 1, relayed: false, send: (m) => sent2.push(JSON.parse(m)) }, authed: false, address: '192.168.1.9', transport: 'ip' };
      s.sockets.add(ctx2);
      s.current = null;
      s.authenticate(ctx2, { deviceId: 'pc2', name: 'PC2', os: 'win' }, { t: 'welcome', v: 1 });
      await until(() => sent2.length === 1, `${name}: welcome 2`);
      assert.ok(!('turn' in sent2[0]) && ctx2.ice === null, `${name}: on the network: nothing`);
      // A phone on the cable keeps the cable's (wired.js iceFor), as before.
      const wired = { iceServers: [{ urls: 'turn:127.0.0.1:47802?transport=tcp' }], iceTransportPolicy: 'relay' };
      s.iceFor = () => wired;
      const ctx3 = { ws: { OPEN: 1, readyState: 1, relayed: false, send() {} }, authed: false, address: '127.0.0.1', transport: 'ip' };
      s.sockets.add(ctx3);
      s.current = null;
      s.authenticate(ctx3, { deviceId: 'ph', name: 'Phone', os: 'android' }, { t: 'welcome', v: 1 });
      await until(() => s.current === ctx3, `${name}: phone`);
      assert.strictEqual(ctx3.ice, wired, `${name}: the cable’s, unchanged`);
      for (const c of s.sockets) clearInterval(c.timer);
      if (s.tick) clearInterval(s.tick);
    }

    // ---- static: no WebRTC site in the apps left without a way in for the relay's ICE ----
    const ROOT = path.join(__dirname, '..', '..');
    const files = execFileSync('git', ['ls-files', 'mac/*.js', 'windows/*.js', 'linux/*.js', 'shared/*.js'], { cwd: ROOT, encoding: 'utf8' }).split('\n').filter((f) => f && !/\/(mesh|dev|test|web)\//.test(f));
    const bare = [];
    for (const f of files) {
      const src = fs.readFileSync(path.join(ROOT, f), 'utf8');
      for (const m of src.matchAll(/new RTCPeerConnection\(([^)]*)\)/g)) if (/^\s*\{\s*iceServers:\s*\[\]\s*\}\s*$/.test(m[1])) bare.push(f);
    }
    assert.deepStrictEqual(bare, [], 'every RTCPeerConnection takes the ICE it is given');
  } finally {
    R.apply({ server: null, fp: '', relay: null });
    tlsServer.close();
    relay.kill();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  clearInterval(keepAlive);
  console.log('turn-relay: ok');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
