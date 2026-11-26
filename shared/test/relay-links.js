// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// A computer reaching another computer through that one's own relay: the real windows/, linux/ and
// mac/ link.js against a stand-in host (its WSS server behind shared/relay.js's RelayHost) and
// relay/twindesk-relay.js, all on this machine.
//   - Not seen on the network: an attempt goes through the relay, the host's certificate pinned as
//     always; the hello asks for nothing the relay can't carry (fx2, unencrypted files, the input lane).
//   - The host's server marks the session relayed; fast files use the pipe's port, never fx2's or plain's.
//   - Seen on the network again (Windows, Linux): the session moves there, the relay stays as fallback.
//   - welcome {relay}: kept, replaced, removed with null, left alone when absent (an older host).
//   - Which attempts go through it: every other one while not seen, none while seen or without one.
//   - The Mac keeps the host's own address for the session (the terminal, shared folders).
// Run with: node shared/test/relay-links.js
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { spawn, execFileSync } = require('child_process');

// A tree without every app's node_modules: ws from whichever app has it (as fx2-welcome.js does).
process.env.NODE_PATH = ['mac', 'windows', 'linux'].map((a) => path.join(__dirname, '..', '..', a, 'node_modules')).join(path.delimiter);
require('module').Module._initPaths();
const { WebSocketServer } = require('ws');

const P = require('../protocol.js');
const R = require('../relay.js');
const RP = require('../relaypipe.js');

const T = P.T;
const PORT = 45000 + Math.floor(Math.random() * 900);
const KEY = 'links-key';
const ADDR = `127.0.0.1:${PORT}`;
P.RECONNECT_MS = [40, 40, 40]; // the links read it on each reconnect: quick attempts here

const until = async (cond, what, ms = 15000) => {
  const t = Date.now();
  while (!cond()) {
    if (Date.now() - t > ms) throw new Error(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
};

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-links-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=test',
  '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem')], { stdio: 'ignore' });
const tls = { key: fs.readFileSync(path.join(dir, 'key.pem')), cert: fs.readFileSync(path.join(dir, 'cert.pem')) };
const FP = P.normFingerprint(new crypto.X509Certificate(tls.cert).fingerprint256);
// Another computer's certificate: an impostor answering on the relay for the host's id.
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=other',
  '-keyout', path.join(dir, 'key2.pem'), '-out', path.join(dir, 'cert2.pem')], { stdio: 'ignore' });
const tls2 = { key: fs.readFileSync(path.join(dir, 'key2.pem')), cert: fs.readFileSync(path.join(dir, 'cert2.pem')) };

// The stand-in host: a WSS server on its own port that welcomes hello {token} and hello {resume}.
async function hostServer(id, relayInWelcome, certs = tls) {
  const server = https.createServer(certs);
  const wss = new WebSocketServer({ server });
  const host = { server, sessions: [], hellos: [], resumes: 0 };
  wss.on('connection', (ws, req) => {
    const s = { ws, relayed: R.isRelayed(req.socket) };
    host.sessions.push(s);
    ws.on('message', (data) => {
      const m = JSON.parse(String(data));
      if (m.t !== T.HELLO) return;
      if (m.resume) {
        host.resumes++;
        return ws.send(JSON.stringify({ t: T.WELCOME, v: P.PROTOCOL_VERSION, resumed: true }));
      }
      host.hellos.push({ ...m, relayed: s.relayed });
      ws.send(JSON.stringify({ t: T.WELCOME, v: P.PROTOCOL_VERSION, macId: 'h1', macName: 'Host', os: P.OS.MAC, resume: 'rk1', fx: 'a'.repeat(32), ...(relayInWelcome === undefined ? {} : { relay: relayInWelcome }) }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  host.port = server.address().port;
  host.relay = new R.RelayHost({ server: { https: server }, addr: ADDR, key: KEY, id });
  const ready = new Promise((r) => host.relay.on('state', (v) => v.state === 'ready' && r()));
  host.relay.start();
  await ready;
  host.close = () => { host.relay.stop(); for (const c of wss.clients) c.terminate(); wss.close(); server.close(); };
  return host;
}

const freePort = () => new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });

// ---- Windows and Linux ----
async function winLinux(platform) {
  const Link = require(`../../${platform}/link.js`);
  const { Peer } = (() => { const m = require(`../../${platform}/peer.js`); return { Peer: m.Peer || m }; })();
  const id = R.idOf(`${platform}-host`);
  const info = { addr: ADDR, key: KEY, id };
  const host = await hostServer(id, info);
  const nobody = await freePort(); // the saved address: nothing there (we're away from its network)
  let pairing = { macId: 'h1', macName: 'Host', os: P.OS.MAC, address: '127.0.0.1', port: nobody, fp: FP, token: 'tok', relay: info };
  const saved = [];
  const store = { load: () => pairing, save: (p) => { pairing = p; saved.push(JSON.parse(JSON.stringify(p))); }, clear: () => { pairing = null; } };
  let seen = null;
  const link = new Link({ device: { id: 'g1', name: 'Guest' }, store, resolveAddress: () => seen, blocked: () => false });
  // The app would offer all of these on the network:
  link.fx2Hello = () => true;
  link.fxPlainHello = () => ({ fxPlain: 1 });
  link.ilHello = () => ({ port: 4242 });
  try {
    link.start();
    await until(() => link.status.state === 'connected', `${platform}: connected through the relay`);
    assert.strictEqual(link.transport, 'relay', `${platform}: the session is on the relay`);
    assert.strictEqual(link.ws.address, '127.0.0.1');
    assert.strictEqual(host.hellos.length, 1);
    const hello = host.hellos[0];
    assert.strictEqual(hello.relayed, true, `${platform}: the host's server sees it came through its relay`);
    assert.strictEqual(hello.token, 'tok');
    assert.strictEqual(hello.fx, 1, `${platform}: fast files go through the pipe`);
    for (const k of ['fx2', 'fxPlain', 'il']) assert.ok(!(k in hello), `${platform}: no ${k} through the relay`);
    assert.strictEqual(pairing.address, '127.0.0.1', `${platform}: the pipe's address isn't saved as the host's`);
    assert.strictEqual(pairing.port, nobody, `${platform}: nor its port`);
    assert.deepStrictEqual(pairing.relay, info);
    assert.ok(!saved.some((p) => p.port !== nobody), `${platform}: no save ever had the pipe's port`);

    // What fast files and the rest of the app see.
    const peer = Object.create(Peer.prototype);
    Object.assign(peer, { server: null, link, fxPlain: { port: 9999, token: 'x' } });
    link.fx2Port = 5555; // even if a host offered it: never used through the relay
    const fx = peer._fxSession();
    assert.strictEqual(fx.address, '127.0.0.1');
    assert.strictEqual(fx.port, link.ws.port, `${platform}: fast files dial the pipe's port`);
    assert.strictEqual(fx.fx2, false, `${platform}: no fx2 through the relay`);
    assert.strictEqual(fx.fx2Port, 0);
    assert.strictEqual(fx.plain, null, `${platform}: no unencrypted files through the relay`);
    assert.strictEqual(peer.current.via, 'relay');
    assert.strictEqual(peer.current.transport, 'ip', `${platform}: netlink.js sees a network session, as before`);
    link.fx2Port = 0;

    // Back on its network: the session moves there; the relay socket stays as the fallback.
    seen = { address: '127.0.0.1', port: host.port };
    link.networkRetryAt = 0;
    link.resumeAt = 0;
    link._tryResume();
    await until(() => link.transport === 'ip', `${platform}: moved to the network`);
    assert.strictEqual(host.resumes, 1);
    assert.ok(link.alt && link.alt.transport === 'relay', `${platform}: the relay is the fallback now`);
    const relaySock = link.alt;
    link.ws.terminate(); // the network goes again
    await until(() => link.transport === 'relay' && link.ws === relaySock, `${platform}: back on the relay`);
    assert.strictEqual(link.status.state, 'connected', `${platform}: the session lived on`);

    // Disconnect: the pipe goes with its socket.
    const pipe = relaySock.relayPipe;
    assert.ok(pipe && pipe.port > 0);
    link.disconnect();
    await until(() => pipe.closed, `${platform}: the pipe closed with its socket`);
  } finally {
    link.disconnect();
    host.close();
  }

  // ---- an impostor on the relay: never "identity changed", only a failed attempt ----
  {
    const fakeId = R.idOf(`${platform}-impostor`);
    const fake = await hostServer(fakeId, null, tls2);
    let p2 = { macId: 'h1', macName: 'Host', os: P.OS.MAC, address: '127.0.0.1', port: await freePort(), fp: FP, token: 'tok', relay: { addr: ADDR, key: KEY, id: fakeId } };
    const l2 = new Link({ device: { id: 'g2', name: 'Guest' }, store: { load: () => p2, save: (x) => { p2 = x; }, clear() {} }, resolveAddress: () => null, blocked: () => false });
    try {
      l2.start();
      await until(() => fake.sessions.length >= 2, `${platform}: tried the relay twice`);
      assert.notStrictEqual(l2.status.state, 'identity_changed', `${platform}: a stranger on the relay doesn't unpair anything`);
      assert.strictEqual(fake.hellos.length, 0, `${platform}: no hello (no token) to a certificate that isn't the host's`);
      assert.ok(l2.pairing && l2.pairing.token === 'tok', `${platform}: still paired`);
    } finally {
      l2.disconnect();
      fake.close();
    }
  }

  // ---- welcome {relay}, kept ----
  const keep = Object.create(Link.prototype);
  const saves = [];
  keep.store = { save: (p) => saves.push(JSON.parse(JSON.stringify(p))) };
  keep.pairing = { macId: 'h1' };
  keep._keepRelay({ t: T.WELCOME }); // an older host: nothing said, nothing changes
  assert.deepStrictEqual([keep.pairing, saves.length], [{ macId: 'h1' }, 0]);
  keep._keepRelay({ relay: { addr: 'relay.example.com', key: 'k', id } });
  assert.deepStrictEqual(keep.pairing.relay, { addr: 'relay.example.com', key: 'k', id });
  keep._keepRelay({ relay: { addr: 'relay.example.com', key: 'k', id } });
  assert.strictEqual(saves.length, 1, `${platform}: the same relay again isn't saved again`);
  keep._keepRelay({ relay: { addr: 'relay.example.com', key: 'k2', id } });
  assert.strictEqual(keep.pairing.relay.key, 'k2', `${platform}: a new key replaces the old`);
  keep._keepRelay({ relay: { addr: 'http://bad', id } });
  assert.ok(!('relay' in keep.pairing), `${platform}: one we can't use is dropped`);
  keep._keepRelay({ relay: { addr: 'relay.example.com', id } });
  keep._keepRelay({ relay: null });
  assert.ok(!('relay' in keep.pairing), `${platform}: null: the host has none now`);
  assert.strictEqual(saves.length, 5, `${platform}: saved on each change only (set, new key, dropped, set, removed)`);

  // ---- which attempts go through it (one reconnect at a time; _connect only records the choice) ----
  const spaced = async (withRelay, seenNow) => {
    const l = new Link({ device: { id: 'g', name: 'G' }, store: { load: () => ({ macId: 'h', address: '10.0.0.9', port: 1, fp: FP, token: 't', ...(withRelay ? { relay: info } : {}) }), save() {}, clear() {} }, resolveAddress: () => seenNow, blocked: () => false });
    const out = [];
    l._connect = () => { out.push(l.dialRelay); l.dialRelay = false; };
    for (let i = 0; i < 4; i++) { l._scheduleReconnect(); await new Promise((r) => setTimeout(r, 80)); }
    return out;
  };
  assert.deepStrictEqual(await spaced(true, null), [true, false, true, false], `${platform}: not seen: every other attempt through the relay`);
  assert.deepStrictEqual(await spaced(true, { address: '10.0.0.9', port: 1 }), [false, false, false, false], `${platform}: seen: never`);
  assert.deepStrictEqual(await spaced(false, null), [false, false, false, false], `${platform}: no relay: never`);
  console.log(`  ${platform}: ok`);
}

// ---- Mac ----
async function mac() {
  const store = require('../../mac/store');
  store.init(path.join(dir, 'mac'));
  const id = R.idOf('mac-host');
  const info = { addr: ADDR, key: KEY, id };
  const host = await hostServer(id, info);
  // The saved address is the host's on its own network (TEST-NET here: never dialled in this test).
  store.write('hosts.json', [{ id: 'h1', name: 'Host', os: P.OS.MAC, address: '192.0.2.10', port: 47800, fp: FP, token: 'tok', lastSeen: 1, relay: info }]);
  const { Link } = require('../../mac/link.js');
  const { Peer } = require('../../mac/peer.js');
  const link = new Link({ macId: 'g1', macName: 'Guest' }, { canConnect: () => true, resolve: () => null });
  link.fx2Hello = () => true;
  link.fxPlainHello = () => ({ fxPlain: 1 });
  link.ilHello = () => ({ port: 4242 });
  try {
    link.start();
    await until(() => link.status.state === 'connected', 'mac: connected through the relay');
    assert.strictEqual(link.via, 'relay');
    const hello = host.hellos[0];
    assert.strictEqual(hello.relayed, true, 'mac: the host sees it came through its relay');
    for (const k of ['fx2', 'fxPlain', 'il']) assert.ok(!(k in hello), `mac: no ${k} through the relay`);
    assert.strictEqual(link.ctx.address, '192.0.2.10', 'mac: the session keeps the host’s own address (terminal, shared folders)');
    assert.strictEqual(link.ctx.via, 'relay');
    assert.ok(R.viaRelay(link.ctx));
    assert.ok(link.dial && link.dial.address === '127.0.0.1' && link.dial.port > 0);
    const saved = store.read('hosts.json', [])[0];
    assert.strictEqual(saved.address, '192.0.2.10', 'mac: the pipe never replaces the saved address');
    assert.deepStrictEqual(saved.relay, info);

    const peer = Object.create(Peer.prototype);
    Object.assign(peer, { server: { current: null }, link });
    link.ctx.fx = 'a'.repeat(32);
    link.ctx.fx2Port = 5555;
    link.ctx.fxPlainMsg = { port: 9999, token: 'x' };
    const fx = peer._fxSession();
    assert.deepStrictEqual([fx.address, fx.port, fx.fx2, fx.fx2Port, fx.plain], ['127.0.0.1', link.dial.port, false, 0, null], 'mac: fast files through the pipe only');

    // welcome {relay: null}: dropped from the host; absent: kept.
    const h = { id: 'x' };
    link._keepRelay(h, { relay: info });
    assert.deepStrictEqual(h.relay, info);
    link._keepRelay(h, {});
    assert.deepStrictEqual(h.relay, info, 'mac: an older host says nothing: kept');
    link._keepRelay(h, { relay: null });
    assert.ok(!('relay' in h), 'mac: null: none now');

    const ws = link.ws;
    link.disconnect();
    await until(() => ws.readyState === ws.CLOSED, 'mac: closed');
  } finally {
    link.stop();
    host.close();
  }
  {
    const fakeId = R.idOf('mac-impostor');
    const fake = await hostServer(fakeId, null, tls2);
    store.write('hosts.json', [{ id: 'h2', name: 'Host', os: P.OS.MAC, address: '192.0.2.11', port: 47800, fp: FP, token: 'tok', lastSeen: 1, relay: { addr: ADDR, key: KEY, id: fakeId } }]);
    const l2 = new Link({ macId: 'g2', macName: 'Guest' }, { canConnect: () => true, resolve: () => null });
    try {
      l2.start();
      await until(() => fake.sessions.length >= 1, 'mac: tried the relay');
      await new Promise((r) => setTimeout(r, 200));
      assert.notStrictEqual(l2.status.state, 'identity_changed', 'mac: a stranger on the relay doesn’t unpair anything');
      assert.strictEqual(fake.hellos.length, 0, 'mac: no hello (no token) to a certificate that isn’t the host’s');
      assert.strictEqual(l2.hosts.length, 1);
    } finally {
      l2.stop();
      fake.close();
    }
  }
  console.log('  mac: ok');
}

(async () => {
  const relay = spawn(process.execPath, [path.join(__dirname, '../../relay/twindesk-relay.js'), '--port', String(PORT), '--host', '127.0.0.1', '--key', KEY], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((r) => relay.stdout.once('data', r));
  try {
    await winLinux('windows');
    await winLinux('linux');
    await mac();
    console.log('relay-links: ok');
  } finally {
    relay.kill();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  process.exit(0); // the links' own timers (quiet-link checks) needn't run out
})().catch((e) => { console.error(e); process.exit(1); });
