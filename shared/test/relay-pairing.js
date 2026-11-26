// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// Pairing with a TwinDesk ID through your own relay (shared/relay.js codeOf/pairTarget, Allow
// pairing through the relay), end to end: relay/twindesk-relay.js on this machine, the real host
// pairing (windows/linux hostpair.js, mac/pairing.js) behind a stand-in WSS server, and the real
// windows/, linux/ and mac/ link.js typing an ID.
//   - The ID: nine digits from the certificate, typed with spaces or dashes; an address isn't one.
//   - Off (the default): the host isn't on the relay under its ID, and a relayed pair.start is
//     refused before any code or prompt; on: the codes on both sides match and Allow pairs.
//   - The guest keeps no address for a host met through the relay, takes the session's relay from
//     its welcome, and comes back through it.
//   - Lockout: failures through the relay count apart from the network's.
// Run with: node shared/test/relay-pairing.js
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { spawn, execFileSync } = require('child_process');

process.env.NODE_PATH = ['mac', 'windows', 'linux'].map((a) => path.join(__dirname, '..', '..', a, 'node_modules')).join(path.delimiter);
require('module').Module._initPaths();
const { WebSocketServer } = require('ws');

// hostpair.js, pairing.js and mac/link.js require('./store'): in memory here.
for (const dir of ['windows', 'linux', 'mac']) {
  const p = require.resolve(path.join(__dirname, '..', '..', dir, 'store.js'));
  require.cache[p] = { exports: { read: (n, fb) => fb, write: () => {}, remove: () => {}, filePath: (n) => path.join(os.tmpdir(), `nope-${n}`) }, loaded: true, id: p, filename: p };
}

const P = require('../protocol.js');
const R = require('../relay.js');
const RP = require('../relaypipe.js');
const { PairFails, MAX } = require('../pairfail.js');

const T = P.T;
const PORT = 44000 + Math.floor(Math.random() * 900);
const KEY = 'pair-key';
const ADDR = `127.0.0.1:${PORT}`;
P.RECONNECT_MS = [40, 40, 40];

const until = async (cond, what, ms = 15000) => {
  const t = Date.now();
  while (!cond()) {
    if (Date.now() - t > ms) throw new Error(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
};

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-pairing-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=host',
  '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem')], { stdio: 'ignore' });
const tls = { key: fs.readFileSync(path.join(dir, 'key.pem')), cert: fs.readFileSync(path.join(dir, 'cert.pem')) };
const FP = P.normFingerprint(new crypto.X509Certificate(tls.cert).fingerprint256);

// ---- the pure parts ----
function pure() {
  const code = R.codeOf(FP);
  assert.match(code, /^\d{9}$/);
  assert.strictEqual(R.codeOf(FP), code, 'the same certificate, the same ID');
  assert.notStrictEqual(R.codeOf(FP + '0'), code);
  assert.strictEqual(R.codeOf('x').length, 9, 'small numbers are padded');
  assert.strictEqual(R.formatCode('012345678'), '012 345 678');
  for (const t of ['012 345 678', '012-345-678', ' 012345678 ', '012 345-678']) assert.strictEqual(R.parseCode(t), '012345678', t);
  for (const t of ['192.168.1.20', '12345678', '1234567890', 'abc', '', null, '012 345 67a', 'host:47800', '100.64.0.1']) assert.strictEqual(R.parseCode(t), null, String(t));
  assert.match(R.idOfCode(code), /^[0-9a-f]{32}$/);
  assert.notStrictEqual(R.idOfCode(code), R.idOf(FP), 'pairing waits under an id of its own, not the session’s');

  assert.deepStrictEqual(R.clean({ addr: 'r.example.com', key: 'k', pair: true }), { addr: 'r.example.com', key: 'k', pair: true });
  assert.strictEqual(R.clean({ addr: 'r.example.com' }).pair, false, 'off by default');
  assert.strictEqual(R.clean({ addr: 'r.example.com', pair: 'yes' }).pair, false, 'only true is on');
  assert.strictEqual(R.clean({ addr: '', pair: true }).pair, false, 'never without an address');

  const relay = { addr: 'r.example.com:47100', key: 'k' };
  assert.strictEqual(R.pairTarget('192.168.1.20', relay, FP), null, 'an address goes on as before');
  assert.strictEqual(R.pairTarget('', relay, FP), null);
  assert.match(R.pairTarget(R.formatCode(code), relay, FP).failed, /own TwinDesk ID/, 'this computer’s own ID');
  assert.match(R.pairTarget('111 222 333', { addr: '' }, FP).failed, /add the same relay/, 'no relay here');
  assert.match(R.pairTarget('111 222 333', undefined, FP).failed, /add the same relay/);
  const ok = R.pairTarget('111-222-333', relay, FP);
  assert.deepStrictEqual(ok, { name: 'ID 111 222 333', code: '111222333', relay: { addr: 'r.example.com:47100', key: 'k', id: R.idOfCode('111222333') } });

  // Lockout buckets: the relay's own, apart from this network's (and 127.0.0.1 isn't exempt there).
  const lan = { address: '192.168.1.50', ws: {} };
  const viaRelay = { address: '203.0.113.9', ws: { relayed: true } };
  const local = { address: '127.0.0.1', ws: { relayed: true } };
  assert.strictEqual(PairFails.who(lan), '192.168.1.50');
  assert.strictEqual(PairFails.who(viaRelay), 'relay:203.0.113.9');
  assert.strictEqual(PairFails.who(null), '');
  const fails = new PairFails();
  for (let i = 0; i < MAX; i++) { fails.fail(PairFails.who(viaRelay)); fails.fail(PairFails.who(local)); }
  assert.ok(fails.locked(PairFails.who(viaRelay)) && fails.locked(PairFails.who(local)), 'too many through the relay: locked there (a relay on this machine too)');
  assert.ok(!fails.locked(PairFails.who(lan)) && !fails.locked('203.0.113.9'), 'this network isn’t');
}

// ---- a stand-in host: a WSS server whose sockets go to the real host pairing ----
async function standInHost(impl, identity) {
  const server = https.createServer(tls);
  const wss = new WebSocketServer({ server });
  const fake = new EventEmitter();
  Object.assign(fake, {
    current: null, phoneGrace: null, failures: [],
    phoneHolds: () => false, endPhoneGrace() {}, closeDevice() {},
    send: (ctx, m) => ctx.ws.readyState === 1 && ctx.ws.send(JSON.stringify(m)),
    fail(ctx, code, message) {
      fake.failures.push({ code, message, relayed: ctx.ws.relayed });
      if (ctx.ws.readyState === 1) ctx.ws.send(JSON.stringify({ t: T.ERROR, code, message }));
      ctx.ws.close();
    },
    authenticate(ctx, who, welcome) {
      Object.assign(ctx, who, { authed: true });
      fake.current = ctx;
      ctx.ws.send(JSON.stringify(welcome));
    },
  });
  const pairing = new impl.Pairing(fake, identity);
  const host = { server, fake, pairing, hellos: [] };
  wss.on('connection', (ws, req) => {
    ws.relayed = R.isRelayed(req.socket);
    const ctx = { ws, address: (req.socket.remoteAddress || '').replace(/^::ffff:/, ''), authed: false };
    ws.on('message', (data) => {
      const m = JSON.parse(String(data));
      if (ctx.authed) return;
      if (m.t === T.HELLO) host.hellos.push({ ...m, relayed: ws.relayed });
      fake.emit('preauth', ctx, m);
    });
    ws.on('close', () => fake.emit('closed', ctx));
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  host.close = () => { for (const c of wss.clients) c.terminate(); wss.close(); server.close(); };
  return host;
}

// The host's General › Your own relay, as its app applies it.
async function hostRelay(host, pair) {
  R.apply({ server: { https: host.server }, fp: FP, relay: { addr: ADDR, key: KEY, pair } });
  await until(() => R.view().state === 'ready', 'the host on its relay');
  // Its ID registration: up once a join under it is taken.
  if (pair) {
    const t0 = Date.now();
    for (;;) {
      try { const s = await RP.join({ addr: ADDR, key: KEY, id: R.idOfCode(R.codeOf(FP)) }); s.destroy(); break; } catch (e) {
        if (Date.now() - t0 > 5000) throw e;
        await new Promise((r) => setTimeout(r, 50));
      }
    }
  }
}

const IMPLS = {
  windows: { host: () => require('../../windows/hostpair.js'), identity: { id: 'host-win', name: 'Host', fp: FP }, os: P.OS.WIN },
  linux: { host: () => require('../../linux/hostpair.js'), identity: { id: 'host-linux', name: 'Host', fp: FP }, os: P.OS.LINUX },
  mac: { host: () => require('../../mac/pairing.js'), identity: { macId: 'host-mac', macName: 'Host', fp: FP }, os: P.OS.MAC },
};

// A guest link of each app, typing the host's ID (pairTarget with its own relay setting).
function guest(platform) {
  const typed = R.pairTarget(R.formatCode(R.codeOf(FP)), { addr: ADDR, key: KEY }, 'guest-fp');
  if (platform === 'mac') {
    const { Link } = require('../../mac/link.js');
    const link = new Link({ macId: 'guest-mac', macName: 'Guest' }, { canConnect: () => true, resolve: () => null });
    return {
      link,
      pair: () => link.startPairing({ name: typed.name, relay: typed.relay }),
      phase: () => link.pairState && link.pairState.phase,
      error: () => link.pairState && link.pairState.error,
      code: () => link.pairState && link.pairState.code,
      saved: () => link.hosts[0],
      connected: () => link.status.state === 'connected',
      relayed: () => link.via === 'relay',
      cancel: () => link.cancelPair(),
      end: () => { link.disconnect(); link.stop(); },
    };
  }
  const Link = require(`../../${platform}/link.js`);
  let pairing = null;
  const link = new Link({ device: { id: `guest-${platform}`, name: 'Guest' }, store: { load: () => pairing, save: (p) => { pairing = JSON.parse(JSON.stringify(p)); }, clear: () => { pairing = null; } }, resolveAddress: () => null, blocked: () => false });
  return {
    link,
    pair: () => link.startPairing({ macName: typed.name, relay: typed.relay }),
    phase: () => link.pairState && link.pairState.phase,
    error: () => link.pairState && link.pairState.error,
    code: () => link.pairState && link.pairState.code,
    saved: () => pairing,
    connected: () => link.status.state === 'connected',
    relayed: () => link.transport === 'relay',
    cancel: () => link.cancelPair(),
    end: () => link.disconnect(),
  };
}

async function scenario(platform) {
  const impl = IMPLS[platform];
  const host = await standInHost(impl.host(), impl.identity);
  try {
    // Off (the default): not on the relay under its ID; the guest is told what to check.
    await hostRelay(host, false);
    assert.strictEqual(R.pairingAllowed(), false);
    assert.strictEqual(R.view().code, '', `${platform}: no ID shown while off`);
    const g0 = guest(platform);
    g0.pair();
    await until(() => g0.phase() === 'failed', `${platform}: refused while off`);
    assert.match(g0.error(), /No computer with that ID is on your relay/);
    assert.strictEqual(host.pairing.pending, null, `${platform}: nothing reached the host`);
    g0.cancel();

    // Off, but a pair.start comes through the session's own id (someone who knows the certificate):
    // refused before any code, nothing pending.
    const pipe = await RP.RelayPipe.open({ addr: ADDR, key: KEY, id: R.idOf(FP) });
    const WebSocket = require('ws');
    const ws = new WebSocket(`wss://127.0.0.1:${pipe.port}`, { rejectUnauthorized: false });
    const got = [];
    ws.on('message', (d) => got.push(JSON.parse(String(d))));
    ws.on('error', () => {});
    let open = false;
    ws.on('open', () => { open = true; });
    await until(() => open, `${platform}: a socket through the session’s relay id`);
    ws.send(JSON.stringify({ t: T.PAIR_START, v: P.PROTOCOL_VERSION, id: 'sneaky', name: 'Sneaky', os: P.OS.WIN, commit: P.commitOf(P.randomHex(16)) }));
    await until(() => got.some((m) => m.t === T.ERROR), `${platform}: an answer`);
    assert.strictEqual(got.find((m) => m.t === T.ERROR).code, P.E.PAIR_REFUSED);
    assert.ok(!got.some((m) => m.t === T.PAIR_NONCE), `${platform}: no nonce, so no code, while off`);
    assert.strictEqual(host.pairing.pending, null);
    assert.ok(host.fake.failures.some((f) => f.relayed && /off on this computer/.test(f.message)));
    ws.terminate();
    pipe.destroy();

    // On: the ID shows; the guest pairs; both codes match; Allow on the host.
    await hostRelay(host, true);
    assert.strictEqual(R.pairingAllowed(), true);
    assert.strictEqual(R.view().code, R.formatCode(R.codeOf(FP)), `${platform}: the ID shows`);
    const g = guest(platform);
    g.pair();
    await until(() => g.phase() === 'code' && host.pairing.pending && host.pairing.pending.code, `${platform}: codes on both sides`);
    assert.strictEqual(g.code(), host.pairing.pending.code, `${platform}: the same code on both`);
    assert.strictEqual(host.pairing.pendingView().relay, true, `${platform}: the host sees it came through its relay`);
    g.link.confirmCode();
    host.pairing.respond(true);
    await until(() => g.connected(), `${platform}: paired and connected through the relay`);
    assert.ok(g.relayed(), `${platform}: the session runs through the relay`);
    const saved = g.saved();
    assert.strictEqual(saved.address, '', `${platform}: no address kept for a host met through the relay`);
    assert.strictEqual(saved.fp, FP, `${platform}: its certificate pinned`);
    assert.deepStrictEqual(saved.relay, { addr: ADDR, key: KEY, id: R.idOf(FP) }, `${platform}: the session’s relay from its welcome, not the ID’s`);
    const hello = host.hellos.at(-1);
    assert.ok(hello.relayed && hello.token, `${platform}: hello with the new token, through the relay`);
    for (const k of ['fx2', 'fxPlain', 'il']) assert.ok(!(k in hello), `${platform}: no ${k}`);

    // Back later: through the relay (it has no address), even with pairing through it off again.
    g.end();
    await until(() => !g.connected(), `${platform}: disconnected`);
    await hostRelay(host, false);
    host.fake.current = null;
    g.link.connect(false);
    await until(() => g.connected(), `${platform}: back through the relay`);
    assert.ok(g.relayed());
    g.end();
  } finally {
    host.close();
  }
  console.log(`  ${platform}: ok`);
}

// The prompt on the host: one more pairing through the relay, the lockout in its own bucket.
async function lockout() {
  const impl = IMPLS.windows;
  const host = await standInHost(impl.host(), impl.identity);
  try {
    await hostRelay(host, true);
    const fails = host.pairing.fails;
    const relayCtx = { address: '127.0.0.1', ws: { relayed: true, close() {}, readyState: 3 } };
    for (let i = 0; i < MAX; i++) fails.fail(PairFails.who(relayCtx));
    const g = guest('windows');
    g.pair();
    await until(() => g.phase() === 'failed', 'locked through the relay');
    assert.match(host.fake.failures.at(-1).message, /Too many failed pairing attempts/);
    assert.ok(!fails.locked('127.0.0.1') && !fails.locked('192.168.1.50'), 'this network can still pair');
    g.cancel();
  } finally {
    host.close();
  }
  console.log('  lockout: ok');
}

(async () => {
  pure();
  const relay = spawn(process.execPath, [path.join(__dirname, '../../relay/twindesk-relay.js'), '--port', String(PORT), '--host', '127.0.0.1', '--key', KEY], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((r) => relay.stdout.once('data', r));
  try {
    for (const p of ['windows', 'linux', 'mac']) await scenario(p);
    await lockout();
    console.log('relay-pairing: ok');
  } finally {
    R.apply({ server: null, fp: '', relay: null });
    relay.kill();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
