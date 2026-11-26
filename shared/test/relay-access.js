// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// Attended and unattended access through your own relay (shared/relayaccess.js):
//   - The rules: only a computer through the relay is asked (not one on the network, not a phone,
//     not one Always allowed); Allow lasts its session and a while after; Always allow is kept;
//     Deny and no answer let it go for good (released); one question at a time; Ask again.
//   - The real host pairing (Windows, Linux, Mac) holds such a hello until the answer.
//   - End to end through relay/twindesk-relay.js with the real Windows and Mac links: the guest
//     waits past its usual hello limit (hello.wait), connects on Allow, stops on Deny, and an Always
//     allowed one comes back without a question.
// Run with: node shared/test/relay-access.js
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { spawn, execFileSync } = require('child_process');

process.env.NODE_PATH = ['mac', 'windows', 'linux'].map((a) => path.join(__dirname, '..', '..', a, 'node_modules')).join(path.delimiter);
require('module').Module._initPaths();
const { WebSocketServer } = require('ws');

for (const dir of ['windows', 'linux', 'mac']) {
  const p = require.resolve(path.join(__dirname, '..', '..', dir, 'store.js'));
  require.cache[p] = { exports: { read: (n, fb) => fb, write: () => {}, remove: () => {}, filePath: (n) => path.join(os.tmpdir(), `nope-${n}`) }, loaded: true, id: p, filename: p };
}

const P = require('../protocol.js');
const R = require('../relay.js');
const RP = require('../relaypipe.js');
const { RelayAccess } = require('../relayaccess.js');

const T = P.T;
P.RECONNECT_MS = [40, 40, 40];
const until = async (cond, what, ms = 15000) => {
  const t = Date.now();
  while (!cond()) {
    if (Date.now() - t > ms) throw new Error(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 10));
  }
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- the rules ----
async function rules() {
  const sent = [];
  const failed = [];
  const server = { send: (ctx, m) => sent.push({ ctx, m }), fail: (ctx, code, message) => failed.push({ ctx, code, message }) };
  let saves = 0;
  let asked = 0;
  const acc = new RelayAccess({ server, save: () => saves++, asked: () => asked++, name: () => 'Studio', askMs: 200, onceMs: 150 });
  const open = () => ({ ws: { relayed: true, readyState: 1, OPEN: 1 } });
  const e = { id: 'pc1', name: 'Laptop', os: 'win' };
  let went = 0;
  const go = () => went++;

  assert.strictEqual(acc.ask({ ws: { relayed: false } }, e, false, go), true, 'on the network: never asked');
  assert.strictEqual(acc.ask(open(), e, true, go), true, 'a phone: never asked');
  assert.strictEqual(acc.ask(open(), { ...e, relayAccess: 'always' }, false, go), true, 'Always allowed: not asked');

  const c1 = open();
  assert.strictEqual(acc.ask(c1, e, false, go), false, 'through the relay: it waits');
  assert.deepStrictEqual(sent.at(-1).m, { t: T.HELLO_WAIT, ms: 200 }, 'told to wait');
  assert.strictEqual(asked, 1, 'the app brings its window up');
  assert.deepStrictEqual({ ...acc.view(), since: 0 }, { id: 'pc1', name: 'Laptop', os: 'win', since: 0 });
  const c2 = open(); // the same computer again (an older one that gave up waiting and retried)
  assert.strictEqual(acc.ask(c2, e, false, go), false);
  assert.strictEqual(sent.at(-1).ctx, c2, 'the newest socket waits');
  assert.strictEqual(asked, 1, 'not asked twice');
  assert.strictEqual(acc.ask(open(), { id: 'pc2', name: 'Other' }, false, go), false, 'another one meanwhile');
  assert.strictEqual(failed.at(-1).code, P.E.BUSY, '… is told this computer is busy asking');

  acc.respond('bogus');
  assert.ok(acc.view(), 'an unknown answer changes nothing');
  acc.respond('once');
  assert.strictEqual(went, 1, 'Allow: the hello goes on');
  assert.strictEqual(acc.view(), null);
  assert.strictEqual(acc.ask(open(), e, false, go), true, 'allowed while its session lasts');
  acc.closed({ deviceId: 'pc1' });
  assert.strictEqual(acc.ask(open(), e, false, go), true, '… and a little after it ends');
  await sleep(200);
  assert.strictEqual(acc.ask(open(), e, false, go), false, 'then it asks again');

  acc.respond('deny');
  assert.strictEqual(failed.at(-1).code, P.E.RELEASED, 'Deny: let go, it doesn’t come back by itself');
  assert.match(failed.at(-1).message, /Studio didn’t allow the connection/);

  assert.strictEqual(acc.ask(open(), e, false, go), false);
  await sleep(260);
  assert.strictEqual(acc.view(), null, 'nobody answered');
  assert.strictEqual(failed.at(-1).code, P.E.RELEASED);
  assert.match(failed.at(-1).message, /Nobody allowed it on Studio/);

  const c3 = open();
  assert.strictEqual(acc.ask(c3, e, false, go), false);
  c3.ws.readyState = 3; // its socket went meanwhile
  acc.respond('once');
  assert.strictEqual(went, 1, 'a socket that went isn’t taken on');

  assert.strictEqual(acc.ask(open(), e, false, go), true, 'that Allow still counts for its retry');
  acc.once.clear();
  assert.strictEqual(acc.ask(open(), e, false, go), false);
  acc.respond('always');
  assert.strictEqual(e.relayAccess, 'always');
  assert.strictEqual(saves, 1, 'Always allow is kept');
  assert.strictEqual(went, 2);
  acc.once.clear();
  assert.strictEqual(acc.ask(open(), e, false, go), true, 'from then on: unattended');
  acc.revoke(e);
  assert.ok(!('relayAccess' in e) && saves === 2, 'Ask again');
  assert.strictEqual(acc.ask(open(), e, false, go), false, 'asked again');
  acc.revoke(e);
  assert.strictEqual(acc.view(), null, 'revoked while asking: the question goes (denied)');
  assert.strictEqual(failed.at(-1).code, P.E.RELEASED);
  acc.revoke(undefined);
}

// ---- the real host pairing holds the hello ----
async function hosts() {
  const impls = {
    windows: { m: require('../../windows/hostpair.js'), id: { id: 'h', name: 'Host', fp: 'x' } },
    linux: { m: require('../../linux/hostpair.js'), id: { id: 'h', name: 'Host', fp: 'x' } },
    mac: { m: require('../../mac/pairing.js'), id: { macId: 'h', macName: 'Host', fp: 'x' } },
  };
  for (const [name, { m, id }] of Object.entries(impls)) {
    const fake = new EventEmitter();
    const sent = [];
    const authed = [];
    Object.assign(fake, { current: null, phoneGrace: null, phoneHolds: () => false, endPhoneGrace() {}, closeDevice() {},
      send: (ctx, x) => sent.push(x), fail: (ctx, code) => sent.push({ t: T.ERROR, code }),
      authenticate: (ctx, who) => { ctx.authed = true; authed.push(who.deviceId); fake.current = ctx; } });
    const pairing = new m.Pairing(fake, id);
    const token = P.randomHex(32);
    pairing.paired.push({ id: 'pc', name: 'Laptop', os: P.OS.WIN, tokenHash: P.sha256Hex(token) });
    let requests = 0;
    pairing.on('request', () => requests++);
    const ctx = { ws: { relayed: true, readyState: 1, OPEN: 1, close() {} }, address: '203.0.113.1' };
    pairing._onMessage(ctx, { t: T.HELLO, v: P.PROTOCOL_VERSION, id: 'pc', name: 'Laptop', os: P.OS.WIN, token });
    assert.deepStrictEqual(authed, [], `${name}: through the relay the hello waits`);
    assert.strictEqual(sent.at(-1).t, T.HELLO_WAIT, `${name}: hello.wait`);
    assert.strictEqual(requests, 1, `${name}: the window comes up`);
    assert.strictEqual(pairing.accessView().name, 'Laptop');
    pairing.respondAccess('always');
    assert.deepStrictEqual(authed, ['pc'], `${name}: Allow: welcomed`);
    assert.strictEqual(pairing.list()[0].always, true, `${name}: listed as Always allowed`);
    fake.current = null;
    const ctx2 = { ws: { relayed: true, readyState: 1, OPEN: 1, close() {} }, address: '203.0.113.1' };
    pairing._onMessage(ctx2, { t: T.HELLO, v: P.PROTOCOL_VERSION, id: 'pc', name: 'Laptop', os: P.OS.WIN, token });
    assert.deepStrictEqual(authed, ['pc', 'pc'], `${name}: Always allowed: straight in`);
    pairing.setAlways('pc', false);
    assert.strictEqual(pairing.list()[0].always, false, `${name}: Ask again`);
    // On the network: nothing asked.
    fake.current = null;
    pairing._onMessage({ ws: { relayed: false, readyState: 1, OPEN: 1, close() {} }, address: '192.168.1.5' }, { t: T.HELLO, v: P.PROTOCOL_VERSION, id: 'pc', name: 'Laptop', os: P.OS.WIN, token });
    assert.deepStrictEqual(authed, ['pc', 'pc', 'pc'], `${name}: on the network: as always`);
    // A bad token through the relay: refused before anything is asked.
    const before = requests;
    pairing._onMessage({ ws: { relayed: true, readyState: 1, OPEN: 1, close() {} }, address: '203.0.113.1' }, { t: T.HELLO, v: P.PROTOCOL_VERSION, id: 'pc', token: 'nope' });
    assert.strictEqual(sent.at(-1).code, P.E.BAD_TOKEN);
    assert.strictEqual(requests, before, `${name}: nobody is asked about a computer that isn't paired`);
    // Forgotten while asking: the question goes.
    fake.current = null;
    pairing._onMessage({ ws: { relayed: true, readyState: 1, OPEN: 1, close() {} }, address: '203.0.113.1' }, { t: T.HELLO, v: P.PROTOCOL_VERSION, id: 'pc', name: 'Laptop', os: P.OS.WIN, token });
    assert.ok(pairing.accessView());
    pairing.forget('pc');
    assert.strictEqual(pairing.accessView(), null, `${name}: forgotten: no question left`);
    clearTimeout(pairing.access.asking && pairing.access.asking.timer);
  }
}

// ---- end to end ----
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relay-access-'));
execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=host',
  '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem')], { stdio: 'ignore' });
const tls = { key: fs.readFileSync(path.join(dir, 'key.pem')), cert: fs.readFileSync(path.join(dir, 'cert.pem')) };
const FP = P.normFingerprint(new crypto.X509Certificate(tls.cert).fingerprint256);
const PORT = 42000 + Math.floor(Math.random() * 900);
const KEY = 'access-key';
const ADDR = `127.0.0.1:${PORT}`;

async function standIn(impl, identity) {
  const server = https.createServer(tls);
  const wss = new WebSocketServer({ server });
  const fake = new EventEmitter();
  Object.assign(fake, {
    current: null, phoneGrace: null, phoneHolds: () => false, endPhoneGrace() {}, closeDevice() {},
    send: (ctx, m) => ctx.ws.readyState === 1 && ctx.ws.send(JSON.stringify(m)),
    fail(ctx, code, message) { if (ctx.ws.readyState === 1) ctx.ws.send(JSON.stringify({ t: T.ERROR, code, message })); ctx.ws.close(); },
    authenticate(ctx, who, welcome) { Object.assign(ctx, who, { authed: true }); fake.current = ctx; ctx.ws.send(JSON.stringify(welcome)); },
  });
  const pairing = new impl.Pairing(fake, identity);
  wss.on('connection', (ws, req) => {
    ws.relayed = R.isRelayed(req.socket);
    const ctx = { ws, address: (req.socket.remoteAddress || '').replace(/^::ffff:/, ''), authed: false };
    ws.on('message', (data) => { if (!ctx.authed) fake.emit('preauth', ctx, JSON.parse(String(data))); });
    ws.on('close', () => { if (fake.current === ctx) fake.current = null; fake.emit('closed', ctx); });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  R.apply({ server: { https: server }, fp: FP, relay: { addr: ADDR, key: KEY } });
  await until(() => R.view().state === 'ready', 'on the relay');
  return { pairing, fake, close: () => { for (const c of wss.clients) c.terminate(); wss.close(); server.close(); } };
}

async function e2e(platform) {
  const hostImpl = platform === 'mac' ? require('../../mac/pairing.js') : require('../../windows/hostpair.js');
  const identity = platform === 'mac' ? { macId: 'host-mac', macName: 'Studio', fp: FP } : { id: 'host-pc', name: 'Studio', fp: FP };
  const host = await standIn(hostImpl, identity);
  const token = P.randomHex(32);
  const relay = { addr: ADDR, key: KEY, id: R.idOf(FP) };
  let link;
  let state;
  if (platform === 'mac') {
    require('../../mac/store'); // the stub
    const { Link } = require('../../mac/link.js');
    link = new Link({ macId: 'guest', macName: 'Laptop' }, { canConnect: () => true, resolve: () => null });
    link.hosts = [{ id: 'host-mac', name: 'Studio', os: P.OS.MAC, address: '', port: P.PORT, fp: FP, token, relay }];
    state = () => link.status;
  } else {
    const Link = require('../../windows/link.js');
    let pairing = { macId: 'host-pc', macName: 'Studio', os: P.OS.WIN, address: '', port: P.PORT, fp: FP, token, relay };
    link = new Link({ device: { id: 'guest', name: 'Laptop' }, store: { load: () => pairing, save: (p) => { pairing = p; }, clear() {} }, resolveAddress: () => null, blocked: () => false });
    state = () => link.status;
  }
  host.pairing.paired.push({ id: 'guest', name: 'Laptop', os: platform === 'mac' ? P.OS.MAC : P.OS.WIN, tokenHash: P.sha256Hex(token) });
  try {
    // Asked; the guest waits past its usual few seconds; Allow lets it in.
    link.connect(false);
    await until(() => host.pairing.accessView(), `${platform}: asked on the host`);
    await until(() => /Waiting for someone on/.test(state().message), `${platform}: the guest says it waits`);
    await sleep(P.HELLO_TIMEOUT_MS + 1500);
    assert.ok(host.pairing.accessView(), `${platform}: still the same question after the usual hello limit`);
    assert.notStrictEqual(state().state, 'connected');
    host.pairing.respondAccess('once');
    await until(() => state().state === 'connected', `${platform}: in on Allow`);
    link.disconnect();
    await until(() => !host.fake.current, `${platform}: gone`);

    // A while later (the Allow ran out): asked again; Deny: it stops and stays away.
    host.pairing.access.once.clear();
    link.connect(false);
    await until(() => host.pairing.accessView(), `${platform}: asked again`);
    host.pairing.respondAccess('deny');
    await until(() => state().state === 'stopped', `${platform}: stopped on Deny`);
    assert.match(state().message, /didn’t allow the connection/);
    await sleep(500);
    assert.strictEqual(host.pairing.accessView(), null, `${platform}: it doesn't come back by itself`);

    // Always allow: from then on it comes straight in.
    link.connect(false);
    await until(() => host.pairing.accessView(), `${platform}: asked once more`);
    host.pairing.respondAccess('always');
    await until(() => state().state === 'connected', `${platform}: in`);
    link.disconnect();
    await until(() => !host.fake.current, `${platform}: gone again`);
    host.pairing.access.once.clear();
    link.connect(false);
    await until(() => state().state === 'connected', `${platform}: Always allowed: straight in`);
    assert.strictEqual(host.pairing.accessView(), null, `${platform}: nobody was asked`);
    link.disconnect();
  } finally {
    if (link.stop) link.stop();
    host.close();
  }
  console.log(`  ${platform}: ok`);
}

(async () => {
  await rules();
  await hosts();
  const relay = spawn(process.execPath, [path.join(__dirname, '../../relay/twindesk-relay.js'), '--port', String(PORT), '--host', '127.0.0.1', '--key', KEY], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((r) => relay.stdout.once('data', r));
  try {
    await e2e('windows');
    await e2e('mac');
    console.log('relay-access: ok');
  } finally {
    R.apply({ server: null, fp: '', relay: null });
    relay.kill();
    fs.rmSync(dir, { recursive: true, force: true });
  }
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
