// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// A computer reaching another through that one's own relay (shared/relaypipe.js), end to end on this
// machine with relay/twindesk-relay.js and shared/relay.js's RelayHost: what a welcome's relay must
// look like, each way joining can fail, the pipe's port carrying the session and further connections,
// close() and destroy(), the first connection that nobody uses, the cap, a cancel while opening, and
// the host's server telling relayed connections from the rest (isRelayed). What a client says first
// decides where it goes on the host (TLS to the session's server, STUN to TURN): these start as TLS
// does, with 0x16, and the echo's answers are compared without it.
// Run with: node shared/test/relaypipe.js
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');
const https = require('https');
const { spawn, execFileSync } = require('child_process');
const R = require('../relay.js');
const RP = require('../relaypipe.js');

const PORT = 46000 + Math.floor(Math.random() * 900);
const KEY = 'pipe-key-123';
const ADDR = `127.0.0.1:${PORT}`;

const until = async (cond, what, ms = 5000) => {
  const t = Date.now();
  while (!cond()) {
    if (Date.now() - t > ms) throw new Error(`timed out: ${what}`);
    await new Promise((r) => setTimeout(r, 5));
  }
};
const rejects = async (p, code, what) => {
  try { await p; } catch (e) { assert.ok(e instanceof RP.RelayError, `${what}: a RelayError`); assert.strictEqual(e.code, code, what); return e; }
  assert.fail(`${what}: should have failed`);
};

// A client of the pipe's port: sends `send`, resolves what came back once `expect` matched (or closed).
function talk(port, send, expect = /echo:/) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port });
    let got = '';
    s.on('connect', () => s.write(`\x16${send}`));
    const clean = () => got.replace(/\x16/g, '');
    s.on('data', (d) => { got += d; if (expect.test(got)) { s.destroy(); resolve(clean()); } });
    s.on('close', () => resolve(clean()));
    s.on('error', () => resolve(clean()));
  });
}

// A server that holds every connection open without a word: the relay that never answers.
function silent() {
  const held = [];
  const s = net.createServer((c) => { held.push(c); c.on('error', () => {}); });
  return new Promise((r) => s.listen(0, '127.0.0.1', () => r({ port: s.address().port, close: () => { held.forEach((c) => c.destroy()); s.close(); } })));
}

(async () => {
  // ---- info(): what a host's welcome {relay} may hold ----
  const id = R.idOf('AA:BB:CC');
  assert.deepStrictEqual(RP.info({ addr: ' relay.example.com:5000 ', key: 'k e\ty', id }), { addr: 'relay.example.com:5000', key: 'key', id });
  assert.deepStrictEqual(RP.info({ addr: '[::1]', id }), { addr: '[::1]', key: '', id });
  for (const bad of [null, undefined, 'x', 7, {}, { addr: 'http://x', id }, { addr: 'a b', id }, { addr: 'x:70000', id }, { addr: 'x', id: 'ABC' }, { addr: 'x', id: id.toUpperCase() }, { addr: 'x', id: id + '0' }, { addr: '', id }]) {
    assert.strictEqual(RP.info(bad), null, `refused: ${JSON.stringify(bad)}`);
  }
  assert.ok(RP.same(null, null) && RP.same(RP.info({ addr: 'a', id }), RP.info({ addr: 'a', id })));
  assert.ok(!RP.same(RP.info({ addr: 'a', id }), null) && !RP.same(RP.info({ addr: 'a', id }), RP.info({ addr: 'a', key: 'k', id })));
  assert.strictEqual(RP.message(new RP.RelayError('absent'), 'Studio PC'), 'Studio PC isn’t on its relay');
  assert.strictEqual(RP.message(new RP.RelayError('absent')), '{Name} isn’t on its relay', 'Windows and Linux fill {Name} themselves');
  assert.strictEqual(RP.message(new Error('x')), RP.MESSAGES.unreachable);
  await rejects(RP.RelayPipe.open(null), 'bad', 'no relay');
  await rejects(RP.join({ addr: 'x', id: 'nope' }), 'bad', 'a join without a usable id');

  // ---- joining, each way it fails ----
  const closed = await new Promise((r) => { const s = net.createServer(); s.listen(0, '127.0.0.1', () => { const p = s.address().port; s.close(() => r(p)); }); });
  await rejects(RP.join({ addr: `127.0.0.1:${closed}`, id }), 'unreachable', 'nothing listening');
  const quiet = await silent();
  await rejects(RP.join({ addr: `127.0.0.1:${quiet.port}`, id }, { joinMs: 300 }), 'timeout', 'a relay that never answers');
  quiet.close();
  const junk = net.createServer((c) => c.end('HTTP/1.1 400 Bad Request\r\n\r\n'));
  await new Promise((r) => junk.listen(0, '127.0.0.1', r));
  await rejects(RP.join({ addr: `127.0.0.1:${junk.address().port}`, id }), 'bad', 'not a TwinDesk relay');
  junk.close();

  const relay = spawn(process.execPath, [path.join(__dirname, '../../relay/twindesk-relay.js'), '--port', String(PORT), '--host', '127.0.0.1', '--key', KEY], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((r) => relay.stdout.once('data', r));
  const hosts = [];
  try {
    const info = RP.info({ addr: ADDR, key: KEY, id });
    await rejects(RP.join(info), 'absent', 'the host isn’t on the relay');
    const t0 = Date.now();
    await rejects(RP.RelayPipe.open(info), 'absent', 'open() with the host away');
    assert.ok(Date.now() - t0 < 2000, 'an absent host is known at once, not after a timeout');

    // The "host": an echo server behind RelayHost (as the session's server would be).
    const accepted = [];
    // The relay hands its connections over paused (a TLS server takes them from there): this echo resumes.
    const echo = net.createServer((s) => { accepted.push(s); s.on('error', () => {}); s.on('data', (d) => s.write(`echo:${d}`)); s.resume(); });
    const host = new R.RelayHost({ server: { https: echo }, addr: ADDR, key: KEY, id });
    hosts.push(host);
    const ready = new Promise((r) => host.on('state', (v) => v.state === 'ready' && r()));
    host.start();
    await ready;

    await rejects(RP.join({ ...info, key: 'wrong' }), 'key', 'the relay’s key is wrong');
    await rejects(RP.RelayPipe.open({ ...info, key: 'wrong' }), 'key', 'open() with the wrong key');

    // ---- the pipe: the session first, then more connections, each to the host on its own ----
    const pipe = await RP.RelayPipe.open(info);
    assert.ok(pipe.port > 0 && pipe.first, 'a port, and the first connection kept for the session');
    assert.strictEqual(await talk(pipe.port, 'session'), 'echo:session');
    assert.strictEqual(pipe.first, null, 'the session used the first connection');
    const [a, b] = await Promise.all([talk(pipe.port, 'files-1'), talk(pipe.port, 'files-2')]);
    assert.deepStrictEqual([a, b], ['echo:files-1', 'echo:files-2'], 'more connections join the relay again');
    await until(() => pipe.live.size === 0, 'pairs gone once their ends closed');

    // close(): a connection open now goes on; new ones are refused.
    const held = net.connect({ host: '127.0.0.1', port: pipe.port });
    let heldGot = '';
    held.on('data', (d) => { heldGot += String(d).replace(/\x16/g, ''); });
    held.on('error', () => {});
    held.write('\x16before');
    await until(() => heldGot === 'echo:before', 'a connection through the pipe');
    pipe.close();
    held.write('after');
    await until(() => heldGot === 'echo:beforeecho:after', 'still going after close()');
    assert.strictEqual(await talk(pipe.port, 'late'), '', 'no new connection after close()');
    pipe.destroy();
    await new Promise((r) => (held.destroyed ? r() : held.once('close', r)));
    assert.strictEqual(pipe.live.size, 0, 'destroy() ends them all');

    // The first connection nobody uses goes after firstMs; the port still works (joins anew).
    const before = accepted.length;
    const idle = await RP.RelayPipe.open(info, { firstMs: 150 });
    await until(() => idle.first === null, 'the unused first connection dropped');
    assert.strictEqual(await talk(idle.port, 'later'), 'echo:later');
    assert.strictEqual(accepted.length - before, 1, 'only the new one reached the host: the dropped one never said a word, so it went nowhere');
    idle.destroy();

    // The cap: no more than maxLive local connections at once.
    const capped = await RP.RelayPipe.open(info, { maxLive: 2 });
    const socks = [];
    for (let i = 0; i < 2; i++) {
      const s = net.connect({ host: '127.0.0.1', port: capped.port });
      s.on('error', () => {});
      let got = '';
      s.on('data', (d) => { got += d; });
      s.write(`\x16c${i}`);
      socks.push({ s, got: () => got });
    }
    await until(() => socks.every((x) => x.got().startsWith('echo:')), 'two under the cap');
    assert.strictEqual(await talk(capped.port, 'third'), '', 'a third one is refused');
    capped.destroy();

    // Cancelled while opening: rejects 'closed', and leaves nothing behind.
    const cancel = new RP.RelayPipe(info);
    const opening = cancel._start();
    cancel.close();
    await rejects(opening, 'closed', 'closed while joining');
    assert.strictEqual(cancel.server, null);

    // ---- the host's side: a relayed connection is marked, a direct one isn't ----
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'relaypipe-'));
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=test',
      '-keyout', path.join(dir, 'key.pem'), '-out', path.join(dir, 'cert.pem')], { stdio: 'ignore' });
    const seen = [];
    const tlsServer = https.createServer({ key: fs.readFileSync(path.join(dir, 'key.pem')), cert: fs.readFileSync(path.join(dir, 'cert.pem')) }, (req, res) => {
      seen.push(R.isRelayed(req.socket));
      res.end('ok');
    });
    await new Promise((r) => tlsServer.listen(0, '127.0.0.1', r));
    const id2 = R.idOf('TLS');
    const host2 = new R.RelayHost({ server: { https: tlsServer }, addr: ADDR, key: KEY, id: id2 });
    hosts.push(host2);
    const ready2 = new Promise((r) => host2.on('state', (v) => v.state === 'ready' && r()));
    host2.start();
    await ready2;
    const get = (port) => new Promise((resolve, reject) => https.get({ host: '127.0.0.1', port, rejectUnauthorized: false, agent: false }, (res) => { res.resume(); res.on('end', resolve); }).on('error', reject));
    const pipe2 = await RP.RelayPipe.open({ addr: ADDR, key: KEY, id: id2 });
    await get(pipe2.port);
    await get(tlsServer.address().port);
    assert.deepStrictEqual(seen, [true, false], 'through the relay: marked; straight to the server: not');
    assert.strictEqual(R.viaRelay({ ws: { relayed: true } }), true);
    assert.strictEqual(R.viaRelay({ via: 'relay' }), true);
    assert.strictEqual(R.viaRelay({ ws: { relayed: false }, via: 'ip' }), false);
    assert.strictEqual(R.viaRelay(null), false);
    pipe2.destroy();
    tlsServer.close();
    fs.rmSync(dir, { recursive: true, force: true });

    echo.close();
    console.log('relaypipe: ok');
  } finally {
    for (const h of hosts) h.stop();
    relay.kill();
  }
})().catch((e) => { console.error(e); process.exit(1); });
