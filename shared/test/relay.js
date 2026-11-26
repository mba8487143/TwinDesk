// TwinDesk — Copyright (C) 2026 inukaasith. GPL-3.0, see LICENSE.
// Your own relay: relay/twindesk-relay.js with shared/relay.js's RelayHost, end to end on this
// machine. A phone-like client joins, its bytes reach the "session server" and the answer comes
// back; a wrong key and an absent computer are refused. What a client says first decides where it
// goes on the computer (TLS, 0x16, to the session's server; STUN to TURN): these start with 0x16.
// Run with: node shared/test/relay.js
'use strict';

const assert = require('assert');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');
const R = require('../relay.js');

const PORT = 47000 + Math.floor(Math.random() * 900);
const KEY = 'test-key-123';

function client(id, key, send) {
  return new Promise((resolve) => {
    const s = net.connect({ host: '127.0.0.1', port: PORT });
    let got = '';
    s.on('connect', () => s.write(`TDR1 join ${id} ${key}\n`));
    s.on('data', (d) => {
      got += d.toString();
      if (got.startsWith('ok\n') && send) { const x = send; send = null; s.write(`\x16${x}`); } // as a TLS record starts
      if (/echo:|^no\n|^key\n/.test(got)) { s.destroy(); resolve(got.replace(/\x16/g, '')); }
    });
    s.on('close', () => resolve(got));
    s.on('error', () => resolve(got));
  });
}

(async () => {
  const relay = spawn(process.execPath, [path.join(__dirname, '../../relay/twindesk-relay.js'), '--port', String(PORT), '--host', '127.0.0.1', '--key', KEY], { stdio: ['ignore', 'pipe', 'inherit'] });
  await new Promise((r) => relay.stdout.once('data', r));
  try {
    assert.deepStrictEqual(R.parseAddr('relay.example.com'), { host: 'relay.example.com', port: 47100 });
    assert.deepStrictEqual(R.parseAddr('[::1]:5000'), { host: '::1', port: 5000 });
    assert.strictEqual(R.parseAddr('http://x'), null);
    const id = R.idOf('AB:CD');
    assert.match(id, /^[0-9a-f]{32}$/);

    // No computer yet: refused.
    assert.strictEqual(await client(id, KEY), 'no\n');

    // The relay hands its connections over paused (a TLS server takes them from there): this echo resumes.
    const stub = net.createServer((s) => { s.on('data', (d) => s.write(`echo:${d}`)); s.resume(); });
    const host = new R.RelayHost({ server: { https: stub }, addr: `127.0.0.1:${PORT}`, key: KEY, id });
    const ready = new Promise((r) => host.on('state', (v) => v.state === 'ready' && r()));
    host.start();
    await ready;

    assert.strictEqual(await client(id, KEY, 'hello'), 'ok\necho:hello');
    assert.strictEqual(await client(id, 'wrong', 'x'), 'key\n');
    // Two at once, each to its own.
    const [a, b] = await Promise.all([client(id, KEY, 'one'), client(id, KEY, 'two')]);
    assert.deepStrictEqual([a, b], ['ok\necho:one', 'ok\necho:two']);

    // A computer with the wrong key never gets ready.
    const bad = new R.RelayHost({ server: { https: stub }, addr: `127.0.0.1:${PORT}`, key: 'nope', id: R.idOf('x') });
    const failed = new Promise((r) => bad.on('state', (v) => v.state === 'failed' && r(v.error)));
    bad.start();
    assert.strictEqual(await failed, 'The relay’s key is wrong');
    bad.stop();

    host.stop();
    stub.close();

    // A joiner that was taken, then closes, must not drop one that's waiting now (it once removed
    // the id's whole waiting list, so the computer's take of the new one got "no").
    {
      const rid = R.idOf('waiting-list');
      const rawLine = (sock) => new Promise((resolve) => { let b = ''; const on = (d) => { b += d; const i = b.indexOf('\n'); if (i >= 0) { sock.removeListener('data', on); resolve(b.slice(0, i)); } }; sock.on('data', on); });
      const dial = () => new Promise((resolve) => { const sck = net.connect({ host: '127.0.0.1', port: PORT }, () => resolve(sck)); sck.on('error', () => {}); });
      const ctl = await dial();
      ctl.write(`TDR1 host ${rid} ${KEY}\n`);
      assert.strictEqual(await rawLine(ctl), 'ok');
      const calls = [];
      ctl.on('data', (d) => String(d).split('\n').forEach((l) => { const m = /^call (\d+)$/.exec(l.trim()); if (m) calls.push(m[1]); }));
      const take = async (n) => { const t = await dial(); t.write(`TDR1 take ${rid} ${n} ${KEY}\n`); return { t, line: await rawLine(t) }; };
      const j1 = await dial();
      j1.write(`TDR1 join ${rid} ${KEY}\n`);
      await new Promise((r) => { const w = () => (calls.length >= 1 ? r() : setTimeout(w, 5)); w(); });
      const t1 = await take(calls[0]);
      assert.strictEqual(t1.line, 'ok');
      const j2 = await dial();
      j2.write(`TDR1 join ${rid} ${KEY}\n`);
      await new Promise((r) => { const w = () => (calls.length >= 2 ? r() : setTimeout(w, 5)); w(); });
      j1.destroy(); // the first one ends while the second waits
      t1.t.destroy();
      await new Promise((r) => setTimeout(r, 100));
      const t2 = await take(calls[1]);
      assert.strictEqual(t2.line, 'ok', 'the second joiner is still there to take');
      for (const x of [ctl, j2, t2.t]) x.destroy();
    }
    console.log('relay: ok');
  } finally {
    relay.kill();
  }
})().catch((e) => { console.error(e); process.exit(1); });
