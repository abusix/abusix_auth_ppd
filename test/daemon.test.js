'use strict';

// Starts the daemon as a child process against a temporary
// abusix_auth_ppd.ini and talks to it like Postfix does. The daemon reads its
// configuration from its own directory, so it is copied into a temporary
// directory next to the config. DNS and Redis are stubbed by test/stubs.js.

const test = require('node:test');
const assert = require('node:assert');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');

function freePort() {
    return new Promise((resolve, reject) => {
        const s = net.createServer();
        s.once('error', reject);
        s.listen(0, '127.0.0.1', () => {
            const { port } = s.address();
            s.close(() => resolve(port));
        });
    });
}

function canConnect(port) {
    return new Promise((resolve) => {
        const c = net.connect(port, '127.0.0.1');
        c.once('connect', () => { c.destroy(); resolve(true); });
        c.once('error', () => resolve(false));
    });
}

async function startDaemon(t, { config = [], env = {} } = {}) {
    const port = await freePort();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'abusix_auth_ppd-test-'));
    fs.copyFileSync(path.join(ROOT, 'abusix_auth_ppd.js'), path.join(dir, 'abusix_auth_ppd.js'));
    fs.symlinkSync(path.join(ROOT, 'node_modules'), path.join(dir, 'node_modules'), 'dir');
    fs.writeFileSync(path.join(dir, 'abusix_auth_ppd.ini'), [
        `listen_port=${port}`,
        'apikey=testkey',
        ...config,
    ].join('\n') + '\n');

    const child = spawn(process.execPath,
        ['--require', path.join(__dirname, 'stubs.js'), path.join(dir, 'abusix_auth_ppd.js')], {
        env: { ...process.env, DEBUG: '', ...env },
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', (d) => { output += d; });
    child.stderr.on('data', (d) => { output += d; });

    t.after(() => {
        child.kill('SIGKILL');
        fs.rmSync(dir, { recursive: true, force: true });
    });

    // Wait until the policy port accepts connections
    const deadline = Date.now() + 10000;
    while (!(await canConnect(port))) {
        if (Date.now() > deadline) throw new Error(`daemon did not start:\n${output}`);
        await new Promise((r) => setTimeout(r, 50));
    }
    // Give the master a moment to log the listening address
    await new Promise((r) => setTimeout(r, 100));

    return { port, output: () => output };
}

// Sends policy requests one after the other on a single connection, like
// Postfix does, and resolves with the daemon's replies
function policyRequests(port, requests) {
    return new Promise((resolve, reject) => {
        const c = net.connect(port, '127.0.0.1');
        const replies = [];
        let buf = '';
        const send = () => replies.length < requests.length && c.write(Object.entries(requests[replies.length]).map(([k, v]) => `${k}=${v}\n`).join('') + '\n');
        c.setEncoding('ascii');
        c.on('error', reject);
        c.on('data', (d) => {
            buf += d;
            let end;
            while ((end = buf.indexOf('\n\n')) !== -1) {
                replies.push(buf.slice(0, end + 2));
                buf = buf.slice(end + 2);
                if (replies.length === requests.length) {
                    c.end();
                    return resolve(replies);
                }
                send();
            }
        });
        send();
        setTimeout(() => { c.destroy(); reject(new Error(`no reply, got: ${JSON.stringify(replies.concat(buf))}`)); }, 5000).unref();
    });
}

async function policyRequest(port, attrs) {
    return (await policyRequests(port, [attrs]))[0];
}

const AUTH_REQUEST = {
    request: 'smtpd_access_policy',
    protocol_state: 'RCPT',
    protocol_name: 'ESMTP',
    instance: 'a.1',
    client_address: '192.0.2.1',
    client_name: 'unknown',
    sasl_method: 'PLAIN',
    sasl_username: 'User@example.org',
    sender: 'user@example.org',
    recipient: 'someone@example.net',
};

async function assertNoWorkerDied(d) {
    // Give a crashing worker time to be reported by the master
    await new Promise((r) => setTimeout(r, 300));
    assert.doesNotMatch(d.output(), /died/);
}

test('listens on 127.0.0.1 by default', async (t) => {
    const d = await startDaemon(t);
    assert.match(d.output(), new RegExp(`listening on 127\\.0\\.0\\.1:${d.port}\\b`));
});

test('listen_host overrides the bind address', async (t) => {
    const d = await startDaemon(t, { config: ['listen_host=0.0.0.0'] });
    assert.match(d.output(), new RegExp(`listening on 0\\.0\\.0\\.0:${d.port}\\b`));
});

test('answers DUNNO for a non-authenticated request', async (t) => {
    const d = await startDaemon(t, { config: ['action=reject'] });
    const { sasl_method, sasl_username, ...attrs } = AUTH_REQUEST;
    assert.strictEqual(await policyRequest(d.port, attrs), 'action=DUNNO\n\n');
    await assertNoWorkerDied(d);
});

test('answers DUNNO for an authenticated client that is not listed', async (t) => {
    const d = await startDaemon(t, { config: ['action=reject'] });
    assert.strictEqual(await policyRequest(d.port, AUTH_REQUEST), 'action=DUNNO\n\n');
    await assertNoWorkerDied(d);
});

test('answers with the configured action for a listed client, then from the cache', async (t) => {
    const d = await startDaemon(t, { config: ['action=reject'], env: { STUB_LISTED_IP: '192.0.2.1' } });
    // The second request comes from an address that is not listed, but the
    // account is now cached. Both go over one connection, so they reach the
    // same worker and its stub cache.
    const replies = await policyRequests(d.port, [AUTH_REQUEST, { ...AUTH_REQUEST, client_address: '198.51.100.7' }]);
    assert.deepStrictEqual(replies, ['action=REJECT\n\n', 'action=REJECT\n\n']);
    assert.match(d.output(), /ip=192\.0\.2\.1 username=user@example\.org found new compromised account/);
    assert.match(d.output(), /ip=198\.51\.100\.7 username=user@example\.org found in cache database/);
    await assertNoWorkerDied(d);
});

test('answers DUNNO when no action is configured', async (t) => {
    const d = await startDaemon(t, { env: { STUB_LISTED_IP: '192.0.2.1' } });
    assert.strictEqual(await policyRequest(d.port, AUTH_REQUEST), 'action=DUNNO\n\n');
    await assertNoWorkerDied(d);
});

test('a request that fails to process is answered with DUNNO and does not crash the worker', async (t) => {
    const d = await startDaemon(t, { config: ['action=reject'], env: { STUB_REDIS_ERROR: '1' } });
    assert.strictEqual(await policyRequest(d.port, AUTH_REQUEST), 'action=DUNNO\n\n');
    assert.match(d.output(), /\[a\.1\] error processing request: WRONGTYPE/);
    await assertNoWorkerDied(d);
});

test('a malformed request is answered with DUNNO and does not crash the worker', async (t) => {
    const d = await startDaemon(t, { config: ['action=reject'] });
    // Authenticated, but without client_address or recipient
    const { client_address, recipient, ...attrs } = AUTH_REQUEST;
    assert.strictEqual(await policyRequest(d.port, attrs), 'action=DUNNO\n\n');
    await assertNoWorkerDied(d);
});

test('several requests on one connection each get a reply', async (t) => {
    const d = await startDaemon(t, { config: ['action=reject'], env: { STUB_LISTED_IP: '192.0.2.1' } });
    const replies = await policyRequests(d.port, [
        AUTH_REQUEST,
        // Not authenticated: must not inherit the previous request's SASL attributes
        { request: 'smtpd_access_policy', instance: 'b.1', client_address: '192.0.2.1' },
    ]);
    assert.deepStrictEqual(replies, ['action=REJECT\n\n', 'action=DUNNO\n\n']);
    await assertNoWorkerDied(d);
});

// A command script that writes the environment it was started with to a file
function envDumpCommand(t) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'abusix_auth_ppd-cmd-'));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const out = path.join(dir, 'env.txt');
    const script = path.join(dir, 'dump_env.sh');
    fs.writeFileSync(script, `#!/bin/sh\n/usr/bin/env > '${out}'\n`, { mode: 0o755 });
    return {
        config: `command=${script}`,
        // Resolves with the dumped environment as an object, or null if the
        // command did not run within the time limit
        read: async (ms = 2000) => {
            const deadline = Date.now() + ms;
            while (Date.now() < deadline) {
                if (fs.existsSync(out)) {
                    await new Promise((r) => setTimeout(r, 50));
                    return Object.fromEntries(fs.readFileSync(out, 'utf8').split('\n').filter(Boolean)
                        .map((l) => [l.slice(0, l.indexOf('=')), l.slice(l.indexOf('=') + 1)]));
                }
                await new Promise((r) => setTimeout(r, 50));
            }
            return null;
        },
    };
}

// Postfix forwards these inside a quoted local part of the envelope sender
// unchanged; only "\n" ends an attribute line in the policy protocol
for (const [name, sep] of Object.entries({
    'U+2028': ' ', 'U+2029': ' ', 'U+0085': '\u0085', 'vertical tab': '\v', 'form feed': '\f', 'carriage return': '\r',
})) {
    test(`a sender containing ${name} cannot add attributes to the request`, async (t) => {
        const cmd = envDumpCommand(t);
        const d = await startDaemon(t, { config: ['action=reject', cmd.config], env: { STUB_LISTED_IP: '192.0.2.1' } });
        const { sasl_method, sasl_username, ...attrs } = AUTH_REQUEST;
        const sender = `"x${sep}sasl_method=PLAIN${sep}sasl_username=victim@corp.example${sep}"@example.org`;
        assert.strictEqual(await policyRequest(d.port, { ...attrs, sender }), 'action=DUNNO\n\n');
        assert.strictEqual(await cmd.read(500), null, 'command must not run');
        assert.doesNotMatch(d.output(), /victim@corp\.example/);
        await assertNoWorkerDied(d);
    });
}

test('command gets only Postfix attributes and a fixed PATH', async (t) => {
    const cmd = envDumpCommand(t);
    const d = await startDaemon(t, { config: ['action=reject', cmd.config], env: { STUB_LISTED_IP: '192.0.2.1' } });
    const reply = await policyRequest(d.port, {
        ...AUTH_REQUEST,
        'BASH_FUNC_mail%%': '() { id; }',
        PATH: '/tmp/evil',
        LD_PRELOAD: '/tmp/evil.so',
        BASH_ENV: '/tmp/evil.sh',
    });
    assert.strictEqual(reply, 'action=REJECT\n\n');
    const env = await cmd.read();
    assert.ok(env, 'command must run');
    assert.strictEqual(env.sasl_username, 'user@example.org');
    assert.strictEqual(env.client_address, '192.0.2.1');
    assert.strictEqual(env.sender, 'user@example.org');
    assert.strictEqual(env.PATH, '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin');
    for (const name of ['BASH_FUNC_mail%%', 'LD_PRELOAD', 'BASH_ENV']) {
        assert.ok(!(name in env), `${name} must not reach the command`);
    }
    await assertNoWorkerDied(d);
});
