'use strict';

// Preloaded into the daemon (master and workers) by test/daemon.test.js with
// --require, so the tests run without an Abusix API key, network access or a
// Redis server. Only the test suite loads this file.
//
// - DNS: the start-up API key check (127.0.0.2 in authbl) returns 127.0.0.4.
//   An address listed in STUB_LISTED_IP returns 127.0.0.2; everything else
//   is not listed.
// - Redis: an in-memory client with the calls the daemon makes. With
//   STUB_REDIS_ERROR set, every command fails (as with a Redis error reply).

const dns = require('node:dns');
const Module = require('node:module');

const listed = (process.env.STUB_LISTED_IP || '').split('.').reverse().join('.');

dns.promises.resolve4 = async (name) => {
    if (/^2\.0\.0\.127\.[^.]+\.authbl\.mail\.abusix\.zone\.$/.test(name)) return ['127.0.0.4'];
    if (listed && name.startsWith(`${listed}.`) && name.includes('.authbl.mail.abusix.zone.')) return ['127.0.0.2'];
    const err = new Error(`queryA ENOTFOUND ${name}`);
    err.code = dns.NOTFOUND;
    throw err;
};

const sets = new Map();
const redisError = async () => {
    if (process.env.STUB_REDIS_ERROR) throw new Error('WRONGTYPE Operation against a key holding the wrong kind of value');
};
const fakeRedis = {
    createClient: () => ({
        on: () => {},
        connect: async () => {},
        sAdd: async (key, member) => {
            await redisError();
            if (!sets.has(key)) sets.set(key, new Set());
            sets.get(key).add(member);
            return 1;
        },
        sIsMember: async (key, member) => {
            await redisError();
            return sets.has(key) && sets.get(key).has(member);
        },
    }),
};

const origLoad = Module._load;
Module._load = function (request, ...rest) {
    if (request === 'redis') return fakeRedis;
    return origLoad.call(this, request, ...rest);
};
