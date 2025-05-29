const test = require('node:test');
const assert = require('node:assert');
const Module = require('module');

function createRes() {
  return {
    statusCode: undefined,
    body: undefined,
    status(code) {
      this.statusCode = code;
      return { json: payload => { this.body = payload; } };
    },
    json(payload) { this.body = payload; }
  };
}

const originalRequire = Module.prototype.require;

function withStubs(stubs, fn) {
  Module.prototype.require = function(path) {
    if (path in stubs) return stubs[path];
    return originalRequire.apply(this, arguments);
  };
  delete require.cache[require.resolve('../controllers/lockController')];
  try { return fn(); } finally { Module.prototype.require = originalRequire; }
}

test('openLock denies access when hasAccessToLock is false', async () => {
  await withStubs({
    '../utils/accessControl': {
      hasAccessToLock: async () => false,
      logAccess: async () => {}
    },
    '../config/db': { query: async () => [] },
    '../adapters/raspberryAdapter': {},
    '../adapters/aviorAdapter': {}
  }, async () => {
    const { openLock } = require('../controllers/lockController');
    const req = { params: { id: 1 }, user: { id: 10 } };
    const res = createRes();
    await openLock(req, res);
    assert.strictEqual(res.statusCode, 403);
    assert.deepStrictEqual(res.body, { error: 'Ingen tilgang til denne låsen' });
  });
});

test('lockLock denies access when hasAccessToLock is false', async () => {
  await withStubs({
    '../utils/accessControl': {
      hasAccessToLock: async () => false,
      logAccess: async () => {}
    },
    '../config/db': { query: async () => [] },
    '../adapters/raspberryAdapter': {},
    '../adapters/aviorAdapter': {}
  }, async () => {
    const { lockLock } = require('../controllers/lockController');
    const req = { params: { id: 1 }, user: { id: 10 } };
    const res = createRes();
    await lockLock(req, res);
    assert.strictEqual(res.statusCode, 403);
    assert.deepStrictEqual(res.body, { error: 'Ingen tilgang til denne låsen' });
  });
});

test('getUsersForLock returns deduplicated users', async () => {
  await withStubs({
    '../config/db': { query: async () => [[
      { id: 1, email: 'owner@example.com', role: 'eier' },
      { id: 2, email: 'admin@example.com', role: 'admin' },
      { id: 2, email: 'admin@example.com', role: 'bruker' },
      { id: 3, email: 'user@example.com', role: 'bruker' }
    ]] },
    '../adapters/raspberryAdapter': {},
    '../adapters/aviorAdapter': {}
  }, async () => {
    const { getUsersForLock } = require('../controllers/lockController');
    const req = { params: { id: 5 }, user: { id: 99, role: 'admin' } };
    const res = createRes();
    await getUsersForLock(req, res);
    assert.strictEqual(res.statusCode, undefined);
    assert.deepStrictEqual(res.body, [
      { id: 1, email: 'owner@example.com', role: 'eier' },
      { id: 2, email: 'admin@example.com', role: 'admin' },
      { id: 3, email: 'user@example.com', role: 'bruker' }
    ]);
  });
});
