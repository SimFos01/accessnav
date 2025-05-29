const test = require('node:test');
const assert = require('node:assert');
const Module = require('module');

function createRes() {
  return {
    statusCode: undefined,
    body: undefined,
    status(code) {
      this.statusCode = code;
      return {
        json: payload => {
          this.body = payload;
        }
      };
    },
    json(payload) {
      this.body = payload;
    }
  };
}

const originalRequire = Module.prototype.require;

function withStubs(stubs, fn) {
  Module.prototype.require = function (path) {
    if (path in stubs) return stubs[path];
    return originalRequire.apply(this, arguments);
  };
  const toClear = ['../controllers/userController'];
  for (const m of toClear) {
    delete require.cache[require.resolve(m)];
  }
  try {
    return fn();
  } finally {
    Module.prototype.require = originalRequire;
  }
}

// Test successful login

test('loginUser returns token on valid credentials', async () => {
  await withStubs({
    '../config/db': { query: async () => [{ id: 1, email: 'e', password: 'h', role: 'user' }] },
    'bcryptjs': { compare: async () => true },
    'jsonwebtoken': { sign: () => 'signed' }
  }, async () => {
    const { loginUser } = require('../controllers/userController');
    const req = { body: { email: 'e', password: 'p' } };
    const res = createRes();
    await loginUser(req, res);
    assert.deepStrictEqual(res.body, { token: 'signed' });
    assert.strictEqual(res.statusCode, undefined);
  });
});

// Test invalid password

test('loginUser rejects invalid password', async () => {
  await withStubs({
    '../config/db': { query: async () => [{ id: 1, email: 'e', password: 'h', role: 'user' }] },
    'bcryptjs': { compare: async () => false },
    'jsonwebtoken': { sign: () => 'signed' }
  }, async () => {
    const { loginUser } = require('../controllers/userController');
    const req = { body: { email: 'e', password: 'wrong' } };
    const res = createRes();
    await loginUser(req, res);
    assert.strictEqual(res.statusCode, 401);
    assert.deepStrictEqual(res.body, { error: 'Ugyldig e-post eller passord' });
  });
});
