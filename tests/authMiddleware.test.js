const test = require('node:test');
const assert = require('node:assert');
const Module = require('module');

// Stub out jsonwebtoken so middleware can be required without dependencies
const originalRequire = Module.prototype.require;
Module.prototype.require = function (path) {
  if (path === 'jsonwebtoken') {
    return { verify: () => ({}), sign: () => '' };
  }
  return originalRequire.apply(this, arguments);
};

const { requireAdmin } = require('../middleware/authMiddleware');

Module.prototype.require = originalRequire;

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
    }
  };
}

test('requireAdmin allows admin users', () => {
  const req = { user: { role: 'admin' } };
  const res = createRes();
  let called = false;
  const next = () => { called = true; };
  requireAdmin(req, res, next);
  assert.strictEqual(res.statusCode, undefined);
  assert.ok(called);
});

test('requireAdmin rejects non-admin users', () => {
  const req = { user: { role: 'user' } };
  const res = createRes();
  const next = () => { throw new Error('next should not be called'); };
  requireAdmin(req, res, next);
  assert.strictEqual(res.statusCode, 403);
  assert.deepStrictEqual(res.body, { error: 'Krever admin-rolle' });
});
