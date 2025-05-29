const test = require('node:test');
const assert = require('node:assert');

const Module = require('module');

const originalRequire = Module.prototype.require;
function withStubs(stubs, fn) {
  Module.prototype.require = function(path) {
    if (path in stubs) return stubs[path];
    return originalRequire.apply(this, arguments);
  };
  for (const mod of [
    '../controllers/userController',
    '../controllers/lockController',
    '../routes/userRoutes',
    '../routes/lockRoutes'
  ]) {
    delete require.cache[require.resolve(mod)];
  }
  try { return fn(); } finally { Module.prototype.require = originalRequire; }
}

function findRoute(router, path, method) {
  return router.stack.find(l => l.route && l.route.path === path && l.route.methods[method]);
}

test('userRoutes exposes POST /login', () => {
  withStubs({
    '../adapters/raspberryAdapter': {},
    '../adapters/aviorAdapter': {}
  }, () => {
    const userRoutes = require('../routes/userRoutes');
    const userController = require('../controllers/userController');
    const layer = findRoute(userRoutes, '/login', 'post');
    assert.ok(layer);
    assert.strictEqual(layer.route.stack[0].handle, userController.loginUser);
  });
});

test('lockRoutes exposes POST /:id/open', () => {
  withStubs({
    '../adapters/raspberryAdapter': {},
    '../adapters/aviorAdapter': {}
  }, () => {
    const lockRoutes = require('../routes/lockRoutes');
    const lockController = require('../controllers/lockController');
    const layer = findRoute(lockRoutes, '/:id/open', 'post');
    assert.ok(layer);
    const handlers = layer.route.stack.map(s => s.handle);
    assert.ok(handlers.includes(lockController.openLock));
  });
});

test('lockRoutes exposes POST /:id/lock', () => {
  withStubs({
    '../adapters/raspberryAdapter': {},
    '../adapters/aviorAdapter': {}
  }, () => {
    const lockRoutes = require('../routes/lockRoutes');
    const lockController = require('../controllers/lockController');
    const layer = findRoute(lockRoutes, '/:id/lock', 'post');
    assert.ok(layer);
    const handlers = layer.route.stack.map(s => s.handle);
    assert.ok(handlers.includes(lockController.lockLock));
  });
});

test('lockRoutes exposes GET /:id/users', () => {
  withStubs({
    '../adapters/raspberryAdapter': {},
    '../adapters/aviorAdapter': {}
  }, () => {
    const lockRoutes = require('../routes/lockRoutes');
    const lockController = require('../controllers/lockController');
    const layer = findRoute(lockRoutes, '/:id/users', 'get');
    assert.ok(layer);
    const handlers = layer.route.stack.map(s => s.handle);
    assert.ok(handlers.includes(lockController.getUsersForLock));
  });
});
