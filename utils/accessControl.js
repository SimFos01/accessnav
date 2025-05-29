const db = require('../config/db');

exports.hasAccessToLock = async (userId, lockId) => {
  try {
    // 1. Direkte eierskap
    const ownerRows = await db.query(
      `SELECT id FROM locks WHERE id = ? AND owner_id = ?`,
      [lockId, userId]
    );
    if (ownerRows.length > 0) return true;

    // 2. Indirekte tilgang via gruppe
    const groupRows = await db.query(`
      SELECT gm.id FROM group_members gm
      JOIN group_locks gl ON gm.group_id = gl.group_id
      WHERE gm.user_id = ? AND gl.lock_id = ?
    `, [userId, lockId]);

    return groupRows.length > 0;
  } catch (err) {
    console.error('🔴 Feil i hasAccessToLock:', err);
    return false;
  }
};

exports.logAccess = async (userId, lockId, action, success) => {
  await db.query(
    'INSERT INTO access_logs (user_id, lock_id, action, success) VALUES (?, ?, ?, ?)',
    [userId, lockId, action, success]
  );
};
