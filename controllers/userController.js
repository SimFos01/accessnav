const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/db');
const logger = require('../utils/logger');

exports.loginUser = async (req, res) => {
    const { email, password } = req.body;
    // Minimal logging of login attempts without sensitive data
    logger.info('[LOGIN] Attempt for email:', email);
  
    try {
      const result = await db.query("SELECT * FROM users WHERE email = ?", [email.trim()]);
      const user = Array.isArray(result) ? result[0] : result;
  
      // Only log that a user record was retrieved
      logger.debug('🔎 Bruker fra SELECT');
  
      if (!user) {
        return res.status(401).json({ error: 'Ugyldig e-post eller passord' });
      }
      logger.debug('🔐 Sammenligner passord...');
        const valid = await bcrypt.compare(password, user.password);
        logger.debug('🔐 bcrypt valid:', valid);
      if (!valid) {
        return res.status(401).json({ error: 'Ugyldig e-post eller passord' });
      }
  
      const token = jwt.sign(
        { id: user.id, email: user.email, role: user.role },
        process.env.JWT_SECRET,
        { expiresIn: '8h' }
      );
  
      res.json({ token });
    } catch (err) {
      console.error('[LOGIN FEIL]', err);
      res.status(500).json({ error: 'Innloggingsfeil' });
    }
};

exports.getSharedUsers = async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ error: 'Mangler token' });

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Ugyldig token' });
  }
  const userId = decoded.id;

  // Hent alle brukere du som admin har delt låser med (direkte deling)
  try {
    const query = `
      SELECT u.email, ul.role, COUNT(ul.lock_id) AS lock_count
      FROM user_locks ul
      JOIN locks l ON ul.lock_id = l.id
      JOIN users u ON ul.user_id = u.id
      WHERE l.owner_id = ?
      GROUP BY u.email, ul.role
    `;
    let rows = await db.query(query, [userId]);
    rows = Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0] : rows;
    res.json(Array.isArray(rows) ? rows : []);
  } catch (err) {
    console.error('🔥 Feil i getSharedUsers:', err);
    res.status(500).json({ error: 'Kunne ikke hente delte brukere' });
  }
};

exports.getUserAccessDetails = async (req, res) => {
  const myUserId = req.user.id; // Din bruker-ID (eier/admin)
  const targetUserId = Number(req.params.userId); // ID til mål-bruker

  try {
    // 1. Hent mål-brukers info
    let [userResult] = await db.query(
      `SELECT id, CONCAT(first_name, ' ', last_name) AS name, email, phone_number FROM users WHERE id = ?`,
      [targetUserId]
    );
    if (Array.isArray(userResult) && Array.isArray(userResult[0])) userResult = userResult[0];
    const user = userResult && userResult[0];
    if (!user) return res.status(404).json({ error: "Bruker ikke funnet" });

    // 2. Finn låser der DU er owner/admin
    let ownerLocks = await db.query(`SELECT id, name FROM locks WHERE owner_id = ?`, [myUserId]);
    if (Array.isArray(ownerLocks) && Array.isArray(ownerLocks[0])) ownerLocks = ownerLocks[0];

    let adminLocks = await db.query(
      `SELECT l.id, l.name
       FROM user_locks ul
       JOIN locks l ON ul.lock_id = l.id
       WHERE ul.user_id = ? AND ul.role = 'admin'`,
      [myUserId]
    );
    if (Array.isArray(adminLocks) && Array.isArray(adminLocks[0])) adminLocks = adminLocks[0];

    // Felles låser du styrer
    const allMyLockIds = [...new Set([...ownerLocks.map(l => l.id), ...adminLocks.map(l => l.id)])];

    if (!allMyLockIds.length) {
      // Du administrerer ingen låser
      return res.json({ user, shared_locks: [], locks_you_can_share: [] });
    }

    // 3. Låser mål-bruker har tilgang til (og du også styrer)
    let sharedLocks = await db.query(
      `
      SELECT l.id AS lock_id, l.name AS lock_name,
        CASE
          WHEN l.owner_id = ? THEN 'owner'
          WHEN ul.role = 'admin' THEN 'admin'
          ELSE 'user'
        END AS my_role,
        CASE
          WHEN l.owner_id = ? THEN 'owner'
          WHEN ul2.role = 'admin' THEN 'admin'
          ELSE 'user'
        END AS user_role
      FROM locks l
      LEFT JOIN user_locks ul ON ul.lock_id = l.id AND ul.user_id = ?
      LEFT JOIN user_locks ul2 ON ul2.lock_id = l.id AND ul2.user_id = ?
      WHERE l.id IN (${allMyLockIds.map(() => '?').join(',')})
        AND (
          l.owner_id = ? OR
          EXISTS (SELECT 1 FROM user_locks WHERE lock_id = l.id AND user_id = ?)
        )
        AND (
          l.owner_id = ? OR
          EXISTS (SELECT 1 FROM user_locks WHERE lock_id = l.id AND user_id = ?)
        )
      `,
      [
        myUserId,
        targetUserId,
        myUserId,
        targetUserId,
        ...allMyLockIds,
        myUserId,
        myUserId,
        targetUserId,
        targetUserId
      ]
    );
    if (Array.isArray(sharedLocks) && Array.isArray(sharedLocks[0])) sharedLocks = sharedLocks[0];

    // 4. Sett can_remove på alle rader hvor du er owner eller admin (eier kan fjerne alle, admin kan fjerne users)
    sharedLocks = sharedLocks.map(lock => ({
      ...lock,
      can_remove:
        lock.my_role === 'owner' ||
        (lock.my_role === 'admin' && lock.user_role === 'user')
    }));

    // 5. Finn låser du kan dele videre (der mål-bruker IKKE allerede har tilgang)
    const sharedLockIds = sharedLocks.map(l => l.lock_id);
    const locksYouCanShare = [
      ...ownerLocks,
      ...adminLocks
    ].filter(l => !sharedLockIds.includes(l.id));

    // 6. Returner svaret!
    res.json({
      user,
      shared_locks: sharedLocks,
      locks_you_can_share: locksYouCanShare
    });
  } catch (error) {
    console.error('Feil i getUserAccessDetails:', error, error.stack);
    res.status(500).json({ error: String(error) });
  }
};

  
