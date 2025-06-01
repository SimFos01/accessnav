const db = require('../config/db');
const { logAccess, hasAccessToLock } = require('../utils/accessControl');
const raspberryAdapter = require('../adapters/raspberryAdapter');
const aviorAdapter = require('../adapters/aviorAdapter');
const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

exports.createLock = async (req, res) => {
    const { name, type, adapter_data } = req.body;
  
    logger.debug('createLock called by user', req.user?.id);
    logger.debug('createLock body:', { name, type });
  
    if (!name || !type || !adapter_data) {
      return res.status(400).json({ error: 'name, type og adapter_data kreves' });
    }
  
    try {
      const result = await db.query(
        'INSERT INTO locks (name, type, adapter_data, owner_id) VALUES (?, ?, ?, ?)',
        [name, type, JSON.stringify(adapter_data), req.user.id]
      );
  
      if (!result || !result.insertId) {
        return res.status(500).json({ error: 'Kunne ikke opprette lås' });
      }
  
      res.json({ success: true, id: Number(result.insertId) });
    } catch (err) {
      console.error('🔥 DB-feil i createLock:', err);
      res.status(500).json({ error: 'Feil ved opprettelse av lås' });
    }
};

exports.getSharedUsers = async (req, res) => {
  const { id: userId } = req.user;
  try {
    // 1. Finn alle låser hvor bruker er EIER eller ADMIN
    // Eier:
    let ownerLocks = await db.query(
      `SELECT id FROM locks WHERE owner_id = ?`,
      [userId]
    );
    if (Array.isArray(ownerLocks) && Array.isArray(ownerLocks[0])) ownerLocks = ownerLocks[0];

    // Admin:
    let adminLocks = await db.query(
      `SELECT lock_id FROM user_locks WHERE user_id = ? AND role = 'admin'`,
      [userId]
    );
    if (Array.isArray(adminLocks) && Array.isArray(adminLocks[0])) adminLocks = adminLocks[0];

    // Slå sammen og fjern duplikater
    const lockIdSet = new Set([
      ...ownerLocks.map(l => l.id),
      ...adminLocks.map(l => l.lock_id)
    ]);
    const lockIds = Array.from(lockIdSet);

    if (!lockIds.length) {
      return res.json([]);
    }

    // 2. Hent alle brukere med tilgang til disse låsene
    // - Eier (fra locks.owner_id)
    // - Admin/User (fra user_locks)
    let usersResult = await db.query(
      `
      SELECT u.id AS user_id,
             CONCAT(u.first_name, ' ', u.last_name) AS user_name,
             u.email AS user_email,
             l.id AS lock_id,
             l.name AS lock_name,
             CASE
               WHEN l.owner_id = u.id THEN 'owner'
               WHEN ul.role = 'admin' THEN 'admin'
               ELSE 'user'
             END AS role
      FROM locks l
      LEFT JOIN user_locks ul ON ul.lock_id = l.id
      LEFT JOIN users u ON (u.id = ul.user_id OR u.id = l.owner_id)
      WHERE l.id IN (?)
      AND u.id IS NOT NULL
      AND u.id != ?
      GROUP BY u.id, l.id
      ORDER BY l.id, user_name
      `,
      [lockIds, userId]
    );
    if (Array.isArray(usersResult) && Array.isArray(usersResult[0])) usersResult = usersResult[0];

    res.json(usersResult);
  } catch (error) {
    console.error('Feil i getSharedUsers:', error, error.stack);
    res.status(500).json({ error: String(error) });
  }
};

exports.getLockList = async (req, res) => {
  try {
    const token = req.body?.token;

    if (!token) {
      return res.status(400).json({ error: 'Token mangler' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decoded.id;

    const result = await db.query(
      'SELECT id, name, type, adapter_data, Eier, Etasje, Rom, Adresse FROM locks WHERE owner_id = ?',
      [userId]
    );
    
    const rows = Array.isArray(result) ? result : result[0] || [];

    const locks = rows.map((lock) => {
      let adapterData = lock.adapter_data;
    
      if (typeof adapterData === 'string') {
        try {
          adapterData = JSON.parse(adapterData);
        } catch {
          adapterData = {};
        }
      }
    
      return {
        id: lock.id,
        name: lock.name,
        type: lock.type,
        eier: lock.Eier,
        floor: lock.Etasje,
        room: lock.Rom,
        adress: lock.Adresse,
        adapter_data: adapterData
      };
    });

    logger.info('🔐 getLockList →', locks.length, 'låser funnet for bruker', userId);
    res.json(locks);
  } catch (err) {
    console.error('🔥 Feil i getLockList:', err.message);
    res.status(500).json({ error: 'Kunne ikke hente låser' });
  }
};

exports.getAllAccessibleLocks = async (req, res) => {
  const userId = req.user && req.user.id;

  if (!userId) {
    return res.status(401).json({ error: 'Mangler brukerinformasjon' });
  }

  try {
    const query = `
      SELECT DISTINCT l.*, l.owner_id
      FROM locks l
      LEFT JOIN access_group_locks agl ON agl.lock_id = l.id
      LEFT JOIN access_group_users agu ON agu.group_id = agl.group_id
      LEFT JOIN user_locks ul ON ul.lock_id = l.id
      WHERE agu.user_id = ? OR ul.user_id = ? OR l.owner_id = ?
    `;

    let rows = await db.query(query, [userId, userId, userId]);
    rows = Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0] : rows;
    if (!Array.isArray(rows)) rows = [];

    const owned = [];
    const shared = [];

    (rows || []).forEach((lock) => {
      let adapterData = lock.adapter_data;
      if (typeof adapterData === 'string') {
        try {
          adapterData = JSON.parse(adapterData);
        } catch {
          adapterData = {};
        }
      }

      const formatted = {
        id: lock.id,
        name: lock.name,
        type: lock.type,
        eier: lock.Eier,
        floor: lock.Etasje,
        room: lock.Rom,
        adress: lock.Adresse,
        adapter_data: adapterData
      };

      if (lock.owner_id === userId) {
        owned.push(formatted);
      } else {
        shared.push(formatted);
      }
    });

    res.json({
      user_id: userId,
      owned: owned,
      shared: shared
    });

  } catch (err) {
    console.error('🔥 Feil i getAllAccessibleLocks:', err);
    res.status(500).json({ error: 'Kunne ikke hente låser' });
  }
};

exports.getLockById = async (req, res) => {
  const { token, id } = req.body;

  if (!token) {
    return res.status(401).json({ error: 'Mangler token' });
  }
  if (!id) {
    return res.status(400).json({ error: 'Mangler id' });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Ugyldig token' });
  }

  try {
    // Kjør query og sørg for lik struktur som ellers
    const result = await db.query(
      'SELECT id, name, type, adapter_data, Eier, Etasje, Rom, Adresse FROM locks WHERE id = ? LIMIT 1',
      [id]
    );
    const rows = Array.isArray(result) ? result : result[0] || [];

    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Lås ikke funnet' });
    }

    const lock = rows[0];
    let adapterData = lock.adapter_data;

    if (typeof adapterData === 'string') {
      try {
        adapterData = JSON.parse(adapterData);
      } catch {
        adapterData = {};
      }
    }

    // Status-sjekk (kan kommenteres ut hvis du bare vil returnere låsen)
    let status = 'unknown';
    try {
      if (lock.type === 'raspberry') {
        status = await raspberryAdapter.status(adapterData);
      } else if (lock.type === 'avior') {
        status = await aviorAdapter.status(adapterData);
      }
    } catch (err) {
      console.warn(`⚠️ Kunne ikke hente status for lås ${lock.id}`, err.message);
    }

    return res.json({
      id: lock.id,
      name: lock.name,
      type: lock.type,
      eier: lock.Eier,
      floor: lock.Etasje,
      room: lock.Rom,
      adress: lock.Adresse,
      adapter_data: adapterData,
      status
    });

  } catch (error) {
    console.error('🔥 DB-feil i getLockById:', error);
    return res.status(500).json({ error: 'Databasefeil' });
  }
};

exports.getAccessibleLocks = async (req, res) => {
    try {
        let rows = await db.query(
            `SELECT * FROM locks WHERE owner_id = ?`,
            [req.user.id]
          );
          logger.debug('[BODY keys]', Object.keys(req.body || {}));
          rows = Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0] : rows;
          const list = Array.isArray(rows) ? rows : [];

          const locks = JSON.parse(JSON.stringify(list)); // Sikrer ren array

            logger.debug('🔎 Hentet locks:', Array.isArray(locks), locks.length);
      const locksWithStatus = await Promise.all(
        locks.map(async (lock) => {
            let adapterData = lock.adapter_data;

            if (typeof adapterData === 'string') {
              try {
                adapterData = JSON.parse(adapterData);
              } catch (err) {
                console.warn(`⚠️ adapter_data kunne ikke parses for lås ${lock.id}`);
                return {
                  id: lock.id,
                  name: lock.name,
                  status: 'invalid-adapter',
                };
              }
            }
            
            if (!adapterData || typeof adapterData !== 'object') {
              console.warn(`⚠️ adapter_data er ikke definert eller ugyldig for lås ${lock.id}`);
              return {
                id: lock.id,
                name: lock.name,
                status: 'invalid-adapter',
              };
            }
            
            if (!adapterData.ip || adapterData.pin == null) {
              console.warn(`⚠️ adapter_data mangler ip eller pin for lås ${lock.id}`);
              return {
                id: lock.id,
                name: lock.name,
                status: 'missing-data',
              };
            }
            
  
          if (!adapterData?.ip || adapterData.pin == null) {
            console.warn(`⚠️ adapter_data mangler ip eller pin for lås ${lock.id}`);
            return {
              id: lock.id,
              name: lock.name,
              status: 'missing-data',
            };
          }
  
          let status = 'unknown';
          try {
            if (lock.type === 'raspberry') {
              status = await raspberryAdapter.status(adapterData);
            } else if (lock.type === 'avior') {
              status = await aviorAdapter.status(adapterData);
            }
          } catch (err) {
            console.warn(`⚠️ Kunne ikke hente status for lås ${lock.id}`, err.message);
          }
  
          return {
            id: lock.id,
            name: lock.name,
            status,
          };
        })
      );
  
      res.json(locksWithStatus);
    } catch (err) {
      console.error('🔥 Feil i getAccessibleLocks:', err);
      res.status(500).json({ error: 'Kunne ikke hente låser' });
    }
};

exports.openLock = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    // 🔐 Sjekk tilgang
    const hasAccess = await hasAccessToLock(userId, id);
    if (!hasAccess) {
      await logAccess(userId, id, 'open', false);
      return res.status(403).json({ error: 'Ingen tilgang til denne låsen' });
    }

    // 🔍 Hent lås fra DB (robust for array/objekt)
    let rows = await db.query(`SELECT * FROM locks WHERE id = ?`, [id]);
    rows = Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0] : rows;
    let lock;
    if (Array.isArray(rows)) {
      if (rows.length === 0) {
        console.error('❌ Fant ikke lås med gitt ID:', id);
        await logAccess(userId, id, 'open', false);
        return res.status(404).json({ error: 'Lås ikke funnet' });
      }
      lock = rows[0];
    } else if (rows && typeof rows === 'object') {
      lock = rows;
    } else {
      console.error('❌ Ukjent format fra DB:', rows);
      await logAccess(userId, id, 'open', false);
      return res.status(500).json({ error: 'Ugyldig svar fra databasen' });
    }

    if (!lock || !lock.adapter_data) {
      console.error('❌ Låsen mangler adapter_data:', lock);
      await logAccess(userId, id, 'open', false);
      return res.status(500).json({ error: 'adapter_data mangler for denne låsen' });
    }

    let adapterData;
    try {
      adapterData = typeof lock.adapter_data === 'string'
        ? JSON.parse(lock.adapter_data)
        : lock.adapter_data;
    } catch (e) {
      console.error('❌ Klarte ikke å parse adapter_data:', lock.adapter_data, e);
      await logAccess(userId, id, 'open', false);
      return res.status(500).json({ error: 'Feil i adapter_data-format – ikke gyldig JSON' });
    }

    // 🟢 Sjekk at nødvendig data finnes for type
    if (lock.type === 'raspberry') {
      if (!adapterData.ip || adapterData.pin == null) {
        console.error('❌ adapterData mangler ip eller pin:', adapterData);
        await logAccess(userId, id, 'open', false);
        return res.status(400).json({ error: 'adapter_data mangler påkrevd info (ip eller pin)' });
      }
    } else if (lock.type === 'avior') {
        if (!adapterData.device || !adapterData.password || !adapterData.out) {
          const { password, ...rest } = adapterData || {};
          console.error('❌ adapterData mangler device, password eller out:', { ...rest, password: password ? '***' : undefined });
        await logAccess(userId, id, 'open', false);
        return res.status(400).json({ error: 'adapter_data mangler påkrevd info (device, password eller out)' });
      }
    } else {
      console.error('❌ Ukjent låstype:', lock.type);
      await logAccess(userId, id, 'open', false);
      return res.status(500).json({ error: 'Ukjent låstype' });
    }

    // ⚡ Kjør adapter
    let result;
    if (lock.type === 'raspberry') {
      result = await raspberryAdapter.unlock(adapterData);
    } else if (lock.type === 'avior') {
      // Mobikey/AVIOR skyadapter – bruk din adapter her:
      result = await aviorAdapter.open(adapterData);
    } else {
      console.error('❌ Ukjent låstype:', lock.type);
      await logAccess(userId, id, 'open', false);
      return res.status(500).json({ error: 'Ukjent låstype' });
    }

    // ✅ Logg suksess og svar
    await logAccess(userId, id, 'open', true);
    res.json({ success: true, result });

  } catch (err) {
    console.error('🔥 openLock-feil:', err, err.stack);
    await logAccess(userId, id, 'open', false);
    res.status(500).json({ error: 'Intern feil under åpning av lås' });
  }
};

exports.lockLock = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  try {
    // 🔐 Sjekk tilgang
    const hasAccess = await hasAccessToLock(userId, id);
    if (!hasAccess) {
      await logAccess(userId, id, 'lock', false);
      return res.status(403).json({ error: 'Ingen tilgang til denne låsen' });
    }

    // 🔍 Hent lås fra DB (robust for array/objekt)
    let rows = await db.query(`SELECT * FROM locks WHERE id = ?`, [id]);
    rows = Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0] : rows;
    let lock;
    if (Array.isArray(rows)) {
      if (rows.length === 0) {
        console.error('❌ Fant ikke lås med gitt ID:', id);
        await logAccess(userId, id, 'lock', false);
        return res.status(404).json({ error: 'Lås ikke funnet' });
      }
      lock = rows[0];
    } else if (rows && typeof rows === 'object') {
      lock = rows;
    } else {
      console.error('❌ Ukjent format fra DB:', rows);
      await logAccess(userId, id, 'lock', false);
      return res.status(500).json({ error: 'Ugyldig svar fra databasen' });
    }

    if (!lock || !lock.adapter_data) {
      console.error('❌ Låsen mangler adapter_data:', lock);
      await logAccess(userId, id, 'lock', false);
      return res.status(500).json({ error: 'adapter_data mangler for denne låsen' });
    }

    let adapterData;
    try {
      adapterData = typeof lock.adapter_data === 'string'
        ? JSON.parse(lock.adapter_data)
        : lock.adapter_data;
    } catch (e) {
      console.error('❌ Klarte ikke å parse adapter_data:', lock.adapter_data, e);
      await logAccess(userId, id, 'lock', false);
      return res.status(500).json({ error: 'Feil i adapter_data-format – ikke gyldig JSON' });
    }

    // 🟢 Sjekk at nødvendig data finnes for type
    if (lock.type === 'raspberry') {
      if (!adapterData.ip || adapterData.pin == null) {
        console.error('❌ adapterData mangler ip eller pin:', adapterData);
        await logAccess(userId, id, 'lock', false);
        return res.status(400).json({ error: 'adapter_data mangler påkrevd info (ip eller pin)' });
      }
    } else if (lock.type === 'avior') {
        if (!adapterData.device || !adapterData.password || !adapterData.out) {
          const { password, ...rest } = adapterData || {};
          console.error('❌ adapterData mangler device, password eller out:', { ...rest, password: password ? '***' : undefined });
        await logAccess(userId, id, 'lock', false);
        return res.status(400).json({ error: 'adapter_data mangler påkrevd info (device, password eller out)' });
      }
    } else {
      console.error('❌ Ukjent låstype:', lock.type);
      await logAccess(userId, id, 'lock', false);
      return res.status(500).json({ error: 'Ukjent låstype' });
    }

    // ⚡ Kjør adapter
    let result;
    if (lock.type === 'raspberry') {
      result = await raspberryAdapter.lock(adapterData);
    } else if (lock.type === 'avior') {
      result = await aviorAdapter.lock(adapterData);
    } else {
      console.error('❌ Ukjent låstype:', lock.type);
      await logAccess(userId, id, 'lock', false);
      return res.status(500).json({ error: 'Ukjent låstype' });
    }

    // ✅ Logg suksess og svar
    await logAccess(userId, id, 'lock', true);
    res.json({ success: true, result });

  } catch (err) {
    console.error('🔥 lockLock-feil:', err, err.stack);
    await logAccess(userId, id, 'lock', false);
    res.status(500).json({ error: 'Intern feil under låsing av lås' });
  }
};

exports.lockStatus = async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;
  let success = false;
  let status = null;

  try {
    const hasAccess = await hasAccessToLock(userId, id);
    if (!hasAccess) {
      await logAccess(userId, id, 'status', false);
      return res.status(403).json({ error: 'Ingen tilgang til denne låsen' });
    }

    let lockRows = await db.query(`SELECT * FROM locks WHERE id = ?`, [id]);
    lockRows = Array.isArray(lockRows) && Array.isArray(lockRows[0]) ? lockRows[0] : lockRows;
    if (!lockRows || lockRows.length === 0) {
      await logAccess(userId, id, 'status', false);
      return res.status(404).json({ error: 'Lås ikke funnet' });
    }

    const lock = Array.isArray(lockRows) ? lockRows[0] : lockRows;
    const adapterData = typeof lock.adapter_data === 'string' 
    ? JSON.parse(lock.adapter_data) 
    : lock.adapter_data;

    if (lock.type === 'raspberry') {
      status = await raspberryAdapter.status(adapterData);
      success = status !== null;
    } else if (lock.type === 'avior') {
      status = await aviorAdapter.status(adapterData);
      success = status !== null;
    } else {
      throw new Error('Ukjent låstype');
    }

    await logAccess(userId, id, 'status', success);

    if (!success) {
      return res.status(500).json({ error: 'Kunne ikke hente status fra lås' });
    }

    res.json({ success: true, status });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Intern feil ved henting av status' });
  }
};

exports.getLastActivityForLock = async (req, res) => {
  const { lockId } = req.params;
  const user = req.user;

  if (!lockId || isNaN(lockId)) {
    return res.status(400).json({ error: 'Ugyldig lockId' });
  }

  try {
    // 🔐 Admin eller eier-sjekk
    if (user.role !== 'admin') {
      const check = await db.query(
        'SELECT 1 FROM locks WHERE id = ? AND owner_id = ?',
        [lockId, user.id]
      );

      if (!check || check.length === 0) {
        return res.status(403).json({ error: 'Ingen tilgang til denne låsen' });
      }
    }

    // 📦 Hent siste logg
      const rows = await db.query(
        `SELECT al.action AS last_action,
              al.timestamp,
              DATE_FORMAT(al.timestamp, '%d.%m.%Y') AS formatted_date,
              DATE_FORMAT(al.timestamp, '%H:%i') AS formatted_time,
              CONCAT(COALESCE(u.first_name, ''), ' ', COALESCE(u.last_name, '')) AS username
       FROM access_logs al
       LEFT JOIN users u ON u.id = al.user_id
       WHERE al.lock_id = ?
       ORDER BY al.timestamp DESC
       LIMIT 1`,
      [lockId]
    );

      if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Ingen logger funnet for denne låsen' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('🔥 Feil i getLastActivityForLock:', err);
    res.status(500).json({ error: 'Kunne ikke hente siste aktivitet' });
  }
};

// Hent brukere som har tilgang til en gitt lås
exports.getUsersForLock = async (req, res) => {
  const lockId = req.params.id;
  const requester = req.user;

  if (!lockId || isNaN(lockId)) {
    return res.status(400).json({ error: 'Ugyldig lockId' });
  }

  try {
    // Kun admin eller eier av låsen kan hente listen
    if (requester.role !== 'admin') {
      const ownerCheck = await db.query(
        'SELECT owner_id FROM locks WHERE id = ?',
        [lockId]
      );

      if (!ownerCheck || ownerCheck.length === 0) {
        return res.status(404).json({ error: 'Lås ikke funnet' });
      }

      if (Number(ownerCheck[0].owner_id) !== requester.id) {
        return res.status(403).json({ error: 'Ingen tilgang til denne låsen' });
      }
    }

    const query = `
      SELECT u.id, u.email, 'eier' AS role
      FROM locks l
      JOIN users u ON l.owner_id = u.id
      WHERE l.id = ?
      UNION ALL
      SELECT u.id, u.email, ul.role
      FROM user_locks ul
      JOIN users u ON ul.user_id = u.id
      WHERE ul.lock_id = ?
      UNION ALL
      SELECT u.id, u.email, agu.role
      FROM access_group_users agu
      JOIN access_group_locks agl ON agl.group_id = agu.group_id
      JOIN users u ON agu.user_id = u.id
      WHERE agl.lock_id = ?
    `;

      let rows = await db.query(query, [lockId, lockId, lockId]);
      rows = Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0] : rows;
      const list = Array.isArray(rows) ? rows : [];

    const priority = { eier: 3, admin: 2, bruker: 1, user: 1 };
    const users = {};
      for (const row of list) {
      const existing = users[row.id];
      if (!existing || (priority[row.role] || 0) > (priority[existing.role] || 0)) {
        users[row.id] = { id: row.id, email: row.email, role: row.role };
      }
    }

    res.json(Object.values(users));
  } catch (err) {
    console.error('🔥 Feil i getUsersForLock:', err);
    res.status(500).json({ error: 'Kunne ikke hente brukere for lås' });
  }
};
