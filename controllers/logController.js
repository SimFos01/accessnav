const db = require('../config/db');

exports.getAllLogs = async (req, res) => {
  try {
    let rows = await db.query(
      `SELECT al.*, u.username, l.name AS lock_name
       FROM access_logs al
       JOIN users u ON u.id = al.user_id
       JOIN locks l ON l.id = al.lock_id
       ORDER BY al.timestamp DESC`
    );
    rows = Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0] : rows;
    res.json(Array.isArray(rows) ? rows : []);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kunne ikke hente logg' });
  }
};

exports.getLogsByLock = async (req, res) => {
  const { lockId } = req.params;
  const userId = req.user.id;
  const userRole = req.user.role;

  // 🧼 Input-sjekk
  if (!lockId || isNaN(lockId)) {
    return res.status(400).json({ error: 'Ugyldig eller manglende lockId' });
  }

  try {
    // 🔐 Kun admin eller eier får hente logg

    if (userRole !== 'admin') {
      const check = await db.query(
        'SELECT 1 FROM locks WHERE id = ? AND owner_id = ?',
        [lockId, userId]
      );

      if (!check || check.length === 0) {
        return res.status(403).json({ error: 'Ingen tilgang til denne låsen' });
      }
    }

    // ✅ Hent logger – med norskformatert timestamp
    let result = await db.query(
      `SELECT
  al.id, al.user_id, al.lock_id, al.action, al.result, al.timestamp, al.success,
  DATE_FORMAT(al.timestamp, '%d.%m.%Y') AS formatted_date,
  DATE_FORMAT(al.timestamp, '%H:%i') AS formatted_time,
  CONCAT(COALESCE(u.first_name, ''), ' ', COALESCE(u.last_name, '')) AS username
FROM access_logs al
LEFT JOIN users u ON u.id = al.user_id
WHERE al.lock_id = ?
ORDER BY al.timestamp DESC`,
      [lockId]
    );

    result = Array.isArray(result) && Array.isArray(result[0]) ? result[0] : result;
    const logs = Array.isArray(result) ? result : [];
    res.json(logs);
  } catch (err) {
    console.error('🔥 Feil i getLogsByLock:', err);
    res.status(500).json({ error: 'Kunne ikke hente logg for valgt lås' });
  }
};

exports.getLastActivityForLock = async (req, res) => {
  const lockId = parseInt(req.params.lockId, 10);
  const user = req.user;

  if (!lockId || isNaN(lockId)) {
    return res.status(400).json({ error: 'Ugyldig lockId' });
  }

  try {
    if (user.role !== 'admin') {
      const check = await db.query(
        'SELECT 1 FROM locks WHERE id = ? AND owner_id = ?',
        [lockId, user.id]
      );

      if (!check || check.length === 0) {
        return res.status(403).json({ error: 'Ingen tilgang til denne låsen' });
      }
    }

    let result = await db.query(
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

    result = Array.isArray(result) && Array.isArray(result[0]) ? result[0] : result;
    const rows = Array.isArray(result) ? result : [];

    if (!rows || rows.length === 0) {
      return res.status(404).json({ error: 'Ingen logger funnet for denne låsen' });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error('🔥 Feil i getLastActivityForLock:', err);
    res.status(500).json({ error: 'Kunne ikke hente siste aktivitet' });
  }
};
