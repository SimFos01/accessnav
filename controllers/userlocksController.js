const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('../config/db');

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
