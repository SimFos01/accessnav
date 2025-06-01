const logger = require('../utils/logger');
logger.debug('>>> accessGroupController loaded');
const jwt = require('jsonwebtoken');

const db = require('../config/db');

exports.createGroup = async (req, res) => {
  const { name } = req.body;
  try {
    // mariadb returnerer et enkelt resultatobjekt for INSERT
    const result = await db.query(
      'INSERT INTO access_groups (name) VALUES (?)',
      [name]
    );
    // MariaDB can return insertId as a BigInt, which JSON.stringify cannot
    // handle. Convert the value to a regular Number before sending the
    // response to avoid `TypeError: Do not know how to serialize a BigInt`.
    res.json({ success: true, groupId: Number(result.insertId) });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kunne ikke opprette gruppe' });
  }
};

exports.addUserToGroup = async (req, res) => {
  const { groupId, userId } = req.body;
  try {
    await db.query(
      'INSERT INTO group_members (group_id, user_id) VALUES (?, ?)',
      [groupId, userId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kunne ikke legge til bruker i gruppe' });
  }
};

exports.addLockToGroup = async (req, res) => {
  const { groupId, lockId } = req.body;
  try {
    await db.query(
      'INSERT INTO group_locks (group_id, lock_id) VALUES (?, ?)',
      [groupId, lockId]
    );
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kunne ikke koble lås til gruppe' });
  }
};

exports.getGroupMembers = async (req, res) => {
  const { groupId } = req.params;
  try {
    let rows = await db.query(
      `SELECT u.id, u.username, u.role FROM users u
       JOIN group_members gm ON gm.user_id = u.id
       WHERE gm.group_id = ?`,
      [groupId]
    );
    rows = Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0] : rows;
    res.json(Array.isArray(rows) ? rows : []);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kunne ikke hente medlemmer' });
  }
};

exports.getGroupLocks = async (req, res) => {
  const { groupId } = req.params;
  try {
    let rows = await db.query(
      `SELECT l.id, l.name, l.type FROM locks l
       JOIN group_locks gl ON gl.lock_id = l.id
       WHERE gl.group_id = ?`,
      [groupId]
    );
    rows = Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0] : rows;
    res.json(Array.isArray(rows) ? rows : []);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Kunne ikke hente låser i gruppe' });
  }
};

exports.getUsersInAccessGroup = async (req, res) => {
  const { token, group_id } = req.body;
  if (!token) return res.status(401).json({ error: 'Mangler token' });
  if (!group_id) return res.status(400).json({ error: 'Mangler group_id' });

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Ugyldig token' });
  }
  const userId = decoded.id;

  // Sjekk at denne brukeren er admin eller eier i gruppa
  try {
    // Finn rollen til brukeren i denne gruppa
    let roleRows = await db.query(
      `SELECT role FROM access_group_users WHERE group_id = ? AND user_id = ?`,
      [group_id, userId]
    );
    roleRows = Array.isArray(roleRows) && Array.isArray(roleRows[0]) ? roleRows[0] : roleRows;
    const userRole = Array.isArray(roleRows) && roleRows[0] ? roleRows[0].role : null;

    if (userRole !== 'admin' && userRole !== 'eier') {
      return res.status(403).json({ error: 'Kun admin/eier kan se listen' });
    }

    // Hent alle brukere i gruppen
    let rows = await db.query(
      `SELECT u.id, u.email, agu.role
       FROM access_group_users agu
       JOIN users u ON agu.user_id = u.id
       WHERE agu.group_id = ?`,
      [group_id]
    );
    rows = Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0] : rows;
    res.json(Array.isArray(rows) ? rows : []);
  } catch (err) {
    console.error('🔥 Feil i getUsersInAccessGroup:', err);
    res.status(500).json({ error: 'Kunne ikke hente brukere i gruppa' });
  }
};

exports.getAccessGroupsForUser = async (req, res) => {
  const userId = req.user.id;

  try {
    const query = `
      SELECT ag.id, ag.name,
        agu.role,
        (SELECT COUNT(*) FROM access_group_users agu2 WHERE agu2.group_id = ag.id) AS user_count,
        (SELECT COUNT(*) FROM access_group_locks agl WHERE agl.group_id = ag.id) AS lock_count
      FROM access_groups ag
      JOIN access_group_users agu ON agu.group_id = ag.id
      WHERE agu.user_id = ?
    `;
    let rows = await db.query(query, [userId]);
    rows = Array.isArray(rows) && Array.isArray(rows[0]) ? rows[0] : rows;
    if (Array.isArray(rows)) {
      rows = rows.map(row => {
        for (const key of Object.keys(row)) {
          if (typeof row[key] === 'bigint') {
            row[key] = Number(row[key]);
          }
        }
        return row;
      });
    }
    res.json(Array.isArray(rows) ? rows : []);
  } catch (err) {
    console.error('🔥 Feil i getAccessGroupsForUser:', err);
    res.status(500).json({ error: 'Kunne ikke hente tilgangsgrupper' });
  }
};

exports.getAccessGroupDetails = async (req, res) => {
  const groupId = req.params.groupId;

  try {
    // Hent gruppenavn
    let [groupRows] = await db.query(
      'SELECT id, name FROM access_groups WHERE id = ?',
      [groupId]
    );
    groupRows = Array.isArray(groupRows) && Array.isArray(groupRows[0]) ? groupRows[0] : groupRows;
    if (!groupRows || groupRows.length === 0) {
      return res.status(404).json({ error: 'Adgangsgruppe ikke funnet' });
    }

    const group = groupRows[0];

    // Hent medlemmer
    let [members] = await db.query(
     `SELECT u.id, u.email, CONCAT(u.first_name, ' ', u.last_name) AS username, agu.role
     FROM access_group_users agu
     JOIN users u ON agu.user_id = u.id
     WHERE agu.group_id = ?`,
     [groupId]
   );
members = Array.isArray(members) && Array.isArray(members[0]) ? members[0] : members;

    // Hent låser
    let [locks] = await db.query(
      `SELECT l.id, l.name, l.type
       FROM access_group_locks agl
       JOIN locks l ON agl.lock_id = l.id
       WHERE agl.group_id = ?`,
      [groupId]
    );
    locks = Array.isArray(locks) && Array.isArray(locks[0]) ? locks[0] : locks;

    res.json({
      group_id: group.id,
      group_name: group.name,
      members: members || [],
      locks: locks || []
    });
  } catch (err) {
    console.error('🔥 Feil i getAccessGroupDetails:', err);
    res.status(500).json({ error: 'Kunne ikke hente detaljer for gruppen' });
  }
};

