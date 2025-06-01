const express = require('express');
const router = express.Router();
const db = require('../config/db');
const { verifyToken } = require('../middleware/authMiddleware');


/**
 * @swagger
 * /profile/profile:
 *   post:
 *     summary: Hent profil for innlogget bruker
 *     tags:
 *       - Profil
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Brukerprofil
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: integer
 *                     first_name:
 *                       type: string
 *                     last_name:
 *                       type: string
 *                     email:
 *                       type: string
 *                     phone_number:
 *                       type: string
 *                     role:
 *                       type: string
 *                     created_at:
 *                       type: string
 *       404:
 *         description: Bruker ikke funnet
 *       500:
 *         description: Feil ved henting av profil
 */

router.post('/profile', verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT id, first_name, last_name, email, phone_number, role, created_at FROM users WHERE id = ?",
      [req.user.id]
    );

    const user = rows[0];

    if (!user) return res.status(404).json({ error: "Bruker ikke funnet" });

    res.json({ user });
  } catch (err) {
    res.status(500).json({ error: 'Feil ved henting av profil' });
  }
});


module.exports = router;
