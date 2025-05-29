// File: /routes/logRoutes.js

const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middleware/authMiddleware'); // ✅ riktig
const logController = require('../controllers/logController');
const { getLastActivityForLock } = require('../controllers/logController');


router.use(verifyToken);

// Hent alle logger

/**
 * @swagger
 * /log:
 *   get:
 *     summary: Hent alle adgangslogger
 *     tags:
 *       - Logger
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Liste over logger
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   user_id:
 *                     type: integer
 *                   lock_id:
 *                     type: integer
 *                   action:
 *                     type: string
 *                   result:
 *                     type: string
 *                   success:
 *                     type: boolean
 *                   timestamp:
 *                     type: string
 *                   username:
 *                     type: string
 *                   lock_name:
 *                     type: string
 *       500:
 *         description: Kunne ikke hente logger
 */
router.get('/', logController.getAllLogs);

/**
 * @swagger
 * /log/{lockId}:
 *   get:
 *     summary: Hent logger for spesifikk lås
 *     tags:
 *       - Logger
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: lockId
 *         schema:
 *           type: integer
 *         required: true
 *         description: ID for låsen
 *     responses:
 *       200:
 *         description: Logger for valgt lås
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   user_id:
 *                     type: integer
 *                   lock_id:
 *                     type: integer
 *                   action:
 *                     type: string
 *                   result:
 *                     type: string
 *                   success:
 *                     type: boolean
 *                   timestamp:
 *                     type: string
 *                   formatted_date:
 *                     type: string
 *                   formatted_time:
 *                     type: string
 *                   username:
 *                     type: string
 *       500:
 *         description: Kunne ikke hente logger
 */

router.get('/:lockId', verifyToken, logController.getLogsByLock);

/**
 * @swagger
 * /log/{lockId}/last:
 *   get:
 *     summary: Hent siste aktivitet for en lås
 *     tags:
 *       - Logger
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: lockId
 *         schema:
 *           type: integer
 *         required: true
 *         description: ID for låsen
 *     responses:
 *       200:
 *         description: Siste aktivitet
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 last_action:
 *                   type: string
 *                 timestamp:
 *                   type: string
 *                 formatted_date:
 *                   type: string
 *                 formatted_time:
 *                   type: string
 *                 username:
 *                   type: string
 */
router.get('/:lockId/last', verifyToken, getLastActivityForLock);

module.exports = router;
