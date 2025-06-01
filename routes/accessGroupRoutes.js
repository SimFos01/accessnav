const express = require('express');
const router = express.Router();
const { verifyToken, requireAdmin } = require('../middleware/authMiddleware');
const accessGroupController = require('../controllers/accessGroupController');
const logger = require('../utils/logger');
logger.debug('TYPE OF requireAdmin:', typeof requireAdmin);
logger.debug('controller:', accessGroupController);
logger.debug('createGroup:', accessGroupController.createGroup);
logger.debug('verifyToken:', typeof verifyToken);
logger.debug('requireAdmin:', typeof requireAdmin);
/**
 * @swagger
 * /accessGroup/list:
 *   post:
 *     summary: Hent tilgangsgrupper for bruker
 *     tags:
 *       - Tilgangsgrupper
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [token]
 *             properties:
 *               token:
 *                 type: string
 *     responses:
 *       200:
 *         description: Liste over tilgangsgrupper
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   name:
 *                     type: string
 *                   role:
 *                     type: string
 *                   user_count:
 *                     type: integer
 *                   lock_count:
 *                     type: integer
 *       401:
 *         description: Ugyldig eller manglende token
 *       500:
 *         description: Serverfeil
 */
router.post('/list', verifyToken, accessGroupController.getAccessGroupsForUser);

// Opprett ny tilgangsgruppe
router.post('/create', verifyToken, accessGroupController.createGroup);

// Legg til bruker i gruppe
router.post('/add-user', verifyToken, accessGroupController.addUserToGroup);

// Legg til lås i gruppe
router.post('/add-lock', verifyToken, accessGroupController.addLockToGroup);
/**
 * @swagger
 * /accessgroup/users:
 *   post:
 *     summary: Hent brukere i en tilgangsgruppe
 *     tags:
 *       - Tilgangsgrupper
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [token, group_id]
 *             properties:
 *               token:
 *                 type: string
 *               group_id:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Liste over brukere i gruppen
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   id:
 *                     type: integer
 *                   email:
 *                     type: string
 *                   role:
 *                     type: string
 *       401:
 *         description: Ugyldig eller manglende token
 *       403:
 *         description: Mangler tilgang
 *       500:
 *         description: Serverfeil
 */
router.post('/accessgroup/users', accessGroupController.getUsersInAccessGroup);

router.get('/:groupId/details', verifyToken, accessGroupController.getAccessGroupDetails);


module.exports = router;
