const express = require('express');
const router = express.Router();
const { verifyToken, requireAdmin } = require('../middleware/authMiddleware');
const accessGroupController = require('../controllers/accessGroupController');
const logger = require('../utils/logger');
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

/**
 * 
 * /accessgroup/create:
 *   post:
 *     summary: Opprett ny tilgangsgruppe
 *     tags:
 *       - Tilgangsgrupper
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *     responses:
 *       200:
 *         description: Resultat av opprettelse
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 groupId:
 *                   type: integer
 *       500:
 *         description: Kunne ikke opprette gruppe
 */
// Opprett ny tilgangsgruppe
router.post('/create', verifyToken, accessGroupController.createGroup);

/**
 * 
 * /accessgroup/add-user:
 *   post:
 *     summary: Legg til bruker i gruppe
 *     tags:
 *       - Tilgangsgrupper
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               groupId:
 *                 type: integer
 *               userId:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Bruker lagt til
 *       500:
 *         description: Kunne ikke legge til bruker
 */
// Legg til bruker i gruppe
router.post('/add-user', verifyToken, accessGroupController.addUserToGroup);

/**
 * 
 * /accessgroup/add-lock:
 *   post:
 *     summary: Legg til lås i gruppe
 *     tags:
 *       - Tilgangsgrupper
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               groupId:
 *                 type: integer
 *               lockId:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Lås lagt til
 *       500:
 *         description: Kunne ikke legge til lås
 */
// Legg til lås i gruppe
router.post('/add-lock', verifyToken, accessGroupController.addLockToGroup);
/**
 * @swagger
 * /users:
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
router.post('/users', verifyToken, accessGroupController.getUsersInAccessGroup);

/**
 * @swagger
 * /accessgroup/{groupId}/details:
 *   get:
 *     summary: Hent detaljer for en tilgangsgruppe
 *     tags:
 *       - Tilgangsgrupper
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - name: groupId
 *         in: path
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Gruppens detaljer
 *       404:
 *         description: Adgangsgruppe ikke funnet
 *       500:
 *         description: Serverfeil
 */
router.get('/:groupId/details', verifyToken, accessGroupController.getAccessGroupDetails);


module.exports = router;
