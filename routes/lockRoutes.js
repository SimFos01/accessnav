// File: /routes/lockRoutes.js

const express = require('express');
const router = express.Router();

const { verifyToken } = require('../middleware/authMiddleware');
const lockController = require('../controllers/lockController');

/**
 * @swagger
 * /lock:
 *   post:
 *     summary: Opprett en ny lås
 *     tags:
 *       - Lås
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [name, type, adapter_data]
 *             properties:
 *               name:
 *                 type: string
 *               type:
 *                 type: string
 *               adapter_data:
 *                 type: object
 *     responses:
 *       200:
 *         description: Låsen ble opprettet
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 id:
 *                   type: integer
 *       400:
 *         description: Ugyldig input
 *       500:
 *         description: Serverfeil
 */
router.post('/', verifyToken, lockController.createLock);

/**
 * @swagger
 * /lock:
 *   get:
 *     summary: Hent låser som brukeren har tilgang til
 *     tags:
 *       - Lås
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Liste over låser
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 user_id:
 *                   type: integer
 *                 locks:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                       name:
 *                         type: string
 *                       type:
 *                         type: string
 *                       eier:
 *                         type: string
 *                       floor:
 *                         type: string
 *                       room:
 *                         type: string
 *                       adress:
 *                         type: string
 *                       adapter_data:
 *                         type: object
 *                       status:
 *                         type: string
 *       500:
 *         description: Feil ved henting av låser
 */
router.get('/', verifyToken, lockController.getAccessibleLocks);

/**
 * @swagger
 * /lock/{id}/status:
 *   get:
 *     summary: Hent status på lås
 *     tags:
 *       - Lås
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Lås-ID
 *     responses:
 *       200:
 *         description: Statusinformasjon
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 status:
 *                   type: string
 *       403:
 *         description: Ingen tilgang
 *       500:
 *         description: Serverfeil
 */
router.get('/:id/status', verifyToken, lockController.lockStatus);

/**
 * @swagger
 * /lock/{id}/open:
 *   post:
 *     summary: Fjernlås en lås
 *     tags:
 *       - Lås
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Låsen åpnet
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 result:
 *                   type: string
 *       403:
 *         description: Ingen tilgang
 *       500:
 *         description: Feil under åpning
 */

router.post('/:id/open', verifyToken, lockController.openLock);

/**
 * @swagger
 * /lock/{id}/lock:
 *   post:
 *     summary: Fjernlås en lås
 *     tags:
 *       - Lås
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *     responses:
 *       200:
 *         description: Låsen låst
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 success:
 *                   type: boolean
 *                 result:
 *                   type: string
 *       403:
 *         description: Ingen tilgang
 *       500:
 *         description: Feil under låsing
 */

router.post('/:id/lock', verifyToken, lockController.lockLock);
/**
 * @swagger
 * /lock/accessible:
 *   post:
 *     summary: Hent låser eid av innlogget bruker
 *     tags:
 *       - Lås
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
 *         description: Låser til bruker
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
 *                   type:
 *                     type: string
 *                   eier:
 *                     type: string
 *                   floor:
 *                     type: string
 *                   room:
 *                     type: string
 *                   adress:
 *                     type: string
 *                   adapter_data:
 *                     type: object
 */
router.post('/accessible', verifyToken, lockController.getLockList);
/**
 * @swagger
 * /lock/getbyid:
 *   post:
 *     summary: Hent en spesifikk lås ved ID
 *     tags:
 *       - Lås
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required: [id, token]
 *             properties:
 *               id:
 *                 type: integer
 *               token:
 *                 type: string
 *     responses:
 *       200:
 *         description: Låsdetaljer
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 name:
 *                   type: string
 *                 type:
 *                   type: string
 *                 eier:
 *                   type: string
 *                 floor:
 *                   type: string
 *                 room:
 *                   type: string
 *                 adress:
 *                   type: string
 *                 adapter_data:
 *                   type: object
 *                 status:
 *                   type: string
 *       404:
 *         description: Ikke funnet
 *       500:
 *         description: Serverfeil
 */
router.post('/getbyid', verifyToken, lockController.getLockById);
/**
 * @swagger
 * /lock/all_accessible:
 *   post:
 *     summary: Hent alle låser brukeren har tilgang til
 *     tags:
 *       - Lås
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
 *         description: Liste over låser
 */
router.post('/all_accessible', verifyToken, lockController.getAllAccessibleLocks);

/**
 * @swagger
 * /lock/{id}/users:
 *   get:
 *     summary: Hent brukere som har tilgang til en lås
 *     tags:
 *       - Lås
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: integer
 *         description: Lås-ID
 *     responses:
 *       200:
 *         description: Liste over brukere med tilgang
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
 *       403:
 *         description: Ingen tilgang
 *       500:
 *         description: Serverfeil
 */
router.get('/:id/users', verifyToken, lockController.getUsersForLock);

/**
 * @swagger
*   /lock/shared-users:
*     get:
*       summary: Hent alle brukere med tilgang til låser du eier eller administrerer
*       tags:
*         - Lås
*       security:
*         - bearerAuth: []
*       responses:
*         '200':
*           description: Liste over brukere med tilgang
*           content:
*             application/json:
*               schema:
*                 type: array
*                 items:
*                   type: object
*                   properties:
*                     user_id:
*                       type: integer
*                       example: 2
*                     user_name:
*                       type: string
*                       example: Ola Nordmann
*                     user_email:
*                       type: string
*                       example: ola@example.com
*                     lock_id:
*                       type: integer
*                       example: 1
*                     lock_name:
*                       type: string
*                       example: Hoveddør
*                     role:
*                       type: string
*                       example: user
*         '401':
*           description: Uautorisert (mangler eller ugyldig JWT)
*         '500':
*           description: Serverfeil
*/
router.get('/shared-users', verifyToken, lockController.getSharedUsers);

module.exports = router;
