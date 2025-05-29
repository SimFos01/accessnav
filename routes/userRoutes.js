const express = require('express');
const router = express.Router();
const userController = require('../controllers/userController');
const userlocksController = require('../controllers/userlocksController')
const { verifyToken } = require('../middleware/authMiddleware');

/**
 * @swagger
 * /user/login:
 *   post:
 *     summary: Logg inn en bruker
 *     tags:
 *       - Autentisering
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Returnerer en JWT-token ved suksess
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *       401:
 *         description: Ugyldig e-post eller passord
 */
router.post('/login', userController.loginUser);
/**
 * @swagger
 * /user/userlocks/shared-users:
 *   post:
 *     summary: Hent brukere en lås er delt med
 *     tags:
 *       - Brukerlås
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               lock_id:
 *                 type: integer
 *     responses:
 *       200:
 *         description: Liste over brukere
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   email:
 *                     type: string
 *                   role:
 *                     type: string
 *                   lock_count:
 *                     type: integer
 *       400:
 *         description: Mangler nødvendig data
 */

router.post('/userlocks/shared-users', userlocksController.getSharedUsers);
/**
 * @swagger
*   /user/details/{userId}:
*     get:
*       summary: Hent detaljert informasjon om en bruker og felles tilgang til låser
*       tags:
*         - Bruker
*       parameters:
*         - name: userId
*           in: path
*           required: true
*           schema:
*             type: integer
*       security:
*         - bearerAuth: []
*       responses:
*         '200':
*           description: Brukerdetaljer, felles låser og delbare låser
*           content:
*             application/json:
*               schema:
*                 type: object
*                 properties:
*                   user:
*                     type: object
*                     properties:
*                       id: { type: integer }
*                       name: { type: string }
*                       email: { type: string }
*                       phone_number: { type: string }
*                   shared_locks:
*                     type: array
*                     items:
*                       type: object
*                       properties:
*                         lock_id: { type: integer }
*                         lock_name: { type: string }
*                         user_role: { type: string }
*                         my_role: { type: string }
*                         can_remove: { type: boolean }
*                   locks_you_can_share:
*                     type: array
*                     items:
*                       type: object
*                       properties:
*                         lock_id: { type: integer }
*                         lock_name: { type: string }
*         '401': { description: Uautorisert }
*         '500': { description: Serverfeil }
*/
router.get('/details/:userId', verifyToken, userController.getUserAccessDetails);

module.exports = router;
