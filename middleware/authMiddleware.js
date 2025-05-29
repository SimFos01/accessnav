const jwt = require('jsonwebtoken');
const logger = require('../utils/logger');

function verifyToken(req, res, next) {
  logger.debug('[DEBUG] Header:', req.headers.authorization);
  logger.debug('[DEBUG] Body:', req.body);
  logger.debug('[DEBUG] Query:', req.query);

  let token = null;

  if (req.headers['authorization']) {
    token = req.headers['authorization'].split(' ')[1];
  }

  if (!token && req.body?.token) {
    token = req.body.token;
  }

  if (!token && req.query?.token) {
    token = req.query.token;
  }

  if (!token) {
    console.warn('[AUTH] Ingen token funnet');
    return res.status(401).json({ error: 'Token mangler' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    logger.info('[AUTH] Token verifisert for bruker', decoded.id);
    next();
  } catch (err) {
    console.warn('[AUTH] Ugyldig token:', err.message);
    res.status(403).json({ error: 'Ugyldig token' });
  }
}



function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Krever admin-rolle' });
  }
  next();
}

module.exports = {
  verifyToken,
  requireAdmin
};

