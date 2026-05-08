const { verifyToken } = require('../lib/auth');

const logger = require('../lib/logger');
const log = logger.log;

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const ip = req.headers['x-forwarded-for'] || 'unknown';
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    log('ACCESS_DENIED', ip, 'ruta: /api/verify | motivo: token ausente');
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);

  if (!decoded) {
    log('ACCESS_DENIED', ip, 'ruta: /api/verify | motivo: JWT inválido');
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }

  log('ACCESS_OK', ip, `user: ${decoded.username} | role: ${decoded.role}`);
  return res.status(200).json({ valid: true, user: decoded });
};