const logger = require('../lib/logger');
const { verifyToken } = require('../lib/auth');

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const ip = req.headers['x-forwarded-for'] || 'unknown';
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    await logger.log('ACCESS_DENIED', ip, 'ruta: /api/logs | motivo: token ausente');
    return res.status(401).json({ error: 'Token requerido' });
  }

  const token = authHeader.split(' ')[1];
  const decoded = verifyToken(token);

  if (!decoded || decoded.role !== 'admin') {
    await logger.log('ACCESS_DENIED', ip, 'ruta: /api/logs | motivo: no es admin');
    return res.status(403).json({ error: 'Acceso denegado' });
  }

  if (req.method === 'GET') {
    const logs = await logger.getLogs();
    return res.status(200).json({ logs });
  }

  if (req.method === 'DELETE') {
    await logger.log('LOG_CLEARED', ip, `user: ${decoded.username} | ALERTA: intento de borrar evidencia`);
    await logger.clearLogs();
    await logger.log('LOG_CLEARED_CONFIRMED', ip, `logs borrados por: ${decoded.username}`);
    return res.status(200).json({ message: 'Logs limpiados. Evento registrado.' });
  }

  return res.status(405).json({ error: 'Método no permitido' });
};