const bcrypt = require('bcryptjs');
const { findUser } = require('../lib/users');
const { generateToken } = require('../lib/auth');

// Rate limiting en memoria por IP
const attempts = {};
const BLOCK_TIME = 30 * 1000; // 30 segundos
const MAX_ATTEMPTS = 4;

const logger = require('../lib/logger');
const log = logger.log;
module.exports = async (req, res) => {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });

  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  }

  // Verificar bloqueo por IP
  const now = Date.now();
  if (attempts[ip] && attempts[ip].blocked) {
    if (now - attempts[ip].blockedAt < BLOCK_TIME) {
      log('LOCKOUT_BLOCKED', ip, `user: ${username}`);
      const remaining = Math.ceil((BLOCK_TIME - (now - attempts[ip].blockedAt)) / 1000);
      return res.status(429).json({ error: `IP bloqueada. Espera ${remaining} segundos.` });
    } else {
      attempts[ip] = { count: 0, blocked: false };
    }
  }

  // Buscar usuario
  const user = findUser(username);
  if (!user) {
    attempts[ip] = attempts[ip] || { count: 0 };
    attempts[ip].count++;
    log('LOGIN_FAIL', ip, `user: ${username} | motivo: usuario no existe`);
    if (attempts[ip].count >= MAX_ATTEMPTS) {
      attempts[ip].blocked = true;
      attempts[ip].blockedAt = now;
      log('LOCKOUT', ip, `user: ${username} | bloqueado 30s`);
    }
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }

  // Verificar contraseña con bcrypt
  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    attempts[ip] = attempts[ip] || { count: 0 };
    attempts[ip].count++;
    log('LOGIN_FAIL', ip, `user: ${username} | motivo: contraseña incorrecta`);
    if (attempts[ip].count >= MAX_ATTEMPTS) {
      attempts[ip].blocked = true;
      attempts[ip].blockedAt = now;
      log('LOCKOUT', ip, `user: ${username} | bloqueado 30s`);
    }
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }

  // Login exitoso
  attempts[ip] = { count: 0, blocked: false };
  const token = generateToken(user);
  log('LOGIN_OK', ip, `user: ${username} | role: ${user.role}`);

  return res.status(200).json({ token, role: user.role, username: user.username });
};