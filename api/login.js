const bcrypt = require('bcryptjs');
const { findUser } = require('../lib/users');
const { generateToken } = require('../lib/auth');
const { log } = require('../lib/logger');

const attempts = {};
const requestCount = {};
const BLOCK_TIME = 30 * 1000;
const MAX_ATTEMPTS = 4;
const EXFILTRATION_LIMIT = 20;
const EXFILTRATION_WINDOW = 60 * 1000;

async function checkExfiltration(ip) {
  const now = Date.now();
  if (!requestCount[ip]) requestCount[ip] = { count: 0, windowStart: now };
  if (now - requestCount[ip].windowStart > EXFILTRATION_WINDOW) {
    requestCount[ip] = { count: 0, windowStart: now };
  }
  requestCount[ip].count++;
  if (requestCount[ip].count > EXFILTRATION_LIMIT) {
    await log('EXFILTRATION_ATTEMPT', ip, `peticiones en 1 min: ${requestCount[ip].count} — comportamiento anómalo detectado`);
    return true;
  }
  return false;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });

  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
  const { username, password } = req.body;

  await checkExfiltration(ip);

  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  }

  const now = Date.now();

  if (attempts[ip]?.blocked) {
    if (now - attempts[ip].blockedAt < BLOCK_TIME) {
      await log('LOCKOUT_BLOCKED', ip, `user: ${username}`);
      const remaining = Math.ceil((BLOCK_TIME - (now - attempts[ip].blockedAt)) / 1000);
      return res.status(429).json({ error: `IP bloqueada. Espera ${remaining} segundos.` });
    } else {
      attempts[ip] = { count: 0, blocked: false };
    }
  }

  const user = findUser(username);
  if (!user) {
    attempts[ip] = attempts[ip] || { count: 0 };
    attempts[ip].count++;
    await log('LOGIN_FAIL', ip, `user: ${username} | motivo: usuario no existe`);
    if (attempts[ip].count >= MAX_ATTEMPTS) {
      attempts[ip].blocked = true;
      attempts[ip].blockedAt = now;
      await log('LOCKOUT', ip, `user: ${username} | bloqueado 30s`);
      return res.status(429).json({ error: 'IP bloqueada. Espera 30 segundos.' });
    }
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }

  const valid = await bcrypt.compare(password, user.passwordHash);
  if (!valid) {
    attempts[ip] = attempts[ip] || { count: 0 };
    attempts[ip].count++;
    await log('LOGIN_FAIL', ip, `user: ${username} | motivo: contraseña incorrecta`);
    if (attempts[ip].count >= MAX_ATTEMPTS) {
      attempts[ip].blocked = true;
      attempts[ip].blockedAt = now;
      await log('LOCKOUT', ip, `user: ${username} | bloqueado 30s`);
      return res.status(429).json({ error: 'IP bloqueada. Espera 30 segundos.' });
    }
    return res.status(401).json({ error: 'Credenciales incorrectas' });
  }

  attempts[ip] = { count: 0, blocked: false };
  const token = generateToken(user);
  await log('LOGIN_OK', ip, `user: ${username} | role: ${user.role}`);
  return res.status(200).json({ token, role: user.role, username: user.username });
};