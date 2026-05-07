const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET || 'aeroseguro_secret_2026';
const JWT_EXPIRES = '2h';

function generateToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRES }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

module.exports = { generateToken, verifyToken };