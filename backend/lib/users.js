const bcrypt = require('bcryptjs');

// Hashes pre-generados con bcrypt (salt rounds: 10)
// admin123 y cliente123
const USERS = [
  {
    id: 1,
    username: 'admin',
    passwordHash: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
    role: 'admin'
  },
  {
    id: 2,
    username: 'cliente',
    passwordHash: '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi',
    role: 'cliente'
  }
];

function findUser(username) {
  return USERS.find(u => u.username === username) || null;
}

module.exports = { findUser };