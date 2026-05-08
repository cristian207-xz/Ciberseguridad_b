const USERS = [
  {
    id: 1,
    username: 'admin',
    passwordHash: '$2b$10$HuRK8FyDM5O7HFuBP0HNZerj2imJWoun7qwcsar/mgc25kvZa1Ulm',
    role: 'admin'
  },
  {
    id: 2,
    username: 'cliente',
    passwordHash: '$2b$10$0pOOtZzDFCEWfGxUAH2DsObmr1eBnfIWGvpxiyXTVVi7fHgMBcSQ2',
    role: 'cliente'
  }
];

function findUser(username) {
  return USERS.find(u => u.username === username) || null;
}

module.exports = { findUser };