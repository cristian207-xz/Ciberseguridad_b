function log(type, ip, extra = '') {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${type} | IP: ${ip} | ${extra}`);
}

module.exports = (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const ip = req.headers['x-forwarded-for'] || 'unknown';
  log('LOGOUT', ip, 'sesión cerrada');

  return res.status(200).json({ message: 'Sesión cerrada' });
};