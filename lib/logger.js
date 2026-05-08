const logs = [];

function log(type, ip, extra = '') {
  const entry = {
    evento: type,
    ip,
    detalle: extra,
    timestamp: new Date().toISOString()
  };
  logs.push(entry);
  console.log(`[${entry.timestamp}] ${type} | IP: ${ip} | ${extra}`);
}

function getLogs() {
  return logs.slice().reverse();
}

module.exports = { log, getLogs };