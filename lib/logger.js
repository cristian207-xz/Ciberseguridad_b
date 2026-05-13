const { Redis } = require('@upstash/redis');

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const LOG_KEY = 'aeroseguro:logs';
const MAX_LOGS = 100;

async function log(type, ip, extra = '') {
  const entry = {
    evento: type,
    ip,
    detalle: extra,
    timestamp: new Date().toISOString()
  };
  console.log(`[${entry.timestamp}] ${type} | IP: ${ip} | ${extra}`);
  try {
    await redis.lpush(LOG_KEY, JSON.stringify(entry));
    await redis.ltrim(LOG_KEY, 0, MAX_LOGS - 1);
  } catch(e) {
    console.error('Redis error:', e);
  }
}

async function getLogs() {
  try {
    const raw = await redis.lrange(LOG_KEY, 0, -1);
    return raw.map(r => typeof r === 'string' ? JSON.parse(r) : r);
  } catch(e) {
    console.error('Redis getLogs error:', e);
    return [];
  }
}

async function clearLogs() {
  try {
    await redis.del(LOG_KEY);
  } catch(e) {
    console.error('Redis clearLogs error:', e);
  }
}

module.exports = { log, getLogs, clearLogs };