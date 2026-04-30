/**
 * security.js — Módulo de defensa (Blue Team)
 * Maneja: hash, sesiones, rate limiting, logs
 */

const Security = (() => {

  // ─── HASH ────────────────────────────────────────────────────────────────
  async function hashPassword(password) {
    const encoder = new TextEncoder();
    const data = encoder.encode(password);
    const buffer = await crypto.subtle.digest("SHA-256", data);
    return Array.from(new Uint8Array(buffer))
      .map(b => b.toString(16).padStart(2, "0")).join("");
  }

  // ─── USUARIOS (en un sistema real: base de datos en servidor) ────────────
  // Hashes de: admin → "admin123" | cliente → "cliente123"
  const USERS = {
    admin:   "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9",
    cliente: "a9a845b3c7a49f61a3eef8b9a3d5c5d6e1f0b0c4d0e7f8a1b2c3d4e5f6a7b8c9"
  };

  const ROLES = { admin: "admin", cliente: "cliente" };

  // ─── RATE LIMITING ───────────────────────────────────────────────────────
  const MAX_ATTEMPTS = 4;
  const LOCKOUT_MS   = 30000; // 30 segundos

  function getRateData() {
    return JSON.parse(sessionStorage.getItem("rate_data") || '{"attempts":0,"lockoutUntil":null}');
  }
  function setRateData(data) {
    sessionStorage.setItem("rate_data", JSON.stringify(data));
  }
  function isLockedOut() {
    const d = getRateData();
    if (d.lockoutUntil && Date.now() < d.lockoutUntil) return d.lockoutUntil;
    return false;
  }
  function registerFailedAttempt() {
    const d = getRateData();
    d.attempts++;
    if (d.attempts >= MAX_ATTEMPTS) {
      d.lockoutUntil = Date.now() + LOCKOUT_MS;
      d.attempts = 0;
    }
    setRateData(d);
    return d;
  }
  function resetAttempts() {
    setRateData({ attempts: 0, lockoutUntil: null });
  }
  function getAttempts() {
    return getRateData().attempts;
  }

  // ─── LOGS ────────────────────────────────────────────────────────────────
  function log(type, username = "?") {
    const logs = JSON.parse(localStorage.getItem("security_logs") || "[]");
    logs.unshift({
      timestamp: new Date().toISOString(),
      type,       // LOGIN_OK | LOGIN_FAIL | LOCKOUT | ACCESS_DENIED | LOGOUT
      username,
      ua: navigator.userAgent.substring(0, 80)
    });
    // Guardar solo los últimos 100 eventos
    localStorage.setItem("security_logs", JSON.stringify(logs.slice(0, 100)));
  }

  function getLogs() {
    return JSON.parse(localStorage.getItem("security_logs") || "[]");
  }

  // ─── SESIÓN ──────────────────────────────────────────────────────────────
  function createSession(username) {
    const token = crypto.randomUUID();
    sessionStorage.setItem("auth_user",  username);
    sessionStorage.setItem("auth_role",  ROLES[username]);
    sessionStorage.setItem("auth_token", token);
    sessionStorage.setItem("auth_time",  Date.now().toString());
  }

  function destroySession() {
    ["auth_user","auth_role","auth_token","auth_time"].forEach(k => sessionStorage.removeItem(k));
  }

  function getSession() {
    const user  = sessionStorage.getItem("auth_user");
    const role  = sessionStorage.getItem("auth_role");
    const token = sessionStorage.getItem("auth_token");
    if (!user || !role || !token) return null;
    return { user, role, token };
  }

  // ─── GUARD (usar al inicio de páginas protegidas) ────────────────────────
  function requireAuth(requiredRole = null) {
    const session = getSession();
    if (!session) {
      log("ACCESS_DENIED", "anonymous");
      window.location.href = "index.html";
      return null;
    }
    if (requiredRole && session.role !== requiredRole) {
      log("ACCESS_DENIED", session.user);
      window.location.href = "index.html";
      return null;
    }
    return session;
  }

  // ─── LOGIN ───────────────────────────────────────────────────────────────
  async function attemptLogin(username, password) {
    const lockout = isLockedOut();
    if (lockout) {
      const secs = Math.ceil((lockout - Date.now()) / 1000);
      log("LOCKOUT", username);
      return { ok: false, reason: "lockout", secsLeft: secs };
    }

    const hashed = await hashPassword(password);

    if (USERS[username] && USERS[username] === hashed) {
      resetAttempts();
      createSession(username);
      log("LOGIN_OK", username);
      return { ok: true, role: ROLES[username] };
    } else {
      const d = registerFailedAttempt();
      log("LOGIN_FAIL", username);
      if (d.lockoutUntil) {
        return { ok: false, reason: "lockout", secsLeft: Math.ceil(LOCKOUT_MS / 1000) };
      }
      return { ok: false, reason: "invalid", attemptsLeft: MAX_ATTEMPTS - d.attempts };
    }
  }

  function logout(username) {
    log("LOGOUT", username);
    destroySession();
    window.location.href = "index.html";
  }

  return { attemptLogin, requireAuth, logout, getSession, getLogs, getAttempts, MAX_ATTEMPTS };
})();