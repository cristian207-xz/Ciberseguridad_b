# ✈️ AeroSeguro — Ejercicio Red Team vs Blue Team

**Clase de Ciberseguridad** · Sistema de login con defensas implementadas

---

## 📁 Estructura del proyecto

```
Ciberseguridad_b/
├── index.html      → Landing page / portal de entrada
├── login.html      → Formulario de autenticación (con defensas)
├── admin.html      → Panel de administrador (ruta protegida)
├── cliente.html    → Portal del cliente (ruta protegida)
├── security.js     → Módulo de seguridad central (Blue Team)
└── README.md       → Este archivo
```

---

## 🔐 Defensas implementadas (Blue Team)

| Defensa | Descripción |
|--------|-------------|
| **Hashing SHA-256** | Las contraseñas nunca se comparan en texto plano |
| **Rate Limiting** | Bloqueo de 30s después de 4 intentos fallidos |
| **Guard de sesión** | admin.html y cliente.html verifican autenticación antes de cargar |
| **Token de sesión** | UUID único generado en cada login con `crypto.randomUUID()` |
| **Logs de seguridad** | Registro de LOGIN_OK, LOGIN_FAIL, LOCKOUT, ACCESS_DENIED, LOGOUT |
| **RBAC básico** | Roles diferenciados: admin vs cliente |

---

## 🗡️ Vulnerabilidades que existían antes (Red Team)

- Credenciales en texto plano en el HTML (`admin/1234`)
- Sin verificación de sesión → acceso directo por URL
- Sin límite de intentos → fuerza bruta libre
- `logout()` solo redirigía, sin destruir sesión

---

## 🌿 Ramas del proyecto

```
main                    → código estable
feature/auth-security   → login, hashing, rate limiting
feature/admin-panel     → panel admin + logs
feature/client-panel    → portal cliente
feature/logs-firewall   → security.js (módulo central)
```

---

## 🚀 Cómo ejecutar

Abrir `index.html` en el navegador. No requiere servidor.

**Credenciales de prueba:**
- Admin: `admin` / `admin123`
- Cliente: `cliente` / `cliente123`