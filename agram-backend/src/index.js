/**
 * Cloudflare Worker for Agram Pilates Reformer Studio Backend
 * Handles booking system, user authentication, credits, and admin actions.
 */

const ALLOWED_ORIGINS = [
  "https://pilates-reformer-agram.com",
  "https://www.pilates-reformer-agram.com",
  "http://localhost",
  "http://127.0.0.1",
  "http://example.com"
];

function getCorsHeaders(request = null) {
  const origin = request && typeof request.headers?.get === "function" ? request.headers.get("Origin") : null;
  let allowedOrigin = "https://pilates-reformer-agram.com";

  if (origin) {
    if (
      ALLOWED_ORIGINS.includes(origin) ||
      /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin) ||
      /\.pages\.dev$/.test(origin) ||
      /\.workers\.dev$/.test(origin) ||
      /\.pilates-reformer-agram\.com$/.test(origin)
    ) {
      allowedOrigin = origin;
    }
  }

  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin",
    "Content-Type": "application/json",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://calendar.google.com https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self' https:; frame-ancestors 'none';"
  };
}

function jsonResponse(data, status = 200, request = null) {
  return new Response(JSON.stringify(data), {
    status,
    headers: getCorsHeaders(request)
  });
}

// Base64Url encoding/decoding helpers
function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  const base64 = btoa(binary);
  return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function base64UrlToArrayBuffer(base64url) {
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4) {
    base64 += "=";
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

async function signHMAC(message, secret) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(message);

  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", key, messageData);
  return arrayBufferToBase64Url(signature);
}

async function verifyHMAC(message, signature, secret) {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(message);
  const signatureData = base64UrlToArrayBuffer(signature);

  const key = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"]
  );

  return await crypto.subtle.verify("HMAC", key, signatureData, messageData);
}

async function createJWT(payload, secret) {
  const now = Math.floor(Date.now() / 1000);
  const fullPayload = {
    iss: "agram-backend",
    aud: "agram-app",
    iat: now,
    exp: now + 7 * 24 * 60 * 60, // 7 days default
    ...payload
  };
  const header = { alg: "HS256", typ: "JWT" };
  const headerPart = arrayBufferToBase64Url(new TextEncoder().encode(JSON.stringify(header)));
  const payloadPart = arrayBufferToBase64Url(new TextEncoder().encode(JSON.stringify(fullPayload)));
  const message = `${headerPart}.${payloadPart}`;
  const signaturePart = await signHMAC(message, secret);
  return `${message}.${signaturePart}`;
}

async function verifyJWT(token, secret) {
  if (!token || typeof token !== "string" || !secret) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;

  const [headerPart, payloadPart, signaturePart] = parts;

  // 1. Verify Header (alg === "HS256" && typ === "JWT")
  try {
    const header = JSON.parse(new TextDecoder().decode(base64UrlToArrayBuffer(headerPart)));
    if (!header || header.alg !== "HS256" || header.typ !== "JWT") {
      return null;
    }
  } catch (e) {
    return null;
  }

  // 2. Verify HMAC Signature
  const message = `${headerPart}.${payloadPart}`;
  const isValid = await verifyHMAC(message, signaturePart, secret);
  if (!isValid) return null;

  // 3. Verify Payload Claims (exp, iat, iss, aud, token_version)
  try {
    const payload = JSON.parse(new TextDecoder().decode(base64UrlToArrayBuffer(payloadPart)));
    const now = Math.floor(Date.now() / 1000);

    // Require valid exp, iat, iss, aud, and token_version
    if (!payload.exp || typeof payload.exp !== "number" || now > payload.exp) {
      return null;
    }
    if (!payload.iat || typeof payload.iat !== "number") {
      return null;
    }
    if (payload.iss !== "agram-backend" || payload.aud !== "agram-app") {
      return null;
    }
    if (payload.token_version === undefined || payload.token_version === null) {
      return null;
    }

    return payload;
  } catch (e) {
    return null;
  }
}

function getJwtSecret(env) {
  if (env && env.JWT_SECRET) {
    return env.JWT_SECRET;
  }
  if (typeof process !== "undefined" && process.env && process.env.NODE_ENV === "test") {
    return "vitest-testing-jwt-secret-key-32-bytes!!";
  }
  throw new Error("Missing JWT_SECRET environment variable in Cloudflare Worker configuration.");
}

async function getAuthUser(request, env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return null;
  }
  const token = authHeader.substring(7);
  let secret;
  try {
    secret = getJwtSecret(env);
  } catch (err) {
    console.error("JWT Secret Error:", err.message);
    return null;
  }

  const decoded = await verifyJWT(token, secret);
  if (!decoded || !decoded.user_id) {
    return null;
  }

  await ensureDbColumns(env);

  // Live database check for account status, admin role, and token_version match
  const dbUser = await env.DB.prepare(
    "SELECT id, username, email, is_admin, status, COALESCE(token_version, 1) as token_version FROM Clients WHERE id = ?"
  ).bind(decoded.user_id).first();

  if (!dbUser) {
    return null;
  }

  // Reject suspended or pending accounts
  if (dbUser.status === 'suspended' || dbUser.status === 'pending') {
    return null;
  }

  // Reject tokens with missing or stale token_version
  if (decoded.token_version === undefined || decoded.token_version !== dbUser.token_version) {
    return null;
  }

  return {
    user_id: dbUser.id,
    is_admin: dbUser.is_admin,
    username: dbUser.username,
    email: dbUser.email,
    token_version: dbUser.token_version
  };
}

const TARGET_PBKDF2_ITERATIONS = 100000;

function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

// Validate password strength (at least 8 characters, at most 128)
function validatePasswordStrength(password) {
  if (!password || typeof password !== 'string') {
    return "Lozinka je obavezna.";
  }
  if (password.length < 8) {
    return "Lozinka mora imati najmanje 8 znakova.";
  }
  if (password.length > 128) {
    return "Lozinka ne smije imati više od 128 znakova.";
  }
  return null;
}

// Input validation helpers for email, username, names, phone, dates, times, and image URLs
function validateAndNormalizeEmail(email) {
  if (!email || typeof email !== 'string') return null;
  const trimmed = email.trim().toLowerCase();
  if (trimmed.length > 254) return null;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(trimmed) ? trimmed : null;
}

function validateUsername(username) {
  if (!username || typeof username !== 'string') return "Korisničko ime je obavezno.";
  const trimmed = username.trim();
  if (trimmed.length < 3 || trimmed.length > 50) return "Korisničko ime mora imati između 3 i 50 znakova.";
  if (!/^[a-zA-Z0-9_.-]+$/.test(trimmed)) return "Korisničko ime smije sadržavati samo slova, brojeve, točku, crticu i donju crtu.";
  return null;
}

function validateName(name, fieldName = "Ime") {
  if (!name || typeof name !== 'string') return `${fieldName} je obavezno polje.`;
  const trimmed = name.trim();
  if (trimmed.length < 1 || trimmed.length > 50) return `${fieldName} mora imati između 1 i 50 znakova.`;
  return null;
}

function validatePhone(phone) {
  if (!phone || typeof phone !== 'string') return "Kontakt broj je obavezan.";
  const trimmed = phone.trim();
  if (trimmed.length < 6 || trimmed.length > 25) return "Kontakt broj mora imati između 6 i 25 znakova.";
  if (!/^[0-9+\s()-]+$/.test(trimmed)) return "Broj telefona sadrži nevažeće znakove.";
  return null;
}

function validateDateStr(dateStr) {
  if (!dateStr || typeof dateStr !== 'string') return false;
  return /^\d{4}-\d{2}-\d{2}$/.test(dateStr);
}

function validateTimeStr(timeStr) {
  if (!timeStr || typeof timeStr !== 'string') return false;
  return /^([01]\d|2[0-3]):[0-5]\d$/.test(timeStr);
}

function validateCapacity(cap) {
  const num = parseInt(cap, 10);
  return !isNaN(num) && num >= 1 && num <= 20 ? num : null;
}

function validateImageUrl(urlStr) {
  if (!urlStr) return null;
  if (typeof urlStr !== 'string' || urlStr.length > 1000) return "URL slike je predugačak ili neispravan.";
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return "URL slike mora koristiti HTTP ili HTTPS protokol.";
    return null;
  } catch (e) {
    return "Neispravan format URL-a slike.";
  }
}

// HTML escaping utility for sanitizing user inputs in HTML responses/emails
function escapeHtml(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Compute legacy SHA-256 hash
async function hashPasswordSha256(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

// Secure password hashing utility using PBKDF2 with SHA-256, 600,000 iterations (OWASP recommendation), and random salt
async function hashPassword(password, iterations = TARGET_PBKDF2_ITERATIONS) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits", "deriveKey"]
  );
  const derivedKey = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: iterations,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );
  const saltHex = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
  const hashHex = Array.from(new Uint8Array(derivedKey)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `pbkdf2:${iterations}:${saltHex}:${hashHex}`;
}

// Verify candidate password against stored password string (supports PBKDF2 and legacy SHA-256)
async function verifyPassword(password, storedPassword) {
  if (!storedPassword || !password || typeof password !== 'string' || password.length > 128) {
    return { valid: false, needsRehash: false };
  }

  if (storedPassword.startsWith("pbkdf2:")) {
    const parts = storedPassword.split(":");
    if (parts.length !== 4) return { valid: false, needsRehash: false };
    let iterations = parseInt(parts[1], 10);
    if (isNaN(iterations) || iterations <= 0) return { valid: false, needsRehash: false };
    if (iterations > 100000) iterations = 100000;
    const saltHex = parts[2];
    const targetHashHex = parts[3];

    const saltBytes = saltHex.match(/.{1,2}/g);
    if (!saltBytes) return { valid: false, needsRehash: false };
    const salt = new Uint8Array(saltBytes.map(byte => parseInt(byte, 16)));

    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits", "deriveKey"]
    );
    const derivedKey = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: iterations,
        hash: "SHA-256"
      },
      keyMaterial,
      256
    );
    const candidateHashHex = Array.from(new Uint8Array(derivedKey)).map(b => b.toString(16).padStart(2, '0')).join('');
    const isValid = timingSafeEqual(candidateHashHex, targetHashHex);
    const needsRehash = isValid && (iterations < TARGET_PBKDF2_ITERATIONS);
    return { valid: isValid, needsRehash };
  }

  const legacyHash = await hashPasswordSha256(password);
  const isValid = timingSafeEqual(legacyHash, storedPassword);
  return { valid: isValid, needsRehash: isValid };
}

// Generate cryptographically secure random token (hex)
function generateSecureToken(length = 32) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// Generate cryptographically secure temporary password
function generateTempPassword() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
  const array = new Uint8Array(10);
  crypto.getRandomValues(array);
  let password = "Ag-";
  for (let i = 0; i < array.length; i++) {
    password += chars.charAt(array[i] % chars.length);
  }
  return password;
}

// AES-256-GCM Application-Level Encryption for Sensitive Health Data (GDPR Compliance)
async function encryptHealthData(textData, envSecret) {
  if (!textData) return null;
  const encoder = new TextEncoder();
  const secretKeyData = encoder.encode(envSecret || "agram-health-secret-key-32bytes-min!");
  const key = await crypto.subtle.importKey(
    "raw",
    await crypto.subtle.digest("SHA-256", secretKeyData),
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    encoder.encode(textData)
  );
  const ivHex = Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join('');
  const encryptedHex = Array.from(new Uint8Array(encrypted)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `enc:${ivHex}:${encryptedHex}`;
}

async function decryptHealthData(cipherText, envSecret) {
  if (!cipherText) return null;
  if (!cipherText.startsWith("enc:")) {
    return cipherText;
  }
  try {
    const parts = cipherText.split(":");
    if (parts.length !== 3) return null;
    const ivHex = parts[1];
    const encryptedHex = parts[2];

    const iv = new Uint8Array(ivHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    const encrypted = new Uint8Array(encryptedHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

    const encoder = new TextEncoder();
    const secretKeyData = encoder.encode(envSecret || "agram-health-secret-key-32bytes-min!");
    const key = await crypto.subtle.importKey(
      "raw",
      await crypto.subtle.digest("SHA-256", secretKeyData),
      { name: "AES-GCM" },
      false,
      ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encrypted
    );
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    console.error("Error decrypting health questionnaire:", e);
    return null;
  }
}

// Log activity to database
async function logActivity(env, details) {
  try {
    await env.DB.prepare("INSERT INTO ActivityLogs (details) VALUES (?)").bind(details).run();
  } catch (e) {
    console.error("Greška pri bilježenju aktivnosti:", e);
  }
}

// Get current date and time in Croatia timezone (Europe/Zagreb)
function getCroatiaNow(dateInput = null) {
  const d = dateInput ? new Date(dateInput) : new Date();
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone: "Europe/Zagreb",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false
  });
  const parts = formatter.formatToParts(d);
  const partVal = type => parts.find(p => p.type === type).value;
  return new Date(`${partVal('year')}-${partVal('month')}-${partVal('day')}T${partVal('hour')}:${partVal('minute')}:${partVal('second')}`);
}

// Format date to human-readable Croatia timezone string (YYYY-MM-DD HH:MM:SS)
function formatCroatiaString(dateInput = null) {
  const d = dateInput ? new Date(dateInput) : new Date();
  const formatter = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Europe/Zagreb",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
    hour12: false
  });
  const parts = formatter.formatToParts(d);
  const partVal = type => parts.find(p => p.type === type).value;
  return `${partVal('year')}-${partVal('month')}-${partVal('day')} ${partVal('hour')}:${partVal('minute')}:${partVal('second')}`;
}

// Format Date object to YYYY-MM-DD
function formatDate(dateObj) {
  const year = dateObj.getFullYear();
  const month = String(dateObj.getMonth() + 1).padStart(2, '0');
  const day = String(dateObj.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

// Format Date object to YYYY-MM-DDTHH:MM:SS
function formatLocalDateTimeISO(dateObj) {
  const year = dateObj.getFullYear();
  const month = String(dateObj.getMonth() + 1).padStart(2, '0');
  const day = String(dateObj.getDate()).padStart(2, '0');
  const hours = String(dateObj.getHours()).padStart(2, '0');
  const minutes = String(dateObj.getMinutes()).padStart(2, '0');
  const seconds = String(dateObj.getSeconds()).padStart(2, '0');
  return `${year}-${month}-${day}T${hours}:${minutes}:${seconds}`;
}

// Calculate base Monday for schedule generation
function getGenerationBaseMonday(dateObj) {
  const day = dateObj.getDay(); // 0 = Sun, 1 = Mon, ..., 6 = Sat
  if (day === 0) {
    // If Sunday, the base Monday is tomorrow (add 1 day)
    return new Date(dateObj.getTime() + 1 * 24 * 60 * 60 * 1000);
  } else {
    // If Monday-Saturday, the base Monday is this week's Monday
    const daysToSubtract = day - 1;
    return new Date(dateObj.getTime() - daysToSubtract * 24 * 60 * 60 * 1000);
  }
}

// Automatically generate weekly schedule for 3 weeks starting from baseMonday (idempotent)
async function autoGenerateWeeks(env, baseMonday) {
  try {
    const instructorName = "Adrijana";
    const morningHours = ["07:00", "08:00", "09:00", "10:00"];
    const afternoonHours = ["16:00", "17:00", "18:00", "19:00", "20:00"];
    const allHours = [...morningHours, ...afternoonHours];

    // Generate Week 1 (baseMonday), Week 2 (baseMonday + 7 days), Week 3 (baseMonday + 14 days)
    for (let weekOffset = 0; weekOffset <= 2; weekOffset++) {
      const mondayDate = new Date(baseMonday.getTime() + weekOffset * 7 * 24 * 60 * 60 * 1000);
      const queries = [];

      for (let dayOffset = 0; dayOffset < 5; dayOffset++) {
        const currentDay = new Date(mondayDate.getTime() + dayOffset * 24 * 60 * 60 * 1000);
        const dateStr = formatDate(currentDay);

        allHours.forEach(time => {
          let type = "grupni";
          let capacity = 4;
          let title = "Grupni trening";

          queries.push(
            env.DB.prepare(`
              INSERT INTO Sessions (title, instructor, date, time, capacity, type)
              SELECT ?, ?, ?, ?, ?, ?
              WHERE NOT EXISTS (
                SELECT 1 FROM Sessions WHERE date = ? AND time = ?
              )
            `).bind(title, instructorName, dateStr, time, capacity, type, dateStr, time)
          );
        });
      }

      if (queries.length > 0) {
        await env.DB.batch(queries);
      }
    }
    console.log(`autoGenerateWeeks: Checked and initialized schedule starting from base Monday ${formatDate(baseMonday)}.`);
  } catch (error) {
    console.error("autoGenerateWeeks failed:", error);
  }
}

// Ensure database columns and tables exist (auto-migration fallback)
async function ensureDbColumns(env) {
  if (!env || !env.DB) return;
  const alterQueries = [
    "ALTER TABLE Clients ADD COLUMN has_seen_onboarding INTEGER DEFAULT 0",
    "ALTER TABLE Clients ADD COLUMN token_version INTEGER DEFAULT 1",
    "ALTER TABLE Clients ADD COLUMN reset_token_hash TEXT",
    "ALTER TABLE Clients ADD COLUMN reset_token_expires INTEGER",
    "ALTER TABLE Clients ADD COLUMN full_name TEXT",
    "ALTER TABLE Clients ADD COLUMN first_name TEXT",
    "ALTER TABLE Clients ADD COLUMN last_name TEXT",
    "ALTER TABLE Clients ADD COLUMN phone TEXT",
    "ALTER TABLE Clients ADD COLUMN questionnaire TEXT"
  ];

  for (const q of alterQueries) {
    try {
      await env.DB.prepare(q).run();
    } catch (e) {}
  }

  const tableQueries = [
    `CREATE TABLE IF NOT EXISTS SentReminders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      target_date TEXT NOT NULL,
      reminder_type TEXT NOT NULL DEFAULT '24h_booking',
      sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, target_date, reminder_type)
    )`,
    `CREATE TABLE IF NOT EXISTS RateLimits (
      key TEXT PRIMARY KEY,
      attempts INTEGER DEFAULT 1,
      first_attempt INTEGER,
      last_attempt INTEGER
    )`,
    `CREATE TABLE IF NOT EXISTS ActivityLogs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      details TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS PackageRequests (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      package_name TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`,
    `CREATE TABLE IF NOT EXISTS ClientNotifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      message TEXT NOT NULL,
      is_read INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )`
  ];

  for (const q of tableQueries) {
    try {
      await env.DB.prepare(q).run();
    } catch (e) {}
  }
}

function getClientIp(request) {
  return request.headers.get("cf-connecting-ip") ||
         request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
         "127.0.0.1";
}

async function checkRateLimit(env, ip, action, maxAttempts = 5, windowSeconds = 60) {
  if (!env || !env.DB) return { allowed: true };
  const key = `${action}:${ip}`;
  const now = Math.floor(Date.now() / 1000);

  try {
    const record = await env.DB.prepare(
      "SELECT attempts, first_attempt FROM RateLimits WHERE key = ?"
    ).bind(key).first();

    if (!record) {
      await env.DB.prepare(
        "INSERT INTO RateLimits (key, attempts, first_attempt, last_attempt) VALUES (?, 1, ?, ?)"
      ).bind(key, now, now).run();
      return { allowed: true };
    }

    if (now - record.first_attempt > windowSeconds) {
      await env.DB.prepare(
        "UPDATE RateLimits SET attempts = 1, first_attempt = ?, last_attempt = ? WHERE key = ?"
      ).bind(now, now, key).run();
      return { allowed: true };
    }

    if (record.attempts >= maxAttempts) {
      const retryAfter = windowSeconds - (now - record.first_attempt);
      return { allowed: false, retryAfter: Math.max(retryAfter, 1) };
    }

    await env.DB.prepare(
      "UPDATE RateLimits SET attempts = attempts + 1, last_attempt = ? WHERE key = ?"
    ).bind(now, key).run();

    return { allowed: true };
  } catch (e) {
    console.error("Rate limit check error:", e);
    return { allowed: true };
  }
}

// Check if Week 3 Monday has sessions, if not, generate schedules
async function checkAndAutoGenerateSchedules(env) {
  try {
    await ensureDbColumns(env);
    const croatiaNow = getCroatiaNow();
    const baseMonday = getGenerationBaseMonday(croatiaNow);
    
    // Check if the Monday of Week 3 (baseMonday + 14 days) already has sessions
    const targetMonday = new Date(baseMonday.getTime() + 14 * 24 * 60 * 60 * 1000);
    const targetMondayStr = formatDate(targetMonday);
    
    const hasSessions = await env.DB.prepare("SELECT 1 FROM Sessions WHERE date = ? LIMIT 1").bind(targetMondayStr).first();
    if (!hasSessions) {
      console.log(`checkAndAutoGenerateSchedules: Week 3 Monday (${targetMondayStr}) has no sessions. Triggering generation...`);
      await autoGenerateWeeks(env, baseMonday);
    }
  } catch (error) {
    console.error("checkAndAutoGenerateSchedules failed:", error);
  }
}

// Allowed packages whitelist & limits
const ALLOWED_PACKAGES = {
  "Paket 4": 4,
  "Paket 8": 8,
  "Paket 12": 12,
  "Paket 16": 16,
  "Poluindividualni 4": 4,
  "Poluindividualni 8": 8,
  "Poluindividualni 12": 12,
  "Privatni 4": 4,
  "Privatni 8": 8,
  "Privatni 12": 12,
  "Nema paketa": 0,
  "Bez paketa": 0
};

// Helper to get limit from package name
function getPackageLimit(packageName) {
  if (!packageName || packageName === "Nema paketa" || packageName === "Bez paketa") {
    return 0;
  }
  if (ALLOWED_PACKAGES[packageName] !== undefined) {
    return ALLOWED_PACKAGES[packageName];
  }
  const match = packageName.match(/\d+/);
  if (!match) return 0;
  const val = parseInt(match[0], 10);
  return (val > 0 && val <= 50) ? val : 0;
}

// Send email using Resend API
async function sendEmail(env, to, subject, htmlContent, idempotencyKey = null) {
  const apiKey = env.RESEND_API_KEY;
  if (!apiKey) {
    console.warn("RESEND_API_KEY is not defined. Skipping email sending (mock success).");
    return true;
  }

  let recipient = to;
  let emailSubject = subject;
  
  // Sandbox mode: if EMAIL_SANDBOX_MODE is true or default sender is used, redirect all emails to the specified test address.
  const isSandbox = env.EMAIL_SANDBOX_MODE !== "false" && (env.EMAIL_SANDBOX_MODE === "true" || !env.EMAIL_FROM_ADDRESS);
  const redirectTo = env.EMAIL_REDIRECT_TO || "filip.kontek@gmail.com";
  
  if (isSandbox && redirectTo) {
    recipient = redirectTo;
    emailSubject = `[TEST ZA: ${to}] ${subject}`;
  }

  const fromAddress = env.EMAIL_FROM_ADDRESS || "Agram Pilates <onboarding@resend.dev>";

  const headers = {
    "Authorization": `Bearer ${apiKey}`,
    "Content-Type": "application/json"
  };
  if (idempotencyKey) {
    headers["Idempotency-Key"] = idempotencyKey;
  }

  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers,
      body: JSON.stringify({
        from: fromAddress,
        to: [recipient],
        subject: emailSubject,
        html: htmlContent
      })
    });
    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      console.error(`[Resend Error] Status ${res.status}: ${errText.substring(0, 300)}`);
      return false;
    }
    return true;
  } catch (e) {
    console.error("Error sending email:", e);
    return false;
  }
}

// Auto-book first eligible waitlisted user when a session spot opens up
async function notifyWaitlist(env, sessionId) {
  try {
    // 1. Get session details
    const session = await env.DB.prepare("SELECT id, title, date, time, capacity FROM Sessions WHERE id = ?").bind(sessionId).first();
    if (!session) return;

    // 2. Check if there is actually a free spot
    const countObj = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM Bookings WHERE session_id = ? AND status >= 0"
    ).bind(sessionId).first();
    const bookedCount = countObj ? countObj.count : 0;
    if (bookedCount >= session.capacity) return; // No free spot

    // 3. Find waitlisted users ordered by FIFO (earliest first)
    const waitlisted = await env.DB.prepare(`
      SELECT w.id as waitlist_id, w.user_id, c.username, c.email, c.remaining_credits, c.package_expires, c.package_name, c.status
      FROM Waitlists w
      JOIN Clients c ON w.user_id = c.id
      WHERE w.session_id = ?
      ORDER BY w.created_at ASC
    `).bind(sessionId).all();

    if (!waitlisted.results || waitlisted.results.length === 0) return;

    const dateStr = session.date.split('-').reverse().join('.') + '.';
    const todayStr = formatDate(getCroatiaNow());

    // Auto-cleanup past waitlists for expired sessions
    await env.DB.prepare("DELETE FROM Waitlists WHERE session_id IN (SELECT id FROM Sessions WHERE date < ?)").bind(todayStr).run();

    // 4. Try to auto-book the first eligible waitlisted user atomically
    for (const user of waitlisted.results) {
      // Auto-prune ineligible users from waitlist so they don't clog position 1
      if (user.status === "frozen" || user.remaining_credits <= 0 || (user.package_expires && user.package_expires < todayStr)) {
        await env.DB.prepare("DELETE FROM Waitlists WHERE id = ?").bind(user.waitlist_id).run();
        continue;
      }

      // Skip users who already have an active booking on the same day
      const existingBookingToday = await env.DB.prepare(`
        SELECT b.id FROM Bookings b
        JOIN Sessions s ON b.session_id = s.id
        WHERE b.user_id = ? AND s.date = ? AND b.status >= 0
      `).bind(user.user_id, session.date).first();
      if (existingBookingToday) continue;

      // Prepare atomic batch transaction for waitlist promotion
      const confirmMsg = `Automatski ste dodani u termin '${session.title}' (${dateStr} u ${session.time}h) s liste čekanja. Kredit je oduzet.`;
      
      const [insertRes, creditRes, deleteWaitlistRes] = await env.DB.batch([
        env.DB.prepare(`
          INSERT INTO Bookings (session_id, user_id, status)
          SELECT ?, ?, 0
          WHERE (
            SELECT COUNT(*) FROM Bookings WHERE session_id = ? AND status >= 0
          ) < (SELECT capacity FROM Sessions WHERE id = ?)
          AND NOT EXISTS (
            SELECT 1 FROM Bookings b JOIN Sessions s ON b.session_id = s.id
            WHERE b.user_id = ? AND s.date = ? AND b.status >= 0
          )
        `).bind(sessionId, user.user_id, sessionId, sessionId, user.user_id, session.date),
        env.DB.prepare(
          "UPDATE Clients SET remaining_credits = remaining_credits - 1 WHERE id = ? AND remaining_credits > 0"
        ).bind(user.user_id),
        env.DB.prepare(
          "DELETE FROM Waitlists WHERE id = ?"
        ).bind(user.waitlist_id),
        env.DB.prepare(
          "INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)"
        ).bind(user.user_id, confirmMsg)
      ]);

      const insertOk = insertRes && insertRes.meta && insertRes.meta.changes === 1;
      const creditOk = creditRes && creditRes.meta && creditRes.meta.changes === 1;
      const deleteOk = deleteWaitlistRes && deleteWaitlistRes.meta && deleteWaitlistRes.meta.changes === 1;

      if (insertOk && creditOk && deleteOk) {
        // Send confirmation email
        const emailSubject = `Dodani ste u termin: ${session.title}`;
        const emailHtml = `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5; border: 1px solid #ebdcc5; border-radius: 6px; max-width: 480px; margin: 0 auto;">
            <h2 style="color: #a98e65; margin-top: 0; text-transform: uppercase; font-size: 1.2rem; border-bottom: 1.5px solid #ebdcc5; padding-bottom: 6px;">Dodani ste u termin!</h2>
            <p>Bok <b>${user.username}</b>,</p>
            <p>Oslobodilo se mjesto i automatski ste dodani u termin s liste čekanja:</p>
            <table style="border-spacing: 10px; margin-bottom: 20px; font-size: 0.9rem;">
              <tr><td><b>Termin:</b></td><td>${session.title}</td></tr>
              <tr><td><b>Datum i vrijeme:</b></td><td>${dateStr} u ${session.time}h</td></tr>
            </table>
            <p>Vidimo se!</p>
            <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
            <p style="font-size: 11px; color: #7c7267; text-align: center; margin: 0;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
          </div>
        `;
        await sendEmail(env, user.email, emailSubject, emailHtml);

        await logActivity(env, `Wait lista → booking: ${user.username} → ${session.title} (${dateStr}, ${session.time}h)`);
        break; // Stop after successfully promoting one user
      } else {
        // Rollback credit if credit deduction succeeded but booking/waitlist delete failed
        if (creditOk && (!insertOk || !deleteOk)) {
          await env.DB.prepare("UPDATE Clients SET remaining_credits = remaining_credits + 1 WHERE id = ?").bind(user.user_id).run();
        }
      }
    }
  } catch (e) {
    console.error("Greška u notifyWaitlist:", e);
  }
}

// Auto-confirm bookings starting in less than 12 hours as attended (status = 1)
async function autoConfirmBookings(env) {
  try {
    const nowCroatia = getCroatiaNow();
    
    // Select all bookings that are currently in status = 0 (Reserved)
    const activeBookings = await env.DB.prepare(`
      SELECT b.id, s.date, s.time, c.username
      FROM Bookings b
      JOIN Sessions s ON b.session_id = s.id
      JOIN Clients c ON b.user_id = c.id
      WHERE b.status = 0
    `).all();

    if (activeBookings.results && activeBookings.results.length > 0) {
      const updates = [];
      for (const b of activeBookings.results) {
        const sessionTime = new Date(`${b.date}T${b.time}:00`);
        const diffHours = (sessionTime.getTime() - nowCroatia.getTime()) / (1000 * 60 * 60);
        if (diffHours < 12) {
          // Less than 12 hours remaining, auto-confirm as attended (status = 1)
          updates.push(env.DB.prepare("UPDATE Bookings SET status = 1 WHERE id = ?").bind(b.id));
          await logActivity(env, `Auto check-in: ${b.username} (manje od 12h do termina)`);
        }
      }
      if (updates.length > 0) {
        await env.DB.batch(updates);
      }
    }

    // Auto-cleanup past waitlists for expired sessions
    const todayStr = formatDate(nowCroatia);
    await env.DB.prepare("DELETE FROM Waitlists WHERE session_id IN (SELECT id FROM Sessions WHERE date < ?)").bind(todayStr).run();
  } catch (e) {
    console.error("Error in autoConfirmBookings:", e);
  }
}

// Calculate Monday and Friday date of the current week (Croatia time)
function getWeeklyReportDates() {
  const croatiaNow = getCroatiaNow();
  const currentDay = croatiaNow.getDay(); // 0 = Sun, 1 = Mon, ..., 5 = Fri, 6 = Sat
  
  // We want Monday of the current week
  const daysToSubtract = currentDay === 0 ? 6 : (currentDay - 1);
  
  const monday = new Date(croatiaNow.getTime() - daysToSubtract * 24 * 60 * 60 * 1000);
  const friday = new Date(monday.getTime() + 4 * 24 * 60 * 60 * 1000);
  
  return {
    mondayStr: formatDate(monday),
    fridayStr: formatDate(friday),
    mondayFormatted: formatDate(monday).split('-').reverse().join('.') + '.',
    fridayFormatted: formatDate(friday).split('-').reverse().join('.') + '.'
  };
}

// Generate and send weekly check-in report email to admin
async function sendWeeklyReportEmail(env) {
  try {
    const dates = getWeeklyReportDates();
    
    // 1. Get all sessions for the week
    const sessionsRes = await env.DB.prepare(`
      SELECT id, title, date, time, instructor, type 
      FROM Sessions 
      WHERE date >= ? AND date <= ?
      ORDER BY date ASC, time ASC
    `).bind(dates.mondayStr, dates.fridayStr).all();

    const sessions = sessionsRes.results || [];

    if (sessions.length === 0) {
      console.log(`No sessions scheduled between ${dates.mondayStr} and ${dates.fridayStr}. Skipping weekly report.`);
      return true;
    }

    // 2. Get checked-in attendees for the week (status = 1)
    const attendeesRes = await env.DB.prepare(`
      SELECT b.session_id, c.username, c.full_name, c.email
      FROM Bookings b
      JOIN Clients c ON b.user_id = c.id
      JOIN Sessions s ON b.session_id = s.id
      WHERE s.date >= ? AND s.date <= ? AND b.status = 1
    `).bind(dates.mondayStr, dates.fridayStr).all();

    const attendees = attendeesRes.results || [];

    // Group sessions by date
    const grouped = {};
    sessions.forEach(session => {
      if (!grouped[session.date]) {
        grouped[session.date] = [];
      }
      grouped[session.date].push(session);
    });

    const dayNames = {
      1: "Ponedjeljak",
      2: "Utorak",
      3: "Srijeda",
      4: "Četvrtak",
      5: "Petak",
      6: "Subota",
      0: "Nedjelja"
    };

    let reportHtml = "";

    // Sort dates
    const sortedDates = Object.keys(grouped).sort();
    
    sortedDates.forEach(dateStr => {
      const [y, m, d] = dateStr.split('-').map(Number);
      const localDate = new Date(y, m - 1, d);
      const dayName = dayNames[localDate.getDay()] || "Nepoznato";
      const dateFormatted = `${String(d).padStart(2, '0')}.${String(m).padStart(2, '0')}.${y}.`;

      reportHtml += `
        <div style="margin-top: 12px; margin-bottom: 4px; font-weight: bold; color: #a98e65; font-size: 0.95rem; text-transform: uppercase; border-bottom: 1px solid #ebdcc5; padding-bottom: 2px;">
          ${dayName} (${dateFormatted})
        </div>
      `;

      grouped[dateStr].forEach(session => {
        const sessionAttendees = attendees.filter(a => a.session_id === session.id);
        
        let attendeesListHtml = "";
        if (sessionAttendees.length === 0) {
          attendeesListHtml = `<li style="color: #7c7267; font-style: italic; list-style-type: none; margin-left: 0; padding-left: 0;">Nije bilo odrađenih dolazaka.</li>`;
        } else {
          attendeesListHtml = sessionAttendees.map(att => {
            const displayName = att.full_name ? `${att.full_name} (${att.username})` : att.username;
            return `<li style="margin-bottom: 4px;"><b>${displayName}</b></li>`;
          }).join('');
        }

        reportHtml += `
          <div style="background-color: #ffffff; padding: 6px 10px; border-radius: 4px; border: 1px solid rgba(197, 168, 128, 0.15); margin-bottom: 6px; margin-top: 4px;">
            <div style="font-size: 0.85rem; color: #2c251e; margin-bottom: 2px;">
              <span style="font-weight: bold; border-left: 2px solid #c5a880; padding-left: 6px;">${session.time}h — ${session.title}</span>
              <span style="color: #7c7267; font-size: 0.75rem; margin-left: 5px;">(Trener: ${session.instructor})</span>
            </div>
            <ul style="margin: 0; padding-left: 15px; font-size: 0.8rem; color: #2c251e; line-height: 1.2rem;">
              ${attendeesListHtml}
            </ul>
          </div>
        `;
      });
    });

    const adminEmail = env.ADMIN_REPORT_EMAIL || "adrijana.kontek@gmail.com";
    const subject = `Agram Pilates - Tjedno izvješće o dolascima (${dates.mondayFormatted} - ${dates.fridayFormatted})`;
    
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; padding: 15px; color: #2c251e; background-color: #faf8f5; border: 1px solid #ebdcc5; border-radius: 6px; max-width: 480px; margin: 0 auto;">
        <h2 style="color: #a98e65; border-bottom: 1.5px solid #ebdcc5; padding-bottom: 6px; margin-top: 0; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; font-size: 1.1rem;">
          Tjedno izvješće o dolascima
        </h2>
        <p style="font-size: 0.85rem; font-weight: bold; color: #7c7267; margin: 0 0 12px 0;">
          Razdoblje: ${dates.mondayFormatted} do ${dates.fridayFormatted}
        </p>
        
        <div>
          ${reportHtml}
        </div>
        
        <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 20px; margin-bottom: 10px;">
        <p style="font-size: 10px; color: #7c7267; text-align: center; margin: 0;">
          Ova poruka je poslana automatski iz sustava Agram Pilates.
        </p>
      </div>
    `;

    const success = await sendEmail(env, adminEmail, subject, htmlContent);
    if (success) {
      console.log(`Weekly report email sent successfully to ${adminEmail}`);
    } else {
      console.error(`Failed to send weekly report email to ${adminEmail}`);
    }
    return success;
  } catch (e) {
    console.error("Error sending weekly report email:", e);
    return false;
  }
}

// Generate and send daily check-in report email to admin
async function sendDailyReportEmail(env, dateStr = null) {
  try {
    const croatiaNow = getCroatiaNow();
    const todayStr = dateStr || formatDate(croatiaNow); // YYYY-MM-DD
    const dateFormatted = todayStr.split('-').reverse().join('.') + '.';

    // 1. Get all sessions for today
    const sessionsRes = await env.DB.prepare(`
      SELECT id, title, time, instructor, type 
      FROM Sessions 
      WHERE date = ? 
      ORDER BY time ASC
    `).bind(todayStr).all();

    const sessions = sessionsRes.results || [];

    // If there are no sessions, we skip sending
    if (sessions.length === 0) {
      console.log(`No sessions scheduled for ${todayStr}. Skipping daily report email.`);
      return true;
    }

    // 2. Get checked-in attendees for all sessions of today (status = 1 means checked-in / attended)
    const attendeesRes = await env.DB.prepare(`
      SELECT b.session_id, c.username, c.full_name, c.email, c.total_credits, c.remaining_credits
      FROM Bookings b
      JOIN Clients c ON b.user_id = c.id
      JOIN Sessions s ON b.session_id = s.id
      WHERE s.date = ? AND b.status = 1
    `).bind(todayStr).all();

    const attendees = attendeesRes.results || [];

    // 3. Build HTML report
    let sessionsHtml = "";
    
    sessions.forEach(session => {
      const sessionAttendees = attendees.filter(a => a.session_id === session.id);
      
      let attendeesListHtml = "";
      if (sessionAttendees.length === 0) {
        attendeesListHtml = `<li style="color: #7c7267; font-style: italic; list-style-type: none; margin-left: 0; padding-left: 0;">Nije bilo odrađenih dolazaka.</li>`;
      } else {
        attendeesListHtml = sessionAttendees.map(att => {
          const displayName = att.full_name ? `${att.full_name} (${att.username})` : att.username;
          const total = att.total_credits || 0;
          const remaining = att.remaining_credits || 0;
          const done = total - remaining;
          return `<li style="margin-bottom: 4px;"><b>${displayName}</b> - odrađeno ${done}/${total} treninga.</li>`;
        }).join('');
      }

      sessionsHtml += `
        <div style="background-color: #ffffff; padding: 6px 10px; border-radius: 4px; border: 1px solid rgba(197, 168, 128, 0.15); margin-bottom: 6px;">
          <div style="font-size: 0.85rem; color: #2c251e; margin-bottom: 2px;">
            <span style="font-weight: bold; border-left: 2px solid #c5a880; padding-left: 6px;">${session.time}h — ${session.title}</span>
            <span style="color: #7c7267; font-size: 0.75rem; margin-left: 5px;">(Trener: ${session.instructor})</span>
          </div>
          <ul style="margin: 0; padding-left: 15px; font-size: 0.8rem; color: #2c251e; line-height: 1.2rem;">
            ${attendeesListHtml}
          </ul>
        </div>
      `;
    });

    const adminEmail = env.ADMIN_REPORT_EMAIL || "adrijana.kontek@gmail.com";
    const subject = `Agram Pilates - Dnevno izvješće o dolascima za ${dateFormatted}`;
    
    const htmlContent = `
      <div style="font-family: Arial, sans-serif; padding: 15px; color: #2c251e; background-color: #faf8f5; border: 1px solid #ebdcc5; border-radius: 6px; max-width: 480px; margin: 0 auto;">
        <h2 style="color: #a98e65; border-bottom: 1.5px solid #ebdcc5; padding-bottom: 6px; margin-top: 0; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; font-size: 1.1rem;">
          Dnevno izvješće o dolascima
        </h2>
        <p style="font-size: 0.85rem; font-weight: bold; color: #7c7267; margin: 0 0 12px 0;">
          Datum: ${dateFormatted}
        </p>
        
        <div>
          ${sessionsHtml}
        </div>
        
        <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 20px; margin-bottom: 10px;">
        <p style="font-size: 10px; color: #7c7267; text-align: center; margin: 0;">
          Ova poruka je poslana automatski iz sustava Agram Pilates.
        </p>
      </div>
    `;

    const success = await sendEmail(env, adminEmail, subject, htmlContent);
    if (success) {
      console.log(`Daily report email sent successfully for ${todayStr} to ${adminEmail}`);
    } else {
      console.error(`Failed to send daily report email for ${todayStr} to ${adminEmail}`);
    }
    return success;
  } catch (e) {
    console.error("Error sending daily report email:", e);
    return false;
  }
}

// Send 24-hour email reminders to clients for tomorrow's bookings (at 20:00 Zagreb time)
async function sendBookingReminders(env, event = null) {
  try {
    await ensureDbColumns(env);
    const croatiaNow = getCroatiaNow(event?.scheduledTime);

    // Enforce that local Croatia hour is 20:00 when triggered by scheduled cron
    if (!event?.force && croatiaNow.getHours() !== 20) {
      console.log(`Skipping sendBookingReminders: current Croatia hour is ${croatiaNow.getHours()}, expected 20.`);
      return;
    }

    const tomorrow = new Date(croatiaNow.getTime() + 24 * 60 * 60 * 1000);
    const tomorrowStr = formatDate(tomorrow);
    
    // Find all active bookings for tomorrow where status is Reserved (0) and reminder hasn't been sent (0)
    const activeBookings = await env.DB.prepare(`
      SELECT b.id as booking_id, b.user_id, c.username, c.email, s.title, s.time, s.date
      FROM Bookings b
      JOIN Clients c ON b.user_id = c.id
      JOIN Sessions s ON b.session_id = s.id
      WHERE s.date = ? AND b.status = 0 AND b.reminder_sent = 0
      ORDER BY b.id ASC
    `).bind(tomorrowStr).all();

    const bookings = activeBookings.results || [];
    if (bookings.length === 0) return;

    // Group bookings by user_id so at most 1 email is sent per user, listing all tomorrow's sessions
    const userBookingsMap = new Map();
    for (const b of bookings) {
      if (!b.email) continue;
      if (!userBookingsMap.has(b.user_id)) {
        userBookingsMap.set(b.user_id, {
          user_id: b.user_id,
          username: b.username,
          email: b.email,
          sessions: []
        });
      }
      userBookingsMap.get(b.user_id).sessions.push(b);
    }

    for (const [userId, userData] of userBookingsMap) {
      const userSessions = userData.sessions;
      const bookingIds = userSessions.map(s => s.booking_id);

      // ATOMIC CLAIM: Insert into SentReminders FIRST before attempting email send.
      // If another concurrent cron worker already claimed it, UNIQUE constraint will fail / changes will be 0.
      let claimed = false;
      try {
        const claimResult = await env.DB.prepare(`
          INSERT INTO SentReminders (user_id, target_date, reminder_type)
          VALUES (?, ?, '24h_booking')
        `).bind(userId, tomorrowStr).run();
        claimed = !!(claimResult && claimResult.meta && claimResult.meta.changes === 1);
      } catch (e) {
        // Unique constraint violation means another worker already claimed this reminder
        claimed = false;
      }

      if (!claimed) {
        console.log(`Reminder for user_id ${userId} on date ${tomorrowStr} already claimed by another execution.`);
        continue;
      }

      // Format all sessions for this user in the email
      const sessionRowsHtml = userSessions.map(s => {
        const dateFormatted = s.date.split('-').reverse().join('.') + '.';
        return `<tr><td><b>${escapeHtml(s.title)}:</b></td><td>Sutra (${dateFormatted}) u ${escapeHtml(s.time)}h</td></tr>`;
      }).join('');

      const emailSubject = userSessions.length > 1
        ? `Podsjetnik na sutrašnje treninge (${userSessions.length})`
        : `Podsjetnik na trening: ${userSessions[0].title}`;

      const emailHtml = `
        <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5; border: 1px solid #ebdcc5; border-radius: 6px; max-width: 480px; margin: 0 auto;">
          <h2 style="color: #a98e65; margin-top: 0; text-transform: uppercase; font-size: 1.2rem; border-bottom: 1.5px solid #ebdcc5; padding-bottom: 6px;">Podsjetnik na trening</h2>
          <p>Bok <b>${escapeHtml(userData.username)}</b>,</p>
          <p>Podsjećamo te da sutra imaš rezervirane sljedeće termine:</p>
          <table style="border-spacing: 10px; margin-bottom: 20px; font-size: 0.9rem;">
            ${sessionRowsHtml}
          </table>
          <p style="margin-top: 20px;">
            Vidimo se!
          </p>
          <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
          <p style="font-size: 11px; color: #7c7267; text-align: center; margin: 0;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
        </div>
      `;

      const idempotencyKey = `reminder-user-${userId}-${tomorrowStr}`;
      const emailSent = await sendEmail(env, userData.email, emailSubject, emailHtml, idempotencyKey);

      // If email succeeded, mark Bookings as reminder_sent = 1
      if (emailSent) {
        const placeholders = bookingIds.map(() => '?').join(',');
        await env.DB.prepare(
          `UPDATE Bookings SET reminder_sent = 1 WHERE id IN (${placeholders})`
        ).bind(...bookingIds).run();
      } else {
        // If email sending failed, rollback SentReminders claim so retry can happen later
        await env.DB.prepare(
          "DELETE FROM SentReminders WHERE user_id = ? AND target_date = ? AND reminder_type = '24h_booking'"
        ).bind(userId, tomorrowStr).run();
        console.error(`Failed to send reminder email to user_id ${userId} for date ${tomorrowStr}. Claim rolled back.`);
      }
    }
  } catch (e) {
    console.error("Error sending booking reminders:", e);
  }
}

// Synchronize Instagram Feed
async function syncInstagramFeed(env) {
  try {
    // 1. Get access token (prefer env secret binding over DB settings)
    let token = env.INSTAGRAM_ACCESS_TOKEN;
    if (!token) {
      const tokenObj = await env.DB.prepare("SELECT value FROM Settings WHERE key = 'instagram_access_token'").first();
      token = tokenObj ? tokenObj.value : null;
    }

    if (!token) {
      console.warn("Instagram access token not configured.");
      return false;
    }

    // 2. Fetch latest media (limit 6) from Instagram Basic Display API
    const res = await fetch(`https://graph.instagram.com/me/media?fields=id,caption,media_type,media_url,permalink,thumbnail_url,timestamp&limit=6&access_token=${encodeURIComponent(token)}`);
    if (!res.ok) {
      const errorText = await res.text();
      const sanitizedError = errorText.replace(/access_token=[^&]+/gi, "access_token=REDACTED");
      console.error("Instagram API error fetching media:", sanitizedError);
      return false;
    }
    const data = await res.json();
    if (!data || !data.data || !Array.isArray(data.data)) {
      console.error("Invalid response format from Instagram API.");
      return false;
    }

    // 3. Store posts in InstagramPosts table
    const statements = [
      env.DB.prepare("DELETE FROM InstagramPosts")
    ];

    for (const post of data.data) {
      statements.push(
        env.DB.prepare(`
          INSERT INTO InstagramPosts (id, caption, media_type, media_url, permalink, thumbnail_url, timestamp)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).bind(
          post.id,
          post.caption || "",
          post.media_type,
          post.media_url,
          post.permalink,
          post.thumbnail_url || null,
          post.timestamp
        )
      );
    }

    await env.DB.batch(statements);

    // 4. Update last sync time
    const croatiaNow = getCroatiaNow();
    const nowStr = croatiaNow.toISOString().replace('T', ' ').substring(0, 19);
    await env.DB.prepare("INSERT OR REPLACE INTO Settings (key, value) VALUES ('instagram_last_synced_at', ?)").bind(nowStr).run();

    // 5. Automatic token refresh (if updated more than 30 days ago)
    const tokenUpdatedObj = await env.DB.prepare("SELECT value FROM Settings WHERE key = 'instagram_token_updated_at'").first();
    const tokenUpdated = tokenUpdatedObj ? new Date(tokenUpdatedObj.value.replace(" ", "T") + "Z") : null;
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    if (!tokenUpdated || tokenUpdated < thirtyDaysAgo) {
      console.log("Refreshing Instagram access token...");
      const refreshRes = await fetch(`https://graph.instagram.com/refresh_access_token?grant_type=ig_refresh_token&access_token=${encodeURIComponent(token)}`);
      if (refreshRes.ok) {
        const refreshData = await refreshRes.json();
        if (refreshData && refreshData.access_token) {
          await env.DB.batch([
            env.DB.prepare("INSERT OR REPLACE INTO Settings (key, value) VALUES ('instagram_access_token', ?)").bind(refreshData.access_token),
            env.DB.prepare("INSERT OR REPLACE INTO Settings (key, value) VALUES ('instagram_token_updated_at', ?)").bind(nowStr)
          ]);
          console.log("Instagram access token successfully refreshed.");
        }
      } else {
        const errText = await refreshRes.text();
        const sanitizedErr = errText.replace(/access_token=[^&]+/gi, "access_token=REDACTED");
        console.error("Failed to refresh Instagram access token:", sanitizedErr);
      }
    }

    return true;
  } catch (e) {
    console.error("Error syncing Instagram feed:", e);
    return false;
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Handle CORS preflight requests
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: getCorsHeaders(request)
      });
    }

    try {
      await ensureDbColumns(env);

      // --- PUBLIC ENDPOINTS ---

      // LOGIN
      if (request.method === "POST" && url.pathname === "/api/login") {
        const ip = getClientIp(request);
        const rateCheck = await checkRateLimit(env, ip, "login", 10, 60);
        if (!rateCheck.allowed) {
          return jsonResponse({ success: false, error: "Previše pokušaja prijave. Molimo pričekajte minutu." }, 429, request);
        }

        let username, password;
        try {
          const reqBody = await request.json();
          username = reqBody.username;
          password = reqBody.password;
        } catch (jsonErr) {
          return jsonResponse({ success: false, error: "Korisničko ime/e-mail i lozinka su obavezni." }, 400, request);
        }

        if (!username || !password) {
          return jsonResponse({ success: false, error: "Korisničko ime/e-mail i lozinka su obavezni." }, 400, request);
        }

        let user;
        try {
          user = await env.DB.prepare(
            "SELECT id, username, password, email, is_admin, must_change_password, package_name, total_credits, remaining_credits, package_expires, status, questionnaire, full_name, first_name, last_name, phone, COALESCE(has_seen_onboarding, 0) as has_seen_onboarding, COALESCE(token_version, 1) as token_version FROM Clients WHERE username = ? OR email = ?"
          ).bind(username, username).first();
        } catch (dbErr) {
          console.error("Login full query failed, trying fallback query:", dbErr);
          user = await env.DB.prepare(
            "SELECT id, username, password, email, is_admin, must_change_password, package_name, total_credits, remaining_credits, package_expires, status FROM Clients WHERE username = ? OR email = ?"
          ).bind(username, username).first();
        }

        if (!user) {
          return jsonResponse({ success: false, error: "Pogrešno korisničko ime/e-mail ili lozinka." }, 401, request);
        }

        const authResult = await verifyPassword(password, user.password);
        if (!authResult.valid) {
          return jsonResponse({ success: false, error: "Pogrešno korisničko ime/e-mail ili lozinka." }, 401, request);
        }

        // Reject login for pending or suspended accounts
        if (user.status === 'pending') {
          return jsonResponse({ success: false, error: "Vaš račun je u postupku odobrenja od strane administratora." }, 403, request);
        }
        if (user.status === 'suspended') {
          return jsonResponse({ success: false, error: "Vaš korisnički račun je suspendiran. Za više informacija kontaktirajte administratora." }, 403, request);
        }

        // Automatic migration of legacy SHA-256 hashes to PBKDF2 upon successful login
        if (authResult.needsRehash) {
          const newHash = await hashPassword(password);
          await env.DB.prepare("UPDATE Clients SET password = ? WHERE id = ?").bind(newHash, user.id).run();
          user.password = newHash;
        }

        const token = await createJWT({
          user_id: user.id,
          is_admin: user.is_admin,
          username: user.username,
          token_version: user.token_version || 1,
          exp: Math.floor(Date.now() / 1000) + 7 * 24 * 60 * 60 // 7 days
        }, getJwtSecret(env));

        const { password: _password, reset_token_hash: _reset, ...safeUser } = user;
        return jsonResponse({ success: true, user: safeUser, token }, 200, request);
      }

      // CHECK USERNAME AVAILABILITY
      if (request.method === "GET" && url.pathname === "/api/check-username") {
        const ip = getClientIp(request);
        const rateCheck = await checkRateLimit(env, ip, "identity-check", 30, 60);
        if (!rateCheck.allowed) {
          return jsonResponse({ success: false, error: "Previše upita." }, 429);
        }

        const username = url.searchParams.get("username");
        if (!username) {
          return jsonResponse({ success: false, error: "Korisničko ime je obavezno." }, 400);
        }
        const existing = await env.DB.prepare("SELECT id FROM Clients WHERE username = ?").bind(username.trim()).first();
        return jsonResponse({ success: true, available: !existing });
      }

      // CHECK EMAIL EXISTENCE
      if (request.method === "GET" && url.pathname === "/api/check-email") {
        const ip = getClientIp(request);
        const rateCheck = await checkRateLimit(env, ip, "identity-check", 30, 60);
        if (!rateCheck.allowed) {
          return jsonResponse({ success: false, error: "Previše upita." }, 429);
        }

        const email = url.searchParams.get("email");
        if (!email) {
          return jsonResponse({ success: false, error: "E-mail je obavezan." }, 400);
        }
        const existing = await env.DB.prepare("SELECT id, status FROM Clients WHERE email = ?").bind(email.trim()).first();
        if (existing) {
          return jsonResponse({ success: true, exists: true, status: existing.status });
        }
        return jsonResponse({ success: true, exists: false });
      }

      // REGISTER (Public registration, status 'pending' awaiting admin approval)
      if (request.method === "POST" && url.pathname === "/api/register") {
        const ip = getClientIp(request);
        const rateCheck = await checkRateLimit(env, ip, "register", 5, 600);
        if (!rateCheck.allowed) {
          return jsonResponse({ success: false, error: "Previše zahtjeva za registraciju. Molimo pričekajte." }, 429);
        }

        const { first_name, last_name, username, email, phone } = await request.json();
        
        const firstNameErr = validateName(first_name, "Ime");
        if (firstNameErr) return jsonResponse({ success: false, error: firstNameErr }, 400);

        const lastNameErr = validateName(last_name, "Prezime");
        if (lastNameErr) return jsonResponse({ success: false, error: lastNameErr }, 400);

        const usernameErr = validateUsername(username);
        if (usernameErr) return jsonResponse({ success: false, error: usernameErr }, 400);

        const normalizedEmail = validateAndNormalizeEmail(email);
        if (!normalizedEmail) return jsonResponse({ success: false, error: "Neispravan format e-mail adrese." }, 400);

        const phoneErr = validatePhone(phone);
        if (phoneErr) return jsonResponse({ success: false, error: phoneErr }, 400);

        // Check if username already exists
        const existingUsername = await env.DB.prepare("SELECT id FROM Clients WHERE username = ?").bind(username.trim()).first();
        if (existingUsername) {
          return jsonResponse({ success: false, error: "Korisničko ime je već zauzeto." }, 400);
        }

        // Check if email already exists
        const existingEmail = await env.DB.prepare("SELECT id FROM Clients WHERE email = ?").bind(normalizedEmail).first();
        if (existingEmail) {
          return jsonResponse({ success: false, error: "Korisnik s ovom e-mail adresom već ima račun." }, 400);
        }

        const fullName = `${first_name.trim()} ${last_name.trim()}`;

        // Insert client with 'pending' status, 'PENDING' password, null questionnaire, full_name, first_name, last_name, phone
        await env.DB.prepare(`
          INSERT INTO Clients (username, email, password, is_admin, must_change_password, package_name, total_credits, remaining_credits, package_expires, status, questionnaire, full_name, first_name, last_name, phone)
          VALUES (?, ?, 'PENDING', 0, 1, 'Nema aktivnog paketa', 0, 0, NULL, 'pending', NULL, ?, ?, ?, ?)
        `).bind(username.trim(), normalizedEmail, fullName, first_name.trim(), last_name.trim(), phone.trim()).run();

        await logActivity(env, `Nova registracija: ${fullName}`);

        return jsonResponse({
          success: true,
          message: "Zahtjev za registraciju je poslan! Nakon što administrator odobri Vaš profil, dobit ćete e-mail s privremenom lozinkom za prijavu."
        });
      }

      // CHANGE PASSWORD (requires valid JWT session)
      if (request.method === "POST" && url.pathname === "/api/change-password") {
        const ip = getClientIp(request);
        const rateCheck = await checkRateLimit(env, ip, "change-pass", 5, 300);
        if (!rateCheck.allowed) {
          return jsonResponse({ success: false, error: "Previše pokušaja promjene lozinke. Molimo pričekajte 5 minuta." }, 429);
        }

        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }

        const { old_password, new_password } = await request.json();
        if (!old_password || !new_password) {
          return jsonResponse({ success: false, error: "Sva polja su obavezna (trenutna i nova lozinka)." }, 400);
        }

        const passwordErr = validatePasswordStrength(new_password);
        if (passwordErr) {
          return jsonResponse({ success: false, error: passwordErr }, 400);
        }

        const user_id = authUser.user_id;
        const user = await env.DB.prepare("SELECT id, username, email, password FROM Clients WHERE id = ?").bind(user_id).first();
        if (!user) {
          return jsonResponse({ success: false, error: "Korisnik nije pronađen." }, 404);
        }

        const authResult = await verifyPassword(old_password, user.password);
        if (!authResult.valid) {
          return jsonResponse({ success: false, error: "Trenutna lozinka nije ispravna." }, 401);
        }

        const hashedNew = await hashPassword(new_password);
        await env.DB.prepare("UPDATE Clients SET password = ?, must_change_password = 0, token_version = COALESCE(token_version, 1) + 1 WHERE id = ?").bind(hashedNew, user_id).run();

        await logActivity(env, `Promjena lozinke: ${user.username}`);

        // Send confirmation email
        if (user.email) {
          const emailSubject = "Agram Pilates - Obavijest o promjeni lozinke";
          const emailHtml = `
            <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
              <h2 style="color: #a98e65;">Lozinka je uspješno promijenjena</h2>
              <p>Bok <b>${escapeHtml(user.username)}</b>,</p>
              <p>Obavještavamo Vas da je lozinka za Vaš korisnički račun uspješno promijenjena.</p>
              <p>Ako vi niste zatražili ovu promjenu, odmah kontaktirajte administratora studija!</p>
              <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
              <p style="font-size: 11px; color: #7c7267;">Pilates Reformer Agram</p>
            </div>
          `;
          ctx.waitUntil(sendEmail(env, user.email, emailSubject, emailHtml));
        }

        return jsonResponse({ success: true, message: "Lozinka je uspješno promijenjena!" });
      }

      // FORGOT PASSWORD (secure email reset token flow)
      if (request.method === "POST" && url.pathname === "/api/forgot-password") {
        const ip = getClientIp(request);
        const rateCheck = await checkRateLimit(env, ip, "forgot-pass", 3, 300);
        if (!rateCheck.allowed) {
          return jsonResponse({ success: false, error: "Previše zahtjeva za resetiranje lozinke. Molimo pričekajte 5 minuta." }, 429);
        }

        const { email } = await request.json();
        const genericMessage = "Ako račun s navedenom e-mail adresom postoji, poslali smo vam upute za poništavanje lozinke na e-mail.";
        
        if (!email) {
          return jsonResponse({ success: false, error: "E-mail adresa je obavezna." }, 400);
        }

        const client = await env.DB.prepare(
          "SELECT id, username, email, status FROM Clients WHERE email = ?"
        ).bind(email.trim()).first();

        if (client && (client.status === "approved" || client.status === "frozen")) {
          const rawToken = generateSecureToken(32);
          const tokenHash = await hashPasswordSha256(rawToken);
          const expires = Math.floor(Date.now() / 1000) + 3600; // 1 hour

          await env.DB.prepare(
            "UPDATE Clients SET reset_token_hash = ?, reset_token_expires = ? WHERE id = ?"
          ).bind(tokenHash, expires, client.id).run();

          await logActivity(env, `Zahtjev za reset lozinke: ${client.username}`);

          const resetLink = `https://pilates-reformer-agram.com/prijava.html?reset_token=${rawToken}`;
          const emailSubject = "Pilates Reformer Agram - Poništavanje lozinke";
          const emailHtml = `
            <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
              <h2 style="color: #a98e65;">Poništavanje lozinke</h2>
              <p>Bok <b>${escapeHtml(client.username)}</b>,</p>
              <p>Zatražili ste ponovno postavljanje lozinke za Vaš račun. Kliknite na donji gumb kako biste postavili novu lozinku (poveznica vrijedi 1 sat):</p>
              <p style="margin: 25px 0;">
                <a href="${resetLink}" style="background-color: #c5a880; color: white; padding: 12px 24px; text-decoration: none; border-radius: 20px; font-weight: bold; display: inline-block;">
                  Postavi novu lozinku
                </a>
              </p>
              <p style="font-size: 12px; color: #7c7267;">Ako niste zatražili poništavanje lozinke, slobodno zanemarite ovu poruku. Vaša lozinka ostaje nepromijenjena.</p>
              <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
              <p style="font-size: 11px; color: #7c7267; text-align: center; margin: 0;">Pilates Reformer Agram</p>
            </div>
          `;
          ctx.waitUntil(sendEmail(env, client.email, emailSubject, emailHtml));
        }

        return jsonResponse({ success: true, message: genericMessage });
      }

      // RESET PASSWORD WITH TOKEN
      if (request.method === "POST" && url.pathname === "/api/reset-password") {
        const ip = getClientIp(request);
        const rateCheck = await checkRateLimit(env, ip, "reset-pass", 5, 300);
        if (!rateCheck.allowed) {
          return jsonResponse({ success: false, error: "Previše pokušaja resetiranja lozinke." }, 429);
        }

        const { reset_token, new_password } = await request.json();
        if (!reset_token || !new_password) {
          return jsonResponse({ success: false, error: "Token i nova lozinka su obavezni." }, 400);
        }

        const passwordErr = validatePasswordStrength(new_password);
        if (passwordErr) {
          return jsonResponse({ success: false, error: passwordErr }, 400);
        }

        const tokenHash = await hashPasswordSha256(reset_token);
        const nowSec = Math.floor(Date.now() / 1000);

        const client = await env.DB.prepare(
          "SELECT id, username, email, reset_token_expires FROM Clients WHERE reset_token_hash = ?"
        ).bind(tokenHash).first();

        if (!client || !client.reset_token_expires || client.reset_token_expires < nowSec) {
          return jsonResponse({ success: false, error: "Poveznica za poništavanje lozinke je nevažeća ili je istekla." }, 400);
        }

        const hashedNew = await hashPassword(new_password);

        // Atomic UPDATE: consume token, update password, invalidate stale JWT sessions, and verify 1 row was changed
        const updateRes = await env.DB.prepare(`
          UPDATE Clients 
          SET password = ?, 
              reset_token_hash = NULL, 
              reset_token_expires = NULL, 
              must_change_password = 0, 
              token_version = COALESCE(token_version, 1) + 1 
          WHERE id = ? 
            AND reset_token_hash = ? 
            AND reset_token_expires >= ?
            AND status != 'suspended'
        `).bind(hashedNew, client.id, tokenHash, nowSec).run();

        if (!updateRes || !updateRes.meta || updateRes.meta.changes === 0) {
          return jsonResponse({ success: false, error: "Poveznica za poništavanje lozinke je nevažeća, istekla ili je već iskorištena." }, 400);
        }

        await logActivity(env, `Lozinka uspješno poništena s tokenom: ${client.username}`);

        // Send password change confirmation email
        if (client.email) {
          const emailSubject = "Agram Pilates - Obavijest o promjeni lozinke";
          const emailHtml = `
            <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
              <h2 style="color: #a98e65;">Lozinka je uspješno promijenjena</h2>
              <p>Bok <b>${escapeHtml(client.username)}</b>,</p>
              <p>Obavještavamo Vas da je lozinka za Vaš korisnički račun uspješno promijenjena.</p>
              <p>Ako vi niste zatražili ovu promjenu, odmah kontaktirajte administratora studija!</p>
              <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
              <p style="font-size: 11px; color: #7c7267;">Pilates Reformer Agram</p>
            </div>
          `;
          ctx.waitUntil(sendEmail(env, client.email, emailSubject, emailHtml));
        }

        return jsonResponse({ success: true, message: "Lozinka je uspješno poništena! Sada se možete prijaviti s novom lozinkom." });
      }

      // GET NEWS FEED
      if (request.method === "GET" && url.pathname === "/api/news") {
        const { results } = await env.DB.prepare("SELECT * FROM News ORDER BY created_at DESC").all();
        return jsonResponse({ success: true, news: results });
      }

      // GET INSTAGRAM FEED
      if (request.method === "GET" && url.pathname === "/api/instagram/posts") {
        const { results } = await env.DB.prepare("SELECT * FROM InstagramPosts ORDER BY timestamp DESC LIMIT 6").all();
        return jsonResponse({ success: true, posts: results });
      }


      // --- CLIENT BOOKING ENDPOINTS ---

      // GET AVAILABLE SESSIONS (with client booking status)
      if (request.method === "GET" && url.pathname === "/api/sessions") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const userId = authUser.user_id;

        ctx.waitUntil(checkAndAutoGenerateSchedules(env));
        await autoConfirmBookings(env);

        const nowCroatia = getCroatiaNow();
        const todayStr = formatDate(nowCroatia);
        // Get current time in HH:MM format for filtering past sessions today
        const currentTimeStr = `${String(nowCroatia.getHours()).padStart(2, '0')}:${String(nowCroatia.getMinutes()).padStart(2, '0')}`;
        // Calculate max date: Sunday of the week after next (3 full weeks)
        const currentDayOfWeek = nowCroatia.getDay();
        const daysToSunday = (7 - currentDayOfWeek) % 7;
        const daysToAdd = daysToSunday + 14; // Sunday of the week after next
        const maxDate = new Date(nowCroatia.getTime() + daysToAdd * 24 * 60 * 60 * 1000);
        const maxDateStr = formatDate(maxDate);
        
        // Fetch sessions up to today + 6 days, excluding past sessions from today
        // For future days: show all; for today: only show sessions that haven't started yet
        const { results } = await env.DB.prepare(`
          SELECT s.*, 
                 (SELECT COUNT(*) FROM Bookings b WHERE b.session_id = s.id AND b.status >= 0) as booked_count,
                 (SELECT COUNT(*) FROM Bookings b WHERE b.session_id = s.id AND b.user_id = ? AND b.status >= 0) as user_booked,
                 (SELECT COUNT(*) FROM Waitlists w WHERE w.session_id = s.id AND w.user_id = ?) as user_waitlisted,
                 (SELECT COUNT(*) FROM Waitlists w WHERE w.session_id = s.id) as waitlist_count,
                 (SELECT COUNT(*) FROM Waitlists w WHERE w.session_id = s.id AND w.created_at <= (SELECT w2.created_at FROM Waitlists w2 WHERE w2.session_id = s.id AND w2.user_id = ?)) as user_waitlist_position
          FROM Sessions s
          WHERE s.date <= ?
            AND (s.date > ? OR (s.date = ? AND s.time > ?))
          ORDER BY s.date ASC, s.time ASC
        `).bind(userId, userId, userId, maxDateStr, todayStr, todayStr, currentTimeStr).all();

        return jsonResponse({ success: true, sessions: results });
      }

      // BOOK A SESSION
      if (request.method === "POST" && url.pathname === "/api/book") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { session_id } = await request.json();
        if (!session_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni." }, 400);
        }
        const user_id = authUser.user_id;

        // 1. Get Client credits and check expiration
        const client = await env.DB.prepare(
          "SELECT username, email, remaining_credits, package_expires, package_name, status FROM Clients WHERE id = ?"
        ).bind(user_id).first();

        if (!client) {
          return jsonResponse({ success: false, error: "Korisnik nije pronađen." }, 404);
        }

        if (client.status === "frozen") {
          return jsonResponse({ success: false, error: "Vaša članarina je trenutno zaleđena. Nije moguće rezervirati nove termine." }, 400);
        }

        if (client.remaining_credits <= 0) {
          return jsonResponse({ success: false, error: "Nemate preostalih treninga (kredita) u paketu." }, 400);
        }

        const todayStr = formatDate(getCroatiaNow());
        if (client.package_expires && client.package_expires < todayStr) {
          return jsonResponse({ success: false, error: `Vaš paket (${client.package_name}) je istekao dana ${client.package_expires}.` }, 400);
        }

        // 2. Check Session capacity and validity
        const session = await env.DB.prepare("SELECT * FROM Sessions WHERE id = ?").bind(session_id).first();
        if (!session) {
          return jsonResponse({ success: false, error: "Termin nije pronađen." }, 404);
        }

        // Check if session is in the past
        const croatiaNow = getCroatiaNow();
        if (session.date < todayStr) {
          return jsonResponse({ success: false, error: "Nije moguće rezervirati termin u prošlosti." }, 400);
        }
        if (session.date === todayStr) {
          const nowHourMin = `${String(croatiaNow.getHours()).padStart(2, '0')}:${String(croatiaNow.getMinutes()).padStart(2, '0')}`;
          if (session.time <= nowHourMin) {
            return jsonResponse({ success: false, error: "Nije moguće rezervirati termin koji je već započeo." }, 400);
          }
        }

        // Check if session date is beyond 3 weeks
        const maxDate = new Date(croatiaNow.getTime() + 21 * 24 * 60 * 60 * 1000);
        const maxDateStr = formatDate(maxDate);
        if (session.date > maxDateStr) {
          return jsonResponse({ success: false, error: "Nije moguće rezervirati termin više od 3 tjedna unaprijed." }, 400);
        }

        // Check package type compatibility
        if (client.package_name) {
          const pkgLower = client.package_name.toLowerCase();
          if (pkgLower.includes("grupni") && session.type !== "grupni") {
            return jsonResponse({ success: false, error: `Vaš paket (${client.package_name}) vrijedi samo za grupne treninge.` }, 400);
          }
          if (pkgLower.includes("privatni") && session.type !== "privatni" && session.type !== "poluindividualni") {
            return jsonResponse({ success: false, error: `Vaš paket (${client.package_name}) vrijedi samo za privatne/poluindividualne treninge.` }, 400);
          }
        }

        // 1. Check for duplicate active booking on the same date
        const existingBookingToday = await env.DB.prepare(`
          SELECT b.id FROM Bookings b 
          JOIN Sessions s ON b.session_id = s.id 
          WHERE b.user_id = ? AND s.date = ? AND b.status >= 0
        `).bind(user_id, session.date).first();

        if (existingBookingToday) {
          return jsonResponse({ success: false, error: "Već imate rezerviran termin za ovaj dan. Nije moguće rezervirati više termina u istom danu." }, 400);
        }

        // 2. Check capacity
        const bookingCountObj = await env.DB.prepare(
          "SELECT COUNT(*) as count FROM Bookings WHERE session_id = ? AND status >= 0"
        ).bind(session_id).first();
        const bookedCount = bookingCountObj ? bookingCountObj.count : 0;

        if (bookedCount >= session.capacity) {
          return jsonResponse({ success: false, error: "Termin je već popunjen." }, 400);
        }

        // 3. Check for existing row (active or cancelled) to handle re-booking vs new insert
        const existingRow = await env.DB.prepare(
          "SELECT id, status FROM Bookings WHERE session_id = ? AND user_id = ?"
        ).bind(session_id, user_id).first();

        if (existingRow && existingRow.status >= 0) {
          return jsonResponse({ success: false, error: "Već ste prijavljeni na ovaj termin." }, 400);
        }

        // 4. ATOMIC BATCH TRANSACTION: Deduct credit & Insert/Update booking in 1 atomic D1 batch!
        const batchQueries = [
          env.DB.prepare(
            "UPDATE Clients SET remaining_credits = remaining_credits - 1 WHERE id = ? AND remaining_credits > 0"
          ).bind(user_id)
        ];

        if (existingRow) {
          batchQueries.push(
            env.DB.prepare(
              "UPDATE Bookings SET status = 0, reminder_sent = 0 WHERE id = ? AND status < 0"
            ).bind(existingRow.id)
          );
        } else {
          batchQueries.push(
            env.DB.prepare(`
              INSERT INTO Bookings (session_id, user_id, status)
              SELECT ?, ?, 0
              WHERE (
                SELECT COUNT(*) FROM Bookings WHERE session_id = ? AND status >= 0
              ) < (SELECT capacity FROM Sessions WHERE id = ?)
              AND NOT EXISTS (
                SELECT 1 FROM Bookings b JOIN Sessions s ON b.session_id = s.id
                WHERE b.user_id = ? AND s.date = ? AND b.status >= 0
              )
            `).bind(session_id, user_id, session_id, session_id, user_id, session.date)
          );
        }

        const [creditRes, bookingRes] = await env.DB.batch(batchQueries);

        if (!creditRes || !creditRes.meta || creditRes.meta.changes === 0) {
          return jsonResponse({ success: false, error: "Nemate dovoljno preostalih treninga u paketu." }, 400);
        }

        if (!bookingRes || !bookingRes.meta || bookingRes.meta.changes === 0) {
          // If booking insertion failed due to concurrent race condition, rollback credit
          await env.DB.prepare("UPDATE Clients SET remaining_credits = remaining_credits + 1 WHERE id = ?").bind(user_id).run();
          return jsonResponse({ success: false, error: "Termin je u međuvremenu popunjen ili već imate rezervaciju na ovaj dan." }, 400);
        }

        const dateStr = session.date.split('-').reverse().join('.') + '.';
        await logActivity(env, `Rezervacija: ${client.username} → ${session.title} (${dateStr}, ${session.time}h)`);

        // Send booking confirmation email with Google Calendar link
        if (client.email) {
          const dateStrFormatted = session.date.split('-').reverse().join('.') + '.';
          const emailSubject = `Potvrda rezervacije: ${session.title}`;
          
          // Generate Google Calendar Link
          const dateFormattedNoDashes = session.date.replace(/-/g, '');
          const timeFormattedNoColons = session.time.replace(/:/g, '');
          const startHour = parseInt(session.time.split(':')[0], 10);
          const startMinute = session.time.split(':')[1];
          const endHour = String(startHour + 1).padStart(2, '0');
          const endTimeFormatted = `${endHour}${startMinute}`;
          
          const googleCalUrl = `https://calendar.google.com/calendar/render?action=TEMPLATE&text=${encodeURIComponent('Agram Pilates - ' + session.title)}&dates=${dateFormattedNoDashes}T${timeFormattedNoColons}00/${dateFormattedNoDashes}T${endTimeFormatted}00&ctz=Europe/Zagreb&details=${encodeURIComponent('Potvrda rezervacije za termin u Agram Pilates studiju.')}`;
          
          const emailHtml = `
            <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5; border: 1px solid #ebdcc5; border-radius: 6px; max-width: 480px; margin: 0 auto;">
              <h2 style="color: #a98e65; margin-top: 0; text-transform: uppercase; font-size: 1.2rem; border-bottom: 1.5px solid #ebdcc5; padding-bottom: 6px;">Uspješna rezervacija termina!</h2>
              <p>Bok <b>${escapeHtml(client.username)}</b>,</p>
              <p>Potvrđujemo da ste uspješno rezervirali sljedeći termin:</p>
              <table style="border-spacing: 10px; margin-bottom: 20px; font-size: 0.9rem;">
                <tr><td><b>Termin:</b></td><td>${escapeHtml(session.title)}</td></tr>
                <tr><td><b>Datum i vrijeme:</b></td><td>${escapeHtml(dateStrFormatted)} u ${escapeHtml(session.time)}h</td></tr>
                <tr><td><b>Trener:</b></td><td>${escapeHtml(session.instructor || 'Adrijana')}</td></tr>
              </table>
              
              <p style="margin-top: 25px; margin-bottom: 25px; text-align: center;">
                <a href="${googleCalUrl}" target="_blank" style="background-color: #c5a880; color: white; padding: 12px 20px; text-decoration: none; border-radius: 20px; font-weight: bold; display: inline-block;">
                  Dodaj svoj termin u google kalendar
                </a>
              </p>
              
              <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
              <p style="font-size: 11px; color: #7c7267; text-align: center; margin: 0;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
            </div>
          `;
          ctx.waitUntil(sendEmail(env, client.email, emailSubject, emailHtml));
        }

        // If they had exactly 1 credit remaining, they used their last credit! Send notification email.
        if (client.remaining_credits === 1 && client.email) {
          const emailSubject = "Agram Pilates - Iskoristili ste sve treninge iz paketa";
          const emailHtml = `
            <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
              <h2 style="color: #a98e65;">Svi treninzi su iskorišteni</h2>
              <p>Bok <b>${client.username}</b>,</p>
              <p>Obavještavamo Vas da ste upravo rezervacijom termina <b>'${session.title}'</b> iskoristili zadnji preostali trening iz Vašeg paketa <b>${client.package_name}</b>.</p>
              <p>Kako biste mogli nastaviti s vježbanjem i rezervirati nove termine, molimo Vas da odaberete novi paket unutar aplikacije.</p>
              <p style="margin-top: 30px;">
                <a href="https://pilates-reformer-agram.com/dashboard.html" style="background-color: #c5a880; color: white; padding: 10px 20px; text-decoration: none; border-radius: 20px;">
                  Otvori Profil i odaberi paket
                </a>
              </p>
              <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
              <p style="font-size: 11px; color: #7c7267;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
            </div>
          `;
          ctx.waitUntil(sendEmail(env, client.email, emailSubject, emailHtml));
        }

        return jsonResponse({ success: true, message: "Uspješna rezervacija termina!" });
      }

      // CANCEL A BOOKING (12-hour rule)
      if (request.method === "POST" && url.pathname === "/api/cancel-booking") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { session_id } = await request.json();
        if (!session_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni." }, 400);
        }
        const user_id = authUser.user_id;

        // 1. Check if an active un-attended booking exists (status = 0)
        const booking = await env.DB.prepare(
          "SELECT id, status FROM Bookings WHERE session_id = ? AND user_id = ? AND status = 0"
        ).bind(session_id, user_id).first();
        if (!booking) {
          return jsonResponse({ success: false, error: "Aktivna rezervacija nije pronađena ili je trening već odrađen/otkazan." }, 404);
        }

        // 2. Get session date/time to check 12h limit
        const session = await env.DB.prepare("SELECT date, time FROM Sessions WHERE id = ?").bind(session_id).first();
        if (!session) {
          return jsonResponse({ success: false, error: "Termin nije pronađen." }, 404);
        }

        const nowCroatia = getCroatiaNow();
        const sessionCroatia = new Date(`${session.date}T${session.time}:00`);
        const diffHours = (sessionCroatia.getTime() - nowCroatia.getTime()) / (1000 * 60 * 60);

        let refunded = false;
        let messageText = "";

        if (diffHours >= 12) {
          // In-time cancel: Refund credit ONLY IF status transition from 0 to -2 AND credit update succeed atomically
          const [updateResult, refundResult] = await env.DB.batch([
            env.DB.prepare(
              "UPDATE Bookings SET status = -2 WHERE session_id = ? AND user_id = ? AND status = 0"
            ).bind(session_id, user_id),
            env.DB.prepare(
              "UPDATE Clients SET remaining_credits = remaining_credits + 1 WHERE id = ?"
            ).bind(user_id)
          ]);

          if (!updateResult || !updateResult.meta || updateResult.meta.changes === 0) {
            return jsonResponse({ success: false, error: "Rezervacija je već otkazana ili nije aktivna." }, 400);
          }

          refunded = true;
          messageText = "Termin je otkazan. Trening Vam je vraćen na račun. Molimo Vas da rezervirate idući slobodan termin ili nas osobno kontaktirate za dogovor.";
        } else {
          // Late cancel: Set status = -1 but do NOT refund credit
          const updateResult = await env.DB.prepare(
            "UPDATE Bookings SET status = -1 WHERE session_id = ? AND user_id = ? AND status = 0"
          ).bind(session_id, user_id).run();

          if (!updateResult || !updateResult.meta || updateResult.meta.changes === 0) {
            return jsonResponse({ success: false, error: "Rezervacija je već otkazana ili nije aktivna." }, 400);
          }
          refunded = false;
          messageText = "Termin je otkazan manje od 12 sati prije treninga. Kredit se ne vraća (broji se kao iskorišten). Molimo Vas da rezervirate idući slobodan termin ili nas osobno kontaktirate za dogovor.";
        }

        const client = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(user_id).first();
        if (client) {
          const dateStr = session.date.split('-').reverse().join('.') + '.';
          const cancelType = refunded ? "pravovremeno" : "neopravdano (kasno)";
          await logActivity(env, `Otkazano (${cancelType}): ${client.username} → ${session.title} (${dateStr}, ${session.time}h)`);
        }

        // Notify waitlist when a session spot opens up
        await notifyWaitlist(env, session_id);

        return jsonResponse({ success: true, refunded, message: messageText });
      }

      // JOIN WAITLIST
      if (request.method === "POST" && url.pathname === "/api/waitlist/join") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { session_id } = await request.json();
        if (!session_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni." }, 400);
        }
        const user_id = authUser.user_id;

        // 1. Check if client exists, has credits, and valid package
        const client = await env.DB.prepare("SELECT username, status, remaining_credits, package_expires FROM Clients WHERE id = ?").bind(user_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Korisnik nije pronađen." }, 404);
        }

        if (client.status === "frozen") {
          return jsonResponse({ success: false, error: "Vaša članarina je trenutno zaleđena. Nije moguće prijaviti se na listu čekanja." }, 400);
        }

        const croatiaNow = getCroatiaNow();
        const todayStr = formatDate(croatiaNow);

        if (client.remaining_credits <= 0) {
          return jsonResponse({ success: false, error: "Nemate preostalih treninga u paketu za prijavu na listu čekanja." }, 400);
        }

        if (client.package_expires && client.package_expires < todayStr) {
          return jsonResponse({ success: false, error: "Vaš paket je istekao. Nije moguće prijaviti se na listu čekanja." }, 400);
        }

        // 2. Check if session exists and is in the future
        const session = await env.DB.prepare("SELECT title, date, time, capacity FROM Sessions WHERE id = ?").bind(session_id).first();
        if (!session) {
          return jsonResponse({ success: false, error: "Termin nije pronađen." }, 404);
        }

        if (session.date < todayStr) {
          return jsonResponse({ success: false, error: "Nije moguće prijaviti se na listu čekanja za termin u prošlosti." }, 400);
        }
        if (session.date === todayStr) {
          const nowHourMin = `${String(croatiaNow.getHours()).padStart(2, '0')}:${String(croatiaNow.getMinutes()).padStart(2, '0')}`;
          if (session.time <= nowHourMin) {
            return jsonResponse({ success: false, error: "Nije moguće prijaviti se na listu čekanja za termin koji je već započeo." }, 400);
          }
        }

        // 3. Verify session is actually FULL before allowing waitlist join
        const bookingCountObj = await env.DB.prepare(
          "SELECT COUNT(*) as count FROM Bookings WHERE session_id = ? AND status >= 0"
        ).bind(session_id).first();
        const bookedCount = bookingCountObj ? bookingCountObj.count : 0;
        if (bookedCount < session.capacity) {
          return jsonResponse({ success: false, error: "Termin još nije popunjen. Možete ga izravno rezervirati." }, 400);
        }

        // 4. Check if user is already booked
        const existingBooking = await env.DB.prepare(
          "SELECT id FROM Bookings WHERE session_id = ? AND user_id = ? AND status >= 0"
        ).bind(session_id, user_id).first();
        if (existingBooking) {
          return jsonResponse({ success: false, error: "Već ste prijavljeni na ovaj termin." }, 400);
        }

        // 5. Check if user already has an active booking on this session's date
        const existingBookingToday = await env.DB.prepare(`
          SELECT b.id FROM Bookings b 
          JOIN Sessions s ON b.session_id = s.id 
          WHERE b.user_id = ? AND s.date = ? AND b.status >= 0
        `).bind(user_id, session.date).first();
        
        if (existingBookingToday) {
          return jsonResponse({ success: false, error: "Već imate rezerviran termin za ovaj dan. Nije moguće biti na listi čekanja za drugi termin istog dana." }, 400);
        }

        // 6. Insert into Waitlists and calculate exact position by counting predecessors
        try {
          await env.DB.prepare(
            "INSERT INTO Waitlists (session_id, user_id) VALUES (?, ?)"
          ).bind(session_id, user_id).run();

          const myWaitlist = await env.DB.prepare(
            "SELECT id, created_at FROM Waitlists WHERE session_id = ? AND user_id = ?"
          ).bind(session_id, user_id).first();

          let position = 1;
          if (myWaitlist) {
            const posObj = await env.DB.prepare(
              "SELECT COUNT(*) as pos FROM Waitlists WHERE session_id = ? AND (created_at < ? OR (created_at = ? AND id <= ?))"
            ).bind(session_id, myWaitlist.created_at, myWaitlist.created_at, myWaitlist.id).first();
            position = posObj ? posObj.pos : 1;
          }

          const dateStr = session.date.split('-').reverse().join('.') + '.';
          await logActivity(env, `Wait lista: ${client.username} → ${session.title} (${dateStr}, ${session.time}h) [${position}. na listi]`);

          return jsonResponse({ success: true, message: `Uspješno ste se prijavili na listu čekanja! Vi ste ${position}. na listi.`, position });
        } catch (err) {
          if (err.message && err.message.includes("UNIQUE")) {
            return jsonResponse({ success: true, message: "Već ste na listi čekanja za ovaj termin." });
          }
          throw err;
        }
      }

      // LEAVE WAITLIST
      if (request.method === "POST" && url.pathname === "/api/waitlist/leave") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { session_id } = await request.json();
        if (!session_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni." }, 400);
        }
        const user_id = authUser.user_id;

        const client = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(user_id).first();
        const session = await env.DB.prepare("SELECT title, date, time FROM Sessions WHERE id = ?").bind(session_id).first();

        await env.DB.prepare(
          "DELETE FROM Waitlists WHERE session_id = ? AND user_id = ?"
        ).bind(session_id, user_id).run();

        if (client && session) {
          const dateStr = session.date.split('-').reverse().join('.') + '.';
          await logActivity(env, `Napustio wait listu: ${client.username} → ${session.title} (${dateStr}, ${session.time}h)`);
        }

        return jsonResponse({ success: true, message: "Uspješno ste se maknuli s liste čekanja." });
      }

      // CLIENT DASHBOARD DATA (Get current bookings and history)
      if (request.method === "GET" && url.pathname === "/api/client/dashboard") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const userId = authUser.user_id;

        await autoConfirmBookings(env);

        const todayStr = formatDate(getCroatiaNow());

        // 1. Upcoming bookings
        const upcomingBookings = await env.DB.prepare(`
          SELECT b.id as booking_id, b.status, s.id as session_id, s.title, s.instructor, s.date, s.time, s.type
          FROM Bookings b
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.user_id = ? AND s.date >= ? AND b.status = 0
          ORDER BY s.date ASC, s.time ASC
        `).bind(userId, todayStr).all();

        // 2. Attendance history (attended or late-cancelled)
        const historyBookings = await env.DB.prepare(`
          SELECT b.id as booking_id, b.status, s.title, s.instructor, s.date, s.time, s.type
          FROM Bookings b
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.user_id = ? AND (s.date < ? OR b.status != 0) AND b.status != -2
          ORDER BY s.date DESC, s.time DESC
          LIMIT 20
        `).bind(userId, todayStr).all();

        const userDetails = await env.DB.prepare(`
          SELECT username, email, package_name, total_credits, remaining_credits, package_expires, must_change_password, questionnaire, status, full_name, first_name, last_name, phone, COALESCE(has_seen_onboarding, 0) as has_seen_onboarding,
                 (total_credits - remaining_credits - (SELECT COUNT(*) FROM Bookings b WHERE b.user_id = Clients.id AND b.status = 0)) as attended_count
          FROM Clients WHERE id = ?
        `).bind(userId).first();

        // 3.5. Check for pending package requests
        const pendingRequest = await env.DB.prepare(
          "SELECT package_name FROM PackageRequests WHERE user_id = ? AND status = 'pending' LIMIT 1"
        ).bind(userId).first();

        // 4. Notifications
        const notifications = await env.DB.prepare(`
          SELECT id, message, is_read, created_at
          FROM ClientNotifications
          WHERE user_id = ?
          ORDER BY id DESC
          LIMIT 10
        `).bind(userId).all();

        const secret = getJwtSecret(env);
        if (userDetails && userDetails.questionnaire) {
          userDetails.questionnaire = await decryptHealthData(userDetails.questionnaire, secret);
        }

        return jsonResponse({
          success: true,
          user: userDetails,
          pending_request: pendingRequest,
          upcoming: upcomingBookings.results,
          history: historyBookings.results,
          notifications: notifications.results
        });
      }

      // CLIENT: MARK NOTIFICATIONS AS READ
      if (request.method === "POST" && url.pathname === "/api/client/notifications/read") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { notification_ids } = await request.json();
        const user_id = authUser.user_id;

        if (notification_ids && notification_ids.length > 0) {
          const placeholders = notification_ids.map(() => "?").join(",");
          await env.DB.prepare(`
            UPDATE ClientNotifications
            SET is_read = 1
            WHERE user_id = ? AND id IN (${placeholders})
          `).bind(user_id, ...notification_ids).run();
        } else {
          await env.DB.prepare("UPDATE ClientNotifications SET is_read = 1 WHERE user_id = ?").bind(user_id).run();
        }

        return jsonResponse({ success: true });
      }




      // CLIENT: SAVE HEALTH QUESTIONNAIRE
      if (request.method === "POST" && url.pathname === "/api/client/questionnaire") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { answers } = await request.json();
        if (!answers) {
          return jsonResponse({ success: false, error: "Nedostaju parametri." }, 400);
        }
        const user_id = authUser.user_id;

        const answersStr = JSON.stringify(answers);
        const secret = getJwtSecret(env);
        const encryptedData = await encryptHealthData(answersStr, secret);

        await env.DB.prepare("UPDATE Clients SET questionnaire = ? WHERE id = ?").bind(encryptedData, user_id).run();
        
        // Log activity
        const user = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(user_id).first();
        if (user) {
          await logActivity(env, `Ispunjen upitnik: ${user.username}`);
        }
        
        return jsonResponse({ success: true, message: "Upitnik uspješno spremljen." });
      }

      // CLIENT: EXPORT PERSONAL DATA (GDPR Right to Data Portability)
      if (request.method === "POST" && url.pathname === "/api/client/export-data") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const user_id = authUser.user_id;

        const client = await env.DB.prepare(
          "SELECT id, username, email, full_name, first_name, last_name, phone, package_name, remaining_credits, package_expires, questionnaire, created_at FROM Clients WHERE id = ?"
        ).bind(user_id).first();

        if (!client) {
          return jsonResponse({ success: false, error: "Korisnik nije pronađen." }, 404);
        }

        const secret = getJwtSecret(env);
        const questionnaireData = await decryptHealthData(client.questionnaire, secret);

        const { results: bookings } = await env.DB.prepare(`
          SELECT b.id, b.status, b.created_at, s.title, s.date, s.time
          FROM Bookings b
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.user_id = ?
        `).bind(user_id).all();

        await logActivity(env, `GDPR izvoz podataka: Korisnik '${client.username}' zatražio je izvoz svojih podataka.`);

        let parsedQuestionnaire = null;
        if (questionnaireData) {
          try { parsedQuestionnaire = JSON.parse(questionnaireData); } catch (e) { parsedQuestionnaire = questionnaireData; }
        }

        return jsonResponse({
          success: true,
          export_date: new Date().toISOString(),
          profile: {
            username: client.username,
            email: client.email,
            full_name: client.full_name,
            first_name: client.first_name,
            last_name: client.last_name,
            phone: client.phone,
            package_name: client.package_name,
            remaining_credits: client.remaining_credits,
            package_expires: client.package_expires,
            created_at: client.created_at
          },
          health_questionnaire: parsedQuestionnaire,
          booking_history: bookings
        });
      }

      // CLIENT: MARK ONBOARDING TOUR AS COMPLETED
      if (request.method === "POST" && url.pathname === "/api/client/onboarding-completed") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        try {
          await ensureDbColumns(env);
          await env.DB.prepare("UPDATE Clients SET has_seen_onboarding = 1 WHERE id = ? OR username = ?")
            .bind(authUser.user_id, authUser.username || "").run();
        } catch (err) {
          console.error("DB update has_seen_onboarding error:", err);
        }
        return jsonResponse({ success: true, message: "Vodič je označen kao pregledan." });
      }


      // ADMIN ONLY ENDPOINTS PROTECTION
      if (url.pathname.startsWith("/api/admin/")) {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        if (!authUser.is_admin) {
          return jsonResponse({ success: false, error: "Nemate administratorska prava." }, 403);
        }
      }

      // --- ADMIN ONLY ENDPOINTS (Wife's dashboard) ---

      // ADMIN: GET PENDING CLIENTS
      if (request.method === "GET" && url.pathname === "/api/admin/pending-clients") {
        const { results } = await env.DB.prepare(
          "SELECT id, username, email, created_at, full_name, first_name, last_name, phone FROM Clients WHERE status = 'pending' ORDER BY created_at DESC"
        ).all();
        return jsonResponse({ success: true, clients: results });
      }

      // ADMIN: REVOKE SESSIONS FOR CLIENT
      if (request.method === "POST" && url.pathname === "/api/admin/revoke-sessions") {
        const { client_id } = await request.json();
        if (!client_id) {
          return jsonResponse({ success: false, error: "ID klijenta je obavezan." }, 400);
        }
        await env.DB.prepare(
          "UPDATE Clients SET token_version = COALESCE(token_version, 1) + 1 WHERE id = ?"
        ).bind(client_id).run();
        return jsonResponse({ success: true, message: "Sve aktivne sesije korisnika su uspješno poništene." });
      }

      // ADMIN: APPROVE CLIENT
      if (request.method === "POST" && url.pathname === "/api/admin/approve-client") {
        const { client_id, used_credits, package_expires } = await request.json();
        if (!client_id) {
          return jsonResponse({ success: false, error: "ID klijenta je obavezan." }, 400);
        }

        const client = await env.DB.prepare("SELECT username, email, package_name, total_credits FROM Clients WHERE id = ? AND status = 'pending'").bind(client_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Klijent na čekanju nije pronađen." }, 404);
        }

        const tempPass = generateTempPassword();
        const hashedTemp = await hashPassword(tempPass);

        const limit = client.total_credits || getPackageLimit(client.package_name);
        const used = (used_credits !== undefined && used_credits !== null && used_credits !== "") ? Math.max(0, parseInt(used_credits) || 0) : 0;
        const remaining = Math.max(0, limit - used);

        const defaultExpiresDate = new Date(getCroatiaNow().getTime() + 30 * 24 * 60 * 60 * 1000);
        const expiresStr = package_expires || formatDate(defaultExpiresDate);

        await env.DB.prepare("UPDATE Clients SET status = 'approved', password = ?, must_change_password = 1, remaining_credits = ?, package_expires = ? WHERE id = ?")
          .bind(hashedTemp, remaining, expiresStr, client_id).run();
        await logActivity(env, `Odobrena registracija: ${client.username} (Iskorišteno: ${used}, Vrijedi do: ${expiresStr})`);

        // Slanje maila s privremenom lozinkom
        const emailSubject = "Pilates Reformer Agram - Profil odobren";
        const emailHtml = `
          <div style="font-family: 'Montserrat', Arial, sans-serif; padding: 25px; color: #2c251e; background-color: #faf8f5; max-width: 600px; border-radius: 12px; border: 1px solid #e0d7c6;">
            <h2 style="color: #8b6b3e; margin-top: 0;">Vaš profil je odobren! 🎉</h2>
            <p style="font-size: 1.05rem; line-height: 1.5;">Dobrodošli u <b>Pilates Reformer studio Agram</b>! Vaš zahtjev za registraciju je uspješno odobren. Pristupni podaci:</p>
            <table style="border-spacing: 10px; background-color: #ffffff; padding: 10px 15px; border-radius: 8px; border: 1px solid #eedfc9; width: 100%;">
              <tr><td><b>Korisničko ime / Email:</b></td><td>${client.username} (${client.email})</td></tr>
              <tr><td><b>Privremena lozinka:</b></td><td><code style="background-color: #f2ebd9; color: #6e4e24; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 1.1rem;">${tempPass}</code></td></tr>
            </table>
            
            <h3 style="color: #8b6b3e; margin-top: 25px; margin-bottom: 10px;">Brze upute za prvu prijavu:</h3>
            <ol style="padding-left: 20px; line-height: 1.7; font-size: 1.05rem;">
              <li><b>Postavite trajnu lozinku:</b> Prijavite se s gornjim podacima i izaberite svoju tajnu lozinku.</li>
              <li><b>Ispunite zdravstveni karton:</b> Kratki upitnik za prilagodbu vježbanja vašem zdravstvenom stanju.</li>
              <li><b>Prođite brzi vodič:</b> Automatski vođeni vodič kroz aplikaciju pomoći će vam s prvom rezervacijom.</li>
            </ol>

            <p style="margin-top: 30px; text-align: center;">
              <a href="https://pilates-reformer-agram.com/prijava.html" style="background-color: #c5a880; color: white; padding: 12px 28px; text-decoration: none; border-radius: 25px; font-weight: bold; display: inline-block;">
                Prijavi se i započni
              </a>
            </p>
          </div>
        `;
        const emailSent = await sendEmail(env, client.email, emailSubject, emailHtml);

        return jsonResponse({ success: true, message: "Klijent je odobren i poslan mu je e-mail s lozinkom.", tempPassword: tempPass, emailSent });
      }

      // ADMIN: REJECT CLIENT
      if (request.method === "POST" && url.pathname === "/api/admin/reject-client") {
        const { client_id } = await request.json();
        if (!client_id) {
          return jsonResponse({ success: false, error: "ID klijenta je obavezan." }, 400);
        }

        const client = await env.DB.prepare("SELECT username FROM Clients WHERE id = ? AND status = 'pending'").bind(client_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Klijent na čekanju nije pronađen." }, 404);
        }

        await env.DB.prepare("DELETE FROM Clients WHERE id = ?").bind(client_id).run();
        await logActivity(env, `Odbijena registracija: ${client.username}`);

        return jsonResponse({ success: true, message: "Zahtjev za registraciju je odbačen." });
      }

      // ADMIN: DELETE CLIENT (complete removal of client and all relational data)
      if (request.method === "POST" && url.pathname === "/api/admin/delete-client") {
        const { client_id } = await request.json();
        if (!client_id) {
          return jsonResponse({ success: false, error: "ID klijenta je obavezan." }, 400);
        }

        const client = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(client_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Klijent nije pronađen." }, 404);
        }

        // Batch delete from all relational tables referencing user_id
        await env.DB.batch([
          env.DB.prepare("DELETE FROM Bookings WHERE user_id = ?").bind(client_id),
          env.DB.prepare("DELETE FROM ClientNotifications WHERE user_id = ?").bind(client_id),
          env.DB.prepare("DELETE FROM WorkshopSignups WHERE user_id = ?").bind(client_id),
          env.DB.prepare("DELETE FROM Clients WHERE id = ?").bind(client_id)
        ]);

        await logActivity(env, `Obrisan klijent: ${client.username}`);

        return jsonResponse({ success: true, message: `Klijent '${client.username}' i svi njegovi podaci su obrisani.` });
      }

      // ADMIN: GET LIST OF APPROVED CLIENTS (Sensitive health data omitted from bulk query)
      if (request.method === "GET" && url.pathname === "/api/admin/clients") {
        const { results } = await env.DB.prepare(`
          SELECT id, username, email, package_name, total_credits, remaining_credits, package_expires, created_at, status, full_name, first_name, last_name, phone,
                 (total_credits - remaining_credits - (SELECT COUNT(*) FROM Bookings b WHERE b.user_id = Clients.id AND b.status = 0)) as attended_count
          FROM Clients
          WHERE is_admin = 0 AND status IN ('approved', 'frozen')
          ORDER BY COALESCE(full_name, username) ASC
        `).all();

        return jsonResponse({ success: true, clients: results });
      }

      // ADMIN: GET CLIENT HEALTH QUESTIONNAIRE (ON-DEMAND AUDITED)
      if (request.method === "GET" && url.pathname === "/api/admin/client-questionnaire") {
        const authUser = await getAuthUser(request, env);
        if (!authUser || authUser.is_admin !== 1) {
          return jsonResponse({ success: false, error: "Nemate administratorska prava." }, 403);
        }

        const client_id = url.searchParams.get("client_id");
        if (!client_id) {
          return jsonResponse({ success: false, error: "client_id je obavezan." }, 400);
        }

        const client = await env.DB.prepare(
          "SELECT id, username, full_name, questionnaire FROM Clients WHERE id = ?"
        ).bind(client_id).first();

        if (!client) {
          return jsonResponse({ success: false, error: "Klijent nije pronađen." }, 404);
        }

        const adminName = authUser.username || "Admin";
        const clientName = client.full_name ? `${client.full_name} (${client.username})` : client.username;
        await logActivity(env, `Pregled zdravstvenog kartona: Admin '${adminName}' pregledao je karton klijenta '${clientName}'`);

        const secret = getJwtSecret(env);
        const decryptedQuestionnaire = await decryptHealthData(client.questionnaire, secret);

        return jsonResponse({ success: true, questionnaire: decryptedQuestionnaire });
      }

      // ADMIN: GET DETAILED BOOKINGS FOR A CLIENT
      if (request.method === "GET" && url.pathname === "/api/admin/client-bookings") {
        const client_id = url.searchParams.get("client_id");
        if (!client_id) {
          return jsonResponse({ success: false, error: "client_id je obavezan." }, 400);
        }

        const { results } = await env.DB.prepare(`
          SELECT b.id as booking_id, b.status, s.title, s.date, s.time
          FROM Bookings b
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.user_id = ? AND b.status >= -1
          ORDER BY s.date DESC, s.time DESC
        `).bind(client_id).all();

        return jsonResponse({ success: true, bookings: results });
      }

      // ADMIN: GET ACTIVITY LOGS
      if (request.method === "GET" && url.pathname === "/api/admin/activity-logs") {
        const { results } = await env.DB.prepare(`
          SELECT id, details, created_at FROM ActivityLogs
          WHERE details LIKE 'Nova registracija%'
             OR details LIKE 'Zahtjev za paket%'
             OR details LIKE 'Otkazano%'
             OR details LIKE 'Admin otkazao%'
          ORDER BY id DESC LIMIT 30
        `).all();
        return jsonResponse({ success: true, logs: results });
      }

      // ADMIN: CREATE CLIENT (with auto email & temp password)
      if (request.method === "POST" && url.pathname === "/api/admin/create-client") {
        const { full_name, username, email, package_name, total_credits, expiration_days } = await request.json();
        
        if (!username || !email) {
          return jsonResponse({ success: false, error: "Korisničko ime i e-mail su obavezni." }, 400);
        }

        const limit = getPackageLimit(package_name);
        if (package_name !== "Nema paketa" && parseInt(total_credits) > limit) {
          return jsonResponse({ success: false, error: `Broj treninga (${total_credits}) ne može biti veći od limita paketa (${limit}).` }, 400);
        }

        // Check if username/email already exists
        const existing = await env.DB.prepare("SELECT id FROM Clients WHERE username = ? OR email = ?").bind(username, email).first();
        if (existing) {
          return jsonResponse({ success: false, error: "Korisnik s tim korisničkim imenom ili e-mailom već postoji." }, 400);
        }

        const tempPass = generateTempPassword();
        const hashedTemp = await hashPassword(tempPass);
        
        // Calculate expiration date
        let expiresStr = null;
        if (expiration_days) {
          const expiresDate = new Date(getCroatiaNow().getTime() + parseInt(expiration_days) * 24 * 60 * 60 * 1000);
          expiresStr = formatDate(expiresDate);
        }

        let firstName = null;
        let lastName = null;
        if (full_name) {
          const nameParts = full_name.trim().split(/\s+/);
          firstName = nameParts[0] || null;
          if (nameParts.length > 1) {
            lastName = nameParts.slice(1).join(" ");
          } else {
            lastName = "";
          }
        }

        // Insert client
        const result = await env.DB.prepare(`
          INSERT INTO Clients (username, email, password, is_admin, must_change_password, package_name, total_credits, remaining_credits, package_expires, full_name, first_name, last_name)
          VALUES (?, ?, ?, 0, 1, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          username, 
          email, 
          hashedTemp, 
          package_name || "Nema paketa", 
          parseInt(total_credits) || 0, 
          parseInt(total_credits) || 0, 
          expiresStr,
          full_name || null,
          firstName,
          lastName
        ).run();

        // Send Email via Resend
        const emailSubject = "Pilates Reformer Agram - Podaci za prijavu";
        const emailHtml = `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
            <h2 style="color: #a98e65;">Dobrodošli u Pilates Reformer studio Agram!</h2>
            <p>Vaš korisnički račun je kreiran. Možete se prijaviti u aplikaciju koristeći sljedeće podatke:</p>
            <table style="border-spacing: 10px;">
              <tr><td><b>Korisničko ime:</b></td><td>${username}</td></tr>
              <tr><td><b>Privremena lozinka:</b></td><td><code style="background-color: #eee; padding: 3px 6px; border-radius: 3px;">${tempPass}</code></td></tr>
            </table>
            <p style="margin-top: 20px;">
              Pri prvoj prijavi od vas će se tražiti da postavite novu, vlastitu lozinku.
            </p>
            <p style="margin-top: 30px;">
              <a href="https://pilates-reformer-agram.com/prijava.html" style="background-color: #c5a880; color: white; padding: 10px 20px; text-decoration: none; border-radius: 20px;">
                Prijavi se ovdje
              </a>
            </p>
            <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
            <p style="font-size: 11px; color: #7c7267;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
          </div>
        `;

        const emailSent = await sendEmail(env, email, emailSubject, emailHtml);

        return jsonResponse({
          success: true,
          message: "Klijent je uspješno kreiran!",
          tempPassword: tempPass,
          emailSent: emailSent
        });
      }

      // ADMIN: UPDATE CLIENT PACKAGE / CREDITS
      if (request.method === "POST" && url.pathname === "/api/admin/update-client-credits") {
        const { client_id, package_name, total_credits, remaining_credits, package_expires } = await request.json();
        
        if (!client_id) {
          return jsonResponse({ success: false, error: "Korisnik ID je obavezan." }, 400);
        }

        const limit = getPackageLimit(package_name);
        if (package_name !== "Nema paketa") {
          if (parseInt(total_credits) > limit) {
            return jsonResponse({ success: false, error: `Ukupno treninga (${total_credits}) ne može biti veći od limita paketa (${limit}).` }, 400);
          }
          if (parseInt(remaining_credits) > limit) {
            return jsonResponse({ success: false, error: `Preostalo treninga (${remaining_credits}) ne može biti veći od limita paketa (${limit}).` }, 400);
          }
        }

        await env.DB.prepare(`
          UPDATE Clients 
          SET package_name = ?, total_credits = ?, remaining_credits = ?, package_expires = ?
          WHERE id = ?
        `).bind(
          package_name,
          parseInt(total_credits) || 0,
          parseInt(remaining_credits) || 0,
          package_expires || null,
          client_id
        ).run();

        return jsonResponse({ success: true, message: "Članarina klijenta je uspješno ažurirana!" });
      }

      // ADMIN: MANUAL CHECK-IN (Forgot to scan QR)
      if (request.method === "POST" && url.pathname === "/api/admin/check-in") {
        const { booking_id } = await request.json();
        if (!booking_id) {
          return jsonResponse({ success: false, error: "Booking ID je obavezan." }, 400);
        }

        // Fetch details for logging
        const details = await env.DB.prepare(`
          SELECT c.username, s.title, s.date, s.time
          FROM Bookings b
          JOIN Clients c ON b.user_id = c.id
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.id = ?
        `).bind(booking_id).first();

        // Set status to 1 (attended)
        await env.DB.prepare("UPDATE Bookings SET status = 1 WHERE id = ?").bind(booking_id).run();

        if (details) {
          const dateStr = details.date.split('-').reverse().join('.') + '.';
          await logActivity(env, `Ručni check-in: ${details.username} → ${details.title} (${dateStr} ${details.time}h)`);
        }

        return jsonResponse({ success: true, message: "Dolazak klijenta je uspješno upisan!" });
      }

      // ADMIN: CANCEL BOOKING (with or without refund)
      if (request.method === "POST" && url.pathname === "/api/admin/cancel-booking") {
        const { booking_id, refund } = await request.json();
        if (!booking_id) {
          return jsonResponse({ success: false, error: "Booking ID je obavezan." }, 400);
        }

        // 1. Get booking details to find user_id
        const booking = await env.DB.prepare(
          "SELECT user_id, session_id FROM Bookings WHERE id = ?"
        ).bind(booking_id).first();
        
        if (!booking) {
          return jsonResponse({ success: false, error: "Rezervacija nije pronađena." }, 404);
        }

        // Fetch details for logging before deleting/updating
        const details = await env.DB.prepare(`
          SELECT c.username, s.title, s.date, s.time
          FROM Bookings b
          JOIN Clients c ON b.user_id = c.id
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.id = ?
        `).bind(booking_id).first();

        const dateStr = details ? details.date.split('-').reverse().join('.') + '.' : '';

        if (refund) {
          const msg = details 
            ? `Studio je otkazao Vašu rezervaciju za termin '${details.title}' (${dateStr} u ${details.time}h). Trening Vam je vraćen na račun te možete odabrati novi termin.`
            : `Studio je otkazao Vašu rezervaciju. Trening Vam je vraćen na račun.`;

          // Refund credit ONLY IF status transition from status = 0 (Reserved) to -2 succeeded
          const [updateResult, refundResult] = await env.DB.batch([
            env.DB.prepare(
              "UPDATE Bookings SET status = -2 WHERE id = ? AND status = 0"
            ).bind(booking_id),
            env.DB.prepare(
              "UPDATE Clients SET remaining_credits = remaining_credits + 1 WHERE id = ?"
            ).bind(booking.user_id),
            env.DB.prepare(
              "INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)"
            ).bind(booking.user_id, msg)
          ]);

          if (!updateResult || !updateResult.meta || updateResult.meta.changes === 0) {
            return jsonResponse({ success: false, error: "Rezervacija je već otkazana ili je trening već odrađen." }, 400);
          }
          
          if (details) {
            await logActivity(env, `Admin otkazao (povrat): ${details.username} → ${details.title} (${dateStr} ${details.time}h)`);
          }

          // Notify waitlist when a session spot opens up
          await notifyWaitlist(env, booking.session_id);

          return jsonResponse({ success: true, message: "Rezervacija je uspješno otkazana, a klijentu je vraćen 1 trening na račun!" });
        } else {
          const msg = details
            ? `Studio je otkazao Vašu rezervaciju za termin '${details.title}' (${dateStr} u ${details.time}h) bez povrata treninga na račun.`
            : `Studio je otkazao Vašu rezervaciju bez povrata treninga na račun.`;

          // No refund: set status to -1 (absent) and add client notification
          await env.DB.batch([
            env.DB.prepare("UPDATE Bookings SET status = -1 WHERE id = ?").bind(booking_id),
            env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)").bind(booking.user_id, msg)
          ]);
          
          if (details) {
            await logActivity(env, `Admin otkazao (bez povrata): ${details.username} → ${details.title} (${dateStr} ${details.time}h)`);
          }

          // Notify waitlist when a session spot opens up
          await notifyWaitlist(env, booking.session_id);

          return jsonResponse({ success: true, message: "Rezervacija je otkazana bez povrata kredita (označeno kao nedolazak)." });
        }
      }

      // ADMIN: GET LIST OF SESSIONS & ATTENDEES FOR A DATE
      if (request.method === "GET" && url.pathname === "/api/admin/sessions-overview") {
        const dateStr = url.searchParams.get("date") || formatDate(getCroatiaNow());
        
        ctx.waitUntil(checkAndAutoGenerateSchedules(env));
        await autoConfirmBookings(env);
        
        const cutoffDate = new Date(getCroatiaNow().getTime() + 12 * 60 * 60 * 1000);
        const cutoffStr = formatLocalDateTimeISO(cutoffDate);
        
        // 1. Get all sessions for this date
        const sessions = await env.DB.prepare(`
          SELECT s.*, 
                 (SELECT COUNT(*) FROM Bookings b WHERE b.session_id = s.id AND b.status >= 0) as booked_count
          FROM Sessions s
          WHERE s.date = ?
          ORDER BY s.time ASC
        `).bind(dateStr).all();

        // 2. Get attendees list for all sessions of this date
        const attendees = await env.DB.prepare(`
          SELECT b.id as booking_id, b.session_id, b.status, c.username, c.email, c.remaining_credits, c.total_credits,
                 (SELECT COUNT(*) FROM Bookings b2 
                  JOIN Sessions s2 ON b2.session_id = s2.id 
                  WHERE b2.user_id = c.id 
                    AND b2.status = 0 
                    AND (s2.date || 'T' || s2.time || ':00') >= ?) as cancelable_count
          FROM Bookings b
          JOIN Clients c ON b.user_id = c.id
          JOIN Sessions s ON b.session_id = s.id
          WHERE s.date = ? AND b.status >= -1
        `).bind(cutoffStr, dateStr).all();

        return jsonResponse({
          success: true,
          sessions: sessions.results,
          attendees: attendees.results
        });
      }

      // ADMIN: CREATE SESSION (Termin)
      if (request.method === "POST" && url.pathname === "/api/admin/create-session") {
        const { title, instructor, date, time, capacity, type } = await request.json();
        
        if (!title || typeof title !== 'string' || title.trim().length > 100) {
          return jsonResponse({ success: false, error: "Naziv termina je obavezan i mora biti kraći od 100 znakova." }, 400);
        }

        if (!validateDateStr(date)) {
          return jsonResponse({ success: false, error: "Neispravan format datuma (očekuje se YYYY-MM-DD)." }, 400);
        }

        if (!validateTimeStr(time)) {
          return jsonResponse({ success: false, error: "Neispravan format vremena (očekuje se HH:MM)." }, 400);
        }

        const capNum = validateCapacity(capacity);
        if (!capNum) {
          return jsonResponse({ success: false, error: "Kapacitet mora biti broj između 1 i 20." }, 400);
        }

        await env.DB.prepare(`
          INSERT INTO Sessions (title, instructor, date, time, capacity, type)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(
          title.trim(),
          (instructor && typeof instructor === 'string' && instructor.trim().length <= 50) ? instructor.trim() : "Adrijana",
          date,
          time,
          capNum,
          type || "grupni"
        ).run();

        return jsonResponse({ success: true, message: "Novi termin je uspješno dodan u raspored!" });
      }

      // ADMIN: GENERATE WEEKLY SCHEDULE TEMPLATE
      if (request.method === "POST" && url.pathname === "/api/admin/generate-weekly-schedule") {
        const { monday_date } = await request.json();
        if (!monday_date) {
          return jsonResponse({ success: false, error: "Datum ponedjeljka je obavezan." }, 400);
        }

        const start = new Date(monday_date);
        if (isNaN(start.getTime())) {
          return jsonResponse({ success: false, error: "Neispravan format datuma." }, 400);
        }

        const queries = [];
        const instructorName = "Adrijana";

        for (let i = 0; i < 5; i++) {
          const currentDay = new Date(start.getTime() + i * 24 * 60 * 60 * 1000);
          const dateStr = formatDate(currentDay);
          const dayOfWeek = currentDay.getDay(); // 1 = Mon, 2 = Tue, ..., 5 = Fri

          const morningHours = ["07:00", "08:00", "09:00", "10:00"];
          const afternoonHours = ["16:00", "17:00", "18:00", "19:00", "20:00"];
          const allHours = [...morningHours, ...afternoonHours];

          allHours.forEach(time => {
            let type = "grupni";
            let capacity = 4;
            let title = "Grupni trening";

            queries.push(
              env.DB.prepare(`
                INSERT INTO Sessions (title, instructor, date, time, capacity, type)
                SELECT ?, ?, ?, ?, ?, ?
                WHERE NOT EXISTS (
                  SELECT 1 FROM Sessions WHERE date = ? AND time = ?
                )
              `).bind(title, instructorName, dateStr, time, capacity, type, dateStr, time)
            );
          });
        }

        await env.DB.batch(queries);
        return jsonResponse({ success: true, message: "Tjedni raspored je uspješno generiran!" });
      }

      // ADMIN: DELETE SESSION (Refunds credits if cancelled by admin)
      if (request.method === "POST" && url.pathname === "/api/admin/delete-session") {
        const { session_id } = await request.json();
        if (!session_id) {
          return jsonResponse({ success: false, error: "ID termina je obavezan." }, 400);
        }

        // Fetch active bookings for this session to notify clients
        const activeBookings = await env.DB.prepare(`
          SELECT b.user_id, s.title, s.date, s.time
          FROM Bookings b
          JOIN Sessions s ON b.session_id = s.id
          WHERE b.session_id = ? AND b.status >= 0
        `).bind(session_id).all();

        const queries = [];

        // 1. Refund credits to all users registered for this session (status = 0 or 1, not absent -1)
        queries.push(
          env.DB.prepare(`
            UPDATE Clients 
            SET remaining_credits = remaining_credits + 1 
            WHERE id IN (SELECT user_id FROM Bookings WHERE session_id = ? AND status >= 0)
          `).bind(session_id)
        );

        // 2. Insert notifications for each user
        if (activeBookings.results && activeBookings.results.length > 0) {
          activeBookings.results.forEach(booking => {
            const dateStr = booking.date.split('-').reverse().join('.') + '.';
            const msg = `Termin '${booking.title}' (${dateStr} u ${booking.time}h) je otkazan od strane studija. Trening Vam je vraćen na račun te možete odabrati novi termin.`;
            queries.push(
              env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)").bind(booking.user_id, msg)
            );
          });
        }

        // 3. Delete waitlists first to preserve foreign key integrity, then delete session
        queries.push(
          env.DB.prepare("DELETE FROM Waitlists WHERE session_id = ?").bind(session_id)
        );
        queries.push(
          env.DB.prepare("DELETE FROM Sessions WHERE id = ?").bind(session_id)
        );

        await env.DB.batch(queries);

        return jsonResponse({ success: true, message: "Termin je uspješno otkazan i izbrisan, a krediti su vraćeni prijavljenim korisnicima!" });
      }

      // ADMIN: CHANGE SESSION TYPE
      if (request.method === "POST" && url.pathname === "/api/admin/change-session-type") {
        const { session_id, new_type } = await request.json();
        
        if (!session_id || !new_type) {
          return jsonResponse({ success: false, error: "ID termina i novi tip su obavezni." }, 400);
        }

        const validTypes = ["grupni", "poluindividualni", "privatni"];
        if (!validTypes.includes(new_type)) {
          return jsonResponse({ success: false, error: "Neispravan tip treninga." }, 400);
        }

        const session = await env.DB.prepare("SELECT * FROM Sessions WHERE id = ?").bind(session_id).first();
        if (!session) {
          return jsonResponse({ success: false, error: "Termin nije pronađen." }, 404);
        }

        // Provjeri ima li aktivnih rezervacija
        const activeBookings = await env.DB.prepare(
          "SELECT COUNT(*) as count FROM Bookings WHERE session_id = ? AND status >= 0"
        ).bind(session_id).first();

        if (activeBookings && activeBookings.count > 0) {
          return jsonResponse({
            success: false,
            error: "Nije moguće promijeniti tip treninga jer u ovom terminu već postoje prijavljeni klijenti. Molimo Vas da prvo ručno otkažete ili prebacite klijente u neki drugi termin."
          }, 400);
        }

        let newCapacity = 4;
        let newTitle = "Grupni trening";

        if (new_type === "poluindividualni") {
          newCapacity = 2;
          newTitle = "Poluindividualni trening";
        } else if (new_type === "privatni") {
          newCapacity = 1;
          newTitle = "Privatni trening";
        }

        await env.DB.prepare(
          "UPDATE Sessions SET type = ?, capacity = ?, title = ? WHERE id = ?"
        ).bind(new_type, newCapacity, newTitle, session_id).run();

        await logActivity(env, `Promjena tipa: ${session.type} → ${new_type} (${newTitle}, kap. ${newCapacity})`);

        return jsonResponse({ success: true, message: "Tip termina je uspješno promijenjen!" });
      }

      // ADMIN: CREATE NEWS OR WORKSHOP
      if (request.method === "POST" && url.pathname === "/api/admin/create-news") {
        const { title, content, image_url, is_workshop } = await request.json();
        
        if (!title || typeof title !== 'string' || title.trim().length > 150) {
          return jsonResponse({ success: false, error: "Naslov obavijesti je obavezan i mora biti kraći od 150 znakova." }, 400);
        }

        if (!content || typeof content !== 'string' || content.trim().length > 10000) {
          return jsonResponse({ success: false, error: "Sadržaj obavijesti je obavezan i mora biti kraći od 10,000 znakova." }, 400);
        }

        const imgErr = validateImageUrl(image_url);
        if (imgErr) {
          return jsonResponse({ success: false, error: imgErr }, 400);
        }

        await env.DB.prepare(`
          INSERT INTO News (title, content, image_url, is_workshop)
          VALUES (?, ?, ?, ?)
        `).bind(
          title.trim(),
          content.trim(),
          image_url ? image_url.trim() : null,
          parseInt(is_workshop) || 0
        ).run();

        return jsonResponse({ success: true, message: "Obavijest/radionica je uspješno objavljena!" });
      }

      // ADMIN: SEND DAILY REPORT EMAIL ON DEMAND
      if (request.method === "POST" && url.pathname === "/api/admin/send-daily-report") {
        const authUser = await getAuthUser(request, env);
        if (!authUser || authUser.is_admin !== 1) {
          return jsonResponse({ success: false, error: "Nemate administratorska prava." }, 403);
        }

        const { date } = await request.json();
        const dateStr = date || formatDate(getCroatiaNow());
        
        const success = await sendDailyReportEmail(env, dateStr);
        if (success) {
          return jsonResponse({ success: true, message: `Dnevno izvješće za ${dateStr.split('-').reverse().join('.')}. je poslano na e-mail.` });
        } else {
          return jsonResponse({ success: false, error: "Greška pri slanju e-maila." }, 500);
        }
      }

      // ADMIN: MANUALLY BOOK CLIENT TO SESSION
      if (request.method === "POST" && url.pathname === "/api/admin/book-client-manual") {
        const { session_id, client_id } = await request.json();
        
        if (!session_id || !client_id) {
          return jsonResponse({ success: false, error: "Svi parametri su obavezni (session_id, client_id)." }, 400);
        }

        // 1. Get Client credits and check expiration
        const client = await env.DB.prepare(
          "SELECT id, username, email, remaining_credits, package_expires, package_name, status FROM Clients WHERE id = ?"
        ).bind(client_id).first();

        if (!client) {
          return jsonResponse({ success: false, error: "Klijent nije pronađen." }, 404);
        }

        if (client.status === "frozen") {
          return jsonResponse({ success: false, error: "Klijentova članarina je zaleđena. Nije moguće rezervirati termine." }, 400);
        }

        // Check if client has remaining credits
        if (client.remaining_credits <= 0) {
          return jsonResponse({ success: false, error: "Klijent nema preostalih treninga (kredita) u paketu." }, 400);
        }

        const todayStr = formatDate(getCroatiaNow());
        if (client.package_expires && client.package_expires < todayStr) {
          return jsonResponse({ success: false, error: `Klijentov paket (${client.package_name}) je istekao dana ${client.package_expires.split('-').reverse().join('.')}.` }, 400);
        }

        // 2. Check Session capacity and if client is already booked
        const session = await env.DB.prepare("SELECT * FROM Sessions WHERE id = ?").bind(session_id).first();
        if (!session) {
          return jsonResponse({ success: false, error: "Termin nije pronađen." }, 404);
        }

        // ATOMIC BATCH TRANSACTION: Deduct credit & Insert booking in 1 atomic D1 batch!
        const [creditResult, insertResult] = await env.DB.batch([
          env.DB.prepare(
            "UPDATE Clients SET remaining_credits = remaining_credits - 1 WHERE id = ? AND remaining_credits > 0"
          ).bind(client_id),
          env.DB.prepare(`
            INSERT INTO Bookings (session_id, user_id, status)
            SELECT ?, ?, 0
            WHERE (
              SELECT COUNT(*) FROM Bookings b
              JOIN Sessions s ON b.session_id = s.id
              WHERE b.user_id = ? AND s.date = ? AND b.status >= 0
            ) = 0
            AND (
              SELECT COUNT(*) FROM Bookings WHERE session_id = ? AND status >= 0
            ) < (SELECT capacity FROM Sessions WHERE id = ?)
          `).bind(session_id, client_id, client_id, session.date, session_id, session_id)
        ]);

        if (!creditResult || !creditResult.meta || creditResult.meta.changes === 0) {
          return jsonResponse({ success: false, error: "Klijent nema preostalih treninga (kredita) u paketu." }, 400);
        }

        // Compensation/rollback if insert failed
        if (!insertResult || !insertResult.meta || insertResult.meta.changes === 0) {
          await env.DB.prepare("UPDATE Clients SET remaining_credits = remaining_credits + 1 WHERE id = ?").bind(client_id).run();

          const existingToday = await env.DB.prepare(`
            SELECT b.id FROM Bookings b 
            JOIN Sessions s ON b.session_id = s.id 
            WHERE b.user_id = ? AND s.date = ? AND b.status >= 0
          `).bind(client_id, session.date).first();
          if (existingToday) {
            return jsonResponse({ success: false, error: "Klijent već ima rezerviran termin za ovaj dan." }, 400);
          }

          const currentCountObj = await env.DB.prepare("SELECT COUNT(*) as count FROM Bookings WHERE session_id = ? AND status >= 0").bind(session_id).first();
          if (currentCountObj && currentCountObj.count >= session.capacity) {
            return jsonResponse({ success: false, error: "Termin je u međuvremenu popunjen." }, 400);
          }

          return jsonResponse({ success: false, error: "Klijent je već prijavljen na ovaj termin." }, 400);
        }

        const dateFormatted = session.date.split('-').reverse().join('.') + '.';
        const notificationMsg = `Studio Vam je rezervirao termin '${session.title}' dana ${dateFormatted} u ${session.time}h.`;
        await env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)").bind(client_id, notificationMsg).run();

        await logActivity(env, `Admin rezervacija: ${client.username} → ${session.title} (${dateFormatted}, ${session.time}h)`);

        // If they had exactly 1 credit remaining, they used their last credit! Send notification email.
        if (client.remaining_credits === 1 && client.email) {
          const emailSubject = "Agram Pilates - Iskoristili ste sve treninge iz paketa";
          const emailHtml = `
            <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
              <h2 style="color: #a98e65;">Svi treninzi su iskorišteni</h2>
              <p>Bok <b>${escapeHtml(client.username)}</b>,</p>
              <p>Obavještavamo Vas da je studio upravo rezervirao termin <b>'${escapeHtml(session.title)}'</b> za Vas čime ste iskoristili zadnji preostali trening iz Vašeg paketa <b>${escapeHtml(client.package_name)}</b>.</p>
              <p>Kako biste mogli nastaviti s vježbanjem i rezervirati nove termine, molimo Vas da odaberete novi paket unutar aplikacije.</p>
              <p style="margin-top: 30px;">
                <a href="https://pilates-reformer-agram.com/dashboard.html" style="background-color: #c5a880; color: white; padding: 10px 20px; text-decoration: none; border-radius: 20px;">
                  Otvori Profil i odaberi paket
                </a>
              </p>
              <hr style="border: 0; border-top: 1px solid #ebdcc5; margin-top: 30px;">
              <p style="font-size: 11px; color: #7c7267;">Ova poruka je poslana automatski. Molimo ne odgovarajte na nju.</p>
            </div>
          `;
          ctx.waitUntil(sendEmail(env, client.email, emailSubject, emailHtml));
        }

        return jsonResponse({ success: true, message: "Rezervacija je uspješno kreirana od strane administratora!" });
      }

      // ADMIN: GET INSTAGRAM CONFIG STATUS
      if (request.method === "GET" && url.pathname === "/api/admin/instagram/status") {
        const tokenObj = await env.DB.prepare("SELECT value FROM Settings WHERE key = 'instagram_access_token'").first();
        const lastSyncObj = await env.DB.prepare("SELECT value FROM Settings WHERE key = 'instagram_last_synced_at'").first();
        const tokenUpdatedObj = await env.DB.prepare("SELECT value FROM Settings WHERE key = 'instagram_token_updated_at'").first();
        
        return jsonResponse({
          success: true,
          isConfigured: !!(tokenObj && tokenObj.value),
          lastSyncedAt: lastSyncObj ? lastSyncObj.value : null,
          tokenUpdatedAt: tokenUpdatedObj ? tokenUpdatedObj.value : null
        });
      }

      // ADMIN: SET INSTAGRAM ACCESS TOKEN
      if (request.method === "POST" && url.pathname === "/api/admin/instagram/token") {
        const { token } = await request.json();
        if (!token) {
          return jsonResponse({ success: false, error: "Pristupni token je obavezan." }, 400);
        }

        const croatiaNow = getCroatiaNow();
        const nowStr = croatiaNow.toISOString().replace('T', ' ').substring(0, 19);

        // Batch save token and mark update time
        await env.DB.batch([
          env.DB.prepare("INSERT OR REPLACE INTO Settings (key, value) VALUES ('instagram_access_token', ?)").bind(token),
          env.DB.prepare("INSERT OR REPLACE INTO Settings (key, value) VALUES ('instagram_token_updated_at', ?)").bind(nowStr)
        ]);

        await logActivity(env, "Ažuriran Instagram token");

        // Pokreni odmah prvu sinkronizaciju objava
        const syncSuccess = await syncInstagramFeed(env);

        return jsonResponse({ 
          success: true, 
          message: "Instagram token je uspješno spremljen!",
          syncSuccess
        });
      }

      // ADMIN: MANUALLY SYNC INSTAGRAM FEED
      if (request.method === "POST" && url.pathname === "/api/admin/instagram/sync") {
        const syncSuccess = await syncInstagramFeed(env);
        if (!syncSuccess) {
          return jsonResponse({ success: false, error: "Neuspješna sinkronizacija. Provjerite ispravnost Instagram tokena." }, 500);
        }

        const { results } = await env.DB.prepare("SELECT * FROM InstagramPosts ORDER BY timestamp DESC LIMIT 6").all();
        return jsonResponse({ success: true, message: "Sinkronizacija uspješna!", posts: results });
      }

      // CLIENT: REQUEST NEW PACKAGE
      if (request.method === "POST" && url.pathname === "/api/client/request-package") {
        const authUser = await getAuthUser(request, env);
        if (!authUser) {
          return jsonResponse({ success: false, error: "Niste prijavljeni." }, 401);
        }
        const { package_name } = await request.json();
        if (!package_name || typeof package_name !== 'string' || package_name.length > 50) {
          return jsonResponse({ success: false, error: "Nedostaju ili su neispravni parametri." }, 400);
        }

        const pkgLimit = getPackageLimit(package_name);
        if (pkgLimit <= 0) {
          return jsonResponse({ success: false, error: "Odabrani paket nije važeći." }, 400);
        }

        const user_id = authUser.user_id;

        const client = await env.DB.prepare("SELECT username, email, status, remaining_credits, package_expires, package_name FROM Clients WHERE id = ?").bind(user_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Korisnik nije pronađen." }, 404);
        }

        if (client.status === "frozen") {
          return jsonResponse({ success: false, error: "Vaša članarina je trenutno zaleđena. Nije moguće slati zahtjeve za novi paket." }, 400);
        }

        const todayStr = formatDate(getCroatiaNow());
        const isExpired = client.package_expires && client.package_expires < todayStr;
        const hasNoPackage = !client.package_name || client.package_name === "Nema paketa" || client.package_name === "Nema aktivnog paketa";

        if (client.remaining_credits > 0 && !isExpired && !hasNoPackage) {
          return jsonResponse({ success: false, error: "Nije moguće zatražiti novi paket dok ne iskoristite sve treninge iz postojećeg." }, 400);
        }

        // Save request to DB atomically (race condition free check-and-insert)
        const insertRes = await env.DB.prepare(`
          INSERT INTO PackageRequests (user_id, package_name, status)
          SELECT ?, ?, 'pending'
          WHERE NOT EXISTS (
            SELECT 1 FROM PackageRequests WHERE user_id = ? AND status = 'pending'
          )
        `).bind(user_id, package_name, user_id).run();

        if (!insertRes || !insertRes.meta || insertRes.meta.changes === 0) {
          return jsonResponse({ success: false, error: "Već imate aktivan zahtjev za paket na čekanju." }, 400);
        }

        // Log activity
        await logActivity(env, `Zahtjev za paket: ${client.username} → ${package_name}`);

        // Send email to admin
        const adminEmail = "adrijana.kontek@gmail.com";
        const subject = `Agram Pilates - Zahtjev za paket: ${escapeHtml(client.username)}`;
        const htmlContent = `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
            <h2 style="color: #a98e65;">Zahtjev za aktivaciju paketa</h2>
            <p>Klijent <b>${escapeHtml(client.username)}</b> (e-mail: ${escapeHtml(client.email)}) je zatražio aktivaciju sljedećeg paketa:</p>
            <p style="font-size: 1.2rem; background-color: #f5eedf; padding: 15px; border-radius: 8px; border: 1px solid #ebdcc5; font-weight: bold; color: #2c251e;">
              ${escapeHtml(package_name)}
            </p>
            <p style="margin-top: 20px;">
              Molimo Vas da se prijavite u <a href="https://pilates-reformer-agram.com/admin.html">Admin panel</a>, kako biste odobrili ili odbili ovaj zahtjev.
            </p>
          </div>
        `;
        ctx.waitUntil(sendEmail(env, adminEmail, subject, htmlContent));

        return jsonResponse({ success: true, message: `Zahtjev za paket '${package_name}' je uspješno poslan! Paket će biti aktiviran nakon što ga administrator odobri.` });
      }

      // ADMIN: TOGGLE FREEZE CLIENT
      if (request.method === "POST" && url.pathname === "/api/admin/toggle-freeze") {
        const { client_id } = await request.json();
        if (!client_id) {
          return jsonResponse({ success: false, error: "ID klijenta je obavezan." }, 400);
        }

        const client = await env.DB.prepare("SELECT username, status FROM Clients WHERE id = ?").bind(client_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Klijent nije pronađen." }, 404);
        }

        let newStatus = "approved";
        let actionMsg = "";
        let respMsg = "";

        if (client.status === "frozen") {
          newStatus = "approved";
          actionMsg = `Admin je odmrznuo račun klijentu '${client.username}'.`;
          respMsg = `Klijent '${client.username}' je uspješno odmrznut.`;
        } else {
          newStatus = "frozen";
          actionMsg = `Admin je zaledio račun klijentu '${client.username}'.`;
          respMsg = `Klijent '${client.username}' je uspješno zaleđen.`;
        }

        await env.DB.prepare(
          "UPDATE Clients SET status = ?, token_version = COALESCE(token_version, 1) + 1 WHERE id = ?"
        ).bind(newStatus, client_id).run();
        await logActivity(env, actionMsg);

        return jsonResponse({ success: true, message: respMsg, newStatus });
      }

      // ADMIN: GET PENDING PACKAGE REQUESTS
      if (request.method === "GET" && url.pathname === "/api/admin/package-requests") {
        const { results } = await env.DB.prepare(`
          SELECT pr.id as request_id, pr.package_name, pr.created_at, pr.status, c.id as user_id, c.username, c.email, c.full_name
          FROM PackageRequests pr
          JOIN Clients c ON pr.user_id = c.id
          WHERE pr.status = 'pending'
          ORDER BY pr.created_at DESC
        `).all();
        return jsonResponse({ success: true, requests: results });
      }

      // ADMIN: APPROVE PACKAGE REQUEST
      if (request.method === "POST" && (url.pathname === "/api/admin/approve-package-request" || url.pathname === "/api/admin/package-requests/approve")) {
        const { request_id, user_id: req_user_id, package_name: req_pkg_name, used_credits, package_expires } = await request.json();
        
        let user_id = req_user_id;
        let package_name = req_pkg_name;
        let targetRequestId = request_id || null;

        if (request_id) {
          const reqObj = await env.DB.prepare("SELECT user_id, package_name, status FROM PackageRequests WHERE id = ? AND status = 'pending'").bind(request_id).first();
          if (!reqObj) {
            return jsonResponse({ success: false, error: "Zahtjev nije pronađen ili je već obrađen." }, 404);
          }
          user_id = reqObj.user_id;
          package_name = reqObj.package_name;
        }

        if (!user_id || !package_name) {
          return jsonResponse({ success: false, error: "Nedostaju obavezni podaci (user_id, package_name ili važeći request_id)." }, 400);
        }

        const client = await env.DB.prepare("SELECT username, email FROM Clients WHERE id = ?").bind(user_id).first();
        if (!client) {
          return jsonResponse({ success: false, error: "Klijent nije pronađen." }, 404);
        }

        const limit = getPackageLimit(package_name);
        if (limit <= 0) {
          return jsonResponse({ success: false, error: "Odabrani paket nije važeći." }, 400);
        }

        const used = (used_credits !== undefined && used_credits !== null && used_credits !== "") ? Math.max(0, parseInt(used_credits) || 0) : 0;
        const remaining = Math.max(0, limit - used);

        const defaultExpiresDate = new Date(getCroatiaNow().getTime() + 30 * 24 * 60 * 60 * 1000);
        const expiresStr = package_expires || formatDate(defaultExpiresDate);

        // Approve: update client credits, mark request as approved atomically
        const msg = `Vaš zahtjev za aktivaciju paketa '${package_name}' je odobren! Paket je aktiviran.`;
        
        const batchQueries = [
          env.DB.prepare("UPDATE Clients SET package_name = ?, total_credits = ?, remaining_credits = ?, package_expires = ? WHERE id = ?")
            .bind(package_name, limit, remaining, expiresStr, user_id),
          env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)")
            .bind(user_id, msg)
        ];

        if (targetRequestId) {
          batchQueries.push(
            env.DB.prepare("UPDATE PackageRequests SET status = 'approved' WHERE id = ? AND status = 'pending'")
              .bind(targetRequestId)
          );
        }

        const results = await env.DB.batch(batchQueries);
        if (targetRequestId && results[2] && results[2].meta && results[2].meta.changes === 0) {
          return jsonResponse({ success: false, error: "Zahtjev je u međuvremenu već obrađen." }, 400);
        }

        await logActivity(env, `Odobren paket: ${client.username} → ${package_name}`);

        // Send confirmation email to client
        const emailSubject = "Agram Pilates - Paket aktiviran";
        const emailHtml = `
          <div style="font-family: Arial, sans-serif; padding: 20px; color: #2c251e; background-color: #faf8f5;">
            <h2 style="color: #a98e65;">Paket je uspješno aktiviran!</h2>
            <p>Bok <b>${escapeHtml(client.username)}</b>,</p>
            <p>Obavještavamo Vas da je Vaš zahtjev odobren te je paket <b>'${escapeHtml(package_name)}'</b> (s ${limit} treninga) sada aktivan na Vašem profilu.</p>
            <p>Članarina vrijedi do <b>${expiresStr.split('-').reverse().join('.')}.</b></p>
            <p style="margin-top: 30px;">
              <a href="https://pilates-reformer-agram.com/dashboard.html" style="background-color: #c5a880; color: white; padding: 10px 20px; text-decoration: none; border-radius: 20px;">
                Otvori raspored i rezerviraj termin
              </a>
            </p>
          </div>
        `;
        ctx.waitUntil(sendEmail(env, client.email, emailSubject, emailHtml));

        return jsonResponse({ success: true, message: "Zahtjev je odobren i paket je aktiviran!" });
      }

      // ADMIN: REJECT PACKAGE REQUEST
      if (request.method === "POST" && url.pathname === "/api/admin/reject-package-request") {
        const { request_id } = await request.json();
        if (!request_id) {
          return jsonResponse({ success: false, error: "ID zahtjeva je obavezan." }, 400);
        }

        const reqObj = await env.DB.prepare("SELECT user_id, package_name FROM PackageRequests WHERE id = ? AND status = 'pending'").bind(request_id).first();
        if (!reqObj) {
          return jsonResponse({ success: false, error: "Zahtjev nije pronađen ili je već obrađen." }, 404);
        }

        const { user_id, package_name } = reqObj;
        const client = await env.DB.prepare("SELECT username FROM Clients WHERE id = ?").bind(user_id).first();
        
        const msg = `Vaš zahtjev za aktivaciju paketa '${package_name}' je odbijen. Molimo kontaktirajte studio za detalje.`;

        await env.DB.batch([
          env.DB.prepare("UPDATE PackageRequests SET status = 'rejected' WHERE id = ?").bind(request_id),
          env.DB.prepare("INSERT INTO ClientNotifications (user_id, message) VALUES (?, ?)").bind(user_id, msg)
        ]);

        if (client) {
          await logActivity(env, `Odbijen paket: ${client.username} → ${package_name}`);
        }

        return jsonResponse({ success: true, message: "Zahtjev je odbijen." });
      }

      // Fallback
      return jsonResponse({ success: false, error: "Stranica nije pronađena (404)." }, 404);

    } catch (e) {
      console.error("Worker error details:", e?.stack || e?.message || e);
      return jsonResponse({
        success: false,
        error: `Došlo je do interne pogreške na poslužitelju. (${e?.message || 'Nepoznata greška'})`
      }, 500, request);
    }
  },
  async scheduled(event, env, ctx) {
    const scheduledTimestamp = event.scheduledTime || Date.now();
    const croatiaNow = getCroatiaNow(scheduledTimestamp);
    const croatiaTimeFormatted = formatCroatiaString(scheduledTimestamp);

    console.log("[SCHEDULED EVENT]", {
      cron: event.cron,
      scheduledTime: event.scheduledTime,
      croatiaTime: croatiaTimeFormatted,
      croatiaHour: croatiaNow.getHours()
    });

    switch (event.cron) {
      case "0 */12 * * *":
        console.log("Executing scheduled task: 0 */12 * * * (syncInstagramFeed, checkAndAutoGenerateSchedules)");
        ctx.waitUntil(Promise.all([
          syncInstagramFeed(env),
          checkAndAutoGenerateSchedules(env)
        ]));
        return;

      case "0 18,19 * * *":
        console.log("Executing scheduled task: 0 18,19 * * * (sendBookingReminders)");
        ctx.waitUntil(sendBookingReminders(env, event));
        return;

      case "15 20,21 * * 5":
        console.log("Executing scheduled task: 15 20,21 * * 5 (sendWeeklyReportEmail)");
        if (croatiaNow.getDay() === 5 && croatiaNow.getHours() === 22) {
          ctx.waitUntil(sendWeeklyReportEmail(env));
        } else {
          console.log(`Skipping weekly report: croatia day=${croatiaNow.getDay()} (expected 5), hour=${croatiaNow.getHours()} (expected 22)`);
        }
        return;

      default:
        console.warn(`Unknown cron trigger: ${event.cron}`);
    }
  }
};