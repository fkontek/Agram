import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { beforeAll, describe, it, expect } from 'vitest';
import worker from '../src';

// Combined SQL Schema in single-line statements to prevent SQLite parse issues
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS Clients (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, is_admin INTEGER DEFAULT 0, credits INTEGER DEFAULT 0, must_change_password INTEGER DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, package_name TEXT, total_credits INTEGER DEFAULT 0, remaining_credits INTEGER DEFAULT 0, package_expires TEXT, status TEXT DEFAULT 'approved', questionnaire TEXT DEFAULT NULL, full_name TEXT);
CREATE TABLE IF NOT EXISTS Sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, instructor TEXT, date TEXT NOT NULL, time TEXT NOT NULL, capacity INTEGER DEFAULT 5, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, type TEXT DEFAULT 'grupni');
CREATE TABLE IF NOT EXISTS Bookings (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, status INTEGER DEFAULT 0, FOREIGN KEY (session_id) REFERENCES Sessions(id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES Clients(id) ON DELETE CASCADE, UNIQUE(session_id, user_id));
CREATE TABLE IF NOT EXISTS News (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, content TEXT NOT NULL, image_url TEXT, is_workshop INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS WorkshopSignups (id INTEGER PRIMARY KEY AUTOINCREMENT, news_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (news_id) REFERENCES News(id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES Clients(id) ON DELETE CASCADE, UNIQUE(news_id, user_id));
CREATE TABLE IF NOT EXISTS ActivityLogs (id INTEGER PRIMARY KEY AUTOINCREMENT, details TEXT NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS ClientNotifications (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, message TEXT NOT NULL, is_read INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY(user_id) REFERENCES Clients(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS Settings (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS InstagramPosts (id TEXT PRIMARY KEY, caption TEXT, media_type TEXT, media_url TEXT, permalink TEXT, thumbnail_url TEXT, timestamp TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS Waitlists (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(session_id, user_id), FOREIGN KEY (session_id) REFERENCES Sessions(id), FOREIGN KEY (user_id) REFERENCES Clients(id));
CREATE TABLE IF NOT EXISTS PackageRequests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, package_name TEXT NOT NULL, status TEXT DEFAULT 'pending', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES Clients(id) ON DELETE CASCADE);
`;

// Helper to hash password using SHA-256
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

describe('JWT Authentication integration tests', () => {
  beforeAll(async () => {
    // 1. Initialize schema by executing statements individually
    const statements = SCHEMA_SQL.split('\n')
      .map(s => s.trim())
      .filter(s => s.length > 0);
    for (const statement of statements) {
      await env.DB.exec(statement);
    }

    // 2. Insert mock client and admin
    const clientPass = await hashPassword('clientpass');
    const adminPass = await hashPassword('adminpass');

    await env.DB.prepare(`
      INSERT INTO Clients (id, username, email, password, is_admin, must_change_password, package_name, total_credits, remaining_credits, status)
      VALUES 
        (1, 'clientuser', 'client@test.com', ?, 0, 0, 'Test paket', 10, 10, 'approved'),
        (2, 'adminuser', 'admin@test.com', ?, 1, 0, 'Nema paketa', 0, 0, 'approved')
    `).bind(clientPass, adminPass).run();
  });

  it('login with invalid credentials fails (401)', async () => {
    const req = new Request('http://example.com/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'clientuser', password: 'wrongpassword' })
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.success).toBe(false);
  });

  it('login with valid credentials returns a token (200)', async () => {
    const req = new Request('http://example.com/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'clientuser', password: 'clientpass' })
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.token).toBeDefined();
    expect(typeof data.token).toBe('string');
  });

  it('client endpoint /api/sessions without token fails (401)', async () => {
    const req = new Request('http://example.com/api/sessions');
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.success).toBe(false);
    expect(data.error).toContain('Niste prijavljeni');
  });

  it('client endpoint /api/sessions with client token succeeds (200)', async () => {
    // First, login to get a token
    const loginReq = new Request('http://example.com/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'clientuser', password: 'clientpass' })
    });
    const loginRes = await worker.fetch(loginReq, env, createExecutionContext());
    const loginData = await loginRes.json();
    const token = loginData.token;

    // Call sessions endpoint with token
    const req = new Request('http://example.com/api/sessions', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.sessions).toBeDefined();
  });

  it('admin endpoint /api/admin/pending-clients without token fails (401)', async () => {
    const req = new Request('http://example.com/api/admin/pending-clients');
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(401);
  });

  it('admin endpoint /api/admin/pending-clients with client token fails (403)', async () => {
    // Login as client
    const loginReq = new Request('http://example.com/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'clientuser', password: 'clientpass' })
    });
    const loginRes = await worker.fetch(loginReq, env, createExecutionContext());
    const loginData = await loginRes.json();
    const token = loginData.token;

    // Call admin endpoint with client token
    const req = new Request('http://example.com/api/admin/pending-clients', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toContain('Nemate administratorska prava');
  });

  it('admin endpoint /api/admin/pending-clients with admin token succeeds (200)', async () => {
    // Login as admin
    const loginReq = new Request('http://example.com/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'adminuser', password: 'adminpass' })
    });
    const loginRes = await worker.fetch(loginReq, env, createExecutionContext());
    const loginData = await loginRes.json();
    const token = loginData.token;

    // Call admin endpoint with admin token
    const req = new Request('http://example.com/api/admin/pending-clients', {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.clients).toBeDefined();
  });
});
