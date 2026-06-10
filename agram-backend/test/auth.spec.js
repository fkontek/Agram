import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { beforeAll, describe, it, expect } from 'vitest';
import worker from '../src';

// Combined SQL Schema in single-line statements to prevent SQLite parse issues
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS Clients (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, is_admin INTEGER DEFAULT 0, credits INTEGER DEFAULT 0, must_change_password INTEGER DEFAULT 1, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, package_name TEXT, total_credits INTEGER DEFAULT 0, remaining_credits INTEGER DEFAULT 0, package_expires TEXT, status TEXT DEFAULT 'approved', questionnaire TEXT DEFAULT NULL, full_name TEXT);
CREATE TABLE IF NOT EXISTS Sessions (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, instructor TEXT, date TEXT NOT NULL, time TEXT NOT NULL, capacity INTEGER DEFAULT 5, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, type TEXT DEFAULT 'grupni');
CREATE TABLE IF NOT EXISTS Bookings (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, status INTEGER DEFAULT 0, reminder_sent INTEGER DEFAULT 0, FOREIGN KEY (session_id) REFERENCES Sessions(id) ON DELETE CASCADE, FOREIGN KEY (user_id) REFERENCES Clients(id) ON DELETE CASCADE, UNIQUE(session_id, user_id));
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

  it('scheduled cron trigger runs successfully and triggers weekly report', async () => {
    // 1. Prepare Monday date
    const d = new Date();
    const currentDay = d.getDay();
    const daysToSubtract = currentDay === 0 ? 6 : (currentDay - 1);
    const monday = new Date(d.getTime() - daysToSubtract * 24 * 60 * 60 * 1000);
    const mondayStr = monday.toISOString().split('T')[0];

    // 2. Insert a mock session for the week
    await env.DB.prepare(`
      INSERT INTO Sessions (id, title, instructor, date, time, capacity, type)
      VALUES (999, 'Test Pilates', 'Adrijana', ?, '17:00', 4, 'grupni')
    `).bind(mondayStr).run();

    // 3. Insert a checked-in booking for this session (status = 1)
    await env.DB.prepare(`
      INSERT INTO Bookings (session_id, user_id, status)
      VALUES (999, 1, 1)
    `).run();

    // 4. Trigger worker.scheduled
    const ctx = createExecutionContext();
    const event = {
      scheduledTime: Date.now()
    };
    
    await worker.scheduled(event, env, ctx);
    await waitOnExecutionContext(ctx);

    // 5. Verify database state is untouched (i.e. query ran without syntax errors)
    const session = await env.DB.prepare("SELECT title FROM Sessions WHERE id = 999").first();
    expect(session).toBeDefined();
    expect(session.title).toBe('Test Pilates');
  });

  it('admin endpoint /api/admin/send-daily-report sends daily report email on demand (200)', async () => {
    // 1. Login as admin
    const loginReq = new Request('http://example.com/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'adminuser', password: 'adminpass' })
    });
    const loginRes = await worker.fetch(loginReq, env, createExecutionContext());
    const loginData = await loginRes.json();
    const token = loginData.token;

    // 2. Call send-daily-report endpoint
    const d = new Date();
    const todayStr = d.toISOString().split('T')[0];

    const req = new Request('http://example.com/api/admin/send-daily-report', {
      method: 'POST',
      headers: { 
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ date: todayStr })
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.message).toContain('Dnevno izvješće');
  });

  it('admin endpoint /api/admin/book-client-manual books a client manually (200)', async () => {
    // 1. Login as admin
    const loginReq = new Request('http://example.com/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'adminuser', password: 'adminpass' })
    });
    const loginRes = await worker.fetch(loginReq, env, createExecutionContext());
    const loginData = await loginRes.json();
    const token = loginData.token;

    // Create a new session
    const d = new Date();
    const dateStr = d.toISOString().split('T')[0];
    await env.DB.prepare(`
      INSERT INTO Sessions (id, title, instructor, date, time, capacity, type)
      VALUES (1001, 'Reformer test', 'Adrijana', ?, '08:00', 4, 'grupni')
    `).bind(dateStr).run();

    // Call book-client-manual
    const req = new Request('http://example.com/api/admin/book-client-manual', {
      method: 'POST',
      headers: { 
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ session_id: 1001, client_id: 1 })
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);

    // Verify booking was created
    const booking = await env.DB.prepare("SELECT * FROM Bookings WHERE session_id = 1001 AND user_id = 1").first();
    expect(booking).toBeDefined();
    expect(booking.status).toBe(0);

    // Verify remaining credits decreased from 10 to 9
    const client = await env.DB.prepare("SELECT remaining_credits FROM Clients WHERE id = 1").first();
    expect(client.remaining_credits).toBe(9);

    // Verify notification was created
    const notif = await env.DB.prepare("SELECT * FROM ClientNotifications WHERE user_id = 1 ORDER BY id DESC LIMIT 1").first();
    expect(notif).toBeDefined();
    expect(notif.message).toContain("Studio Vam je rezervirao termin 'Reformer test'");
  });

  it('admin endpoint /api/admin/book-client-manual fails if client has no credits (400)', async () => {
    // Set credits to 0 for client
    await env.DB.prepare("UPDATE Clients SET remaining_credits = 0 WHERE id = 1").run();

    // Login as admin
    const loginReq = new Request('http://example.com/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'adminuser', password: 'adminpass' })
    });
    const loginRes = await worker.fetch(loginReq, env, createExecutionContext());
    const loginData = await loginRes.json();
    const token = loginData.token;

    const req = new Request('http://example.com/api/admin/book-client-manual', {
      method: 'POST',
      headers: { 
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ session_id: 1001, client_id: 1 })
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.success).toBe(false);
  });

  it('admin endpoint /api/admin/change-session-type changes session type when empty (200)', async () => {
    // 1. Login as admin
    const loginReq = new Request('http://example.com/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'adminuser', password: 'adminpass' })
    });
    const loginRes = await worker.fetch(loginReq, env, createExecutionContext());
    const loginData = await loginRes.json();
    const token = loginData.token;

    // Create a new session
    const d = new Date();
    const dateStr = d.toISOString().split('T')[0];
    await env.DB.prepare(`
      INSERT INTO Sessions (id, title, instructor, date, time, capacity, type)
      VALUES (1002, 'Grupni trening', 'Adrijana', ?, '09:00', 4, 'grupni')
    `).bind(dateStr).run();

    // Call change-session-type to change to privatni
    const req = new Request('http://example.com/api/admin/change-session-type', {
      method: 'POST',
      headers: { 
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ session_id: 1002, new_type: 'privatni' })
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);

    // Verify session was updated in database
    const session = await env.DB.prepare("SELECT type, capacity, title FROM Sessions WHERE id = 1002").first();
    expect(session.type).toBe('privatni');
    expect(session.capacity).toBe(1);
    expect(session.title).toBe('Privatni trening');
  });

  it('admin endpoint /api/admin/change-session-type fails when session has bookings (400)', async () => {
    // 1. Login as admin
    const loginReq = new Request('http://example.com/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'adminuser', password: 'adminpass' })
    });
    const loginRes = await worker.fetch(loginReq, env, createExecutionContext());
    const loginData = await loginRes.json();
    const token = loginData.token;

    // Create a new session specifically for this test
    const d = new Date();
    const dateStr = d.toISOString().split('T')[0];
    await env.DB.prepare(`
      INSERT INTO Sessions (id, title, instructor, date, time, capacity, type)
      VALUES (1003, 'Grupni trening', 'Adrijana', ?, '10:00', 4, 'grupni')
    `).bind(dateStr).run();

    // Add booking to session 1003
    await env.DB.prepare("INSERT INTO Bookings (session_id, user_id, status) VALUES (1003, 1, 0)").run();

    // Attempt to change type
    const req = new Request('http://example.com/api/admin/change-session-type', {
      method: 'POST',
      headers: { 
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ session_id: 1003, new_type: 'poluindividualni' })
    });
    const ctx = createExecutionContext();
    const res = await worker.fetch(req, env, ctx);
    await waitOnExecutionContext(ctx);

    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.success).toBe(false);
    expect(data.error).toContain("Nije moguće promijeniti tip treninga");
  });

  it('scheduled cron trigger runs successfully and sends daily booking reminders', async () => {
    // 1. Prepare tomorrow's date
    const d = new Date();
    const tomorrow = new Date(d.getTime() + 24 * 60 * 60 * 1000);
    const tomorrowStr = tomorrow.toISOString().split('T')[0];

    // 2. Insert a mock session for tomorrow
    await env.DB.prepare(`
      INSERT INTO Sessions (id, title, instructor, date, time, capacity, type)
      VALUES (888, 'Tomorrow Pilates', 'Adrijana', ?, '10:00', 4, 'grupni')
    `).bind(tomorrowStr).run();

    // 3. Insert a reserved booking for tomorrow (status = 0, reminder_sent = 0)
    await env.DB.prepare(`
      INSERT INTO Bookings (session_id, user_id, status, reminder_sent)
      VALUES (888, 1, 0, 0)
    `).run();

    // 4. Trigger worker.scheduled
    const ctx = createExecutionContext();
    const event = {
      cron: "0 */12 * * *",
      scheduledTime: Date.now()
    };
    
    await worker.scheduled(event, env, ctx);
    await waitOnExecutionContext(ctx);

    // 5. Verify that booking reminder_sent was updated to 1
    const booking = await env.DB.prepare("SELECT reminder_sent FROM Bookings WHERE session_id = 888 AND user_id = 1").first();
    expect(booking).toBeDefined();
    expect(booking.reminder_sent).toBe(1);
  });
});
