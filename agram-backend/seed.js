const { execSync } = require('child_process');
const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

async function run() {
  const adminPassHash = hashPassword('adminpass');
  const clientPassHash = hashPassword('clientpass');

  // Dates
  const today = new Date();
  const formatDate = (d) => d.toISOString().split('T')[0];
  
  const todayStr = formatDate(today);
  const tomorrow = new Date(today.getTime() + 24 * 60 * 60 * 1000);
  const tomorrowStr = formatDate(tomorrow);
  const dayAfterTomorrow = new Date(today.getTime() + 2 * 24 * 60 * 60 * 1000);
  const dayAfterTomorrowStr = formatDate(dayAfterTomorrow);

  console.log(`Seeding dates: Today=${todayStr}, Tomorrow=${tomorrowStr}`);

  // SQL statements
  const sql = `
-- Reset clients and sessions
DELETE FROM Clients;
DELETE FROM Sessions;
DELETE FROM Bookings;

-- Insert Admin
INSERT INTO Clients (id, username, email, password, is_admin, must_change_password, package_name, total_credits, remaining_credits, status)
VALUES (1, 'admin', 'filip.kontek@gmail.com', '${adminPassHash}', 1, 0, 'Nema paketa', 0, 0, 'approved');

-- Insert Client
INSERT INTO Clients (id, username, email, password, is_admin, must_change_password, package_name, total_credits, remaining_credits, package_expires, status, questionnaire, full_name)
VALUES (2, 'ivana_h', 'ivana.h@test.com', '${clientPassHash}', 0, 0, 'Grupni Paket 12', 12, 10, '2026-07-10', 'approved', '{"completed":true}', 'Ivana Horvat');

-- Insert Sessions for Today
INSERT INTO Sessions (id, title, instructor, date, time, capacity, type)
VALUES (100, 'Grupni trening', 'Adrijana', '${todayStr}', '09:00', 4, 'grupni');
INSERT INTO Sessions (id, title, instructor, date, time, capacity, type)
VALUES (101, 'Privatni trening', 'Adrijana', '${todayStr}', '10:00', 1, 'privatni');
INSERT INTO Sessions (id, title, instructor, date, time, capacity, type)
VALUES (102, 'Poluindividualni', 'Adrijana', '${todayStr}', '18:00', 2, 'poluindividualni');

-- Insert Sessions for Tomorrow
INSERT INTO Sessions (id, title, instructor, date, time, capacity, type)
VALUES (200, 'Grupni trening', 'Adrijana', '${tomorrowStr}', '09:00', 4, 'grupni');
INSERT INTO Sessions (id, title, instructor, date, time, capacity, type)
VALUES (201, 'Grupni trening', 'Adrijana', '${tomorrowStr}', '17:00', 4, 'grupni');

-- Insert Sessions for Day After Tomorrow
INSERT INTO Sessions (id, title, instructor, date, time, capacity, type)
VALUES (300, 'Grupni trening', 'Adrijana', '${dayAfterTomorrowStr}', '09:00', 4, 'grupni');
`;

  const fs = require('fs');
  fs.writeFileSync('seed.sql', sql);
  
  console.log('Applying seed.sql to local database...');
  execSync('npx wrangler d1 execute agram-auth --local --file=seed.sql', { stdio: 'inherit' });
  console.log('Seeding completed successfully!');
}

run().catch(console.error);
