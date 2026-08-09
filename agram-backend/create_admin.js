const crypto = require('crypto');
const { execSync } = require('child_process');
const readline = require('readline');

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function question(query) {
  return new Promise(resolve => rl.question(query, resolve));
}

async function main() {
  console.log("=== Agram Backend: Secure Admin Account Generator ===");
  const username = (await question("Enter admin username [default: admin]: ")).trim() || "admin";
  const email = (await question("Enter admin email [default: filip.kontek@gmail.com]: ")).trim() || "filip.kontek@gmail.com";
  const password = await question("Enter new admin password: ");

  if (!password || password.length < 8) {
    console.error("Error: Password must be at least 8 characters long.");
    rl.close();
    process.exit(1);
  }

  const passHash = hashPassword(password);
  console.log(`Generated SHA-256 Hash for password.`);

  const remote = (await question("Apply directly to REMOTE Cloudflare D1 database? (y/N): ")).trim().toLowerCase();
  const remoteFlag = (remote === 'y' || remote === 'yes') ? '--remote' : '--local';

  const sql = `
  INSERT INTO Clients (username, email, password, is_admin, credits, must_change_password, status)
  VALUES ('${username}', '${email}', '${passHash}', 1, 0, 0, 'approved')
  ON CONFLICT(username) DO UPDATE SET
    password = '${passHash}',
    email = '${email}',
    is_admin = 1,
    must_change_password = 0;
  `;

  console.log(`Executing query on D1 (${remoteFlag})...`);
  try {
    const cmd = `cmd /c npx wrangler d1 execute agram-auth-test ${remoteFlag} --command="${sql.replace(/\n/g, ' ')}"`;
    execSync(cmd, { stdio: 'inherit' });
    console.log("Admin user successfully updated/created!");
  } catch (err) {
    console.error("Failed to execute query:", err.message);
  }

  rl.close();
}

main().catch(err => {
  console.error(err);
  rl.close();
});
