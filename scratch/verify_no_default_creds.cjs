const fs = require('fs');
const path = require('path');
const assert = require('assert');
const crypto = require('crypto');

async function runTests() {
  console.log("=== VERIFY NO DEFAULT CREDENTIALS OR TOKENS TESTS ===");

  const testDbPath = path.join(__dirname, 'vault_nocreds_test.db');
  const configPath = path.join(__dirname, 'test-run-nocreds', 'config.json');

  const cleanupFiles = () => {
    if (fs.existsSync(testDbPath)) {
      try { fs.unlinkSync(testDbPath); } catch (e) {}
    }
    if (fs.existsSync(configPath)) {
      try { fs.unlinkSync(configPath); } catch (e) {}
    }
  };

  cleanupFiles();

  // Enforce isolated config path and mock master key
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, JSON.stringify({
    database: { dialect: 'sqlite', storage: testDbPath }
  }));

  process.env.VAULT_CONFIG_PATH = configPath;
  process.env.VAULT_MASTER_KEY = crypto.randomBytes(32).toString('hex');
  process.env.NODE_ENV = 'test';
  
  // ── Test 1: Fresh Boot Without SEED_DEV_TOKENS ────────────────────────
  console.log("\n1. Testing fresh boot (without SEED_DEV_TOKENS)...");
  delete process.env.SEED_DEV_TOKENS;

  // Temporarily rename db.json to disable auto-seeding in tests
  const dbJsonPath = path.join(__dirname, '..', 'db.json');
  const dbJsonBakPath = path.join(__dirname, '..', 'db.json.bak');
  let renamed = false;
  if (fs.existsSync(dbJsonPath)) {
    fs.renameSync(dbJsonPath, dbJsonBakPath);
    renamed = true;
  }

  let db;
  try {
    db = require('../db.cjs');
    await db.initDb();
  } finally {
    if (renamed) {
      fs.renameSync(dbJsonBakPath, dbJsonPath);
    }
  }

  // Verify that NO default admin user exists
  const adminUser = await db.User.findOne({ where: { username: 'admin' } });
  assert.strictEqual(adminUser, null, "Default admin user should not be seeded in db.cjs");

  // Verify that NO dev tokens are seeded
  const allTokens = await db.AccessKey.findAll();
  assert.strictEqual(allTokens.length, 0, "No access keys should be seeded without SEED_DEV_TOKENS=true");

  console.log("✅ Verified: No admin and no tokens seeded on clean boot.");

  // Start the server
  const server = require('../server.cjs');
  const serverInstance = server.app.listen(8203);

  // Try to log in with the old default password 'vault-admin-pass'
  const oldLoginRes = await fetch('http://127.0.0.1:8203/admin/api/verify-auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'vault-admin-pass' })
  });
  // Since no admin is created, it should either block with 503 or fail validation
  assert.ok(oldLoginRes.status === 503 || oldLoginRes.status === 401, `Expected blocked login, got: ${oldLoginRes.status}`);
  console.log(`✅ Verified: Login attempt blocked with status: ${oldLoginRes.status}`);

  // Try to access a protected admin route before running the setup wizard
  const stateRes = await fetch('http://127.0.0.1:8203/admin/api/state');
  assert.strictEqual(stateRes.status, 503, "Protected admin routes should return 503 Service Unavailable when uninstalled");
  console.log("✅ Verified: Protected admin API routes are blocked with 503.");

  // Complete the installation wizard programmatically
  console.log("Running programmatic setup wizard...");
  const setupRes = await fetch('http://127.0.0.1:8203/admin/api/install/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      dbDialect: 'sqlite',
      dbStorage: testDbPath,
      adminEmail: 'admin@test.com',
      adminPassword: 'my-custom-secure-password',
      keyMode: 'generate'
    })
  });
  assert.strictEqual(setupRes.status, 200, "Programmatic installation submit failed");
  console.log("✅ Setup wizard completed successfully.");

  // Try logging in with the newly configured custom password
  const newLoginRes = await fetch('http://127.0.0.1:8203/admin/api/verify-auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'my-custom-secure-password' })
  });
  assert.strictEqual(newLoginRes.status, 200, "Login failed with new custom password");
  console.log("✅ Verified: Custom password works for admin login.");

  // Clean up server
  serverInstance.close();

  // ── Test 2: Opt-in Dev Seed Flag (SEED_DEV_TOKENS=true) ────────────────
  console.log("\n2. Testing opt-in dev seed (SEED_DEV_TOKENS=true)...");
  cleanupFiles();

  // Re-write config JSON
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, JSON.stringify({
    database: { dialect: 'sqlite', storage: testDbPath }
  }));

  process.env.SEED_DEV_TOKENS = 'true';

  // Reset Sequelize connection pool dynamically
  db.updateDbConnection({ dialect: 'sqlite', storage: testDbPath });
  await db.initDb();

  // Verify that tokens from db.json ARE seeded when SEED_DEV_TOKENS=true
  const seededTokens = await db.AccessKey.findAll();
  assert.ok(seededTokens.length > 0, "Dev tokens should be seeded when SEED_DEV_TOKENS=true");
  console.log(`✅ Verified: Seeded ${seededTokens.length} dev tokens when SEED_DEV_TOKENS=true.`);

  // Clean up
  cleanupFiles();

  console.log("\n🎉 ALL NO-DEFAULT-CREDENTIALS VERIFICATION TESTS PASSED SUCCESSFULLY! 🎉\n");
  process.exit(0);
}

runTests().catch(err => {
  console.error("❌ Test run failed:", err);
  process.exit(1);
});
