const fs = require('fs');
const path = require('path');
const assert = require('assert');
const crypto = require('crypto');

async function runTests() {
  console.log("=== COMPLIANCE EXPORT & DRIFT DETECTION TESTS ===");

  const testDbPath = path.join(__dirname, 'vault_compliance_test.db');
  if (fs.existsSync(testDbPath)) {
    fs.unlinkSync(testDbPath);
  }

  // Set configuration JSON
  const configPath = path.join(__dirname, 'test-run-compliance', 'config.json');
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, JSON.stringify({
    database: { dialect: 'sqlite', storage: testDbPath }
  }));

  // Bind mock config path to environment
  process.env.VAULT_CONFIG_PATH = configPath;
  process.env.VAULT_MASTER_KEY = crypto.randomBytes(32).toString('hex');
  process.env.NODE_ENV = 'test'; // Enforces 5s interval for compliance drift task

  // Mock global fetch to capture SIEM webhook posts
  let siemWebhookPayloads = [];
  const originalFetch = global.fetch;
  global.fetch = async (url, options) => {
    if (url.includes('/siem')) {
      siemWebhookPayloads.push({
        url,
        method: options.method,
        headers: options.headers,
        body: JSON.parse(options.body)
      });
      return { ok: true };
    }
    return originalFetch(url, options);
  };

  // Temporarily rename db.json to disable auto-seeding in tests
  const dbJsonPath = path.join(__dirname, '..', 'db.json');
  const dbJsonBakPath = path.join(__dirname, '..', 'db.json.bak');
  let renamed = false;
  if (fs.existsSync(dbJsonPath)) {
    fs.renameSync(dbJsonPath, dbJsonBakPath);
    renamed = true;
  }

  let db, initDb;
  try {
    db = require('../db.cjs');
    initDb = db.initDb;
    await initDb();
  } finally {
    if (renamed) {
      fs.renameSync(dbJsonBakPath, dbJsonPath);
    }
  }

  // DB starts fresh as the file is unlinked before startup

  console.log("Database initialized. Seeding test data...");

  // 1. Seed a Vault Group with empty IP allowlist (triggers RULE_NO_IP_ALLOWLIST)
  const group1 = await db.VaultGroup.create({
    id: 'g_no_allowlist',
    name: 'No Allowlist Group',
    ipAllowlist: '',
    kms_provider: 'local',
    dek_version: 1
  });

  // 2. Seed a Vault Group on local KEK (triggers RULE_LOCAL_KEK)
  const group2 = await db.VaultGroup.create({
    id: 'g_local_kek',
    name: 'Local KEK Group',
    ipAllowlist: '127.0.0.1',
    kms_provider: 'local',
    dek_version: 1
  });

  // 3. Seed a token issued 100 days ago (triggers RULE_TOKEN_AGE_90)
  const hundredDaysAgo = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000);
  const tokenKey = await db.AccessKey.create({
    token_hash: crypto.createHash('sha256').update('legacy-test-token-value').digest('hex'),
    userId: null,
    groupId: 'g_local_kek',
    status: 'active',
    expiresAt: null,
    createdAt: hundredDaysAgo,
    updatedAt: hundredDaysAgo
  });

  // 4. Seed a KeyVersion version 1 created 200 days ago (triggers RULE_KEK_ROTATION_180)
  const twoHundredDaysAgo = new Date(Date.now() - 200 * 24 * 60 * 60 * 1000);
  const existingKeyVersion = await db.KeyVersion.findByPk(1);
  if (existingKeyVersion) {
    existingKeyVersion.createdAt = twoHundredDaysAgo;
    await existingKeyVersion.save();
  } else {
    await db.KeyVersion.create({
      version: 1,
      createdAt: twoHundredDaysAgo
    });
  }

  // 5. Seed admin and auditor users
  const adminUser = await db.User.create({
    username: 'compliance-admin',
    passwordHash: crypto.createHash('sha256').update('admin-pass').digest('hex'),
    role: 'admin'
  });

  // 6. Seed SIEM webhook configurations
  const [siemUrlConfig] = await db.SystemConfig.findOrCreate({
    where: { key: 'siem_webhook_url' },
    defaults: { value: 'http://127.0.0.1:9000/siem' }
  });
  siemUrlConfig.value = 'http://127.0.0.1:9000/siem';
  await siemUrlConfig.save();

  const [siemSecretConfig] = await db.SystemConfig.findOrCreate({
    where: { key: 'siem_webhook_secret' },
    defaults: { value: 'siem-secret-key' }
  });
  siemSecretConfig.value = 'siem-secret-key';
  await siemSecretConfig.save();

  console.log("Test data seeded. Starting server...");

  // Load and start server components dynamically
  const server = require('../server.cjs');
  const serverInstance = server.app.listen(8202);

  // Authenticate as Admin
  const loginRes = await fetch('http://127.0.0.1:8202/admin/api/verify-auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'compliance-admin', password: 'admin-pass' })
  });

  assert.strictEqual(loginRes.status, 200, "Login failed");
  const cookie = loginRes.headers.get('set-cookie').split(';')[0];
  const { csrfToken } = await loginRes.json();

  const authHeaders = {
    'Cookie': cookie,
    'X-CSRF-Token': csrfToken,
    'Content-Type': 'application/json'
  };

  // --- Test 1: Verify drift detection endpoint ---
  console.log("1. Testing Drift Detection API...");
  const driftRes = await fetch('http://127.0.0.1:8202/admin/api/compliance/drift', { headers: authHeaders });
  assert.strictEqual(driftRes.status, 200, `Drift API failed: ${driftRes.status}`);
  const driftData = await driftRes.json();
  const findings = driftData.findings || [];

  console.log(`Found ${findings.length} compliance violations:`);
  findings.forEach(f => console.log(`  - [${f.severity.toUpperCase()}] ${f.ruleId}: ${f.description}`));

  // Assert rule triggers
  const ruleNoIpAllowlist = findings.find(f => f.ruleId === 'RULE_NO_IP_ALLOWLIST');
  assert.ok(ruleNoIpAllowlist, "RULE_NO_IP_ALLOWLIST did not trigger");
  assert.strictEqual(ruleNoIpAllowlist.affectedEntity, 'Vault Group: No Allowlist Group (g_no_allowlist)');

  const ruleTokenAge = findings.find(f => f.ruleId === 'RULE_TOKEN_AGE_90');
  assert.ok(ruleTokenAge, "RULE_TOKEN_AGE_90 did not trigger");
  assert.ok(ruleTokenAge.description.includes('100 days'), "Token age description was incorrect");

  const ruleNoMfa = findings.find(f => f.ruleId === 'RULE_NO_MFA');
  assert.ok(ruleNoMfa, "RULE_NO_MFA did not trigger");
  assert.strictEqual(ruleNoMfa.severity, 'high');

  const ruleLocalKek = findings.filter(f => f.ruleId === 'RULE_LOCAL_KEK');
  assert.strictEqual(ruleLocalKek.length, 2, "RULE_LOCAL_KEK should trigger for both local groups");

  const ruleKekRotation = findings.find(f => f.ruleId === 'RULE_KEK_ROTATION_180');
  assert.ok(ruleKekRotation, "RULE_KEK_ROTATION_180 did not trigger");
  assert.ok(ruleKekRotation.description.includes('200 days'), "KEK rotation age description was incorrect");

  console.log("✅ Drift Detection API verified successfully.");

  // --- Test 2: Verify Compliance Export JSON and PDF ---
  console.log("2. Testing Compliance Evidence Export API...");
  
  // JSON format
  const exportJsonRes = await fetch('http://127.0.0.1:8202/admin/api/compliance/export?framework=soc2&format=json', { headers: authHeaders });
  assert.strictEqual(exportJsonRes.status, 200);
  const report = await exportJsonRes.json();
  assert.strictEqual(report.framework, 'soc2');
  assert.ok(report.evidence, "Report should contain evidence data");
  assert.strictEqual(report.evidence.length, 5, "SOC 2 report must contain 5 evidence items");
  assert.ok(report.disclaimer.includes("evidence"), "Disclaimer was missing or invalid");

  // PDF format
  const exportPdfRes = await fetch('http://127.0.0.1:8202/admin/api/compliance/export?framework=hipaa&format=pdf', { headers: authHeaders });
  assert.strictEqual(exportPdfRes.status, 200);
  assert.strictEqual(exportPdfRes.headers.get('content-type'), 'application/pdf');
  const pdfBuffer = await exportPdfRes.arrayBuffer();
  const pdfPrefix = Buffer.from(pdfBuffer).toString('utf8', 0, 5);
  assert.strictEqual(pdfPrefix, '%PDF-', "Exported PDF header must begin with '%PDF-'");

  console.log("✅ Compliance Evidence Export (JSON + PDF) verified successfully.");

  // --- Test 3: Verify Audit Logging of Export ---
  console.log("3. Testing Audit Logging of Exports...");
  const logs = await db.TransferLog.findAll({ order: [['id', 'DESC']] });
  const exportLog = logs.find(l => l.metadata && l.metadata.includes('compliance_evidence_exported'));
  assert.ok(exportLog, "Audit log should contain a compliance_evidence_exported entry");
  const logMetadata = JSON.parse(exportLog.metadata);
  assert.strictEqual(logMetadata.performedByUsername, 'compliance-admin');
  assert.strictEqual(logMetadata.framework, 'hipaa');
  console.log("✅ Audit Logging of compliance exports verified.");

  // --- Test 4: Verify SIEM Webhook Integration on High Drift ---
  console.log("4. Testing Scheduled Drift check & SIEM Webhook trigger...");
  // Wait 6 seconds to let the interval task trigger compliance scan (which triggers the High-severity RULE_NO_MFA finding)
  await new Promise(r => setTimeout(r, 6500));

  assert.ok(siemWebhookPayloads.length > 0, "SIEM Webhook was not triggered by compliance checker");
  const webhook = siemWebhookPayloads.find(p => p.body.scope === 'Compliance Drift');
  assert.ok(webhook, "Webhook payload for 'Compliance Drift' was not found");
  assert.ok(webhook.body.action.includes('MFA'), "Webhook payload action should mention MFA finding");
  assert.strictEqual(webhook.body.status, 'high');
  console.log("✅ Continuous Compliance Drift check interval and SIEM webhook notification verified.");

  // Clean up
  serverInstance.close();
  await db.sequelize.close();
  try {
    if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
    if (fs.existsSync(configPath)) fs.unlinkSync(configPath);
  } catch (err) {
    console.log("Cleanup warning (non-fatal): Could not unlink test DB because it was still locked: " + err.message);
  }
  global.fetch = originalFetch;

  console.log("\n🎉 ALL COMPLIANCE EXPORT & DRIFT TESTS PASSED CLEANLY! 🎉\n");
  process.exit(0);
}

runTests().catch(err => {
  console.error("❌ Test run failed:", err);
  process.exit(1);
});
