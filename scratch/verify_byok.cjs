const fs = require('fs');
const path = require('path');
const assert = require('assert');
const crypto = require('crypto');

// Mock SDK classes to test remote provider integrations
const awsKms = require('@aws-sdk/client-kms');
const azureKeys = require('@azure/keyvault-keys');
const azureId = require('@azure/identity');

// Mock AWS KMS Client Send method
let awsSendMock = null;
awsKms.KMSClient.prototype.send = async function(command) {
  if (awsSendMock) {
    return awsSendMock(command);
  }
  throw new Error("AWS KMS client send unmocked");
};

// Mock Azure KeyClient getKey method
let azureGetKeyMock = null;
azureKeys.KeyClient.prototype.getKey = async function(name, options) {
  if (azureGetKeyMock) {
    return azureGetKeyMock(name, options);
  }
  return { id: 'https://mockvault.vault.azure.net/keys/' + name + '/version' };
};

// Mock Azure CryptographyClient wrap/unwrap methods
let azureWrapMock = null;
let azureUnwrapMock = null;
azureKeys.CryptographyClient.prototype.wrapKey = async function(algo, key) {
  if (azureWrapMock) return azureWrapMock(algo, key);
  return { result: Buffer.from("azure-mocked-ciphertext") };
};
azureKeys.CryptographyClient.prototype.unwrapKey = async function(algo, key) {
  if (azureUnwrapMock) return azureUnwrapMock(algo, key);
  return { result: Buffer.from("azure-mocked-plaintext") };
};

// Import Providers
const { providers } = require('../kms-providers.cjs');

// Mock HashiCorp Vault transit responses
let fetchMock = null;
const originalFetch = global.fetch;
global.fetch = async (url, options) => {
  if (fetchMock && (url.includes('/v1/transit') || url.includes('/auth/approle'))) {
    return fetchMock(url, options);
  }
  return originalFetch(url, options);
};

async function runTests() {
  console.log("=== BYOK KMS PROVIDERS UNIT TESTS ===");

  // --- Test 1: Local Provider (Existing behaviour) ---
  console.log("1. Testing Local KMS Provider...");
  const localKek = crypto.randomBytes(32);
  const localDek = crypto.randomBytes(32);
  
  const wrappedLocal = await providers.local.wrapDek({ kek: localKek }, localDek);
  const unwrappedLocal = await providers.local.unwrapDek({ kek: localKek }, wrappedLocal);
  
  assert.deepStrictEqual(unwrappedLocal, localDek, "Local DEK unwrap did not return original DEK");
  const localTest = await providers.local.testConnection({ kek: localKek });
  assert.ok(localTest.success, "Local connection test failed");
  console.log("✅ Local KMS Provider tests passed.");

  // --- Test 2: AWS KMS Provider ---
  console.log("2. Testing AWS KMS Provider...");
  const awsKeyArn = "arn:aws:kms:us-east-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab";
  const awsConfig = { region: 'us-east-1', keyArn: awsKeyArn, accessKeyId: 'testAccess', secretAccessKey: 'testSecret' };
  
  // Test connection
  awsSendMock = (cmd) => {
    assert.ok(cmd instanceof awsKms.DescribeKeyCommand, "Expected DescribeKeyCommand");
    assert.strictEqual(cmd.input.KeyId, awsKeyArn);
    return { KeyMetadata: { KeyId: awsKeyArn, Enabled: true } };
  };
  const awsTestConn = await providers['aws-kms'].testConnection(awsConfig);
  assert.ok(awsTestConn.success, "AWS connection test failed");

  // Test Wrap
  const testDek = crypto.randomBytes(32);
  const awsCiphertext = "aws-ciphertext-blob";
  awsSendMock = (cmd) => {
    assert.ok(cmd instanceof awsKms.EncryptCommand, "Expected EncryptCommand");
    assert.strictEqual(cmd.input.KeyId, awsKeyArn);
    assert.deepStrictEqual(cmd.input.Plaintext, testDek);
    return { CiphertextBlob: Buffer.from(awsCiphertext) };
  };
  const wrappedAws = await providers['aws-kms'].wrapDek(awsConfig, testDek);
  assert.strictEqual(wrappedAws, Buffer.from(awsCiphertext).toString('base64'), "AWS Wrap mismatch");

  // Test Unwrap
  awsSendMock = (cmd) => {
    assert.ok(cmd instanceof awsKms.DecryptCommand, "Expected DecryptCommand");
    assert.strictEqual(cmd.input.KeyId, awsKeyArn);
    assert.deepStrictEqual(cmd.input.CiphertextBlob, Buffer.from(awsCiphertext));
    return { Plaintext: testDek };
  };
  const unwrappedAws = await providers['aws-kms'].unwrapDek(awsConfig, wrappedAws);
  assert.deepStrictEqual(unwrappedAws, testDek, "AWS Unwrap mismatch");
  console.log("✅ AWS KMS Provider tests passed.");

  // --- Test 3: Azure Key Vault Provider ---
  console.log("3. Testing Azure Key Vault Provider...");
  const azureConfig = { vaultUrl: 'https://testvault.vault.azure.net', keyName: 'test-kek', keyVersion: 'v1', tenantId: 't', clientId: 'c', clientSecret: 's' };
  
  // Test Connection
  let getKeyCalled = false;
  azureGetKeyMock = (name, opts) => {
    getKeyCalled = true;
    assert.strictEqual(name, 'test-kek');
    assert.strictEqual(opts.version, 'v1');
    return { id: 'https://testvault.vault.azure.net/keys/test-kek/v1' };
  };
  const azureTestConn = await providers['azure-keyvault'].testConnection(azureConfig);
  assert.ok(azureTestConn.success && getKeyCalled);

  // Test Wrap
  azureWrapMock = (algo, rawKey) => {
    assert.strictEqual(algo, "RSA-OAEP-256");
    assert.deepStrictEqual(rawKey, testDek);
    return { result: Buffer.from("azure-ciphertext") };
  };
  const wrappedAzure = await providers['azure-keyvault'].wrapDek(azureConfig, testDek);
  assert.strictEqual(wrappedAzure, Buffer.from("azure-ciphertext").toString('base64'));

  // Test Unwrap
  azureUnwrapMock = (algo, cipher) => {
    assert.strictEqual(algo, "RSA-OAEP-256");
    assert.deepStrictEqual(cipher, Buffer.from("azure-ciphertext"));
    return { result: testDek };
  };
  const unwrappedAzure = await providers['azure-keyvault'].unwrapDek(azureConfig, wrappedAzure);
  assert.deepStrictEqual(unwrappedAzure, testDek);
  console.log("✅ Azure Key Vault Provider tests passed.");

  // --- Test 4: HashiCorp Vault Provider ---
  console.log("4. Testing HashiCorp Vault Provider...");
  const vaultConfig = { vaultAddr: 'http://127.0.0.1:8200', transitKeyName: 'test-kek', vaultToken: 'hvs.token' };

  // Test Connection
  fetchMock = async (url, options) => {
    assert.strictEqual(url, 'http://127.0.0.1:8200/v1/transit/keys/test-kek');
    assert.strictEqual(options.headers['X-Vault-Token'], 'hvs.token');
    return {
      ok: true,
      json: async () => ({ data: { name: 'test-kek' } })
    };
  };
  const vaultTestConn = await providers['hashicorp-vault'].testConnection(vaultConfig);
  assert.ok(vaultTestConn.success);

  // Test Wrap
  fetchMock = async (url, options) => {
    assert.strictEqual(url, 'http://127.0.0.1:8200/v1/transit/encrypt/test-kek');
    const body = JSON.parse(options.body);
    assert.strictEqual(body.plaintext, testDek.toString('base64'));
    return {
      ok: true,
      json: async () => ({ data: { ciphertext: 'vault:v1:ciphertext' } })
    };
  };
  const wrappedVault = await providers['hashicorp-vault'].wrapDek(vaultConfig, testDek);
  assert.strictEqual(wrappedVault, 'vault:v1:ciphertext');

  // Test Unwrap
  fetchMock = async (url, options) => {
    assert.strictEqual(url, 'http://127.0.0.1:8200/v1/transit/decrypt/test-kek');
    const body = JSON.parse(options.body);
    assert.strictEqual(body.ciphertext, 'vault:v1:ciphertext');
    return {
      ok: true,
      json: async () => ({ data: { plaintext: testDek.toString('base64') } })
    };
  };
  const unwrappedVault = await providers['hashicorp-vault'].unwrapDek(vaultConfig, wrappedVault);
  assert.deepStrictEqual(unwrappedVault, testDek);
  console.log("✅ HashiCorp Vault Provider tests passed.");

  // --- Test 5: KMS Switch & DEK Re-wrap (Integration Check) ---
  console.log("\n=== TESTING KMS MIGRATION / RE-WRAP & GRACEFUL DEGRADATION ===");
  const testDbPath = path.join(__dirname, 'vault_byok_test.db');
  if (fs.existsSync(testDbPath)) {
    fs.unlinkSync(testDbPath);
  }
  
  // Set configuration JSON
  const configPath = path.join(__dirname, 'test-run-byok', 'config.json');
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, JSON.stringify({
    database: { dialect: 'sqlite', storage: testDbPath }
  }));

  // Temporarily bind mock config path to environment
  process.env.VAULT_CONFIG_PATH = configPath;
  process.env.VAULT_MASTER_KEY = crypto.randomBytes(32).toString('hex');

  // Temporarily rename db.json to disable auto-seeding in tests
  const dbJsonPath = path.join(__dirname, '..', 'db.json');
  const dbJsonBakPath = path.join(__dirname, '..', 'db.json.bak');
  let renamed = false;
  if (fs.existsSync(dbJsonPath)) {
    fs.renameSync(dbJsonPath, dbJsonBakPath);
    renamed = true;
  }

  let initDb, VaultGroup, ConnectionProfile, AccessKey;
  try {
    const db = require('../db.cjs');
    initDb = db.initDb;
    VaultGroup = db.VaultGroup;
    ConnectionProfile = db.ConnectionProfile;
    AccessKey = db.AccessKey;
    await initDb();
  } finally {
    if (renamed) {
      fs.renameSync(dbJsonBakPath, dbJsonPath);
    }
  }

  await ConnectionProfile.destroy({ where: {} });
  await AccessKey.destroy({ where: {} });
  await VaultGroup.destroy({ where: {} });

  // Create a default local group
  const group = await VaultGroup.create({
    id: 'g_byok_test',
    name: 'BYOK Test Group',
    kms_provider: 'local',
    migrated: true,
    wrapped_dek: wrapDekLocal(testDek, Buffer.from(process.env.VAULT_MASTER_KEY, 'hex')),
    dek_version: 1
  });

  // Verify initial DEK resolves
  // Load server components dynamically to bind to temporary DB
  const server = require('../server.cjs');
  const resolvedDekLocal = await server.getGroupDek(group);
  assert.deepStrictEqual(resolvedDekLocal, testDek, "Resolved DEK does not match original DEK under local provider");
  console.log("✅ Local DEK resolved correctly.");

  // Simulate migration to AWS KMS provider via server endpoint config update
  console.log("Switching group to AWS KMS provider...");
  
  // Mock connection test and wrap during update
  awsSendMock = (cmd) => {
    if (cmd instanceof awsKms.DescribeKeyCommand) {
      return { KeyMetadata: { Enabled: true } };
    }
    if (cmd instanceof awsKms.EncryptCommand) {
      return { CiphertextBlob: Buffer.from("aws-migrated-ciphertext-blob") };
    }
    throw new Error("Unexpected AWS command");
  };

  // Start the server on a test port
  const serverInstance = server.app.listen(8201);

  // Since we removed default admin seeding, we must programmatically complete the setup wizard first
  const setupRes = await fetch('http://localhost:8201/admin/api/install/submit', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      dbDialect: 'sqlite',
      dbStorage: testDbPath,
      adminEmail: 'admin@test.com',
      adminPassword: 'vault-admin-pass',
      keyMode: 'custom',
      customKey: Buffer.from(process.env.VAULT_MASTER_KEY, 'hex').toString('hex')
    })
  });
  assert.strictEqual(setupRes.status, 200, "Programmatic setup failed");
  
  const loginRes = await fetch('http://localhost:8201/admin/api/verify-auth', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ password: 'vault-admin-pass' }) // Setup custom password
  });
  assert.strictEqual(loginRes.status, 200, "Login to test server failed");
  const cookie = loginRes.headers.get('set-cookie').split(';')[0];
  const { csrfToken } = await loginRes.json();
  
  // Trigger KMS Update / Migration
  const updateRes = await fetch(`http://localhost:8201/admin/api/groups/${group.id}/kms`, {
    method: 'POST',
    headers: {
      'Cookie': cookie,
      'X-CSRF-Token': csrfToken,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      kms_provider: 'aws-kms',
      kms_config: { region: 'us-east-1', keyArn: awsKeyArn },
      kms_credentials: { accessKeyId: 'newAccess', secretAccessKey: 'newSecret' }
    })
  });

  assert.strictEqual(updateRes.status, 200, `KMS Update failed with status ${updateRes.status}`);
  
  // Reload group and verify new values
  const updatedGroup = await VaultGroup.findByPk(group.id);
  assert.strictEqual(updatedGroup.kms_provider, 'aws-kms');
  assert.strictEqual(updatedGroup.wrapped_dek, Buffer.from("aws-migrated-ciphertext-blob").toString('base64'));
  console.log("✅ Group KMS provider updated and DEK re-wrapped successfully.");

  // Test resolved DEK on aws-kms provider
  awsSendMock = (cmd) => {
    assert.ok(cmd instanceof awsKms.DecryptCommand);
    assert.strictEqual(cmd.input.KeyId, awsKeyArn);
    assert.deepStrictEqual(cmd.input.CiphertextBlob, Buffer.from("aws-migrated-ciphertext-blob"));
    return { Plaintext: testDek };
  };
  const resolvedDekAws = await server.getGroupDek(updatedGroup);
  assert.deepStrictEqual(resolvedDekAws, testDek, "AWS resolved DEK mismatch after migration");
  console.log("✅ Migrated DEK resolves correctly under AWS KMS.");

  // --- Test 6: Graceful Degradation & Audit Logs ---
  console.log("Testing graceful degradation when KMS is unreachable...");
  
  // Simulate AWS KMS throwing an error (e.g. invalid credentials)
  awsSendMock = (cmd) => {
    throw new Error("AccessDenied: User is not authorized to decrypt this key");
  };

  let unwrapErrorThrown = false;
  try {
    await server.getGroupDek(updatedGroup);
  } catch (err) {
    unwrapErrorThrown = true;
    assert.ok(err.message.includes("AWS KMS: Decrypt failed"), "Error message should contain KMS details");
  }
  assert.ok(unwrapErrorThrown, "Unwrap should have failed");

  // Query audit logs to confirm the error was registered
  const { TransferLog } = require('../db.cjs');
  const { Op } = require('sequelize');
  const kmsErrorLog = await TransferLog.findOne({
    where: {
      metadata: {
        [Op.like]: '%"action":"kms_error"%'
      }
    },
    order: [['createdAt', 'DESC']]
  });
  assert.ok(kmsErrorLog, "Audit log should contain a kms_error entry");
  const logMetadata = JSON.parse(kmsErrorLog.metadata);
  assert.ok(logMetadata.details.includes("KMS Unwrap Error"), "Log description should mention KMS unwrap error");
  assert.ok(logMetadata.details.includes("AccessDenied"), "Log should contain the specific KMS error details");
  console.log("✅ Graceful degradation and audit log routing verified.");

  // Clean up
  serverInstance.close();
  const db = require('../db.cjs');
  await db.sequelize.close();
  try {
    if (fs.existsSync(testDbPath)) fs.unlinkSync(testDbPath);
    if (fs.existsSync(configPath)) fs.unlinkSync(configPath);
  } catch (err) {
    console.log("Cleanup warning (non-fatal): " + err.message);
  }
  
  console.log("\n🎉 ALL KMS PROVIDER AND BYOK MIGRATION TESTS PASSED SUCCESSFULLY! 🎉\n");
  process.exit(0);
}

// Local helper matching provider local wrap implementation
function wrapDekLocal(dek, kek) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  let encrypted = cipher.update(dek);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([iv, tag, encrypted]);
  return combined.toString('base64');
}

runTests().catch(err => {
  console.error("❌ Test run failed:", err);
  process.exit(1);
});
