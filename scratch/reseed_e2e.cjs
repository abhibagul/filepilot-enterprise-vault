const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// 1. Load config and keys
const DATA_DIR = process.env.VAULT_DATA_DIR || path.join(__dirname, '..');
const KEY_FILE = path.join(DATA_DIR, '.vault_key');
const configPath = path.join(DATA_DIR, 'config.json');

// Ensure they exist. If not, generate them.
let encryptionKey;
if (fs.existsSync(KEY_FILE)) {
  const fileKey = fs.readFileSync(KEY_FILE).toString('utf8').trim();
  if (fileKey.length === 64 && /^[0-9a-fA-F]+$/.test(fileKey)) {
    encryptionKey = Buffer.from(fileKey, 'hex');
  } else {
    encryptionKey = fs.readFileSync(KEY_FILE);
  }
} else {
  encryptionKey = crypto.randomBytes(32);
  fs.writeFileSync(KEY_FILE, encryptionKey);
}

// Ensure .env points to the root vault.db
const envContent = [
  `# E2E test configuration`,
  `VAULT_MASTER_KEY=${encryptionKey.toString('hex')}`,
  `DB_DIALECT=sqlite`,
  `DB_STORAGE=${path.join(DATA_DIR, 'vault.db')}`
].join('\n');
fs.writeFileSync(path.join(DATA_DIR, '.env'), envContent, 'utf8');

// Clean up legacy files
if (fs.existsSync(configPath)) {
  try { fs.unlinkSync(configPath); } catch (_) {}
}
if (fs.existsSync(KEY_FILE)) {
  try { fs.unlinkSync(KEY_FILE); } catch (_) {}
}

// Set env vars
process.env.VAULT_DATA_DIR = DATA_DIR;
process.env.VAULT_MASTER_KEY = encryptionKey.toString('hex');
process.env.DB_DIALECT = 'sqlite';
process.env.DB_STORAGE = path.join(DATA_DIR, 'vault.db');

// Load DB
const db = require('../db.cjs');

// Local encryption helpers
function wrapDek(dek, kek) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  let encrypted = cipher.update(dek);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([iv, tag, encrypted]);
  return combined.toString('base64');
}

function encrypt(text, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return `enc:${iv.toString('hex')}:${tag}:${encrypted}`;
}

async function reseed() {
  console.log("Reseeding E2E database...");
  
  // Clean database file if exists
  const dbFile = path.join(DATA_DIR, 'vault.db');
  if (fs.existsSync(dbFile)) {
    fs.unlinkSync(dbFile);
  }

  // Initialize DB
  await db.initDb();

  // Create admin user
  const adminPassword = 'vault-admin-pass';
  const adminHash = crypto.createHash('sha256').update(adminPassword).digest('hex');
  const adminUser = await db.User.create({
    username: 'admin',
    passwordHash: adminHash,
    role: 'admin'
  });
  console.log("Created admin user.");

  // Create walkthrough user
  const userPassword = 'walkthrough-user-pass';
  const userHash = crypto.createHash('sha256').update(userPassword).digest('hex');
  const walkthroughUser = await db.User.create({
    username: 'walkthrough_user',
    passwordHash: userHash,
    role: 'operator'
  });
  console.log("Created walkthrough user.");

  // Create VaultGroup
  const groupId = 'g_jpqy5go';
  const groupDek = crypto.randomBytes(32);
  const wrappedDek = wrapDek(groupDek, encryptionKey);
  const vaultGroup = await db.VaultGroup.create({
    id: groupId,
    name: 'Walkthrough Group',
    kms_provider: 'local',
    wrapped_dek: wrappedDek,
    dek_version: 1,
    migrated: true
  });
  console.log("Created VaultGroup.");

  // Create ConnectionProfile
  const passwordEncrypted = encrypt('secure_sftp_password', groupDek);
  const profile = await db.ConnectionProfile.create({
    id: 'ent_sftp_walkthrough',
    clientProfileId: 'CONN_WALKTHROUGH',
    groupId: groupId,
    name: 'Walkthrough SFTP',
    protocol: 'sftp',
    host: 'sftp.corp.internal',
    port: 22,
    username: 'backup_operator',
    passwordEncrypted: passwordEncrypted,
    authMode: 'password'
  });
  console.log("Created ConnectionProfile.");

  // Create AccessKey
  const token = '8bd62d17bebeee8f9c745eff50c1629052b1f58d91babab47e5b7d3579a58dd4';
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  await db.AccessKey.create({
    token_hash: tokenHash,
    userId: walkthroughUser.id,
    groupId: groupId,
    status: 'active'
  });
  console.log("Created AccessKey.");

  console.log("Reseeding completed successfully!");
  process.exit(0);
}

reseed().catch(err => {
  console.error(err);
  process.exit(1);
});
