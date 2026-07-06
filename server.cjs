const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const urlParser = require('url');

const {
  sequelize,
  User,
  VaultGroup,
  ConnectionProfile,
  AccessKey,
  TransferLog,
  FileVersion,
  SystemConfig,
  PendingReversion,
  AdminSession,
  MfaChallenge,
  KeyVersion,
  initDb,
  updateDbConnection
} = require('./db.cjs');

const kmsProviders = require('./kms-providers.cjs');

// Base32 & TOTP helpers
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(str) {
  str = str.toUpperCase().replace(/=+$/, '');
  let bits = '';
  for (let i = 0; i < str.length; i++) {
    const val = BASE32_CHARS.indexOf(str[i]);
    if (val === -1) throw new Error('Invalid Base32 character');
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substring(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function base32Encode(buffer) {
  let bits = '';
  for (let i = 0; i < buffer.length; i++) {
    bits += buffer[i].toString(2).padStart(8, '0');
  }
  let str = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.substring(i, i + 5).padEnd(5, '0');
    str += BASE32_CHARS[parseInt(chunk, 2)];
  }
  return str;
}

function generateTotp(secretBase32, timeStepOffset = 0) {
  const secretBytes = base32Decode(secretBase32);
  const timeStep = Math.floor(Date.now() / 1000 / 30) + timeStepOffset;
  
  const buffer = Buffer.alloc(8);
  buffer.writeUInt32BE(0, 0); // High 32 bits
  buffer.writeUInt32BE(timeStep, 4); // Low 32 bits
  
  const hmac = crypto.createHmac('sha1', secretBytes);
  hmac.update(buffer);
  const hash = hmac.digest();
  
  const offset = hash[hash.length - 1] & 0x0f;
  const binary = ((hash[offset] & 0x7f) << 24) |
                 ((hash[offset + 1] & 0xff) << 16) |
                 ((hash[offset + 2] & 0xff) << 8) |
                 (hash[offset + 3] & 0xff);
                 
  const code = binary % 1000000;
  return code.toString().padStart(6, '0');
}

function verifyTotp(secretBase32, code, window = 1) {
  for (let i = -window; i <= window; i++) {
    if (generateTotp(secretBase32, i) === code) {
      return true;
    }
  }
  return false;
}

const app = express();
const PORT = process.env.PORT || 8200;

// Cookie parser helper
function parseCookies(cookieHeader) {
  const list = {};
  if (!cookieHeader) return list;
  cookieHeader.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    list[parts.shift().trim()] = decodeURI(parts.join('='));
  });
  return list;
}

// Periodic database session cleanup
setInterval(async () => {
  try {
    const { Op } = require('sequelize');
    const deletedCount = await AdminSession.destroy({
      where: {
        expiresAt: {
          [Op.lt]: new Date()
        }
      }
    });
    if (deletedCount > 0) {
      console.log(`[Session Cleanup] Pruned ${deletedCount} expired admin sessions.`);
    }
  } catch (err) {
    console.error("[Session Cleanup Error] Failed to prune expired sessions:", err);
  }
}, 10 * 60 * 1000);

// Login attempts map for lockout policy
const loginAttempts = new Map();

app.use(cors());
app.use(express.json());

const DATA_DIR = process.env.VAULT_DATA_DIR || process.cwd();
const KEY_FILE = path.join(DATA_DIR, '.vault_key');
const configPath = process.env.VAULT_CONFIG_PATH || path.join(DATA_DIR, 'config.json');
let encryptionKey;
let activeHttpServer;
let activeWss;

// WebSockets connected clients mapping: token string -> WebSocket connection
const clients = new Map();

// Cryptographic Key Initialization
function loadOrCreateKey() {
  try {
    const envKey = process.env.VAULT_MASTER_KEY;
    if (envKey) {
      console.log("[VAULT KEY] Using master key from environment variable (VAULT_MASTER_KEY).");
      if (envKey.length === 64 && /^[0-9a-fA-F]+$/.test(envKey)) {
        encryptionKey = Buffer.from(envKey, 'hex');
      } else if (envKey.length === 44 && /^[0-9a-zA-Z+/=]+$/.test(envKey)) {
        encryptionKey = Buffer.from(envKey, 'base64');
      } else {
        encryptionKey = Buffer.from(envKey, 'utf8');
      }
      return;
    }

    console.warn("WARNING: Using file-based master key. Set VAULT_MASTER_KEY env variable for production use.");

    if (fs.existsSync(KEY_FILE)) {
      const fileKey = fs.readFileSync(KEY_FILE).toString('utf8').trim();
      if (fileKey.length === 64 && /^[0-9a-fA-F]+$/.test(fileKey)) {
        encryptionKey = Buffer.from(fileKey, 'hex');
      } else if (fileKey.length === 44 && /^[0-9a-zA-Z+/=]+$/.test(fileKey)) {
        encryptionKey = Buffer.from(fileKey, 'base64');
      } else {
        encryptionKey = fs.readFileSync(KEY_FILE);
      }
    } else {
      encryptionKey = crypto.randomBytes(32);
      fs.writeFileSync(KEY_FILE, encryptionKey);
    }
  } catch (err) {
    console.error("Failed to load or generate vault key:", err);
    encryptionKey = crypto.scryptSync("fallback-vault-salt", "salt", 32);
  }
}
loadOrCreateKey();

// Cryptographic Helper Functions (AES-256-GCM)
function wrapDek(dek, kek) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  let encrypted = cipher.update(dek);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([iv, tag, encrypted]);
  return combined.toString('base64');
}

function unwrapDek(wrappedDek, kek) {
  const combined = Buffer.from(wrappedDek, 'base64');
  const iv = combined.subarray(0, 12);
  const tag = combined.subarray(12, 28);
  const encrypted = combined.subarray(28);
  
  const decipher = crypto.createDecipheriv('aes-256-gcm', kek, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted; // raw DEK Buffer
}

const kekCache = new Map();

// Get KEK by version
async function getKekByVersion(version) {
  if (kekCache.has(version)) {
    return kekCache.get(version);
  }
  const activeVersion = await KeyVersion.max('version') || 1;
  if (version === activeVersion) {
    kekCache.set(version, encryptionKey);
    return encryptionKey; // current/active KEK
  } else if (version === activeVersion - 1 && process.env.VAULT_MASTER_KEY_PREVIOUS) {
    const prevKey = process.env.VAULT_MASTER_KEY_PREVIOUS;
    let prevBuffer;
    if (prevKey.length === 64 && /^[0-9a-fA-F]+$/.test(prevKey)) {
      prevBuffer = Buffer.from(prevKey, 'hex');
    } else if (prevKey.length === 44 && /^[0-9a-zA-Z+/=]+$/.test(prevKey)) {
      prevBuffer = Buffer.from(prevKey, 'base64');
    } else {
      prevBuffer = Buffer.from(prevKey, 'utf8');
    }
    kekCache.set(version, prevBuffer);
    return prevBuffer;
  }
  // Fallback to active KEK
  return encryptionKey;
}

function decryptKmsCredentials(encryptedStr) {
  if (!encryptedStr) return {};
  const decrypted = decrypt(encryptedStr, encryptionKey);
  if (decrypted === "[Decryption Error]") {
    return {};
  }
  try {
    return JSON.parse(decrypted);
  } catch (err) {
    console.error("Failed to parse decrypted KMS credentials:", err);
    return {};
  }
}

function encryptKmsCredentials(credsObj) {
  if (!credsObj) return null;
  return encrypt(JSON.stringify(credsObj), encryptionKey);
}

// Unwrap group DEK
async function getGroupDek(vaultGroup) {
  if (!vaultGroup.wrapped_dek) {
    return encryptionKey;
  }
  
  const providerType = vaultGroup.kms_provider || 'local';
  const provider = kmsProviders.providers[providerType];
  if (!provider) {
    throw new Error(`Unsupported KMS provider: ${providerType}`);
  }

  let providerConfig = {};
  if (providerType === 'local') {
    const version = vaultGroup.dek_version || 1;
    const kek = await getKekByVersion(version);
    providerConfig = { kek };
  } else {
    if (vaultGroup.kms_config) {
      try {
        providerConfig = JSON.parse(vaultGroup.kms_config);
      } catch (err) {
        console.error("Failed to parse kms_config:", err);
      }
    }
    if (vaultGroup.kms_credentials_encrypted) {
      const decryptedCreds = decryptKmsCredentials(vaultGroup.kms_credentials_encrypted);
      providerConfig = { ...providerConfig, ...decryptedCreds };
    }
  }

  try {
    return await provider.unwrapDek(providerConfig, vaultGroup.wrapped_dek);
  } catch (err) {
    console.error(`[KMS Error] Failed to unwrap DEK for group ${vaultGroup.name} (${vaultGroup.id}) using provider ${providerType}:`, err);
    
    // Log the failure to the audit log cleanly
    await addAuditLog(
      'System',
      JSON.stringify({
        action: 'kms_error',
        performedBy: 'System',
        performedByUsername: 'System',
        ipAddress: '127.0.0.1',
        details: `KMS Unwrap Error for Group ${vaultGroup.name}: ${err.message}`,
        status: 'failed',
        groupId: vaultGroup.id
      }),
      'failed'
    );
    
    throw err;
  }
}

function encrypt(text, key) {
  if (!text) return text;
  if (text.startsWith('enc:')) return text; // Already encrypted
  const encKey = key || encryptionKey;
  try {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', encKey, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const tag = cipher.getAuthTag().toString('hex');
    return `enc:${iv.toString('hex')}:${tag}:${encrypted}`;
  } catch (err) {
    console.error("Encryption failed:", err);
    return text;
  }
}

// Decrypt text
function decrypt(text, key) {
  if (!text || !text.startsWith('enc:')) return text;
  const decKey = key || encryptionKey;
  try {
    const parts = text.split(':');
    if (parts.length !== 4) return text;
    const iv = Buffer.from(parts[1], 'hex');
    const tag = Buffer.from(parts[2], 'hex');
    const encryptedText = Buffer.from(parts[3], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', decKey, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    console.error("Decryption failed:", err);
    return "[Decryption Error]";
  }
}

// IP Allowlist matching utility
function ipMatches(clientIp, allowlistStr) {
  if (!allowlistStr || allowlistStr.trim() === '') return true;
  
  let ip = clientIp.trim();
  // Handle IPv6 mapped IPv4 addresses
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  // Localhost aliases
  if (ip === '::1') {
    ip = '127.0.0.1';
  }

  const list = allowlistStr.split(',').map(s => s.trim()).filter(Boolean);
  for (const allowed of list) {
    if (allowed === ip) return true;
    
    // Wildcard prefix match (e.g. 192.168.1.*)
    if (allowed.endsWith('*')) {
      const prefix = allowed.slice(0, -1);
      if (ip.startsWith(prefix)) return true;
    }
    
    // CIDR subnet matching (e.g. 192.168.1.0/24)
    if (allowed.includes('/')) {
      const [subnet, mask] = allowed.split('/');
      const maskInt = parseInt(mask, 10);
      if (ip4ToInt(ip) && ip4ToInt(subnet)) {
        const ipInt = ip4ToInt(ip);
        const subInt = ip4ToInt(subnet);
        const maskBits = ~((1 << (32 - maskInt)) - 1);
        if ((ipInt & maskBits) === (subInt & maskBits)) return true;
      }
    }
  }
  return false;
}

function ip4ToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(isNaN)) return null;
  return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

const dns = require('dns').promises;
const net = require('net');

function isPrivateIp(ip) {
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }

  const ipv4Parts = ip.split('.');
  if (ipv4Parts.length === 4) {
    const a = parseInt(ipv4Parts[0], 10);
    const b = parseInt(ipv4Parts[1], 10);
    const c = parseInt(ipv4Parts[2], 10);
    const d = parseInt(ipv4Parts[3], 10);
    
    if (isNaN(a) || isNaN(b) || isNaN(c) || isNaN(d)) return false;

    // 127.0.0.0/8 (Loopback)
    if (a === 127) return true;
    // 10.0.0.0/8 (Private)
    if (a === 10) return true;
    // 172.16.0.0/12 (Private)
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16 (Private)
    if (a === 192 && b === 168) return true;
    // 169.254.0.0/16 (Link-local)
    if (a === 169 && b === 254) return true;

    return false;
  }

  const cleanIp = ip.toLowerCase().trim();
  if (cleanIp === '::1' || cleanIp === '0:0:0:0:0:0:0:1') {
    return true;
  }
  // Link-local: starts with fe80, fe90, fea0, feb0 (fe80::/10)
  if (cleanIp.startsWith('fe80:') || cleanIp.startsWith('fe90:') || cleanIp.startsWith('fea0:') || cleanIp.startsWith('feb0:') ||
      /^[fF][eE][89abAB]/i.test(cleanIp)) {
    return true;
  }

  return false;
}

async function isHostPrivate(host) {
  try {
    if (net.isIP(host)) {
      return isPrivateIp(host);
    }
    
    const addresses = await dns.lookup(host, { all: true });
    for (const addr of addresses) {
      if (isPrivateIp(addr.address)) {
        return true;
      }
    }
    return false;
  } catch (err) {
    return false;
  }
}

// Lightweight In-Memory Rate Limiter Middleware
const ipRequestCounts = new Map();

function createRateLimiter(maxRequests, windowMs, message) {
  return (req, res, next) => {
    if (process.env.NODE_ENV === 'test') {
      return next();
    }
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    
    // Bypass rate limits for local loopback development connections
    if (ip === '127.0.0.1' || ip === '::1' || ip === '::ffff:127.0.0.1') {
      return next();
    }

    const now = Date.now();
    
    if (!ipRequestCounts.has(ip)) {
      ipRequestCounts.set(ip, []);
    }
    
    const timestamps = ipRequestCounts.get(ip);
    const activeTimestamps = timestamps.filter(t => now - t < windowMs);
    
    if (activeTimestamps.length >= maxRequests) {
      return res.status(429).json({ error: message || "Too many requests. Please try again later." });
    }
    
    activeTimestamps.push(now);
    ipRequestCounts.set(ip, activeTimestamps);
    next();
  };
}

const authLimiter = createRateLimiter(5, 10 * 60 * 1000, "Too many login attempts. Please try again after 10 minutes.");
const syncLimiter = createRateLimiter(30, 60 * 1000, "Too many profile sync attempts. Please try again in a minute.");

// Server Audit log helper
async function addAuditLog(tokenDesc, action, status = "success") {
  try {
    const loggingEnabled = await SystemConfig.findOne({ where: { key: 'audit_logging_enabled' } });
    if (loggingEnabled && loggingEnabled.value === 'false') return;

    // Check if there is an AccessKey matching tokenDesc (using hash if it looks like a token)
    let key = null;
    if (tokenDesc && tokenDesc.length > 10 && !tokenDesc.includes(' ')) {
      const hashed = crypto.createHash('sha256').update(tokenDesc).digest('hex');
      key = await AccessKey.findOne({
        where: { token_hash: hashed },
        include: [User]
      });
    }
    
    let username = key && key.User ? key.User.username : null;
    let tokenVal = key ? key.token_hash : null;
    
    if (!username && tokenDesc === 'admin-token') {
      username = 'Master Token';
      tokenVal = 'admin-token';
    }

    let errMsg = action;
    let metadataVal = null;
    if (action && action.startsWith('{') && action.endsWith('}')) {
      try {
        JSON.parse(action);
        metadataVal = action;
        errMsg = null;
      } catch (e) {}
    }

    await TransferLog.create({
      token: tokenVal,
      username: username || tokenDesc,
      connectionId: 'VaultServer',
      filePath: 'SystemAudit',
      action: 'audit',
      status: status,
      errorMessage: errMsg,
      metadata: metadataVal
    });
  } catch (err) {
    console.error("Failed to write system audit log:", err);
  }
  
  // Forward to SIEM Webhook
  triggerSiemWebhook(tokenDesc, action, status);
}

// SIEM Webhook Integration
async function triggerSiemWebhook(scope, action, status) {
  try {
    const siemUrl = await SystemConfig.findOne({ where: { key: 'siem_webhook_url' } });
    if (!siemUrl || !siemUrl.value || siemUrl.value.trim() === '') return;

    const siemSecretConfig = await SystemConfig.findOne({ where: { key: 'siem_webhook_secret' } });
    const secret = siemSecretConfig ? siemSecretConfig.value : '';

    const payload = {
      timestamp: new Date().toISOString(),
      system: "FilePilot Enterprise Engine",
      scope,
      action,
      status
    };
    const rawBody = JSON.stringify(payload);
    const signature = crypto.createHmac('sha256', secret).update(rawBody).digest('hex');

    const attemptPost = async (attempt = 0) => {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      try {
        const res = await fetch(siemUrl.value, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-Vault-Signature-256': `sha256=${signature}`
          },
          body: rawBody,
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (!res.ok) {
          throw new Error(`HTTP error status ${res.status}`);
        }
      } catch (err) {
        clearTimeout(timeoutId);
        console.error(`[SIEM Webhook Error] Attempt ${attempt} failed: ${err.message}`);

        if (attempt < 3) {
          const backoffs = [1000, 4000, 16000];
          const delay = backoffs[attempt];
          await new Promise(resolve => setTimeout(resolve, delay));
          return attemptPost(attempt + 1);
        } else {
          console.error(`[SIEM Webhook Error] All attempts exhausted. Logging permanent failure.`);
          try {
            await TransferLog.create({
              token: null,
              username: 'System',
              connectionId: 'VaultServer',
              filePath: 'SystemAudit',
              action: 'siem_failure',
              status: 'failed',
              errorMessage: `SIEM Webhook delivery permanently failed for action "${action}"`
            });
          } catch (logErr) {
            console.error("Failed to write SIEM failure log:", logErr);
          }
        }
      }
    };

    attemptPost();
  } catch (e) {
    console.error("SIEM Webhook error:", e);
  }
}

// Admin Authentication Middleware
async function authMiddleware(req, res, next) {
  const cookies = parseCookies(req.headers.cookie);
  const sessionId = cookies['vault_session'];

  if (!sessionId) {
    return res.status(401).json({ error: "Unauthorized access: Session missing" });
  }

  const hashedSession = crypto.createHash('sha256').update(sessionId).digest('hex');
  const session = await AdminSession.findOne({
    where: { session_hash: hashedSession },
    include: [User]
  });

  if (!session || new Date() > new Date(session.expiresAt)) {
    if (session) await session.destroy();
    return res.status(401).json({ error: "Unauthorized access: Session expired or invalid" });
  }

  // Check CSRF token for state-changing requests (POST, PUT, DELETE)
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const csrfHeader = req.headers['x-csrf-token'];
    if (!csrfHeader || csrfHeader !== session.csrfToken) {
      console.warn(`[CSRF] Blocked ${req.method} request to ${req.path} - CSRF mismatch or missing`);
      return res.status(403).json({ error: "Forbidden: CSRF token invalid or missing" });
    }
  }

  const user = session.User;
  if (!user) {
    return res.status(401).json({ error: "Unauthorized access: User not found" });
  }

  // Throttle lastActivityAt update to at most once per minute
  const now = new Date();
  if (!session.lastActivityAt || (now - new Date(session.lastActivityAt)) > 60000) {
    session.lastActivityAt = now;
    await session.save();
  }

  req.adminUser = user;
  req.session = session;
  req.sessionId = session.id;
  req.rawSessionToken = sessionId;
  next();
}

// Granular RBAC Permission Matrix
const ROLE_PERMISSIONS = {
  admin: ['*'], // Special wildcard for all permissions
  manager: [
    'vault.*',
    'profile.*',
    'token.*',
    'backup.*',
    'audit.view',
    'system.view_dashboard',
    'legal_hold.manage',
    'user.view'
  ],
  operator: [
    'vault.view_groups',
    'profile.view',
    'profile.create',
    'profile.edit',
    'profile.test_connection',
    'token.view',
    'token.issue',
    'backup.view',
    'system.view_dashboard'
  ],
  auditor: [
    'vault.view_groups',
    'profile.view',
    'token.view',
    'audit.view',
    'audit.export',
    'backup.view',
    'system.view_dashboard'
  ]
};

// Helper to check permission
function hasPermission(user, requiredPermission) {
  if (!user || !user.role) return false;
  const role = user.role.toLowerCase();
  const permissions = ROLE_PERMISSIONS[role] || [];

  if (permissions.includes('*')) return true;
  if (permissions.includes(requiredPermission)) return true;

  // Handle wildcard matching (e.g. "profile.*" matches "profile.view")
  const requiredParts = requiredPermission.split('.');
  if (requiredParts.length === 2) {
    const wildcardPattern = `${requiredParts[0]}.*`;
    if (permissions.includes(wildcardPattern)) return true;
  }

  return false;
}

// Middleware to check permission
function requirePermission(requiredPermission) {
  return (req, res, next) => {
    if (!req.adminUser) {
      return res.status(401).json({ error: "Unauthorized access: Session missing or invalid" });
    }
    if (hasPermission(req.adminUser, requiredPermission)) {
      return next();
    }
    return res.status(403).json({ error: `Forbidden: Missing required permission '${requiredPermission}'` });
  };
}

// Health Check Endpoint
app.get('/healthz', async (req, res) => {
  let dbStatus = "error";
  let httpStatus = 503;
  try {
    await sequelize.query('SELECT 1');
    dbStatus = "connected";
    httpStatus = 200;
  } catch (err) {
    console.error("[Healthcheck] Database check failed:", err.message);
  }

  res.status(httpStatus).json({
    status: httpStatus === 200 ? "ok" : "error",
    db: dbStatus,
    uptime: Math.floor(process.uptime())
  });
});

// Check if installation is complete helper (async to verify admin user exists)
const checkIsInstalled = async () => {
  const hasKey = !!process.env.VAULT_MASTER_KEY || fs.existsSync(KEY_FILE);
  const hasConfig = !!process.env.DB_DIALECT || fs.existsSync(configPath);
  if (!hasKey || !hasConfig) return false;
  try {
    const adminCount = await User.count({ where: { role: 'admin' } });
    return adminCount > 0;
  } catch (err) {
    return false;
  }
};

// Middleware to block API requests if setup is incomplete
app.use('/admin/api', async (req, res, next) => {
  if (req.path.startsWith('/install/')) {
    return next();
  }
  const installed = await checkIsInstalled();
  if (!installed) {
    return res.status(503).json({ error: "Vault Setup is incomplete. Please access the setup wizard at http://localhost:8200/admin" });
  }
  next();
});

// Installer Endpoint: Test Database Connection
app.post('/admin/api/install/test-db', async (req, res) => {
  const { dialect, host, port, username, password, database, storage } = req.body;
  try {
    const { Sequelize } = require('sequelize');
    let tempSequelize;
    if (dialect === 'sqlite') {
      tempSequelize = new Sequelize({
        dialect: 'sqlite',
        storage: storage || path.join(DATA_DIR, 'vault.db'),
        logging: false
      });
    } else if (dialect === 'postgres') {
      tempSequelize = new Sequelize({
        dialect: 'postgres',
        host: host || 'localhost',
        port: parseInt(port) || 5432,
        username,
        password,
        database,
        logging: false,
        dialectOptions: {
          ssl: {
            require: true,
            rejectUnauthorized: false
          }
        }
      });
    } else { // mysql
      tempSequelize = new Sequelize({
        dialect: 'mysql',
        host: host || 'localhost',
        port: parseInt(port) || 3306,
        username,
        password,
        database,
        logging: false
      });
    }
    await tempSequelize.authenticate();
    await tempSequelize.close();
    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Installer Endpoint: Complete Installation and Seeding
app.post('/admin/api/install/submit', async (req, res) => {
  if (await checkIsInstalled()) {
    return res.status(400).json({ error: "System is already configured and installed." });
  }

  const {
    dbDialect,
    dbHost,
    dbPort,
    dbUsername,
    dbPassword,
    dbName,
    dbStorage,
    adminEmail,
    adminPassword,
    keyMode,
    customKey
  } = req.body;

  try {
    // 1. Resolve master key string representation
    let masterKeyStr;
    if (keyMode === 'custom') {
      masterKeyStr = customKey;
    } else {
      masterKeyStr = crypto.randomBytes(32).toString('hex');
    }
    
    // Parse key to set the in-memory encryptionKey variable
    if (masterKeyStr.length === 64 && /^[0-9a-fA-F]+$/.test(masterKeyStr)) {
      encryptionKey = Buffer.from(masterKeyStr, 'hex');
    } else if (masterKeyStr.length === 44 && /^[0-9a-zA-Z+/=]+$/.test(masterKeyStr)) {
      encryptionKey = Buffer.from(masterKeyStr, 'base64');
    } else {
      encryptionKey = Buffer.from(masterKeyStr, 'utf8');
    }

    // 2. Write all configuration parameters to .env file
    const envContent = [
      `# FilePilot Corporate Vault Environment Configuration`,
      `VAULT_MASTER_KEY=${masterKeyStr}`,
      `DB_DIALECT=${dbDialect}`,
      `DB_HOST=${dbHost || 'localhost'}`,
      `DB_PORT=${dbPort || ''}`,
      `DB_USERNAME=${dbUsername || ''}`,
      `DB_PASSWORD=${dbPassword || ''}`,
      `DB_NAME=${dbName || ''}`,
      `DB_STORAGE=${dbStorage || ''}`,
      `DB_SSL=false`
    ].join('\n');
    
    const envFilePath = path.join(DATA_DIR, '.env');
    fs.writeFileSync(envFilePath, envContent, 'utf8');
    
    // Clean up any legacy configuration files if they exist to avoid confusion
    if (fs.existsSync(configPath)) {
      try { fs.unlinkSync(configPath); } catch (_) {}
    }
    if (fs.existsSync(KEY_FILE)) {
      try { fs.unlinkSync(KEY_FILE); } catch (_) {}
    }

    // Set the loaded environment variables in the active process
    process.env.VAULT_MASTER_KEY = masterKeyStr;
    process.env.DB_DIALECT = dbDialect;
    process.env.DB_HOST = dbHost || 'localhost';
    if (dbPort) process.env.DB_PORT = String(dbPort);
    if (dbUsername) process.env.DB_USERNAME = dbUsername;
    if (dbPassword) process.env.DB_PASSWORD = dbPassword;
    if (dbName) process.env.DB_NAME = dbName;
    if (dbStorage) process.env.DB_STORAGE = dbStorage;
    process.env.DB_SSL = 'false';

    // 3. Dynamically re-connect and synchronize Sequelize models on the target database
    console.log('[Setup] Loading fresh database module to apply configuration...');
    try {
      const dbPath = require.resolve('./db.cjs');
      delete require.cache[dbPath];
    } catch (_) {}
    const db = require('./db.cjs');

    db.updateDbConnection({
      dialect: dbDialect,
      host: dbHost,
      port: dbPort,
      username: dbUsername,
      password: dbPassword,
      database: dbName,
      storage: dbStorage,
      ssl: false
    });
    
    // Initialize database, run migrations and sync models
    await db.initDb();

    // 4. Seed Admin user
    const adminHash = crypto.createHash('sha256').update(adminPassword).digest('hex');
    let adminUser = await db.User.findOne({ where: { username: 'admin' } });
    if (adminUser) {
      adminUser.passwordHash = adminHash;
      await adminUser.save();
    } else {
      await db.User.create({
        username: 'admin',
        passwordHash: adminHash,
        role: 'admin'
      });
    }

    // 5. Seed default configurations
    await db.SystemConfig.findOrCreate({ where: { key: 'siem_webhook_url' }, defaults: { value: '' } });
    await db.SystemConfig.findOrCreate({ where: { key: 'siem_webhook_secret' }, defaults: { value: crypto.randomBytes(32).toString('hex') } });
    await db.SystemConfig.findOrCreate({ where: { key: 'audit_logging_enabled' }, defaults: { value: 'true' } });

    res.json({ success: true });
    
    console.log("[Setup] Installation successful. Restarting server to apply new configuration...");
    setTimeout(() => {
      if (activeWss) {
        try { activeWss.close(); } catch (_) {}
      }
      if (activeHttpServer) {
        try {
          if (typeof activeHttpServer.closeAllConnections === 'function') {
            activeHttpServer.closeAllConnections();
          }
          activeHttpServer.close(() => {
            const isServerOrCli = process.argv[1] && (process.argv[1].endsWith('server.cjs') || process.argv[1].endsWith('cli.js'));
            if (isServerOrCli) {
              const { spawn } = require('child_process');
              const child = spawn(process.argv[0], process.argv.slice(1), {
                stdio: 'inherit'
              });
              child.on('close', (code) => {
                process.exit(code || 0);
              });
            } else {
              process.exit(0);
            }
          });
        } catch (_) {
          process.exit(0);
        }
      } else {
        process.exit(0);
      }
    }, 1000);
  } catch (err) {
    console.error("Installation failed:", err);
    res.status(500).json({ error: err.message });
  }
});

// Admin Authentication Verification Probe
app.post('/admin/api/verify-auth', authLimiter, async (req, res) => {
  const username = req.body.username || 'admin';
  const password = req.body.password;
  
  // Check if locked
  const now = Date.now();
  const attempt = loginAttempts.get(username);
  if (attempt && attempt.lockUntil > now) {
    const waitMins = Math.ceil((attempt.lockUntil - now) / 60000);
    return res.status(429).json({ error: `Account locked. Try again in ${waitMins} minutes.` });
  }

  if (!password) {
    return res.status(401).json({ error: "Password required" });
  }

  const hash = crypto.createHash('sha256').update(password).digest('hex');
  const user = await User.findOne({ where: { username } });

  if (user && user.passwordHash === hash) {
    if (user.mfa_enabled) {
      const challengeId = crypto.randomBytes(32).toString('hex');
      await MfaChallenge.create({
        id: challengeId,
        userId: user.id,
        expiresAt: new Date(Date.now() + 5 * 60 * 1000), // 5 minutes
        consumed: false
      });
      return res.json({ mfaRequired: true, challengeId });
    }

    // Reset login attempts
    loginAttempts.delete(username);

    // Generate Session ID
    const sessionId = crypto.randomBytes(32).toString('hex');
    const csrfToken = crypto.randomBytes(16).toString('hex');
    const expiresAt = Date.now() + 8 * 60 * 60 * 1000; // 8 hours

    // Soft cap check
    const MAX_SESSIONS_PER_USER = 5;
    const activeSessions = await AdminSession.findAll({
      where: { userId: user.id },
      order: [['createdAt', 'ASC']]
    });
    if (activeSessions.length >= MAX_SESSIONS_PER_USER) {
      const deleteCount = activeSessions.length - MAX_SESSIONS_PER_USER + 1;
      for (let i = 0; i < deleteCount; i++) {
        await activeSessions[i].destroy();
      }
    }

    const sessionHash = crypto.createHash('sha256').update(sessionId).digest('hex');
    const clientIp = req.ip || req.connection.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'Unknown';

    await AdminSession.create({
      session_hash: sessionHash,
      userId: user.id,
      ipAddress: clientIp,
      userAgent: userAgent,
      csrfToken,
      expiresAt: new Date(expiresAt)
    });

    // Set cookie
    res.setHeader('Set-Cookie', `vault_session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`);
    
    // Add audit log
    await addAuditLog(username, "Administrator logged in successfully");

    return res.json({ success: true, csrfToken });
  } else {
    // Increment failed login attempt
    let count = 1;
    let lockUntil = 0;
    if (attempt) {
      count = attempt.count + 1;
      if (count >= 5) {
        lockUntil = now + 15 * 60 * 1000; // 15 minutes lock
        console.log(`[AUTH] Locking user "${username}" for 15 minutes due to 5 consecutive failures.`);
      }
    }
    loginAttempts.set(username, { count, lockUntil });

    await addAuditLog(username, `Failed login attempt (${count}/5)`, "error");
    
    if (count >= 5) {
      return res.status(429).json({ error: "Account locked. Try again in 15 minutes." });
    }
    return res.status(401).json({ error: "Invalid password" });
  }
});

// Admin Logout Endpoint
app.post('/admin/api/logout', authMiddleware, async (req, res) => {
  if (req.sessionId) {
    await AdminSession.destroy({ where: { id: req.sessionId } });
  }
  // Clear cookie
  res.setHeader('Set-Cookie', 'vault_session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0');
  res.json({ success: true });
});

// Admin Password Update Endpoint
app.post('/admin/api/change-password', authMiddleware, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const oldHash = crypto.createHash('sha256').update(oldPassword).digest('hex');
  
  if (req.adminUser.passwordHash !== oldHash) {
    return res.status(400).json({ error: "Current admin password does not match." });
  }
  if (!newPassword || newPassword.trim().length < 4) {
    return res.status(400).json({ error: "Password must be at least 4 characters long." });
  }
  
  const newHash = crypto.createHash('sha256').update(newPassword.trim()).digest('hex');
  req.adminUser.passwordHash = newHash;
  await req.adminUser.save();
  await addAuditLog(
    req.adminUser.username,
    JSON.stringify({
      action: "password_changed",
      performedBy: req.adminUser.id,
      performedByUsername: req.adminUser.username
    })
  );
  res.json({ success: true });
});

// ── Multi-Factor Authentication (MFA) APIs ───────────────────────────
app.post('/admin/api/mfa/enroll', authMiddleware, async (req, res) => {
  try {
    const user = req.adminUser;
    const rawSecret = crypto.randomBytes(20);
    const secretBase32 = base32Encode(rawSecret);
    
    // Encrypt the secret
    const secretEncrypted = encrypt(secretBase32);
    user.mfa_secret_encrypted = secretEncrypted;
    await user.save();
    
    const QRCode = require('qrcode');
    const otpAuthUrl = `otpauth://totp/FilePilot:${user.username}?secret=${secretBase32}&issuer=FilePilot`;
    const qrCodeDataUri = await QRCode.toDataURL(otpAuthUrl);
    
    res.json({
      success: true,
      qrCode: qrCodeDataUri,
      secret: secretBase32
    });
  } catch (err) {
    console.error("MFA enroll failed:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/api/mfa/enroll/verify', authMiddleware, async (req, res) => {
  try {
    const { code } = req.body;
    if (!code) {
      return res.status(400).json({ error: "Verification code required" });
    }
    const user = req.adminUser;
    if (!user.mfa_secret_encrypted) {
      return res.status(400).json({ error: "MFA enrollment not initiated" });
    }
    
    const secretBase32 = decrypt(user.mfa_secret_encrypted);
    const isValid = verifyTotp(secretBase32, code);
    if (!isValid) {
      return res.status(400).json({ error: "Invalid verification code. Please try again." });
    }
    
    // Generate 10 single-use backup codes
    const rawBackupCodes = [];
    const hashedBackupCodes = [];
    for (let i = 0; i < 10; i++) {
      const rawCode = crypto.randomBytes(6).toString('hex');
      const hashed = crypto.createHash('sha256').update(rawCode).digest('hex');
      rawBackupCodes.push(rawCode);
      hashedBackupCodes.push(hashed);
    }
    
    user.mfa_enabled = true;
    user.mfa_backup_codes_hash = JSON.stringify(hashedBackupCodes);
    await user.save();
    
    await addAuditLog(
      user.username,
      JSON.stringify({
        action: "mfa_enabled",
        userId: user.id
      })
    );
    
    res.json({
      success: true,
      backupCodes: rawBackupCodes
    });
  } catch (err) {
    console.error("MFA enroll verify failed:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/api/mfa/disable', authMiddleware, async (req, res) => {
  try {
    const { password, code } = req.body;
    if (!password || !code) {
      return res.status(400).json({ error: "Password and code are required." });
    }
    const user = req.adminUser;
    
    const passHash = crypto.createHash('sha256').update(password).digest('hex');
    if (user.passwordHash !== passHash) {
      return res.status(400).json({ error: "Invalid password." });
    }
    
    let isValid = false;
    if (user.mfa_secret_encrypted) {
      const secretBase32 = decrypt(user.mfa_secret_encrypted);
      if (verifyTotp(secretBase32, code)) {
        isValid = true;
      }
    }
    
    if (!isValid && user.mfa_backup_codes_hash) {
      const backupHashes = JSON.parse(user.mfa_backup_codes_hash);
      const inputHash = crypto.createHash('sha256').update(code).digest('hex');
      const idx = backupHashes.indexOf(inputHash);
      if (idx !== -1) {
        isValid = true;
        backupHashes.splice(idx, 1);
        user.mfa_backup_codes_hash = JSON.stringify(backupHashes);
      }
    }
    
    if (!isValid) {
      return res.status(400).json({ error: "Invalid verification code or backup code." });
    }
    
    user.mfa_enabled = false;
    user.mfa_secret_encrypted = null;
    user.mfa_backup_codes_hash = null;
    await user.save();
    
    await addAuditLog(
      user.username,
      JSON.stringify({
        action: "mfa_disabled",
        userId: user.id
      })
    );
    
    res.json({ success: true });
  } catch (err) {
    console.error("MFA disable failed:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/api/mfa/regenerate-backup-codes', authMiddleware, async (req, res) => {
  try {
    const { password, code } = req.body;
    if (!password || !code) {
      return res.status(400).json({ error: "Password and code are required." });
    }
    const user = req.adminUser;
    
    const passHash = crypto.createHash('sha256').update(password).digest('hex');
    if (user.passwordHash !== passHash) {
      return res.status(400).json({ error: "Invalid password." });
    }
    
    let isValid = false;
    if (user.mfa_secret_encrypted) {
      const secretBase32 = decrypt(user.mfa_secret_encrypted);
      if (verifyTotp(secretBase32, code)) {
        isValid = true;
      }
    }
    
    if (!isValid && user.mfa_backup_codes_hash) {
      const backupHashes = JSON.parse(user.mfa_backup_codes_hash);
      const inputHash = crypto.createHash('sha256').update(code).digest('hex');
      const idx = backupHashes.indexOf(inputHash);
      if (idx !== -1) {
        isValid = true;
        backupHashes.splice(idx, 1);
        user.mfa_backup_codes_hash = JSON.stringify(backupHashes);
      }
    }
    
    if (!isValid) {
      return res.status(400).json({ error: "Invalid verification code or backup code." });
    }
    
    const rawBackupCodes = [];
    const hashedBackupCodes = [];
    for (let i = 0; i < 10; i++) {
      const rawCode = crypto.randomBytes(6).toString('hex');
      const hashed = crypto.createHash('sha256').update(rawCode).digest('hex');
      rawBackupCodes.push(rawCode);
      hashedBackupCodes.push(hashed);
    }
    
    user.mfa_backup_codes_hash = JSON.stringify(hashedBackupCodes);
    await user.save();
    
    await addAuditLog(
      user.username,
      JSON.stringify({
        action: "mfa_backup_codes_regenerated",
        userId: user.id
      })
    );
    
    res.json({
      success: true,
      backupCodes: rawBackupCodes
    });
  } catch (err) {
    console.error("MFA regenerate backup codes failed:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/api/mfa/verify-login', authLimiter, async (req, res) => {
  try {
    const { challengeId, code } = req.body;
    if (!challengeId || !code) {
      return res.status(400).json({ error: "Challenge ID and code are required." });
    }
    
    const challenge = await MfaChallenge.findByPk(challengeId);
    if (!challenge || challenge.consumed || new Date(challenge.expiresAt) < new Date()) {
      return res.status(400).json({ error: "Invalid or expired login challenge." });
    }
    
    const user = await User.findByPk(challenge.userId);
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }
    
    const username = user.username;
    
    // Check lock
    const now = Date.now();
    const attempt = loginAttempts.get(username);
    if (attempt && attempt.lockUntil > now) {
      const waitMins = Math.ceil((attempt.lockUntil - now) / 60000);
      return res.status(429).json({ error: `Account locked. Try again in ${waitMins} minutes.` });
    }
    
    let isValid = false;
    if (user.mfa_secret_encrypted) {
      const secretBase32 = decrypt(user.mfa_secret_encrypted);
      if (verifyTotp(secretBase32, code)) {
        isValid = true;
      }
    }
    
    if (!isValid && user.mfa_backup_codes_hash) {
      const backupHashes = JSON.parse(user.mfa_backup_codes_hash);
      const inputHash = crypto.createHash('sha256').update(code).digest('hex');
      const idx = backupHashes.indexOf(inputHash);
      if (idx !== -1) {
        isValid = true;
        backupHashes.splice(idx, 1);
        user.mfa_backup_codes_hash = JSON.stringify(backupHashes);
        await user.save();
      }
    }
    
    if (!isValid) {
      let count = 1;
      let lockUntil = 0;
      if (attempt) {
        count = attempt.count + 1;
        if (count >= 5) {
          lockUntil = now + 15 * 60 * 1000;
        }
      }
      loginAttempts.set(username, { count, lockUntil });
      await addAuditLog(username, `Failed MFA login attempt (${count}/5)`, "error");
      
      if (count >= 5) {
        return res.status(429).json({ error: "Account locked. Try again in 15 minutes." });
      }
      return res.status(401).json({ error: "Invalid MFA code" });
    }
    
    loginAttempts.delete(username);
    challenge.consumed = true;
    await challenge.save();
    
    const sessionId = crypto.randomBytes(32).toString('hex');
    const csrfToken = crypto.randomBytes(16).toString('hex');
    const expiresAt = Date.now() + 8 * 60 * 60 * 1000;
    
    const MAX_SESSIONS_PER_USER = 5;
    const activeSessions = await AdminSession.findAll({
      where: { userId: user.id },
      order: [['createdAt', 'ASC']]
    });
    if (activeSessions.length >= MAX_SESSIONS_PER_USER) {
      const deleteCount = activeSessions.length - MAX_SESSIONS_PER_USER + 1;
      for (let i = 0; i < deleteCount; i++) {
        await activeSessions[i].destroy();
      }
    }
    
    const sessionHash = crypto.createHash('sha256').update(sessionId).digest('hex');
    const clientIp = req.ip || req.connection.remoteAddress || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'Unknown';
    
    await AdminSession.create({
      session_hash: sessionHash,
      userId: user.id,
      ipAddress: clientIp,
      userAgent,
      csrfToken,
      expiresAt: new Date(expiresAt)
    });
    
    res.setHeader('Set-Cookie', `vault_session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`);
    await addAuditLog(username, "Administrator logged in successfully (MFA verified)");
    
    return res.json({ success: true, csrfToken });
  } catch (err) {
    console.error("MFA verify login failed:", err);
    res.status(500).json({ error: err.message });
  }
});

if (process.env.NODE_ENV === 'test') {
  app.post('/admin/api/test/reset-lockout', async (req, res) => {
    const { username } = req.body;
    loginAttempts.delete(username);
    res.json({ success: true });
  });
}

// SIEM & SMTP Webhook Config Update Endpoint
app.post('/admin/api/settings', authMiddleware, async (req, res) => {
  const {
    siem_webhook_url,
    siem_webhook_secret,
    audit_logging_enabled,
    smtp_host,
    smtp_port,
    smtp_username,
    smtp_password,
    smtp_sender,
    backup_retention_limit,
    backup_enabled
  } = req.body;
  
  const hasSiemFields = siem_webhook_url !== undefined || siem_webhook_secret !== undefined;
  const hasSystemFields = audit_logging_enabled !== undefined ||
                          smtp_host !== undefined || smtp_port !== undefined ||
                          smtp_username !== undefined || smtp_password !== undefined ||
                          smtp_sender !== undefined || backup_retention_limit !== undefined ||
                          backup_enabled !== undefined;

  if (hasSiemFields && !hasPermission(req.adminUser, 'siem.configure')) {
    return res.status(403).json({ error: "Forbidden: Missing required permission 'siem.configure'" });
  }

  if (hasSystemFields && !hasPermission(req.adminUser, 'system.configure')) {
    return res.status(403).json({ error: "Forbidden: Missing required permission 'system.configure'" });
  }
  
  if (siem_webhook_url !== undefined) {
    const [config] = await SystemConfig.findOrCreate({ where: { key: 'siem_webhook_url' } });
    config.value = siem_webhook_url || "";
    await config.save();
  }

  if (siem_webhook_secret !== undefined) {
    const [config] = await SystemConfig.findOrCreate({ where: { key: 'siem_webhook_secret' } });
    config.value = siem_webhook_secret || "";
    await config.save();
  }

  if (audit_logging_enabled !== undefined) {
    const [config] = await SystemConfig.findOrCreate({ where: { key: 'audit_logging_enabled' } });
    config.value = String(audit_logging_enabled);
    await config.save();
  }

  if (backup_retention_limit !== undefined) {
    const [config] = await SystemConfig.findOrCreate({ where: { key: 'backup_retention_limit' } });
    config.value = String(backup_retention_limit);
    await config.save();
  }

  if (backup_enabled !== undefined) {
    const [config] = await SystemConfig.findOrCreate({ where: { key: 'backup_enabled' } });
    config.value = String(backup_enabled);
    await config.save();
  }

  const smtpFields = { smtp_host, smtp_port, smtp_username, smtp_password, smtp_sender };
  for (const [key, val] of Object.entries(smtpFields)) {
    if (val !== undefined) {
      const [config] = await SystemConfig.findOrCreate({ where: { key } });
      config.value = String(val) || "";
      await config.save();
    }
  }

  await addAuditLog(
    req.adminUser.username,
    JSON.stringify({
      action: "settings_updated",
      performedBy: req.adminUser.id,
      performedByUsername: req.adminUser.username
    })
  );
  res.json({ success: true });
});

// Maintenance API: Clear all stored file backups from disk and DB
app.post('/admin/api/maintenance/clear-backups', authMiddleware, requirePermission('system.configure'), async (req, res) => {
  try {
    const activeHolds = await VaultGroup.findAll({ where: { legal_hold_active: true } });
    const heldGroupIds = activeHolds.map(g => g.id);

    const list = await FileVersion.findAll();
    for (const f of list) {
      let isHeld = false;
      let profile = await ConnectionProfile.findByPk(f.connectionId);
      if (!profile) {
        profile = await ConnectionProfile.findOne({ where: { clientProfileId: f.connectionId } });
      }
      if (profile && heldGroupIds.includes(profile.groupId)) {
        isHeld = true;
      }
      if (isHeld) {
        continue;
      }

      if (f.backupPath && fs.existsSync(f.backupPath)) {
        try {
          fs.unlinkSync(f.backupPath);
        } catch (_) {}
      }
      await f.destroy();
    }
    
    // Clean up empty connection subdirectories
    const backupsDir = path.join(DATA_DIR, 'backups');
    if (fs.existsSync(backupsDir)) {
      try {
        const dirs = fs.readdirSync(backupsDir);
        for (const d of dirs) {
          const sub = path.join(backupsDir, d);
          if (fs.statSync(sub).isDirectory()) {
            fs.rmdirSync(sub);
          }
        }
      } catch (_) {}
    }

    await addAuditLog(
      req.adminUser.username,
      JSON.stringify({
        action: "backups_purged",
        performedBy: req.adminUser.id,
        performedByUsername: req.adminUser.username
      })
    );
    res.json({ success: true, message: "All stored file version backups have been deleted." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Maintenance API: Archive security audit logs older than cutoff_date
app.post('/admin/api/maintenance/clear-logs', authMiddleware, requirePermission('system.configure'), async (req, res) => {
  try {
    const { cutoff_date } = req.body;
    if (!cutoff_date) {
      return res.status(400).json({ error: "Missing cutoff_date parameter" });
    }
    const cutoff = new Date(cutoff_date);
    if (isNaN(cutoff.getTime())) {
      return res.status(400).json({ error: "Invalid cutoff_date format" });
    }

    const { Op } = require('sequelize');
    
    const activeHolds = await VaultGroup.findAll({ where: { legal_hold_active: true } });
    const heldGroupIds = activeHolds.map(g => g.id);
    const heldKeys = await AccessKey.findAll({ where: { groupId: { [Op.in]: heldGroupIds } } });
    const heldTokens = heldKeys.map(k => k.token_hash);

    const heldProfiles = await ConnectionProfile.findAll({ where: { groupId: { [Op.in]: heldGroupIds } } });
    const heldProfileIds = heldProfiles.map(p => p.id);

    const whereClause = {
      createdAt: { [Op.lt]: cutoff },
      archived: false,
      [Op.and]: [
        {
          metadata: {
            [Op.or]: [
              { [Op.eq]: null },
              { [Op.notLike]: '%legal_hold_%' }
            ]
          }
        }
      ]
    };

    if (heldTokens.length > 0) {
      whereClause[Op.and].push({
        token: { [Op.or]: [ { [Op.eq]: null }, { [Op.notIn]: heldTokens } ] }
      });
    }
    
    if (heldProfileIds.length > 0) {
      whereClause[Op.and].push({
        connectionId: { [Op.or]: [ { [Op.eq]: null }, { [Op.notIn]: heldProfileIds } ] }
      });
    }
    
    // Count how many we are archiving
    const count = await TransferLog.count({
      where: whereClause
    });

    // Update to archived
    await TransferLog.update(
      { archived: true },
      {
        where: whereClause
      }
    );

    // Create a new audit log entry recording this archiving action
    await addAuditLog(
      req.adminUser.username,
      JSON.stringify({
        action: "logs_archived",
        performedBy: req.adminUser.id,
        performedByUsername: req.adminUser.username,
        cutoffDate: cutoff.toISOString(),
        entriesArchived: count
      })
    );

    res.json({
      success: true,
      message: `Successfully archived ${count} logs older than ${cutoff.toLocaleDateString()}.`,
      archivedCount: count
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ── Audit Logs CSV/JSON Export Route ──────────────────────────────────
app.get('/admin/api/audit/export', authMiddleware, requirePermission('audit.export'), async (req, res) => {
  const format = req.query.format || 'json';
  const includeArchived = req.query.include_archived === 'true';
  const whereClause = includeArchived ? {} : { archived: false };
  
  const logs = await TransferLog.findAll({
    where: whereClause,
    order: [['createdAt', 'DESC']],
    limit: 500
  });

  const formattedLogs = formatLogsForExport(logs);

  if (format === 'csv') {
    let csv = 'Timestamp,Event Scope,Action Log,Result\n';
    formattedLogs.forEach(l => {
      const escapedAction = `"${l.action.replace(/"/g, '""')}"`;
      csv += `${l.timestamp},"${l.token_desc}",${escapedAction},${l.status}\n`;
    });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename=filepilot_audit_logs.csv');
    return res.send(csv);
  }
  
  res.json(formattedLogs);
});

function computeLogHash(log, expectedPrevHash) {
  let logFields;
  if (!log.hash_version || log.hash_version === 1) {
    logFields = {
      token: log.token || null,
      username: log.username || null,
      connectionId: log.connectionId,
      filePath: log.filePath,
      fileSize: log.fileSize ? parseInt(log.fileSize) : 0,
      action: log.action,
      status: log.status || 'success',
      errorMessage: log.metadata || log.errorMessage || null,
      prev_hash: expectedPrevHash
    };
  } else {
    logFields = {
      token: log.token || null,
      username: log.username || null,
      connectionId: log.connectionId,
      filePath: log.filePath,
      fileSize: log.fileSize ? parseInt(log.fileSize) : 0,
      action: log.action,
      status: log.status || 'success',
      errorMessage: log.errorMessage || null,
      metadata: log.metadata || null,
      prev_hash: expectedPrevHash
    };
  }
  const hashInput = JSON.stringify(logFields);
  return crypto.createHash('sha256').update(hashInput).digest('hex');
}

function formatLogsForExport(logs) {
  return logs.map(l => {
    let scopeDesc = l.username || 'System';
    if (l.token) {
      const displayToken = l.token.length > 8 ? `${l.token.substring(0, 8)}...` : l.token;
      if (l.username && l.username !== 'System' && l.username !== 'Anonymous Client') {
        scopeDesc = `${l.username} (${displayToken})`;
      } else {
        scopeDesc = displayToken;
      }
    }
    let actionDesc = l.errorMessage || '';
    const jsonStr = l.metadata || (l.errorMessage && l.errorMessage.startsWith('{') && l.errorMessage.endsWith('}') ? l.errorMessage : null);
    if (l.action === 'audit' && jsonStr) {
      try {
        const parsed = JSON.parse(jsonStr);
        if (parsed.action === 'logs_archived') {
          actionDesc = `Archived ${parsed.entriesArchived} logs older than ${new Date(parsed.cutoffDate).toLocaleDateString()} (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'kek_rotated') {
          actionDesc = `Rotated Vault KEK to version ${parsed.targetVersion} (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'user_created') {
          actionDesc = `Created user "${parsed.targetUser}" with role "${parsed.targetRole}" (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'user_updated') {
          actionDesc = `Updated user "${parsed.targetUser}" details (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'user_deleted') {
          actionDesc = `Deleted user "${parsed.targetUser}" (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'backups_purged') {
          actionDesc = `Purged all physical file backup versions and DB history (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'password_changed') {
          actionDesc = `Changed vault console password (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'settings_updated') {
          actionDesc = `Updated system settings (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'db_config_updated') {
          actionDesc = `Updated database configuration. Dialect set to ${parsed.dialect.toUpperCase()} (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'group_created') {
          actionDesc = `Created Vault Group "${parsed.groupName}" (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'group_updated') {
          actionDesc = `Updated Vault Group "${parsed.groupName}" details (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'group_deleted') {
          actionDesc = `Deleted Vault Group "${parsed.groupName}" (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'profile_created') {
          actionDesc = `Added profile "${parsed.profileName}" to group "${parsed.groupName}" (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'profile_updated') {
          actionDesc = `Updated profile "${parsed.profileName}" in group "${parsed.groupName}" (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'profile_deleted') {
          actionDesc = `Deleted profile "${parsed.profileName}" (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'token_issued') {
          actionDesc = `Issued Access Key for "${parsed.targetUser}" (Assigned: ${parsed.targetGroup}) (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'token_updated') {
          actionDesc = `Updated Access Key for "${parsed.targetUser}" (Performed by admin: ${parsed.performedByUsername})`;
        } else if (parsed.action === 'token_revoked') {
          actionDesc = `Revoked Access Key for "${parsed.tokenOwner}" (Performed by admin: ${parsed.performedByUsername})`;
        }
      } catch (e) {
        // fallback to raw errorMessage
      }
    } else if (l.action !== 'audit') {
      actionDesc = `${l.action.toUpperCase()}: ${l.filePath} (${l.status})${l.errorMessage ? ' - ' + l.errorMessage : ''}`;
    }
    return {
      timestamp: l.createdAt.toISOString(),
      token_desc: scopeDesc,
      action: actionDesc,
      status: l.status,
      archived: l.archived
    };
  });
}

// ── Audit Logs Integrity Chain Verification ──────────────────────────
app.get('/admin/api/audit/verify', authMiddleware, requirePermission('audit.export'), async (req, res) => {
  try {
    const logs = await TransferLog.findAll({ order: [['id', 'ASC']] });
    
    let expectedPrevHash = '0';
    for (const log of logs) {
      if (log.prev_hash !== expectedPrevHash) {
        return res.json({
          intact: false,
          brokenAtId: log.id,
          reason: `prev_hash mismatch. Expected: ${expectedPrevHash}, Actual: ${log.prev_hash}`
        });
      }

      const computedHash = computeLogHash(log, expectedPrevHash);
      
      if (log.entry_hash !== computedHash) {
        return res.json({
          intact: false,
          brokenAtId: log.id,
          reason: `entry_hash mismatch. Expected: ${computedHash}, Actual: ${log.entry_hash}`
        });
      }
      
      expectedPrevHash = computedHash;
    }
    
    res.json({ intact: true });
  } catch (err) {
    console.error("Audit log verification error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ── Full Audit Logs Chain Verification (Archived + Active) ───────────
app.get('/admin/api/audit/verify-full', authMiddleware, requirePermission('audit.export'), async (req, res) => {
  try {
    const logs = await TransferLog.findAll({ order: [['id', 'ASC']] });
    
    let expectedPrevHash = '0';
    let activeCount = 0;
    let archivedCount = 0;

    for (const log of logs) {
      if (log.prev_hash !== expectedPrevHash) {
        return res.json({
          intact: false,
          brokenAtId: log.id,
          reason: `prev_hash mismatch. Expected: ${expectedPrevHash}, Actual: ${log.prev_hash}`
        });
      }

      const computedHash = computeLogHash(log, expectedPrevHash);

      if (log.entry_hash !== computedHash) {
        return res.json({
          intact: false,
          brokenAtId: log.id,
          reason: `entry_hash mismatch. Computed: ${computedHash}, Actual: ${log.entry_hash}`
        });
      }

      if (log.archived) {
        archivedCount++;
      } else {
        activeCount++;
      }
      expectedPrevHash = computedHash;
    }

    res.json({
      intact: true,
      activeCount,
      archivedCount,
      totalCount: logs.length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── User Management CRUD ──────────────────────────────────────────────
app.get('/admin/api/users', authMiddleware, requirePermission('user.view'), async (req, res) => {
  const users = await User.findAll({
    attributes: ['id', 'username', 'role', 'mfa_enabled', 'createdAt']
  });
  res.json(users);
});

app.post('/admin/api/users', authMiddleware, requirePermission('user.manage'), async (req, res) => {
  const { id, username, password, role } = req.body;
  if (!username) {
    return res.status(400).json({ error: "Username is required" });
  }

  if (!id) {
    // Create new user
    if (!password) {
      return res.status(400).json({ error: "Password is required for new users" });
    }
    const hash = crypto.createHash('sha256').update(password).digest('hex');
    try {
      const newUser = await User.create({
        username,
        passwordHash: hash,
        role: role || 'operator'
      });
      await addAuditLog(
        req.adminUser.username,
        JSON.stringify({
          action: "user_created",
          performedBy: req.adminUser.id,
          performedByUsername: req.adminUser.username,
          targetUser: username,
          targetRole: role
        })
      );
      res.json({ success: true, user: { id: newUser.id, username: newUser.username, role: newUser.role } });
    } catch (e) {
      res.status(400).json({ error: "Username already exists" });
    }
  } else {
    // Edit existing user
    const user = await User.findByPk(id);
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    user.username = username;
    user.role = role || user.role;
    if (password) {
      user.passwordHash = crypto.createHash('sha256').update(password).digest('hex');
    }
    await user.save();
    await addAuditLog(
      req.adminUser.username,
      JSON.stringify({
        action: "user_updated",
        performedBy: req.adminUser.id,
        performedByUsername: req.adminUser.username,
        targetUser: username
      })
    );
    res.json({ success: true });
  }
});

app.delete('/admin/api/users/:id', authMiddleware, requirePermission('user.manage'), async (req, res) => {
  const user = await User.findByPk(req.params.id);
  if (user) {
    if (user.username === 'admin') {
      return res.status(400).json({ error: "Cannot delete master administrator user" });
    }
    const username = user.username;
    await user.destroy();
    await addAuditLog(
      req.adminUser.username,
      JSON.stringify({
        action: "user_deleted",
        performedBy: req.adminUser.id,
        performedByUsername: req.adminUser.username,
        targetUser: username
      })
    );
    res.json({ success: true });
  } else {
    res.status(404).json({ error: "User not found" });
  }
});

// User-Agent parser helper for sessions friendly labels
function parseUserAgent(ua) {
  if (!ua) return 'Unknown Device';
  
  let browser = 'Unknown Browser';
  let os = 'Unknown OS';
  
  if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Macintosh') || ua.includes('Mac OS')) os = 'macOS';
  else if (ua.includes('Linux')) os = 'Linux';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
  
  if (ua.includes('Firefox')) browser = 'Firefox';
  else if (ua.includes('Edg')) browser = 'Microsoft Edge';
  else if (ua.includes('Chrome')) browser = 'Chrome';
  else if (ua.includes('Safari')) browser = 'Safari';
  else if (ua.includes('Postman')) browser = 'Postman';
  
  return `${browser} on ${os}`;
}

// ── Session & Device Management API Endpoints ────────────────────────
app.get('/admin/api/sessions', authMiddleware, async (req, res) => {
  try {
    const sessionsList = await AdminSession.findAll({
      where: { userId: req.adminUser.id },
      order: [['createdAt', 'DESC']]
    });
    
    const result = sessionsList.map(s => ({
      id: s.id,
      ipAddress: s.ipAddress,
      userAgent: parseUserAgent(s.userAgent),
      createdAt: s.createdAt,
      lastActivityAt: s.lastActivityAt,
      isCurrent: s.id === req.sessionId
    }));
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/admin/api/sessions/all', authMiddleware, requirePermission('user.manage'), async (req, res) => {
  try {
    const sessionsList = await AdminSession.findAll({
      include: [User],
      order: [['createdAt', 'DESC']]
    });
    
    const result = sessionsList.map(s => ({
      id: s.id,
      username: s.User ? s.User.username : 'Unknown',
      ipAddress: s.ipAddress,
      userAgent: parseUserAgent(s.userAgent),
      createdAt: s.createdAt,
      lastActivityAt: s.lastActivityAt,
      isCurrent: s.id === req.sessionId
    }));
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/admin/api/sessions/:id', authMiddleware, async (req, res) => {
  try {
    const session = await AdminSession.findByPk(req.params.id);
    if (!session) {
      return res.status(404).json({ error: "Session not found" });
    }
    
    const isOwner = session.userId === req.adminUser.id;
    if (!isOwner && !hasPermission(req.adminUser, 'user.manage')) {
      return res.status(403).json({ error: "Forbidden: Missing user.manage permission to revoke other users' sessions" });
    }
    
    await session.destroy();
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/api/sessions/revoke-others', authMiddleware, async (req, res) => {
  try {
    const { Op } = require('sequelize');
    const deletedCount = await AdminSession.destroy({
      where: {
        userId: req.adminUser.id,
        id: {
          [Op.ne]: req.sessionId
        }
      }
    });
    res.json({ success: true, revokedCount: deletedCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Enterprise Client Connection Session Management Endpoints ────────
app.get('/admin/api/client-connections', authMiddleware, requirePermission('user.view'), async (req, res) => {
  try {
    const list = [];
    for (const [tokenHash, ws] of clients.entries()) {
      if (ws.clientConnection) {
        const key = await AccessKey.findByPk(tokenHash, { include: [User, VaultGroup] });
        list.push({
          tokenHash,
          username: key && key.User ? key.User.username : 'Unknown',
          groupName: key && key.VaultGroup ? key.VaultGroup.name : 'Unknown',
          connection: ws.clientConnection
        });
      }
    }
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/admin/api/client-connections/disconnect', authMiddleware, requirePermission('user.manage'), async (req, res) => {
  try {
    const { tokenHash } = req.body;
    const ws = clients.get(tokenHash);
    if (ws) {
      console.log(`[WS] Terminating client session for token: ${tokenHash}`);
      ws.send(JSON.stringify({ type: "force_disconnect" }));
      res.json({ success: true });
    } else {
      res.status(404).json({ error: "Active client connection not found" });
    }
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});


// ── Master KEK Rotation ──────────────────────────────────────────────
app.post('/admin/api/system/rotate-kek', authMiddleware, requirePermission('system.configure'), async (req, res) => {
  try {
    const { new_kek } = req.body;
    const { Op } = require('sequelize');

    const activeVersion = await KeyVersion.max('version') || 1;
    const pendingGroups = await VaultGroup.findAll({
      where: {
        dek_version: { [Op.lt]: activeVersion }
      }
    });

    let targetVersion;
    let targetKekBuffer;
    let resolvedNewKekHex = '';

    if (pendingGroups.length > 0) {
      console.log(`[KEK Rotation] Resuming interrupted rotation for ${pendingGroups.length} VaultGroups to KEK version ${activeVersion}...`);
      targetVersion = activeVersion;
      targetKekBuffer = encryptionKey;
    } else {
      // Start a new rotation
      targetVersion = activeVersion + 1;
      const generatedKey = crypto.randomBytes(32).toString('hex');
      resolvedNewKekHex = new_kek || generatedKey;

      if (resolvedNewKekHex.length === 64 && /^[0-9a-fA-F]+$/.test(resolvedNewKekHex)) {
        targetKekBuffer = Buffer.from(resolvedNewKekHex, 'hex');
      } else if (resolvedNewKekHex.length === 44 && /^[0-9a-zA-Z+/=]+$/.test(resolvedNewKekHex)) {
        targetKekBuffer = Buffer.from(resolvedNewKekHex, 'base64');
      } else {
        targetKekBuffer = Buffer.from(resolvedNewKekHex, 'utf8');
      }

      // Idempotent insertion of KeyVersion
      await KeyVersion.findOrCreate({
        where: { version: targetVersion },
        defaults: { createdAt: new Date() }
      });
    }

    const groups = await VaultGroup.findAll();
    console.log(`[KEK Rotation] Rotating VaultGroups to KEK version ${targetVersion}...`);

    for (const group of groups) {
      if (group.dek_version === targetVersion) {
        continue; // Already processed
      }

      // Unwrap DEK using the group's current KEK version
      const dek = await getGroupDek(group);

      // Re-wrap DEK using the target KEK
      const newWrappedDek = wrapDek(dek, targetKekBuffer);

      group.wrapped_dek = newWrappedDek;
      group.dek_version = targetVersion;
      await group.save();
    }

    if (targetVersion > activeVersion) {
      // Cache the old key under activeVersion before overwriting encryptionKey
      const oldKek = await getKekByVersion(activeVersion);
      kekCache.set(activeVersion, oldKek);

      // Retire the previous KEK version
      await KeyVersion.update(
        { retiredAt: new Date() },
        { where: { version: activeVersion } }
      );

      // Update in-memory active key and cache
      encryptionKey = targetKekBuffer;
      kekCache.set(targetVersion, targetKekBuffer);
    }

    await addAuditLog(
      req.adminUser.username,
      JSON.stringify({
        action: "kek_rotated",
        performedBy: req.adminUser.id,
        performedByUsername: req.adminUser.username,
        targetVersion: targetVersion
      })
    );

    res.json({
      success: true,
      new_kek: resolvedNewKekHex,
      new_version: targetVersion,
      instructions: "Rotation successful. Please update your environment variables: set 'VAULT_MASTER_KEY' to the new key value, set 'VAULT_MASTER_KEY_PREVIOUS' to your old master key, and restart the server process. Once validated, you can safely remove 'VAULT_MASTER_KEY_PREVIOUS'."
    });
  } catch (err) {
    console.error("KEK Rotation failed:", err);
    res.status(500).json({ error: "KEK Rotation failed: " + err.message });
  }
});

// ── Database Configuration Update ────────────────────────────────────
app.post('/admin/api/config/db', authMiddleware, requirePermission('system.configure'), async (req, res) => {
  const { dialect, host, port, username, password, database, storage, ssl } = req.body;
  if (!dialect) {
    return res.status(400).json({ error: "Missing database dialect" });
  }

  let defaultPort = 5432;
  let defaultUsername = '';
  let defaultDatabase = 'vault';
  if (dialect === 'mysql') {
    defaultPort = 3306;
    defaultUsername = 'root';
    defaultDatabase = 'filepilotenterprise';
  } else if (dialect === 'postgres') {
    defaultPort = 5432;
    defaultUsername = 'postgres';
    defaultDatabase = 'vault';
  }

  const currentMasterKey = process.env.VAULT_MASTER_KEY || '';

  const envContent = [
    `# FilePilot Corporate Vault Environment Configuration`,
    `VAULT_MASTER_KEY=${currentMasterKey}`,
    `DB_DIALECT=${dialect}`,
    `DB_HOST=${host || 'localhost'}`,
    `DB_PORT=${port ? parseInt(port) : defaultPort}`,
    `DB_USERNAME=${username || ''}`,
    `DB_PASSWORD=${password || ''}`,
    `DB_NAME=${database || defaultDatabase}`,
    `DB_STORAGE=${storage || path.join(DATA_DIR, 'vault.db')}`,
    `DB_SSL=${ssl ? 'true' : 'false'}`
  ].join('\n');

  const envFilePath = path.join(DATA_DIR, '.env');
  fs.writeFileSync(envFilePath, envContent, 'utf8');

  // Clean up legacy files to avoid confusion
  if (fs.existsSync(configPath)) {
    try { fs.unlinkSync(configPath); } catch (_) {}
  }
  await addAuditLog(
    req.adminUser.username,
    JSON.stringify({
      action: "db_config_updated",
      performedBy: req.adminUser.id,
      performedByUsername: req.adminUser.username,
      dialect: dialect
    })
  );
  
  res.json({ success: true, message: "Database config saved. Please restart the vault server to apply settings." });
});

// Get current user profile and permissions
app.get('/admin/api/me', authMiddleware, (req, res) => {
  const role = req.adminUser.role.toLowerCase();
  const allPermissionsList = [
    'vault.view_groups', 'vault.manage_groups',
    'profile.view', 'profile.create', 'profile.edit', 'profile.delete', 'profile.decrypt_credentials', 'profile.test_connection',
    'token.view', 'token.issue', 'token.revoke',
    'user.view', 'user.manage',
    'audit.view', 'audit.export',
    'backup.view', 'backup.restore',
    'siem.configure', 'system.configure', 'system.view_dashboard',
    'legal_hold.manage'
  ];

  res.json({
    username: req.adminUser.username,
    role: req.adminUser.role,
    mfa_enabled: req.adminUser.mfa_enabled,
    permissions: role === 'admin'
      ? allPermissionsList
      : ROLE_PERMISSIONS[role] || []
  });
});

// ── Groups Administration API ──────────────────────────────────────
app.get('/admin/api/state', authMiddleware, async (req, res) => {
  const siemConfig = await SystemConfig.findOne({ where: { key: 'siem_webhook_url' } });
  const auditConfig = await SystemConfig.findOne({ where: { key: 'audit_logging_enabled' } });
  const keyVersions = await KeyVersion.findAll({ order: [['version', 'ASC']] });
  
  const groups = await VaultGroup.findAll({
    include: [ConnectionProfile]
  });
  
  const hasDecryptPermission = hasPermission(req.adminUser, 'profile.decrypt_credentials');

  const stateGroups = [];
  for (const g of groups) {
    const groupJson = g.toJSON();
    let dek = null;
    let dekError = false;
    try {
      dek = await getGroupDek(g);
    } catch (err) {
      console.error(`Failed to load DEK for group ${g.name}:`, err.message);
      dekError = true;
    }
    const profiles = [];
    for (const p of (groupJson.ConnectionProfiles || [])) {
      let decryptedPass = '';
      if (!dekError && p.passwordEncrypted) {
        decryptedPass = decrypt(p.passwordEncrypted, dek);
      } else if (dekError) {
        decryptedPass = '[Decryption Error]';
      }
      let decryptedKey = '';
      if (p.authMode === 'keypair') {
        decryptedKey = decryptedPass;
        decryptedPass = '';
      }
      profiles.push({
        id: p.id,
        name: p.name,
        protocol: p.protocol,
        host: p.host,
        port: p.port,
        username: p.username,
        password: hasDecryptPermission ? decryptedPass : '********',
        options: p.authMode === 'keypair' ? { private_key: hasDecryptPermission ? decryptedKey : '********' } : {}
      });
    }
    let maskedCredentials = {};
    if (g.kms_credentials_encrypted) {
      try {
        const decryptedCreds = decryptKmsCredentials(g.kms_credentials_encrypted);
        for (const keyName in decryptedCreds) {
          maskedCredentials[keyName] = '********';
        }
      } catch (err) {}
    }
    stateGroups.push({
      id: groupJson.id,
      name: groupJson.name,
      status: 'active',
      ip_allowlist: groupJson.ipAllowlist || '',
      wrapped_dek: groupJson.wrapped_dek,
      dek_version: groupJson.dek_version || 1,
      kms_provider: groupJson.kms_provider || 'local',
      kms_config: groupJson.kms_config || '{}',
      kms_credentials: maskedCredentials,
      legal_hold_active: groupJson.legal_hold_active,
      legal_hold_reason: groupJson.legal_hold_reason,
      legal_hold_placed_by: groupJson.legal_hold_placed_by,
      legal_hold_placed_at: groupJson.legal_hold_placed_at,
      legal_hold_freeze_writes: groupJson.legal_hold_freeze_writes,
      profiles
    });
  }

  const tokens = await AccessKey.findAll({
    include: [User]
  });
  const stateTokens = tokens.map(t => ({
    token_hash: t.token_hash,
    token_display: t.token_hash.substring(0, 8) + '...',
    user: t.User ? t.User.username : 'Master Token',
    groupId: t.groupId,
    status: t.status,
    expires_at: t.expiresAt || ''
  }));

  const hasUserView = hasPermission(req.adminUser, 'user.view');
  const users = await User.findAll({
    attributes: hasUserView
      ? ['id', 'username', 'role', 'mfa_enabled', 'createdAt']
      : ['id', 'username', 'role', 'createdAt']
  });

  let configJson = {
    database: {
      dialect: process.env.DB_DIALECT || 'sqlite',
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT ? parseInt(process.env.DB_PORT) || '' : '',
      username: process.env.DB_USERNAME || '',
      database: process.env.DB_NAME || '',
      storage: process.env.DB_STORAGE || '',
      ssl: process.env.DB_SSL === 'true'
    }
  };
  if (fs.existsSync(configPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      if (parsed && parsed.database) {
        configJson.database = { ...configJson.database, ...parsed.database };
      }
    } catch {}
  }

  const totalVersionsCount = await FileVersion.count();
  const totalVersionsSize = (await FileVersion.sum('size')) || 0;
  const recentLogs = await TransferLog.findAll({
    where: { archived: false },
    order: [['createdAt', 'DESC']],
    limit: 5
  });

  const smtpHostConfig = await SystemConfig.findOne({ where: { key: 'smtp_host' } });
  const smtpPortConfig = await SystemConfig.findOne({ where: { key: 'smtp_port' } });
  const smtpUsernameConfig = await SystemConfig.findOne({ where: { key: 'smtp_username' } });
  const smtpPasswordConfig = await SystemConfig.findOne({ where: { key: 'smtp_password' } });
  const smtpSenderConfig = await SystemConfig.findOne({ where: { key: 'smtp_sender' } });

  const backupLimitConfig = await SystemConfig.findOne({ where: { key: 'backup_retention_limit' } });
  const backupEnabledConfig = await SystemConfig.findOne({ where: { key: 'backup_enabled' } });

  const allPermissionsList = [
    'vault.view_groups', 'vault.manage_groups',
    'profile.view', 'profile.create', 'profile.edit', 'profile.delete', 'profile.decrypt_credentials', 'profile.test_connection',
    'token.view', 'token.issue', 'token.revoke',
    'user.view', 'user.manage',
    'audit.view', 'audit.export',
    'backup.view', 'backup.restore',
    'siem.configure', 'system.configure', 'system.view_dashboard',
    'legal_hold.manage'
  ];

  res.json({
    currentUser: {
      username: req.adminUser.username,
      role: req.adminUser.role,
      permissions: req.adminUser.role.toLowerCase() === 'admin'
        ? allPermissionsList
        : ROLE_PERMISSIONS[req.adminUser.role.toLowerCase()] || []
    },
    siem_webhook_url: siemConfig ? siemConfig.value : '',
    audit_logging_enabled: auditConfig ? auditConfig.value === 'true' : true,
    groups: stateGroups,
    tokens: stateTokens,
    users,
    database: configJson.database,
    activeSocketsCount: clients.size,
    databaseDialect: sequelize.options.dialect || 'sqlite',
    totalVersionsCount,
    totalVersionsSize,
    recentLogs,
    smtp_host: smtpHostConfig ? smtpHostConfig.value : '',
    smtp_port: smtpPortConfig ? parseInt(smtpPortConfig.value) || 25 : 25,
    smtp_username: smtpUsernameConfig ? smtpUsernameConfig.value : '',
    smtp_password: hasPermission(req.adminUser, 'system.configure') ? (smtpPasswordConfig ? smtpPasswordConfig.value : '') : '********',
    smtp_sender: smtpSenderConfig ? smtpSenderConfig.value : '',
    backup_retention_limit: backupLimitConfig ? parseInt(backupLimitConfig.value) || 10 : 10,
    backup_enabled: backupEnabledConfig ? backupEnabledConfig.value === 'true' : true,
    keyVersions
  });
});

app.post('/admin/api/groups', authMiddleware, requirePermission('vault.manage_groups'), async (req, res) => {
  const group = req.body;
  if (!group.name) {
    return res.status(400).json({ error: "Missing group name" });
  }
  
  if (!group.id) {
    const newId = 'g_' + Math.random().toString(36).substring(2, 9);
    const dek = crypto.randomBytes(32);
    const activeVersion = await KeyVersion.max('version') || 1;
    const activeKek = await getKekByVersion(activeVersion);
    const wrappedDek = wrapDek(dek, activeKek);

    await VaultGroup.create({
      id: newId,
      name: group.name,
      ipAllowlist: group.ip_allowlist || '',
      wrapped_dek: wrappedDek,
      dek_version: activeVersion,
      migrated: true
    });
    await addAuditLog(
      req.adminUser.username,
      JSON.stringify({
        action: "group_created",
        performedBy: req.adminUser.id,
        performedByUsername: req.adminUser.username,
        groupName: group.name
      })
    );
  } else {
    const g = await VaultGroup.findByPk(group.id);
    if (g) {
      g.name = group.name;
      g.ipAllowlist = group.ip_allowlist || '';
      await g.save();
      await addAuditLog(
        req.adminUser.username,
        JSON.stringify({
          action: "group_updated",
          performedBy: req.adminUser.id,
          performedByUsername: req.adminUser.username,
          groupName: group.name
        })
      );
    } else {
      return res.status(404).json({ error: "Group not found" });
    }
  }
  res.json({ success: true });
});

app.delete('/admin/api/groups/:id', authMiddleware, requirePermission('vault.manage_groups'), async (req, res) => {
  const id = req.params.id;
  const g = await VaultGroup.findByPk(id);
  if (g) {
    if (g.legal_hold_active) {
      return res.status(403).json({ error: "Cannot delete Group: Vault Group is under active Legal Hold" });
    }
    const groupName = g.name;
    await g.destroy();
    notifyGroupRevocation(id);
    await addAuditLog(
      req.adminUser.username,
      JSON.stringify({
        action: "group_deleted",
        performedBy: req.adminUser.id,
        performedByUsername: req.adminUser.username,
        groupName: groupName
      })
    );
    res.json({ success: true });
  } else {
    res.status(404).json({ error: "Group not found" });
  }
});

app.post('/admin/api/groups/:id/legal-hold', authMiddleware, requirePermission('legal_hold.manage'), async (req, res) => {
  const { id } = req.params;
  const { reason, freeze_writes } = req.body;
  if (!reason || reason.trim() === '') {
    return res.status(400).json({ error: "Missing required reason parameter" });
  }

  const group = await VaultGroup.findByPk(id);
  if (!group) {
    return res.status(404).json({ error: "Group not found" });
  }

  group.legal_hold_active = true;
  group.legal_hold_reason = reason;
  group.legal_hold_placed_by = req.adminUser.username;
  group.legal_hold_placed_at = new Date();
  group.legal_hold_freeze_writes = !!freeze_writes;
  await group.save();

  await addAuditLog(
    req.adminUser.username,
    JSON.stringify({
      action: "legal_hold_placed",
      performedBy: req.adminUser.id,
      performedByUsername: req.adminUser.username,
      groupId: id,
      groupName: group.name,
      reason: reason,
      freezeWrites: !!freeze_writes
    })
  );

  // Disconnect active client connections for this group in real time!
  try {
    const keys = await AccessKey.findAll({ where: { groupId: id } });
    const tokenHashes = keys.map(k => k.token_hash);
    for (const tokenHash of tokenHashes) {
      const ws = clients.get(tokenHash);
      if (ws) {
        console.log(`[WS] Terminating client session for token ${tokenHash} due to Legal Hold on group ${id}`);
        try {
          ws.send(JSON.stringify({ type: "access_suspended" }));
          ws.close();
        } catch (_) {}
      }
    }
  } catch (err) {
    console.error("Error disconnecting client sessions on legal hold placement:", err);
  }

  res.json({ success: true, message: "Legal Hold placed successfully." });
});

app.delete('/admin/api/groups/:id/legal-hold', authMiddleware, requirePermission('legal_hold.manage'), async (req, res) => {
  const { id } = req.params;
  const { reason } = req.body;
  if (!reason || reason.trim() === '') {
    return res.status(400).json({ error: "Missing required reason parameter for lifting hold" });
  }

  const group = await VaultGroup.findByPk(id);
  if (!group) {
    return res.status(404).json({ error: "Group not found" });
  }

  group.legal_hold_active = false;
  group.legal_hold_reason = null;
  group.legal_hold_placed_by = null;
  group.legal_hold_placed_at = null;
  group.legal_hold_freeze_writes = false;
  await group.save();

  await addAuditLog(
    req.adminUser.username,
    JSON.stringify({
      action: "legal_hold_lifted",
      performedBy: req.adminUser.id,
      performedByUsername: req.adminUser.username,
      groupId: id,
      groupName: group.name,
      reason: reason
    })
  );

  // Notify active clients that hold is lifted and access is restored!
  try {
    const keys = await AccessKey.findAll({ where: { groupId: id } });
    const tokenHashes = keys.map(k => k.token_hash);
    for (const tokenHash of tokenHashes) {
      const ws = clients.get(tokenHash);
      if (ws) {
        try {
          ws.send(JSON.stringify({ type: "access_restored" }));
        } catch (_) {}
      }
    }
  } catch (err) {
    console.error("Error notifying clients on legal hold lifting:", err);
  }

  res.json({ success: true, message: "Legal Hold lifted successfully." });
});

app.post('/admin/api/groups/:id/kms/test', authMiddleware, requirePermission('system.configure'), async (req, res) => {
  const { id } = req.params;
  const { kms_provider, kms_config, kms_credentials } = req.body;
  
  const group = await VaultGroup.findByPk(id);
  if (!group) {
    return res.status(404).json({ error: "Group not found" });
  }

  const provider = kmsProviders.providers[kms_provider];
  if (!provider) {
    return res.status(400).json({ error: `Unsupported KMS provider: ${kms_provider}` });
  }

  let currentCreds = {};
  if (group.kms_credentials_encrypted) {
    currentCreds = decryptKmsCredentials(group.kms_credentials_encrypted);
  }
  const mergedCreds = { ...currentCreds };
  if (kms_credentials && typeof kms_credentials === 'object') {
    for (const key in kms_credentials) {
      if (kms_credentials[key] !== '********') {
        mergedCreds[key] = kms_credentials[key];
      }
    }
  }

  let testConfig = { ...(kms_config || {}), ...mergedCreds };
  if (kms_provider === 'local') {
    const version = group.dek_version || 1;
    const kek = await getKekByVersion(version);
    testConfig = { kek };
  }

  try {
    await provider.testConnection(testConfig);
    res.json({ success: true, message: "KMS connection test succeeded!" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/admin/api/groups/:id/kms', authMiddleware, requirePermission('system.configure'), async (req, res) => {
  const { id } = req.params;
  const { kms_provider, kms_config, kms_credentials } = req.body;
  
  const group = await VaultGroup.findByPk(id);
  if (!group) {
    return res.status(404).json({ error: "Group not found" });
  }

  const provider = kmsProviders.providers[kms_provider];
  if (!provider) {
    return res.status(400).json({ error: `Unsupported KMS provider: ${kms_provider}` });
  }

  let currentCreds = {};
  if (group.kms_credentials_encrypted) {
    currentCreds = decryptKmsCredentials(group.kms_credentials_encrypted);
  }
  const mergedCreds = { ...currentCreds };
  if (kms_credentials && typeof kms_credentials === 'object') {
    for (const key in kms_credentials) {
      if (kms_credentials[key] !== '********') {
        mergedCreds[key] = kms_credentials[key];
      }
    }
  }

  let testConfig = { ...(kms_config || {}), ...mergedCreds };
  if (kms_provider === 'local') {
    const version = group.dek_version || 1;
    const kek = await getKekByVersion(version);
    testConfig = { kek };
  }

  try {
    await provider.testConnection(testConfig);
    const rawDek = await getGroupDek(group);
    const wrappedDek = await provider.wrapDek(testConfig, rawDek);
    
    group.kms_provider = kms_provider;
    group.kms_config = JSON.stringify(kms_config || {});
    group.kms_credentials_encrypted = encryptKmsCredentials(mergedCreds);
    group.wrapped_dek = wrappedDek;
    await group.save();

    await addAuditLog(
      req.adminUser.username,
      JSON.stringify({
        action: "kms_updated",
        performedBy: req.adminUser.id,
        performedByUsername: req.adminUser.username,
        groupId: group.id,
        groupName: group.name,
        kms_provider: kms_provider
      })
    );

    res.json({ success: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/admin/api/groups/:groupId/profiles', authMiddleware, async (req, res) => {
  const groupId = req.params.groupId;
  const profile = req.body;

  if (!profile.id) {
    if (!hasPermission(req.adminUser, 'profile.create')) {
      return res.status(403).json({ error: "Forbidden: Missing required permission 'profile.create'" });
    }
  } else {
    if (!hasPermission(req.adminUser, 'profile.edit')) {
      return res.status(403).json({ error: "Forbidden: Missing required permission 'profile.edit'" });
    }
  }
  
  if (!profile.name || !profile.host || !profile.protocol) {
    return res.status(400).json({ error: "Missing required profile fields" });
  }
  
  const g = await VaultGroup.findByPk(groupId);
  if (!g) {
    return res.status(404).json({ error: "Vault Group not found" });
  }
  if (g.legal_hold_active && g.legal_hold_freeze_writes) {
    return res.status(403).json({ error: "Cannot create/modify profiles: Vault Group writes are frozen under active Legal Hold" });
  }
  
  try {
    const dek = await getGroupDek(g);

    let keyVal = profile.password || '';
    if (profile.options && profile.options.private_key) {
      keyVal = profile.options.private_key;
    }
    const encryptedKey = (keyVal && keyVal !== '********') ? encrypt(keyVal, dek) : '';

    const jumpHost = profile.options && profile.options.jump_host ? profile.options.jump_host : null;
    const jumpPort = profile.options && profile.options.jump_port ? parseInt(profile.options.jump_port) || 22 : null;
    const jumpUsername = profile.options && profile.options.jump_username ? profile.options.jump_username : null;
    const jumpAuthMode = profile.options && profile.options.jump_auth_mode ? profile.options.jump_auth_mode : 'password';

    let jumpKeyVal = '';
    if (profile.options) {
      if (jumpAuthMode === 'keypair' && profile.options.jump_private_key) {
        jumpKeyVal = profile.options.jump_private_key;
      } else if (profile.options.jump_password) {
        jumpKeyVal = profile.options.jump_password;
      }
    }
    const encryptedJumpKey = (jumpKeyVal && jumpKeyVal !== '********') ? encrypt(jumpKeyVal, dek) : '';

    if (!profile.id) {
      const newId = 'p_' + Math.random().toString(36).substring(2, 9);
      await ConnectionProfile.create({
        id: newId,
        groupId,
        name: profile.name,
        protocol: profile.protocol,
        host: profile.host,
        port: parseInt(profile.port) || 22,
        username: profile.username,
        passwordEncrypted: encryptedKey,
        authMode: profile.options && profile.options.private_key ? 'keypair' : 'password',
        jumpHost,
        jumpPort,
        jumpUsername,
        jumpPasswordEncrypted: encryptedJumpKey,
        jumpAuthMode
      });
      await addAuditLog(
        req.adminUser.username,
        JSON.stringify({
          action: "profile_created",
          performedBy: req.adminUser.id,
          performedByUsername: req.adminUser.username,
          profileName: profile.name,
          groupName: g.name
        })
      );
    } else {
      const p = await ConnectionProfile.findByPk(profile.id);
      if (p) {
        p.name = profile.name;
        p.protocol = profile.protocol;
        p.host = profile.host;
        p.port = parseInt(profile.port) || 22;
        p.username = profile.username;
        p.passwordEncrypted = encryptedKey || p.passwordEncrypted;
        p.authMode = profile.options && profile.options.private_key ? 'keypair' : 'password';
        
        p.jumpHost = jumpHost;
        p.jumpPort = jumpPort;
        p.jumpUsername = jumpUsername;
        p.jumpAuthMode = jumpAuthMode;
        p.jumpPasswordEncrypted = encryptedJumpKey || p.jumpPasswordEncrypted;
        
        await p.save();
        await addAuditLog(
          req.adminUser.username,
          JSON.stringify({
            action: "profile_updated",
            performedBy: req.adminUser.id,
            performedByUsername: req.adminUser.username,
            profileName: profile.name,
            groupName: g.name
          })
        );
      } else {
        await ConnectionProfile.create({
          id: profile.id,
          groupId,
          name: profile.name,
          protocol: profile.protocol,
          host: profile.host,
          port: parseInt(profile.port) || 22,
          username: profile.username,
          passwordEncrypted: encryptedKey,
          authMode: profile.options && profile.options.private_key ? 'keypair' : 'password',
          jumpHost,
          jumpPort,
          jumpUsername,
          jumpPasswordEncrypted: encryptedJumpKey,
          jumpAuthMode
        });
        await addAuditLog(
          req.adminUser.username,
          JSON.stringify({
            action: "profile_created",
            performedBy: req.adminUser.id,
            performedByUsername: req.adminUser.username,
            profileName: profile.name,
            groupName: g.name
          })
        );
      }
    }
    res.json({ success: true });
  } catch (err) {
    console.error("Profile save failed:", err);
    res.status(500).json({ error: `Failed to save profile: ${err.message}` });
  }
});

// Connection Testing API Endpoint
app.post('/admin/api/profiles/test-connection', authMiddleware, requirePermission('profile.test_connection'), async (req, res) => {
  const { profileId } = req.body;
  
  if (!profileId) {
    return res.status(400).json({ error: "Missing target profile ID" });
  }

  const profile = await ConnectionProfile.findByPk(profileId);
  if (!profile) {
    return res.status(404).json({ error: "Connection profile not found" });
  }

  const host = profile.host;
  const port = profile.port || 22;
  const protocol = profile.protocol || 'sftp';

  const logs = [];
  const log = (msg) => {
    const timestamp = new Date().toLocaleTimeString();
    logs.push(`[${timestamp}] ${msg}`);
  };

  log(`[SYSTEM] Starting connectivity test for profile "${profile.name}" (${protocol.toUpperCase()})`);
  log(`[DNS] Resolving address for target host "${host}"...`);

  // Check if private targets are allowed
  let allowPrivateTargets = false;
  if (process.env.ALLOW_PRIVATE_TARGETS === 'true') {
    allowPrivateTargets = true;
  }
  if (fs.existsSync(configPath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(configPath, 'utf8'));
      if (parsed.allowPrivateTargets === true) {
        allowPrivateTargets = true;
      }
    } catch {}
  }
  try {
    const dbConfigVal = await SystemConfig.findOne({ where: { key: 'allow_private_targets' } });
    if (dbConfigVal && dbConfigVal.value === 'true') {
      allowPrivateTargets = true;
    }
  } catch {}

  if (!allowPrivateTargets) {
    const isPrivate = await isHostPrivate(host);
    if (isPrivate) {
      log(`[SECURITY ERROR] Connection to private/local target "${host}" was blocked to prevent SSRF.`);
      return res.status(403).json({ 
        success: false, 
        error: "Forbidden: Connection to private/local targets is disabled.",
        logs
      });
    }
  }

  const net = require('net');
  const targetPort = parseInt(port) || 22;
  const targetHost = host.trim();
  
  log(`[TCP] Opening connection to ${targetHost}:${targetPort}...`);
  
  const startTime = Date.now();
  const socket = new net.Socket();
  let completed = false;

  const cleanup = () => {
    if (!socket.destroyed) {
      try {
        socket.destroy();
      } catch (_) {}
    }
  };

  const promise = new Promise((resolve) => {
    socket.setTimeout(5000); // 5 seconds timeout

    socket.connect(targetPort, targetHost, () => {
      const elapsed = Date.now() - startTime;
      log(`[TCP] Connection established successfully in ${elapsed}ms.`);
      
      if (['sftp', 'ssh', 'ftp'].includes(protocol.toLowerCase())) {
        log(`[PROTOCOL] Connection open. Waiting for protocol greeting banner...`);
      } else {
        completed = true;
        log(`[SYSTEM] Connectivity check completed successfully.`);
        cleanup();
        resolve({ success: true });
      }
    });

    socket.on('data', (data) => {
      if (completed) return;
      const banner = data.toString('utf8').trim().split('\n')[0];
      log(`[PROTOCOL] Received remote banner: "${banner}"`);
      completed = true;
      log(`[SYSTEM] Connection test completed successfully.`);
      cleanup();
      resolve({ success: true });
    });

    socket.on('timeout', () => {
      if (completed) return;
      completed = true;
      log(`[TCP] Connection timed out after 5000ms.`);
      cleanup();
      resolve({ success: false, error: "Connection Timeout" });
    });

    socket.on('error', (err) => {
      if (completed) return;
      completed = true;
      log(`[TCP] Socket error: ${err.message}`);
      
      let hint = "Verify the target host is correct, the port is open, and vault server's IP is allowed by target firewalls.";
      if (err.code === 'ECONNREFUSED') {
        hint = "The target port is closed or connection was actively refused. Verify that the SSH/SFTP/FTP daemon is active.";
      } else if (err.code === 'ENOTFOUND') {
        hint = "Hostname resolution failed. Check DNS settings and hostname spellings.";
      }
      log(`[HINT] ${hint}`);
      cleanup();
      resolve({ success: false, error: err.message });
    });
  });

  const result = await promise;
  res.json({
    success: result.success,
    error: result.error,
    logs
  });
});


app.delete('/admin/api/groups/:groupId/profiles/:profileId', authMiddleware, requirePermission('profile.delete'), async (req, res) => {
  const { groupId, profileId } = req.params;
  const g = await VaultGroup.findByPk(groupId);
  if (g && g.legal_hold_active) {
    return res.status(403).json({ error: "Cannot delete Connection Profile: Vault Group is under active Legal Hold" });
  }
  const p = await ConnectionProfile.findByPk(profileId);
  if (p) {
    const name = p.name;
    await p.destroy();
    await addAuditLog(
      req.adminUser.username,
      JSON.stringify({
        action: "profile_deleted",
        performedBy: req.adminUser.id,
        performedByUsername: req.adminUser.username,
        profileName: name
      })
    );
    res.json({ success: true });
  } else {
    res.status(404).json({ error: "Profile not found" });
  }
});

// ── User Scoped Tokens Management API ──────────────────────────────
app.post('/admin/api/tokens', authMiddleware, requirePermission('token.issue'), async (req, res) => {
  const { token_hash, user, groupId, status, expires_at } = req.body;
  if (!user || !groupId) {
    return res.status(400).json({ error: "Missing required token fields (user and groupId)" });
  }
  
  const g = await VaultGroup.findByPk(groupId);
  if (!g) {
    return res.status(404).json({ error: "Assigned Vault Group not found" });
  }
  if (g.legal_hold_active && g.legal_hold_freeze_writes) {
    return res.status(403).json({ error: "Cannot issue/modify token: Vault Group writes are frozen under active Legal Hold" });
  }

  // Find or create User mapping based on name
  const [usr] = await User.findOrCreate({
    where: { username: user },
    defaults: {
      passwordHash: crypto.createHash('sha256').update('temporary-user-password').digest('hex'),
      role: 'operator'
    }
  });
  
  if (token_hash) {
    const key = await AccessKey.findByPk(token_hash);
    if (key) {
      key.groupId = groupId;
      key.expiresAt = expires_at || "";
      key.userId = usr.id;
      const oldStatus = key.status;
      key.status = status || key.status;
      await key.save();
      
      await addAuditLog(
        req.adminUser.username,
        JSON.stringify({
          action: "token_updated",
          performedBy: req.adminUser.id,
          performedByUsername: req.adminUser.username,
          targetUser: user
        })
      );
      if (status === 'blocked' && oldStatus !== 'blocked') {
        notifyTokenSuspension(token_hash);
      } else if (status === 'active' && oldStatus === 'blocked') {
        notifyTokenRestoration(token_hash);
      }
      res.json({ success: true });
    } else {
      res.status(404).json({ error: "Access key not found" });
    }
  } else {
    // Generate new key on the server
    const rawToken = crypto.randomBytes(32).toString('hex');
    const hashed = crypto.createHash('sha256').update(rawToken).digest('hex');

    await AccessKey.create({
      token_hash: hashed,
      userId: usr.id,
      groupId,
      status: status || "active",
      expiresAt: expires_at || ""
    });
    
    await addAuditLog(
      req.adminUser.username,
      JSON.stringify({
        action: "token_issued",
        performedBy: req.adminUser.id,
        performedByUsername: req.adminUser.username,
        targetUser: user,
        targetGroup: groupId
      })
    );
    
    // Return raw token ONE TIME to the admin/client
    res.json({ success: true, token: rawToken });
  }
});

app.delete('/admin/api/tokens/:token', authMiddleware, requirePermission('token.revoke'), async (req, res) => {
  const tokenVal = req.params.token;
  const key = await AccessKey.findByPk(tokenVal, { include: [User] });
  if (key) {
    const group = await VaultGroup.findByPk(key.groupId);
    if (group && group.legal_hold_active) {
      return res.status(403).json({ error: "Cannot delete Access Key: Scoped Vault Group is under active Legal Hold" });
    }
    const ownerName = key.User ? key.User.username : 'Master Token';
    await key.destroy();
    await addAuditLog(
      req.adminUser.username,
      JSON.stringify({
        action: "token_revoked",
        performedBy: req.adminUser.id,
        performedByUsername: req.adminUser.username,
        tokenOwner: ownerName
      })
    );
    notifyTokenRevocation(tokenVal);
    res.json({ success: true });
  } else {
    res.status(404).json({ error: "Access key not found" });
  }
});

// ── Client-side Transfer Audit Logging endpoint ──────────────────────
app.post('/v1/audit/log', async (req, res) => {
  const { token, connectionId, filePath, fileSize, action, status, errorMessage } = req.body;
  if (!connectionId || !filePath || !action) {
    return res.status(400).json({ error: "Missing required logging parameters" });
  }

  // Resolve token owner
  let username = 'Anonymous Client';
  let tokenHash = null;
  if (token) {
    tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const key = await AccessKey.findOne({ where: { token_hash: tokenHash }, include: [User] });
    if (key && key.User) {
      username = key.User.username;
    }
  }

  await TransferLog.create({
    token: tokenHash || null,
    username,
    connectionId,
    filePath,
    fileSize: parseInt(fileSize) || 0,
    action,
    status: status || 'success',
    errorMessage: errorMessage || null
  });

  res.json({ success: true });
});

// ── File Versioning System & Backup management ────────────────────────
app.post('/v1/files/version', async (req, res) => {
  const { token, connectionId, profileName, filePath, size, hash, content, modifiedBy } = req.body;
  if (!connectionId || !filePath || content === undefined) {
    return res.status(400).json({ error: "Missing version data parameters" });
  }

  const backupEnabledConfig = await SystemConfig.findOne({ where: { key: 'backup_enabled' } });
  const isBackupEnabled = backupEnabledConfig ? backupEnabledConfig.value === 'true' : true;
  if (!isBackupEnabled) {
    return res.json({ success: true, version: 0, message: "Backups are globally disabled" });
  }

  // Resolve user from token
  let username = 'System';
  if (token) {
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const key = await AccessKey.findOne({ where: { token_hash: tokenHash }, include: [User] });
    if (key && key.User) {
      username = key.User.username;
    }
    if (key && profileName) {
      const profile = await ConnectionProfile.findOne({
        where: { groupId: key.groupId, name: profileName }
      });
      if (profile) {
        profile.clientProfileId = connectionId;
        await profile.save();
        console.log(`[Version Link] Linked client profile ID "${connectionId}" to server profile "${profile.name}" (${profile.id})`);
      }
    }
  }

  // Get current max version
  const lastVersion = await FileVersion.findOne({
    where: { connectionId, filePath },
    order: [['version', 'DESC']]
  });

  const nextVerNum = lastVersion ? lastVersion.version + 1 : 1;

  // Save previous version content to backup path
  const backupDir = path.join(DATA_DIR, 'backups', connectionId);
  fs.mkdirSync(backupDir, { recursive: true });
  
  const backupFileName = `${Buffer.from(filePath).toString('hex')}_v${nextVerNum}.bak`;
  const backupPath = path.join(backupDir, backupFileName);
  fs.writeFileSync(backupPath, content, 'utf8');

  await FileVersion.create({
    connectionId,
    filePath,
    version: nextVerNum,
    size: parseInt(size) || content.length,
    hash: hash || crypto.createHash('md5').update(content).digest('hex'),
    backupPath,
    modifiedBy: modifiedBy || username
  });

  // Apply backup retention policy dynamically
  try {
    const backupLimitConfig = await SystemConfig.findOne({ where: { key: 'backup_retention_limit' } });
    const retentionLimit = backupLimitConfig ? parseInt(backupLimitConfig.value) || 10 : 10;

    const existingVersions = await FileVersion.findAll({
      where: { connectionId, filePath },
      order: [['version', 'ASC']]
    });
    if (existingVersions.length > retentionLimit) {
      const deleteLimit = existingVersions.length - retentionLimit;
      const oldVersions = existingVersions.slice(0, deleteLimit);
      for (const oldVer of oldVersions) {
        if (oldVer.backupPath && fs.existsSync(oldVer.backupPath)) {
          try {
            fs.unlinkSync(oldVer.backupPath);
            console.log(`[Retention] Deleted old physical backup file: ${oldVer.backupPath}`);
          } catch (unlinkErr) {
            console.error(`[Retention] Failed to delete backup file: ${oldVer.backupPath}`, unlinkErr);
          }
        }
        await oldVer.destroy();
        console.log(`[Retention] Removed version ${oldVer.version} entry for file ${filePath} from database`);
      }
    }
  } catch (retentionErr) {
    console.error('[Retention] Error enforcing backup retention policy:', retentionErr);
  }

  res.json({ success: true, version: nextVerNum });
});

app.get('/admin/api/versions', authMiddleware, requirePermission('backup.view'), async (req, res) => {
  const list = await FileVersion.findAll({ order: [['createdAt', 'DESC']], limit: 200 });
  res.json(list);
});

app.get('/admin/api/versions/:id/content', authMiddleware, requirePermission('backup.view'), async (req, res) => {
  const ver = await FileVersion.findByPk(req.params.id);
  if (!ver) return res.status(404).json({ error: "Version not found" });
  if (!fs.existsSync(ver.backupPath)) {
    return res.status(404).json({ error: "Backup file not found on server disk" });
  }
  const content = fs.readFileSync(ver.backupPath, 'utf8');
  res.json({ content });
});

app.post('/admin/api/versions/restore', authMiddleware, requirePermission('backup.restore'), async (req, res) => {
  const { versionId, clear } = req.body;
  const ver = await FileVersion.findByPk(versionId);
  if (!ver) {
    return res.status(404).json({ error: "File version record not found" });
  }

  let content = "";
  if (!clear) {
    if (!fs.existsSync(ver.backupPath)) {
      return res.status(404).json({ error: "Physical backup file does not exist on server disk" });
    }
    content = fs.readFileSync(ver.backupPath, 'utf8');
  }

  // Trigger WebSocket client write if connection ID is active
  try {
    let profile = await ConnectionProfile.findByPk(ver.connectionId);
    if (!profile) {
      profile = await ConnectionProfile.findOne({ where: { clientProfileId: ver.connectionId } });
    }
    if (profile) {
      const keys = await AccessKey.findAll({ where: { groupId: profile.groupId } });
      let sentCount = 0;
      for (const k of keys) {
        const clientWs = clients.get(k.token_hash);
        if (clientWs && clientWs.readyState === 1 && k.status !== 'blocked') { // OPEN and not blocked
          clientWs.send(JSON.stringify({
            type: 'write_file',
            connectionId: ver.connectionId,
            filePath: ver.filePath,
            content: content,
            isQueued: false,
            timestamp: Date.now()
          }));
          sentCount++;
          await PendingReversion.create({
            groupId: profile.groupId,
            connectionId: ver.connectionId,
            filePath: ver.filePath,
            content: content,
            status: 'applied',
            tokenHash: k.token_hash
          });
        } else {
          await PendingReversion.create({
            groupId: profile.groupId,
            connectionId: ver.connectionId,
            filePath: ver.filePath,
            content: content,
            status: 'pending',
            tokenHash: k.token_hash
          });
        }
      }
      console.log(`[Revert] Dispatched write_file command to ${sentCount} active clients for profile ${ver.connectionId}`);
    }
  } catch (err) {
    console.error('Failed to notify clients of file reversion:', err);
  }

  res.json({ success: true, filePath: ver.filePath, connectionId: ver.connectionId, content });
});

// ── Client Synchronization Endpoint (Multi-Token RBAC model) ─────────
app.get(['/v1/secret/data/filepilot/profiles', '/v1/secret/data/filepilot/profiles/:group_id'], syncLimiter, async (req, res) => {
  if (!(await checkIsInstalled())) {
    return res.status(503).json({ errors: ["Vault Setup is incomplete. Please complete setup at http://localhost:8200/admin"] });
  }

  const groupId = req.params.group_id;
  const vaultToken = req.headers['x-vault-token'];
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  if (!vaultToken) {
    await addAuditLog("Unauthorized Access", `Blocked sync request (Missing Token)`, "error");
    return res.status(401).json({
      errors: ['Permission denied, missing X-Vault-Token header']
    });
  }

  const isMasterToken = (vaultToken === 'admin-token');
  let tokenObj = null;
  if (!isMasterToken) {
    const tokenHash = crypto.createHash('sha256').update(vaultToken).digest('hex');
    tokenObj = await AccessKey.findOne({
      where: { token_hash: tokenHash },
      include: [User]
    });
  }

  let targetGroupId;
  let tokenDesc = "Master Token";

  if (!isMasterToken) {
    if (!tokenObj) {
      await addAuditLog(`Token "${vaultToken.substring(0, 8)}..."`, `Blocked sync request (Invalid Token)`, "error");
      return res.status(403).json({
        errors: ['Permission denied, invalid X-Vault-Token']
      });
    }
    
    if (tokenObj.status === 'blocked') {
      const owner = tokenObj.User ? tokenObj.User.username : 'Unknown';
      await addAuditLog(owner, `Blocked sync request for "${owner}" (Access Key Blocked)`, "error");
      return res.status(403).json({
        errors: ['Permission denied: Your Access Key has been blocked']
      });
    }

    if (tokenObj.expiresAt) {
      const expiry = new Date(tokenObj.expiresAt);
      if (expiry < new Date()) {
        tokenObj.status = 'expired';
        await tokenObj.save();
        const owner = tokenObj.User ? tokenObj.User.username : 'Unknown';
        await addAuditLog(owner, `Blocked sync request for "${owner}" (Access Key Expired)`, "error");
        notifyTokenRevocation(tokenObj.token_hash);
        return res.status(403).json({
          errors: ['Permission denied: Your Access Key has expired']
        });
      }
    }
    
    targetGroupId = tokenObj.groupId;
    tokenDesc = tokenObj.User ? tokenObj.User.username : 'Operator';
  } else {
    targetGroupId = groupId;
  }

  if (!targetGroupId) {
    return res.status(400).json({
      errors: ['Missing Vault Group target ID']
    });
  }

  const group = await VaultGroup.findByPk(targetGroupId, { include: [ConnectionProfile] });
  if (!group) {
    return res.status(404).json({
      errors: ['Vault Group not found']
    });
  }

  if (group.ipAllowlist && !ipMatches(clientIp, group.ipAllowlist)) {
    await addAuditLog(tokenDesc, `Blocked sync request for group "${group.name}" (IP ${clientIp} not whitelisted)`, "error");
    return res.status(403).json({
      errors: [`Permission denied: Client IP ${clientIp} is not in the group's IP allowlist`]
    });
  }

  try {
    const dek = await getGroupDek(group);
    const decryptedProfiles = (group.ConnectionProfiles || []).map(p => {
      const pJson = p.toJSON();
      let pass = pJson.passwordEncrypted ? decrypt(pJson.passwordEncrypted, dek) : '';
      let privKey = '';
      if (pJson.authMode === 'keypair') {
        privKey = pass;
        pass = '';
      }

      const options = {};
      if (pJson.authMode === 'keypair') {
        options.private_key = privKey;
      }

      if (pJson.jumpHost) {
        let jumpPass = pJson.jumpPasswordEncrypted ? decrypt(pJson.jumpPasswordEncrypted, dek) : '';
        let jumpPrivKey = '';
        if (pJson.jumpAuthMode === 'keypair') {
          jumpPrivKey = jumpPass;
          jumpPass = '';
        }

        options.jump_host = pJson.jumpHost;
        options.jump_port = String(pJson.jumpPort || 22);
        options.jump_username = pJson.jumpUsername;
        options.jump_auth_mode = pJson.jumpAuthMode || 'password';
        if (pJson.jumpAuthMode === 'keypair') {
          options.jump_private_key = jumpPrivKey;
        } else {
          options.jump_password = jumpPass;
        }
      }

      if (group.legal_hold_active) {
        options.legal_hold = 'true';
        if (group.legal_hold_freeze_writes) {
          options.legal_hold_freeze_writes = 'true';
        }
      }

      return {
        id: pJson.id,
        name: pJson.name,
        protocol: pJson.protocol,
        host: pJson.host,
        port: pJson.port,
        username: pJson.username,
        password: pass,
        tags: ['enterprise'],
        options
      };
    });

    await addAuditLog(tokenDesc, `Sync request for vault "${group.name}" (Returned ${decryptedProfiles.length} profiles)`);

    res.json({
      vault_name: group.name,
      profiles: decryptedProfiles
    });
  } catch (err) {
    console.error("Profile sync failed:", err);
    res.status(500).json({
      errors: [`Decryption or KMS key unwrapping failed: ${err.message}`]
    });
  }
});

// Serve Admin UI static files
app.get('/admin', async (req, res) => {
  if (!(await checkIsInstalled())) {
    return res.sendFile(path.join(__dirname, 'admin', 'install.html'));
  }
  res.sendFile(path.join(__dirname, 'admin', 'index.html'));
});

app.get('/admin/install.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'install.html'));
});

// Fallback static files
app.use('/admin', async (req, res, next) => {
  if (!(await checkIsInstalled())) {
    if (req.path === '/' || req.path === '/index.html') {
      return res.sendFile(path.join(__dirname, 'admin', 'install.html'));
    }
  }
  next();
}, express.static(path.join(__dirname, 'admin')));

// Boot server after database initialization (if configured)
if (require.main === module || process.env.RUN_VAULT_SERVER === 'true') {
  const bootServer = async () => {
    const hasKey = !!process.env.VAULT_MASTER_KEY || fs.existsSync(KEY_FILE);
    const hasConfig = !!process.env.DB_DIALECT || fs.existsSync(configPath);
    
    if (hasKey && hasConfig) {
      console.log("Vault is configured. Initializing database...");
      await initDb();
    } else {
      console.log("Vault is not configured. Starting in setup wizard mode...");
    }

    activeHttpServer = app.listen(PORT, () => {
      console.log(`FilePilot Corporate Vault Server running on port ${PORT}`);
      console.log(`Admin Portal: http://localhost:${PORT}/admin`);
      console.log(`Sync URL: http://localhost:${PORT}/v1/secret/data/filepilot/profiles`);
    });

  // Setup WebSocket server
  activeWss = new WebSocketServer({ server: activeHttpServer });
  const wss = activeWss;

  const keepaliveInterval = setInterval(() => {
    wss.clients.forEach(ws => {
      if (ws.isAlive === false) {
        console.log("[WS] Terminating unresponsive client connection.");
        return ws.terminate();
      }
      ws.isAlive = false;
      ws.ping();
    });
  }, 30000);

  wss.on('close', () => {
    clearInterval(keepaliveInterval);
  });

  wss.on('connection', async (ws, req) => {
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    const parameters = urlParser.parse(req.url, true).query;
    const isCollab = parameters.collaboration === 'true';
    const file = parameters.file;
    const user = parameters.user || 'Collaborator';

    if (isCollab && file) {
      ws.isCollab = true;
      ws.collabFile = file;
      ws.collabUser = user;
      
      console.log(`[WS Collab] User "${user}" joined collaboration for file: ${file}`);
      
      ws.on('message', (message) => {
        try {
          const payload = JSON.parse(message.toString());
          if (payload.type === 'cursor' || payload.type === 'edit') {
            wss.clients.forEach((client) => {
              if (client !== ws && client.isCollab && client.readyState === 1 && client.collabFile === file) {
                client.send(JSON.stringify({
                  ...payload,
                  user: user,
                }));
              }
            });
          }
        } catch (err) {
          console.error("[WS Collab] Error processing collab message:", err);
        }
      });
      
      ws.on('close', () => {
        console.log(`[WS Collab] User "${user}" left collaboration for file: ${file}`);
        wss.clients.forEach((client) => {
          if (client !== ws && client.isCollab && client.readyState === 1 && client.collabFile === file) {
            client.send(JSON.stringify({
              type: 'leave',
              user: user,
            }));
          }
        });
      });
      
      return;
    }

    // If the vault is not installed/configured, reject WebSocket token connections immediately to prevent database crashes
    if (!(await checkIsInstalled())) {
      console.log("[WS] Connection rejected: Vault is not configured/installed yet.");
      try {
        ws.send(JSON.stringify({ type: "revoked" }));
        ws.close();
      } catch (_) {}
      return;
    }

    const token = parameters.token;
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    console.log(`[WS] Connection attempt. Token (truncated): ${token ? token.substring(0, 8) + '...' : 'none'} from IP: ${clientIp}`);
    
    if (token) {
      const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
      const tokenObj = await AccessKey.findByPk(tokenHash, { include: [User] });
      
      if (!tokenObj) {
        console.log(`[WS] Connection rejected: Token not found`);
        try {
          ws.send(JSON.stringify({ type: "access_revoked" }));
          ws.close();
        } catch (_) {}
        return;
      }

      if (tokenObj.expiresAt) {
        const expiry = new Date(tokenObj.expiresAt);
        if (expiry < new Date()) {
          tokenObj.status = 'expired';
          await tokenObj.save();
          console.log(`[WS] Connection rejected: Token has expired`);
          try {
            ws.send(JSON.stringify({ type: "access_revoked" }));
            ws.close();
          } catch (_) {}
          return;
        }
      }

      const group = await VaultGroup.findByPk(tokenObj.groupId);
      if (group && group.ipAllowlist && !ipMatches(clientIp, group.ipAllowlist)) {
        console.log(`[WS] Connection rejected: Client IP ${clientIp} is not whitelisted for group "${group.name}"`);
        try {
          ws.send(JSON.stringify({ type: "access_revoked" }));
          ws.close();
        } catch (_) {}
        return;
      }

      clients.set(tokenHash, ws);
      console.log(`[WS] Client registered. Active clients count: ${clients.size}`);
      
      ws.on('message', (message) => {
        try {
          const payload = JSON.parse(message.toString());
          if (payload.type === 'client_session') {
            ws.clientConnection = payload.connected ? {
              host: payload.host,
              protocol: payload.protocol,
              username: payload.username,
              profileId: payload.profileId,
              connectedAt: new Date().toISOString()
            } : null;
            console.log(`[WS] Token ${tokenHash.substring(0, 8)} updated connection status:`, ws.clientConnection);
          }
        } catch (err) {
          console.error("[WS] Error processing client message:", err);
        }
      });
      
      if (tokenObj.status === 'blocked') {
        console.log(`[WS] Client connected but token is blocked (suspended)`);
        try {
          ws.send(JSON.stringify({ type: "access_suspended" }));
        } catch (_) {}
      } else {
        // Fetch and push any pending reversions for this specific token!
        try {
          const pending = await PendingReversion.findAll({
            where: { tokenHash: tokenHash, status: 'pending' }
          });
          if (pending.length > 0) {
            console.log(`[WS] Pushing ${pending.length} pending file reversions to client ${tokenObj.User?.username || 'Operator'}`);
            for (const p of pending) {
              ws.send(JSON.stringify({
                type: 'write_file',
                connectionId: p.connectionId,
                filePath: p.filePath,
                content: p.content,
                isQueued: true,
                timestamp: p.createdAt.getTime()
              }));
              p.status = 'applied';
              await p.save();
            }
          }
        } catch (pendingErr) {
          console.error('[WS] Failed to fetch and dispatch pending reversions:', pendingErr);
        }
      }
      
      ws.on('error', (err) => {
        console.error(`[WS] Socket error for client:`, err);
      });

      ws.on('close', () => {
        clients.delete(tokenHash);
        console.log(`[WS] Client disconnected. Active clients count: ${clients.size}`);
      });
    }
  });
  };
  bootServer().catch(err => {
    console.error("Server boot failed:", err);
    process.exit(1);
  });
}

function notifyTokenSuspension(tokenVal) {
  console.log(`[WS] Attempting to suspend token: ${tokenVal}`);
  const ws = clients.get(tokenVal);
  if (ws) {
    try {
      console.log(`[WS] Sending 'access_suspended' message to client with token: ${tokenVal}`);
      ws.send(JSON.stringify({ type: "access_suspended" }));
      ws.close();
    } catch (e) {
      console.error("[WS] Failed to send WebSocket suspension message:", e);
    }
    clients.delete(tokenVal);
  }
}

function notifyTokenRestoration(tokenVal) {
  console.log(`[WS] Attempting to restore token: ${tokenVal}`);
  const ws = clients.get(tokenVal);
  if (ws) {
    try {
      console.log(`[WS] Sending 'access_restored' message to client with token: ${tokenVal}`);
      ws.send(JSON.stringify({ type: "access_restored" }));
    } catch (e) {
      console.error("[WS] Failed to send WebSocket restoration message:", e);
    }
  }
}

function notifyTokenRevocation(tokenVal) {
  console.log(`[WS] Attempting to revoke token: ${tokenVal}`);
  const ws = clients.get(tokenVal);
  if (ws) {
    try {
      console.log(`[WS] Sending 'access_revoked' message to client with token: ${tokenVal}`);
      ws.send(JSON.stringify({ type: "access_revoked" }));
      ws.close();
    } catch (e) {
      console.error("[WS] Failed to send WebSocket revocation message:", e);
    }
    clients.delete(tokenVal);
  } else {
    console.log(`[WS] No active socket connection found for token: ${tokenVal}`);
  }
}

async function notifyGroupRevocation(groupId) {
  const tokens = await AccessKey.findAll({ where: { groupId } });
  tokens.forEach(t => {
    notifyTokenRevocation(t.token_hash);
  });
}

// ── Compliance Export and Continuous Drift Detection ─────────────────
const complianceChecks = require('./compliance-checks.cjs');
const PDFDocument = require('pdfkit');

const FRAMEWORK_MAPPINGS = {
  soc2: {
    name: "SOC 2 Type II",
    disclaimer: "This report provides technical evidence to support a SOC 2 Type II compliance assessment. It does not constitute certification and should be reviewed by a qualified auditor.",
    controls: [
      {
        controlId: "CC6.1",
        title: "Logical access security measures (Encryption Posture)",
        postureSource: "encryption"
      },
      {
        controlId: "CC6.3",
        title: "Access registration and role assignment (Access Control Posture)",
        postureSource: "accessControl"
      },
      {
        controlId: "CC6.6",
        title: "Boundary protection and firewalls (Access Policy Posture)",
        postureSource: "accessPolicy"
      },
      {
        controlId: "CC7.2",
        title: "System monitoring and logging (Audit Integrity Posture)",
        postureSource: "auditIntegrity"
      },
      {
        controlId: "CC6.4",
        title: "Session security and terminal locks (Session Security Posture)",
        postureSource: "sessionSecurity"
      }
    ]
  },
  hipaa: {
    name: "HIPAA Security Rule",
    disclaimer: "This report provides technical evidence to support a HIPAA Security Rule compliance assessment. It does not constitute certification and should be reviewed by a qualified auditor.",
    controls: [
      {
        controlId: "§164.312(a)(2)(iv)",
        title: "Encryption and Decryption (Encryption Posture)",
        postureSource: "encryption"
      },
      {
        controlId: "§164.312(a)(1)",
        title: "Access Control (Access Control Posture)",
        postureSource: "accessControl"
      },
      {
        controlId: "§164.312(e)(1)",
        title: "Transmission Security (Access Policy Posture)",
        postureSource: "accessPolicy"
      },
      {
        controlId: "§164.312(b)",
        title: "Audit controls (Audit Integrity Posture)",
        postureSource: "auditIntegrity"
      },
      {
        controlId: "§164.312(a)(2)(iii)",
        title: "Automatic logoff (Session Security Posture)",
        postureSource: "sessionSecurity"
      }
    ]
  },
  iso27001: {
    name: "ISO/IEC 27001:2022 Annex A",
    disclaimer: "This report provides technical evidence to support an ISO/IEC 27001 compliance assessment. It does not constitute certification and should be reviewed by a qualified auditor.",
    controls: [
      {
        controlId: "A.8.24",
        title: "Use of cryptography (Encryption Posture)",
        postureSource: "encryption"
      },
      {
        controlId: "A.8.2",
        title: "Privileged access rights (Access Control Posture)",
        postureSource: "accessControl"
      },
      {
        controlId: "A.8.20",
        title: "Network security (Access Policy Posture)",
        postureSource: "accessPolicy"
      },
      {
        controlId: "A.8.15",
        title: "Logging (Audit Integrity Posture)",
        postureSource: "auditIntegrity"
      },
      {
        controlId: "A.5.15",
        title: "Access control (Session Security Posture)",
        postureSource: "sessionSecurity"
      }
    ]
  },
  generic: {
    name: "Generic Security Posture",
    disclaimer: "This report provides technical evidence to support a general compliance assessment. It does not constitute certification and should be reviewed by a qualified auditor.",
    controls: [
      {
        controlId: "GEN-CRYPTO",
        title: "Cryptographic Protection",
        postureSource: "encryption"
      },
      {
        controlId: "GEN-RBAC",
        title: "Role-Based Access Control",
        postureSource: "accessControl"
      },
      {
        controlId: "GEN-NET",
        title: "Network Policy & IP Control",
        postureSource: "accessPolicy"
      },
      {
        controlId: "GEN-AUDIT",
        title: "Audit Log Integrity",
        postureSource: "auditIntegrity"
      },
      {
        controlId: "GEN-SESS",
        title: "Session Control & Security limits",
        postureSource: "sessionSecurity"
      }
    ]
  }
};

const DRIFT_RULES = [
  {
    id: "RULE_NO_IP_ALLOWLIST",
    description: "Vault Group has no IP allowlist configured",
    severity: "medium",
    check: async (postures) => {
      const findings = [];
      for (const group of postures.accessPolicy) {
        if (!group.hasIpAllowlist) {
          findings.push({
            ruleId: "RULE_NO_IP_ALLOWLIST",
            severity: "medium",
            description: `Vault Group "${group.groupName}" has no IP allowlist configured, allowing connections from any IP address.`,
            affectedEntity: `Vault Group: ${group.groupName} (${group.groupId})`
          });
        }
      }
      return findings;
    }
  },
  {
    id: "RULE_TOKEN_AGE_90",
    description: "Token has been active more than 90 days without rotation",
    severity: "medium",
    check: async (postures) => {
      const findings = [];
      for (const token of postures.accessControl.activeTokens) {
        if (token.ageDays > 90) {
          findings.push({
            ruleId: "RULE_TOKEN_AGE_90",
            severity: "medium",
            description: `Token issued to user "${token.user}" has been active for ${token.ageDays} days without rotation.`,
            affectedEntity: `Token: ${token.token_hash_truncated} (User: ${token.user})`
          });
        }
      }
      return findings;
    }
  },
  {
    id: "RULE_NO_MFA",
    description: "Admin user does not have MFA enabled",
    severity: "high",
    check: async (postures) => {
      const findings = [];
      if (postures.accessControl && postures.accessControl.users) {
        for (const u of postures.accessControl.users) {
          if (!u.mfa_enabled) {
            findings.push({
              ruleId: "RULE_NO_MFA",
              severity: "high",
              description: `Admin Portal user "${u.username}" does not have Multi-Factor Authentication (MFA) enabled.`,
              affectedEntity: `User: ${u.username} (Role: ${u.role})`
            });
          }
        }
      }
      return findings;
    }
  },
  {
    id: "RULE_LOCAL_KEK",
    description: "Vault Group is still using the app-managed local KEK instead of a dedicated BYOK provider",
    severity: "low",
    check: async (postures) => {
      const findings = [];
      for (const group of postures.encryption.groups) {
        if (group.kmsProvider === 'local') {
          findings.push({
            ruleId: "RULE_LOCAL_KEK",
            severity: "low",
            description: `Vault Group "${group.groupName}" is using the app-managed local KEK instead of an external BYOK KMS provider.`,
            affectedEntity: `Vault Group: ${group.groupName} (${group.groupId})`
          });
        }
      }
      return findings;
    }
  },
  {
    id: "RULE_KEK_ROTATION_180",
    description: "KEK/DEK has not been rotated in over 180 days",
    severity: "medium",
    check: async (postures) => {
      const findings = [];
      const oldestRotation = await KeyVersion.findOne({ order: [['version', 'DESC']] });
      const refDate = oldestRotation ? new Date(oldestRotation.createdAt) : new Date();
      const ageDays = (Date.now() - refDate.getTime()) / (1000 * 60 * 60 * 24);
      if (ageDays > 180) {
        findings.push({
          ruleId: "RULE_KEK_ROTATION_180",
          severity: "medium",
          description: `The master Key Encryption Key (KEK) has not been rotated in ${Math.round(ageDays)} days (threshold is 180 days).`,
          affectedEntity: "Global KEK"
        });
      }
      return findings;
    }
  },
  {
    id: "RULE_SESSION_TIMEOUT_24",
    description: "Session timeout is configured longer than 24 hours",
    severity: "low",
    check: async (postures) => {
      const findings = [];
      if (postures.sessionSecurity.sessionTimeoutMs > 24 * 60 * 60 * 1000) {
        findings.push({
          ruleId: "RULE_SESSION_TIMEOUT_24",
          severity: "low",
          description: `The session timeout limit is configured for ${Math.round(postures.sessionSecurity.sessionTimeoutMs / (1000 * 60 * 60))} hours, which exceeds the 24-hour limit.`,
          affectedEntity: "Session Configuration"
        });
      }
      return findings;
    }
  },
  {
    id: "RULE_NO_SYNC_7_DAYS",
    description: "A Vault Group has zero successful syncs in the last 7 days",
    severity: "low",
    check: async (postures) => {
      const findings = [];
      const { Op } = require('sequelize');
      for (const group of postures.accessPolicy) {
        const recentSync = await TransferLog.findOne({
          where: {
            action: {
              [Op.like]: `Sync request for vault "${group.groupName}"%`
            },
            status: {
              [Op.not]: 'failed'
            },
            createdAt: {
              [Op.gt]: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
            }
          }
        });
        if (!recentSync) {
          findings.push({
            ruleId: "RULE_NO_SYNC_7_DAYS",
            severity: "low",
            description: `Vault Group "${group.groupName}" has zero successful client profile synchronization logs in the last 7 days.`,
            affectedEntity: `Vault Group: ${group.groupName} (${group.groupId})`
          });
        }
      }
      return findings;
    }
  }
];

// Endpoint: One-Click Compliance Evidence Export
app.get('/admin/api/compliance/export', authMiddleware, requirePermission('audit.export'), async (req, res) => {
  try {
    const framework = (req.query.framework || 'generic').toLowerCase();
    const format = (req.query.format || 'pdf').toLowerCase();
    const mapping = FRAMEWORK_MAPPINGS[framework];

    if (!mapping) {
      return res.status(400).json({ error: `Unsupported compliance framework: ${framework}` });
    }

    // Call all five collector functions
    const assembledPostures = {
      encryption: await complianceChecks.getEncryptionPosture(),
      accessControl: await complianceChecks.getAccessControlPosture(),
      auditIntegrity: await complianceChecks.getAuditIntegrityPosture(),
      accessPolicy: await complianceChecks.getAccessPolicyPosture(),
      sessionSecurity: await complianceChecks.getSessionSecurityPosture()
    };

    // Log the export action to the audit log (with attribution)
    await addAuditLog(
      req.adminUser.username,
      JSON.stringify({
        action: "compliance_evidence_exported",
        performedBy: req.adminUser.id,
        performedByUsername: req.adminUser.username,
        framework
      })
    );

    // Format output
    if (format === 'json') {
      const report = {
        generationTimestamp: new Date().toISOString(),
        vaultInstanceIdentifier: process.env.VAULT_INSTANCE_ID || 'filepilot-corporate-vault',
        framework: framework,
        disclaimer: mapping.disclaimer,
        evidence: mapping.controls.map(c => ({
          controlId: c.controlId,
          controlTitle: c.title,
          data: assembledPostures[c.postureSource]
        }))
      };
      return res.json(report);
    }

    // PDF format
    const doc = new PDFDocument({ margin: 50 });
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="compliance_report_${framework}.pdf"`);
    doc.pipe(res);

    // Title
    doc.fontSize(20).text(`Compliance Evidence Report: ${mapping.name}`, { align: 'center' });
    doc.moveDown(0.5);

    // Gen info
    doc.fontSize(10).text(`Generated On: ${new Date().toUTCString()}`);
    doc.text(`Vault Instance ID: ${process.env.VAULT_INSTANCE_ID || 'filepilot-corporate-vault'}`);
    doc.moveDown(1);

    // Disclaimer
    doc.fontSize(10).fillColor('#64748b').text(mapping.disclaimer, { oblique: true });
    doc.fillColor('black'); // Reset color
    doc.moveDown(1.5);

    // Iterate controls
    for (const c of mapping.controls) {
      doc.fontSize(14).text(`${c.controlId} - ${c.title}`, { underline: true });
      doc.moveDown(0.5);
      
      const data = assembledPostures[c.postureSource];
      const jsonStr = JSON.stringify(data, null, 2);
      
      doc.fontSize(9).font('Courier').text(jsonStr);
      doc.font('Helvetica'); // Restore font
      doc.moveDown(1.5);
    }

    doc.end();
  } catch (err) {
    console.error("[Compliance Export Error] Failed to generate compliance report:", err);
    res.status(500).json({ error: err.message });
  }
});

// Endpoint: Continuous Compliance Drift Findings
app.get('/admin/api/compliance/drift', authMiddleware, requirePermission('audit.view'), async (req, res) => {
  try {
    const postures = {
      encryption: await complianceChecks.getEncryptionPosture(),
      accessControl: await complianceChecks.getAccessControlPosture(),
      auditIntegrity: await complianceChecks.getAuditIntegrityPosture(),
      accessPolicy: await complianceChecks.getAccessPolicyPosture(),
      sessionSecurity: await complianceChecks.getSessionSecurityPosture()
    };

    const findings = [];
    for (const rule of DRIFT_RULES) {
      try {
        const ruleFindings = await rule.check(postures);
        findings.push(...ruleFindings);
      } catch (err) {
        console.error(`[Compliance Drift API] Error running rule ${rule.id}:`, err);
      }
    }

    res.json({
      timestamp: new Date().toISOString(),
      findings
    });
  } catch (err) {
    console.error("[Compliance Drift Error] Failed to fetch drift findings:", err);
    res.status(500).json({ error: err.message });
  }
});

// Scheduled Compliance Drift Checker (runs automatically once every 24 hours, or 5s in test)
let lastHighFindingIds = new Set();

async function runComplianceDriftCheck() {
  if (!(await checkIsInstalled())) {
    return;
  }
  try {
    const postures = {
      encryption: await complianceChecks.getEncryptionPosture(),
      accessControl: await complianceChecks.getAccessControlPosture(),
      auditIntegrity: await complianceChecks.getAuditIntegrityPosture(),
      accessPolicy: await complianceChecks.getAccessPolicyPosture(),
      sessionSecurity: await complianceChecks.getSessionSecurityPosture()
    };

    const findings = [];
    for (const rule of DRIFT_RULES) {
      try {
        const ruleFindings = await rule.check(postures);
        findings.push(...ruleFindings);
      } catch (err) {
        console.error(`[Drift Job] Error running rule ${rule.id}:`, err);
      }
    }

    const currentHighIds = new Set();
    const currentHighs = findings.filter(f => f.severity === 'high');

    for (const f of currentHighs) {
      const uniqueId = `${f.ruleId}:${f.affectedEntity}`;
      currentHighIds.add(uniqueId);

      if (!lastHighFindingIds.has(uniqueId)) {
        console.log(`[Drift Job] NEW HIGH SEVERITY FINDING DETECTED: ${f.description}`);
        await triggerSiemWebhook('Compliance Drift', f.description, 'high');
      }
    }

    lastHighFindingIds = currentHighIds;
  } catch (err) {
    console.error("[Drift Job] Failed to execute compliance check:", err);
  }
}

const DRIFT_INTERVAL_MS = process.env.NODE_ENV === 'test' ? 5000 : 24 * 60 * 60 * 1000;
setInterval(runComplianceDriftCheck, DRIFT_INTERVAL_MS);
setTimeout(runComplianceDriftCheck, 1000);

module.exports = {
  computeLogHash,
  formatLogsForExport,
  getGroupDek,
  app,
  decryptKmsCredentials,
  encryptKmsCredentials
};
