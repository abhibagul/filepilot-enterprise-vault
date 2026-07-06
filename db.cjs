const { Sequelize, DataTypes } = require('sequelize');
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.VAULT_DATA_DIR || process.cwd();

// Load environment variables from .env if present in DATA_DIR
const envPath = path.join(DATA_DIR, '.env');
console.log(`[DB] DATA_DIR resolved to: ${DATA_DIR}`);
console.log(`[DB] Checking for .env file at: ${envPath} (Exists: ${fs.existsSync(envPath)})`);
if (fs.existsSync(envPath)) {
  try {
    const content = fs.readFileSync(envPath, 'utf8');
    content.split(/\r?\n/).forEach(line => {
      const parts = line.split('=');
      if (parts.length >= 2) {
        const key = parts[0].trim();
        const val = parts.slice(1).join('=').trim().replace(/^['"]|['"]$/g, '');
        if (key && !key.startsWith('#')) {
          console.log(`[DB] Setting process.env.${key} from .env file`);
          if (!process.env[key]) {
            process.env[key] = val;
          }
        }
      }
    });
  } catch (err) {
    console.error("Failed to load .env file:", err);
  }
}

const configPath = process.env.VAULT_CONFIG_PATH || path.join(DATA_DIR, 'config.json');

// Default database configuration (embedded SQLite fallback on first boot)
let dbConfig = {
  dialect: 'sqlite',
  storage: path.join(DATA_DIR, 'vault.db'),
  logging: false
};

if (process.env.DB_DIALECT) {
  const dialect = process.env.DB_DIALECT;
  if (dialect === 'postgres') {
    dbConfig = {
      dialect: 'postgres',
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT) || 5432,
      username: process.env.DB_USERNAME,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      logging: false,
      dialectOptions: (process.env.DB_SSL === 'true') ? {
        ssl: {
          require: true,
          rejectUnauthorized: false
        }
      } : {}
    };
  } else if (dialect === 'mysql') {
    dbConfig = {
      dialect: 'mysql',
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT) || 3306,
      username: process.env.DB_USERNAME,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      logging: false
    };
  } else {
    dbConfig = {
      dialect: 'sqlite',
      storage: process.env.DB_STORAGE || path.join(DATA_DIR, 'vault.db'),
      logging: false
    };
  }
} else if (fs.existsSync(configPath)) {
  try {
    const raw = fs.readFileSync(configPath, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed.database) {
      if (parsed.database.dialect === 'postgres') {
        dbConfig = {
          dialect: 'postgres',
          host: parsed.database.host || 'localhost',
          port: parseInt(parsed.database.port) || 5432,
          username: parsed.database.username,
          password: parsed.database.password,
          database: parsed.database.database,
          logging: false,
          dialectOptions: parsed.database.ssl ? {
            ssl: {
              require: true,
              rejectUnauthorized: false
            }
          } : {}
        };
      } else if (parsed.database.dialect === 'mysql') {
        dbConfig = {
          dialect: 'mysql',
          host: parsed.database.host || 'localhost',
          port: parseInt(parsed.database.port) || 3306,
          username: parsed.database.username,
          password: parsed.database.password,
          database: parsed.database.database,
          logging: false
        };
      } else {
        dbConfig = {
          dialect: 'sqlite',
          storage: parsed.database.storage || path.join(DATA_DIR, 'vault.db'),
          logging: false
        };
      }
    }
  } catch (err) {
    console.error('Error loading database configuration:', err);
  }
}

const sequelize = new Sequelize(dbConfig);

// Define Models:
// 1. User
const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true
  },
  passwordHash: {
    type: DataTypes.STRING,
    allowNull: false
  },
  role: {
    type: DataTypes.STRING, // 'admin' | 'manager' | 'operator' | 'auditor'
    allowNull: false,
    defaultValue: 'operator'
  },
  mfa_enabled: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false
  },
  mfa_secret_encrypted: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  mfa_backup_codes_hash: {
    type: DataTypes.TEXT,
    allowNull: true
  }
});

// 2. VaultGroup
const VaultGroup = sequelize.define('VaultGroup', {
  id: {
    type: DataTypes.STRING,
    primaryKey: true
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  ipAllowlist: {
    type: DataTypes.TEXT,
    allowNull: true,
    defaultValue: ''
  },
  wrapped_dek: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  dek_version: {
    type: DataTypes.INTEGER,
    defaultValue: 1
  },
  migrated: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  kms_provider: {
    type: DataTypes.STRING,
    allowNull: false,
    defaultValue: 'local'
  },
  kms_config: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  kms_credentials_encrypted: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  legal_hold_active: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  },
  legal_hold_reason: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  legal_hold_placed_by: {
    type: DataTypes.STRING,
    allowNull: true
  },
  legal_hold_placed_at: {
    type: DataTypes.DATE,
    allowNull: true
  },
  legal_hold_freeze_writes: {
    type: DataTypes.BOOLEAN,
    defaultValue: false
  }
});

// 3. ConnectionProfile
const ConnectionProfile = sequelize.define('ConnectionProfile', {
  id: {
    type: DataTypes.STRING,
    primaryKey: true
  },
  groupId: {
    type: DataTypes.STRING,
    allowNull: false
  },
  name: {
    type: DataTypes.STRING,
    allowNull: false
  },
  protocol: {
    type: DataTypes.STRING,
    allowNull: false
  },
  host: {
    type: DataTypes.STRING,
    allowNull: false
  },
  port: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  username: {
    type: DataTypes.STRING,
    allowNull: false
  },
  passwordEncrypted: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  authMode: {
    type: DataTypes.STRING,
    allowNull: false,
    defaultValue: 'password'
  },
  clientProfileId: {
    type: DataTypes.STRING,
    allowNull: true
  },
  jumpHost: {
    type: DataTypes.STRING,
    allowNull: true
  },
  jumpPort: {
    type: DataTypes.INTEGER,
    allowNull: true
  },
  jumpUsername: {
    type: DataTypes.STRING,
    allowNull: true
  },
  jumpPasswordEncrypted: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  jumpAuthMode: {
    type: DataTypes.STRING,
    allowNull: true,
    defaultValue: 'password'
  }
});

// 4. AccessKey
const AccessKey = sequelize.define('AccessKey', {
  token_hash: {
    type: DataTypes.STRING,
    primaryKey: true
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: true
  },
  groupId: {
    type: DataTypes.STRING,
    allowNull: false
  },
  status: {
    type: DataTypes.STRING,
    allowNull: false,
    defaultValue: 'active'
  },
  expiresAt: {
    type: DataTypes.STRING,
    allowNull: true
  }
});

// Associations
User.hasMany(AccessKey, { foreignKey: 'userId', onDelete: 'SET NULL' });
AccessKey.belongsTo(User, { foreignKey: 'userId' });

VaultGroup.hasMany(ConnectionProfile, { foreignKey: 'groupId', onDelete: 'CASCADE' });
ConnectionProfile.belongsTo(VaultGroup, { foreignKey: 'groupId' });

VaultGroup.hasMany(AccessKey, { foreignKey: 'groupId', onDelete: 'CASCADE' });
AccessKey.belongsTo(VaultGroup, { foreignKey: 'groupId' });

// 5. TransferLog
const TransferLog = sequelize.define('TransferLog', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  token: {
    type: DataTypes.STRING,
    allowNull: true
  },
  username: {
    type: DataTypes.STRING,
    allowNull: true
  },
  connectionId: {
    type: DataTypes.STRING,
    allowNull: false
  },
  filePath: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  fileSize: {
    type: DataTypes.BIGINT,
    allowNull: true,
    defaultValue: 0
  },
  action: {
    type: DataTypes.STRING, // 'upload' | 'download' | 'delete'
    allowNull: false
  },
  status: {
    type: DataTypes.STRING, // 'success' | 'failed'
    allowNull: false,
    defaultValue: 'success'
  },
  errorMessage: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  archived: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false
  },
  entry_hash: {
    type: DataTypes.STRING(64),
    allowNull: true
  },
  prev_hash: {
    type: DataTypes.STRING(64),
    allowNull: true
  },
  metadata: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  hash_version: {
    type: DataTypes.INTEGER,
    allowNull: true
  }
}, {
  hooks: {
    beforeCreate: async (log, options) => {
      const crypto = require('crypto');
      const prevLog = await TransferLog.findOne({
        order: [['id', 'DESC']]
      });
      const prevHash = prevLog ? (prevLog.entry_hash || '0') : '0';
      log.prev_hash = prevHash;
      log.hash_version = 2; // New entries are version 2

      const logFields = {
        token: log.token || null,
        username: log.username || null,
        connectionId: log.connectionId,
        filePath: log.filePath,
        fileSize: log.fileSize ? parseInt(log.fileSize) : 0,
        action: log.action,
        status: log.status || 'success',
        errorMessage: log.errorMessage || null,
        metadata: log.metadata || null,
        prev_hash: prevHash
      };

      const hashInput = JSON.stringify(logFields);
      log.entry_hash = crypto.createHash('sha256').update(hashInput).digest('hex');
    }
  }
});

// 6. FileVersion
const FileVersion = sequelize.define('FileVersion', {
  id: {
    type: DataTypes.INTEGER,
    primaryKey: true,
    autoIncrement: true
  },
  connectionId: {
    type: DataTypes.STRING,
    allowNull: false
  },
  filePath: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  version: {
    type: DataTypes.INTEGER,
    allowNull: false
  },
  size: {
    type: DataTypes.BIGINT,
    allowNull: false
  },
  hash: {
    type: DataTypes.STRING,
    allowNull: true
  },
  backupPath: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  modifiedBy: {
    type: DataTypes.STRING, // username or user_id
    allowNull: true
  }
});

// 7. SystemConfig
const SystemConfig = sequelize.define('SystemConfig', {
  key: {
    type: DataTypes.STRING,
    primaryKey: true
  },
  value: {
    type: DataTypes.TEXT,
    allowNull: true
  }
});

// 8. PendingReversion
const PendingReversion = sequelize.define('PendingReversion', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true
  },
  groupId: {
    type: DataTypes.STRING,
    allowNull: false
  },
  connectionId: {
    type: DataTypes.STRING,
    allowNull: false
  },
  filePath: {
    type: DataTypes.STRING,
    allowNull: false
  },
  content: {
    type: DataTypes.TEXT,
    allowNull: false
  },
  status: {
    type: DataTypes.STRING,
    defaultValue: 'pending'
  },
  tokenHash: {
    type: DataTypes.STRING,
    allowNull: true
  }
});

// 9. AdminSession
const AdminSession = sequelize.define('AdminSession', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true
  },
  session_hash: {
    type: DataTypes.STRING(64),
    unique: true,
    allowNull: false
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'Users',
      key: 'id'
    },
    onDelete: 'CASCADE'
  },
  ipAddress: {
    type: DataTypes.STRING(45),
    allowNull: false
  },
  userAgent: {
    type: DataTypes.TEXT,
    allowNull: true
  },
  csrfToken: {
    type: DataTypes.STRING(32),
    allowNull: false
  },
  expiresAt: {
    type: DataTypes.DATE,
    allowNull: false
  },
  lastActivityAt: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  }
});

// 9.5. MfaChallenge
const MfaChallenge = sequelize.define('MfaChallenge', {
  id: {
    type: DataTypes.STRING,
    primaryKey: true
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: false,
    references: {
      model: 'Users',
      key: 'id'
    },
    onDelete: 'CASCADE'
  },
  createdAt: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  },
  expiresAt: {
    type: DataTypes.DATE,
    allowNull: false
  },
  consumed: {
    type: DataTypes.BOOLEAN,
    allowNull: false,
    defaultValue: false
  }
});

// Associations
User.hasMany(AdminSession, { foreignKey: 'userId', onDelete: 'CASCADE' });
AdminSession.belongsTo(User, { foreignKey: 'userId' });

User.hasMany(MfaChallenge, { foreignKey: 'userId', onDelete: 'CASCADE' });
MfaChallenge.belongsTo(User, { foreignKey: 'userId' });

// 10. KeyVersion
const KeyVersion = sequelize.define('KeyVersion', {
  version: {
    type: DataTypes.INTEGER,
    primaryKey: true
  },
  createdAt: {
    type: DataTypes.DATE,
    allowNull: false,
    defaultValue: DataTypes.NOW
  },
  retiredAt: {
    type: DataTypes.DATE,
    allowNull: true
  }
});

// Initialize database (sync schema)
// Initialize database (sync schema)
async function initDb() {
  const crypto = require('crypto');
  
  let existingKeys = [];
  try {
    const [results] = await sequelize.query("SELECT * FROM `AccessKeys` LIMIT 1");
    if (results.length > 0 && 'token' in results[0]) {
      const [allKeys] = await sequelize.query("SELECT * FROM `AccessKeys`");
      existingKeys = allKeys;
      console.log(`[Migration] Found ${existingKeys.length} existing plaintext tokens to migrate.`);
      await sequelize.query("DROP TABLE `AccessKeys`");
      console.log("[Migration] Dropped old AccessKeys table.");
    }
  } catch (err) {
    // Table or column doesn't exist yet, which is fine
  }

  if (sequelize.getDialect() === 'sqlite') {
    await sequelize.query("PRAGMA foreign_keys = OFF;");
  }
  await sequelize.sync({ alter: true });
  if (sequelize.getDialect() === 'sqlite') {
    await sequelize.query("PRAGMA foreign_keys = ON;");
  }

  // Enforce DB-level delete prevention triggers on TransferLogs
  try {
    const dialect = (sequelize.connectionManager && sequelize.connectionManager.dialectName) || sequelize.getDialect();
    if (dialect === 'sqlite') {
      await sequelize.query(`
        CREATE TRIGGER IF NOT EXISTS prevent_delete_transferlog
        BEFORE DELETE ON \`TransferLogs\`
        BEGIN
          SELECT RAISE(ABORT, 'Deletes are not allowed on TransferLogs table');
        END;
      `);
      console.log("[DB Trigger] SQLite prevent_delete_transferlog trigger configured.");
    } else if (dialect === 'mysql') {
      await sequelize.query(`DROP TRIGGER IF EXISTS prevent_delete_transferlog;`);
      await sequelize.query(`
        CREATE TRIGGER prevent_delete_transferlog BEFORE DELETE ON \`TransferLogs\`
        FOR EACH ROW
        BEGIN
          SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Deletes are not allowed on TransferLogs table';
        END;
      `);
      console.log("[DB Trigger] MySQL prevent_delete_transferlog trigger configured.");

      // Defensively attempt to revoke DELETE, DROP privileges on TransferLogs for the current user
      try {
        await sequelize.query(`REVOKE DELETE, DROP ON \`TransferLogs\` FROM CURRENT_USER;`);
        console.log("[DB Privilege] Revoked DELETE, DROP on TransferLogs from CURRENT_USER.");
      } catch (privErr) {
        console.warn(`[DB Privilege Warning] Could not revoke privileges (current connection user may have global grants or lack grant privileges): ${privErr.message}`);
      }
    } else if (dialect === 'postgres') {
      await sequelize.query(`
        CREATE OR REPLACE FUNCTION prevent_delete_transferlog_func()
        RETURNS TRIGGER AS $$
        BEGIN
          RAISE EXCEPTION 'Deletes are not allowed on TransferLogs table';
        END;
        $$ LANGUAGE plpgsql;
      `);
      await sequelize.query(`DROP TRIGGER IF EXISTS prevent_delete_transferlog ON "TransferLogs";`);
      await sequelize.query(`
        CREATE TRIGGER prevent_delete_transferlog
        BEFORE DELETE ON "TransferLogs"
        FOR EACH ROW
        EXECUTE FUNCTION prevent_delete_transferlog_func();
      `);
      console.log("[DB Trigger] PostgreSQL prevent_delete_transferlog trigger configured.");

      try {
        await sequelize.query(`REVOKE DELETE, TRUNCATE ON "TransferLogs" FROM CURRENT_USER;`);
        console.log("[DB Privilege] Revoked DELETE, TRUNCATE on TransferLogs from CURRENT_USER.");
      } catch (privErr) {
        console.warn(`[DB Privilege Warning] Could not revoke privileges: ${privErr.message}`);
      }
    }
  } catch (triggerErr) {
    console.error("Failed to configure database-level triggers or privileges:", triggerErr);
  }

  if (existingKeys.length > 0) {
    console.log(`[Migration] Migrating ${existingKeys.length} tokens to SHA-256...`);
    for (const key of existingKeys) {
      const rawToken = key.token;
      if (rawToken) {
        const hashed = crypto.createHash('sha256').update(rawToken).digest('hex');
        await AccessKey.create({
          token_hash: hashed,
          userId: key.userId,
          groupId: key.groupId,
          status: key.status,
          expiresAt: key.expiresAt
        });
      }
    }
    console.log("[Migration] Successfully migrated all existing tokens in-place.");
  }
  
  // Seed default system configs if not present
  await SystemConfig.findOrCreate({
    where: { key: 'siem_webhook_url' },
    defaults: { value: '' }
  });

  await SystemConfig.findOrCreate({
    where: { key: 'siem_webhook_secret' },
    defaults: { value: crypto.randomBytes(32).toString('hex') }
  });
  
  await SystemConfig.findOrCreate({
    where: { key: 'audit_logging_enabled' },
    defaults: { value: 'true' }
  });

  // Default admin user auto-seeding removed for security. First admin account must be created via setup wizard.

  // One-time migration from db.json if tables are empty
  const groupCount = await VaultGroup.count();
  const dbJsonPath = path.join(DATA_DIR, 'db.json');
  if (fs.existsSync(dbJsonPath)) {
    try {
      const rawJson = fs.readFileSync(dbJsonPath, 'utf8');
      const dbJson = JSON.parse(rawJson);

      if (groupCount === 0) {
        console.log('Migrating data from db.json into database...');
        // 1. Migrate Groups & Profiles
        if (dbJson.groups) {
          for (const g of dbJson.groups) {
            await VaultGroup.create({
              id: g.id,
              name: g.name,
              ipAllowlist: g.ip_allowlist || ''
            });

            if (g.profiles) {
              for (const p of g.profiles) {
                let keyVal = p.password || '';
                if (p.options && p.options.private_key) {
                  keyVal = p.options.private_key;
                }
                await ConnectionProfile.create({
                  id: p.id,
                  groupId: g.id,
                  name: p.name,
                  protocol: p.protocol,
                  host: p.host,
                  port: parseInt(p.port) || 22,
                  username: p.username || '',
                  passwordEncrypted: keyVal,
                  authMode: p.options && p.options.private_key ? 'keypair' : 'password'
                });
              }
            }
          }
        }
      }

      // 2. Migrate Access Tokens if table is empty AND SEED_DEV_TOKENS=true is set
      const tokenCount = await AccessKey.count();
      if (tokenCount === 0 && dbJson.tokens && process.env.SEED_DEV_TOKENS === 'true') {
        console.log('Seeding dev tokens from db.json into database...');
        for (const t of dbJson.tokens) {
          const username = t.user || 'Unknown User';
          const [usr] = await User.findOrCreate({
            where: { username },
            defaults: {
              passwordHash: crypto.createHash('sha256').update('temporary-user-password').digest('hex'),
              role: 'operator'
            }
          });

          const hashed = crypto.createHash('sha256').update(t.token).digest('hex');
          await AccessKey.create({
            token_hash: hashed,
            userId: usr.id,
            groupId: t.groupId,
            status: t.status || 'active',
            expiresAt: t.expires_at || ''
          });
        }
      }

      // 3. Backfill TransferLog hashes if missing
      const unhashedLogs = await TransferLog.findAll({
        where: { entry_hash: null },
        order: [['id', 'ASC']]
      });
      if (unhashedLogs.length > 0) {
        console.log(`[Migration] Backfilling hash chain for ${unhashedLogs.length} audit logs...`);
        for (const log of unhashedLogs) {
          const prevLog = await TransferLog.findOne({
            where: {
              id: {
                [Sequelize.Op.lt]: log.id
              }
            },
            order: [['id', 'DESC']]
          });
          const prevHash = prevLog ? (prevLog.entry_hash || '0') : '0';
          log.prev_hash = prevHash;

          const logFields = {
            token: log.token || null,
            username: log.username || null,
            connectionId: log.connectionId,
            filePath: log.filePath,
            fileSize: log.fileSize ? parseInt(log.fileSize) : 0,
            action: log.action,
            status: log.status || 'success',
            errorMessage: log.errorMessage || null,
            prev_hash: prevHash
          };
          const hashInput = JSON.stringify(logFields);
          log.entry_hash = crypto.createHash('sha256').update(hashInput).digest('hex');
          await log.save();
        }
        console.log('[Migration] Finished backfilling audit log hashes.');
      }

      // 4. Envelope Encryption Migration for VaultGroups
      await KeyVersion.findOrCreate({
        where: { version: 1 },
        defaults: { createdAt: new Date() }
      });

      const loadKekLocal = () => {
        const envKey = process.env.VAULT_MASTER_KEY;
        if (envKey) {
          if (envKey.length === 64 && /^[0-9a-fA-F]+$/.test(envKey)) {
            return Buffer.from(envKey, 'hex');
          } else if (envKey.length === 44 && /^[0-9a-zA-Z+/=]+$/.test(envKey)) {
            return Buffer.from(envKey, 'base64');
          } else {
            return Buffer.from(envKey, 'utf8');
          }
        }
        const keyPath = path.join(DATA_DIR, '.vault_key');
        if (fs.existsSync(keyPath)) {
          const fileKey = fs.readFileSync(keyPath).toString('utf8').trim();
          if (fileKey.length === 64 && /^[0-9a-fA-F]+$/.test(fileKey)) {
            return Buffer.from(fileKey, 'hex');
          } else if (fileKey.length === 44 && /^[0-9a-zA-Z+/=]+$/.test(fileKey)) {
            return Buffer.from(fileKey, 'base64');
          } else {
            return fs.readFileSync(keyPath);
          }
        }
        return crypto.scryptSync("fallback-vault-salt", "salt", 32);
      };

      const localKek = loadKekLocal();

      const decryptWithKeyLocal = (ciphertext, key) => {
        if (!ciphertext || !ciphertext.startsWith('enc:')) return ciphertext;
        try {
          const parts = ciphertext.split(':');
          if (parts.length !== 4) return ciphertext;
          const iv = Buffer.from(parts[1], 'hex');
          const tag = Buffer.from(parts[2], 'hex');
          const encryptedText = Buffer.from(parts[3], 'hex');
          const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
          decipher.setAuthTag(tag);
          let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
          decrypted += decipher.final('utf8');
          return decrypted;
        } catch (err) {
          console.error("Migration decryption failed:", err);
          return null;
        }
      };

      const encryptWithKeyLocal = (plaintext, key) => {
        if (!plaintext) return plaintext;
        try {
          const iv = crypto.randomBytes(12);
          const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
          let encrypted = cipher.update(plaintext, 'utf8', 'hex');
          encrypted += cipher.final('hex');
          const tag = cipher.getAuthTag().toString('hex');
          return `enc:${iv.toString('hex')}:${tag}:${encrypted}`;
        } catch (err) {
          console.error("Migration encryption failed:", err);
          throw err;
        }
      };

      const wrapDekLocal = (dek, kek) => {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
        let encrypted = cipher.update(dek);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        const tag = cipher.getAuthTag();
        const combined = Buffer.concat([iv, tag, encrypted]);
        return combined.toString('base64');
      };

      const unmigratedGroups = await VaultGroup.findAll({ where: { migrated: false } });
      if (unmigratedGroups.length > 0) {
        console.log(`[Migration] Migrating ${unmigratedGroups.length} VaultGroups to Envelope Encryption...`);
        for (const group of unmigratedGroups) {
          const dek = crypto.randomBytes(32);
          const profiles = await ConnectionProfile.findAll({ where: { groupId: group.id } });
          
          for (const p of profiles) {
            const decPass = decryptWithKeyLocal(p.passwordEncrypted, localKek);
            const decJumpPass = decryptWithKeyLocal(p.jumpPasswordEncrypted, localKek);
            
            p.passwordEncrypted = encryptWithKeyLocal(decPass, dek);
            p.jumpPasswordEncrypted = encryptWithKeyLocal(decJumpPass, dek);
            await p.save();
          }

          group.wrapped_dek = wrapDekLocal(dek, localKek);
          group.dek_version = 1;
          group.migrated = true;
          await group.save();
        }
        console.log('[Migration] Finished migrating groups to Envelope Encryption.');
      }

    } catch (err) {
      console.error('Failed to migrate/seed data from db.json:', err);
    }
  }

  // 3. Migrate legacy audit logs (move attribution JSON from errorMessage to metadata)
  try {
    const logs = await TransferLog.findAll();
    const unmigratedLogs = logs.filter(l => l.hash_version !== 1 && l.hash_version !== 2);
    if (unmigratedLogs.length > 0) {
      console.log(`[Migration] Migrating ${unmigratedLogs.length} legacy TransferLog entries...`);
      for (const log of unmigratedLogs) {
        if (log.errorMessage && log.errorMessage.trim().startsWith('{') && log.errorMessage.trim().endsWith('}')) {
          try {
            JSON.parse(log.errorMessage);
            log.metadata = log.errorMessage;
            log.errorMessage = null;
          } catch (e) {
            // Not valid JSON, keep as plain text errorMessage
          }
        }
        log.hash_version = 1;
        await log.save();
      }
      console.log("[Migration] Legacy TransferLog entries migration completed.");
    }
  } catch (migErr) {
    console.error("Failed to migrate legacy TransferLogs:", migErr);
  }
}

function updateDbConnection(config) {
  sequelize.config.database = config.database;
  sequelize.config.username = config.username;
  sequelize.config.password = config.password;
  sequelize.config.host = config.host || 'localhost';
  sequelize.config.port = config.port || 3306;
  
  sequelize.options.dialect = config.dialect || 'mysql';
  if (config.storage) {
    sequelize.options.storage = config.storage;
  }
  
  sequelize.options.dialectOptions = config.ssl ? {
    ssl: {
      require: true,
      rejectUnauthorized: false
    }
  } : {};

  if (sequelize.connectionManager) {
    if (sequelize.connectionManager.pool) {
      try {
        sequelize.connectionManager.pool.destroyAllNow();
      } catch (_) {}
    }
    if (sequelize.connectionManager.connections) {
      sequelize.connectionManager.connections = {};
    }
  }
}

module.exports = {
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
};
