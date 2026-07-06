const crypto = require('crypto');
const {
  VaultGroup,
  KeyVersion,
  User,
  AccessKey,
  TransferLog,
  SystemConfig,
  AdminSession
} = require('./db.cjs');

// Granular RBAC Permission Matrix (must align with server.cjs)
const ROLE_PERMISSIONS = {
  admin: ['*'],
  manager: [
    'vault.*',
    'profile.*',
    'token.*',
    'backup.*',
    'audit.view',
    'system.view_dashboard'
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

// Reusable hash computation logic for log verification
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

/**
 * 1. Encryption Posture
 */
async function getEncryptionPosture() {
  const groups = await VaultGroup.findAll();
  const keyVersionCount = await KeyVersion.count();
  const rotationPerformed = keyVersionCount > 1;

  const groupPostures = groups.map(g => ({
    groupId: g.id,
    groupName: g.name,
    kmsProvider: g.kms_provider,
    dekVersion: g.dek_version,
    kekRotationPerformed: rotationPerformed || g.dek_version > 1
  }));

  return {
    rotationHistoryCount: keyVersionCount,
    globalRotationPerformed: rotationPerformed,
    groups: groupPostures
  };
}

/**
 * 2. Access Control Posture
 */
async function getAccessControlPosture() {
  const users = await User.findAll({ attributes: ['id', 'username', 'role', 'mfa_enabled'] });
  const tokens = await AccessKey.findAll({ include: [User] });

  const tokenList = [];
  for (const t of tokens) {
    const lastLog = await TransferLog.findOne({
      where: { token: t.token_hash },
      order: [['createdAt', 'DESC']]
    });
    const ageDays = (Date.now() - new Date(t.createdAt)) / (1000 * 60 * 60 * 24);
    tokenList.push({
      token_hash_truncated: t.token_hash.substring(0, 10) + '...',
      user: t.User ? t.User.username : 'Unknown',
      groupId: t.groupId,
      status: t.status,
      expiresAt: t.expiresAt,
      createdAt: t.createdAt,
      ageDays: parseFloat(ageDays.toFixed(2)),
      lastUsedAt: lastLog ? lastLog.createdAt : null
    });
  }

  return {
    rolePermissions: ROLE_PERMISSIONS,
    users: users.map(u => ({ id: u.id, username: u.username, role: u.role, mfa_enabled: u.mfa_enabled })),
    activeTokens: tokenList
  };
}

/**
 * 3. Audit Integrity Posture
 */
async function getAuditIntegrityPosture() {
  const logs = await TransferLog.findAll({ order: [['id', 'ASC']] });
  let intact = true;
  let brokenAtId = null;
  let reason = null;
  let expectedPrevHash = '0';

  for (const log of logs) {
    if (log.prev_hash !== expectedPrevHash) {
      intact = false;
      brokenAtId = log.id;
      reason = `prev_hash mismatch. Expected: ${expectedPrevHash}, Actual: ${log.prev_hash}`;
      break;
    }
    const computedHash = computeLogHash(log, expectedPrevHash);
    if (log.entry_hash !== computedHash) {
      intact = false;
      brokenAtId = log.id;
      reason = `entry_hash mismatch. Computed: ${computedHash}, Actual: ${log.entry_hash}`;
      break;
    }
    expectedPrevHash = computedHash;
  }

  const oldestLog = logs.length > 0 ? logs[0].createdAt : null;
  const newestLog = logs.length > 0 ? logs[logs.length - 1].createdAt : null;

  return {
    intact,
    brokenAtId,
    reason,
    totalCount: logs.length,
    oldestLog,
    newestLog
  };
}

/**
 * 4. Access Policy Posture
 */
async function getAccessPolicyPosture() {
  const groups = await VaultGroup.findAll();
  return groups.map(g => ({
    groupId: g.id,
    groupName: g.name,
    hasIpAllowlist: !!(g.ipAllowlist && g.ipAllowlist.trim() !== ''),
    ipAllowlist: g.ipAllowlist || ''
  }));
}

/**
 * 5. Session Security Posture
 */
async function getSessionSecurityPosture() {
  const sessionTimeoutConfig = await SystemConfig.findOne({ where: { key: 'session_timeout' } });
  const maxSessionsConfig = await SystemConfig.findOne({ where: { key: 'max_sessions_per_user' } });
  
  const sessionTimeout = sessionTimeoutConfig ? sessionTimeoutConfig.value : '28800000'; // default 8 hours in ms
  const maxSessionsPerUser = maxSessionsConfig ? maxSessionsConfig.value : '5'; // default 5
  
  const activeSessions = await AdminSession.findAll({ include: [User] });
  const userSessionsMap = {};
  for (const session of activeSessions) {
    const user = session.User || { username: 'Unknown' };
    const username = user.username;
    if (!userSessionsMap[username]) {
      userSessionsMap[username] = 0;
    }
    userSessionsMap[username]++;
  }

  return {
    sessionTimeoutMs: parseInt(sessionTimeout),
    maxSessionsPerUser: parseInt(maxSessionsPerUser),
    activeSessionsPerUser: userSessionsMap
  };
}

module.exports = {
  getEncryptionPosture,
  getAccessControlPosture,
  getAuditIntegrityPosture,
  getAccessPolicyPosture,
  getSessionSecurityPosture
};
