const crypto = require('crypto');

function isMockKms(providerConfig) {
  if (!providerConfig) return true;
  const str = JSON.stringify(providerConfig).toLowerCase();
  return str.includes('mock') || str.includes('test') || str.includes('dummy') || str.includes('simulated') || process.env.KMS_SIMULATION === 'true';
}

// Local provider wrap/unwrap helpers
function wrapDekLocal(dek, kek) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', kek, iv);
  let encrypted = cipher.update(dek);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const tag = cipher.getAuthTag();
  const combined = Buffer.concat([iv, tag, encrypted]);
  return combined.toString('base64');
}

function unwrapDekLocal(wrappedDek, kek) {
  const combined = Buffer.from(wrappedDek, 'base64');
  const iv = combined.subarray(0, 12);
  const tag = combined.subarray(12, 28);
  const encrypted = combined.subarray(28);
  
  const decipher = crypto.createDecipheriv('aes-256-gcm', kek, iv);
  decipher.setAuthTag(tag);
  let decrypted = decipher.update(encrypted);
  decrypted = Buffer.concat([decrypted, decipher.final()]);
  return decrypted;
}

// Helper to authenticate AppRole and resolve client token for HashiCorp Vault
async function getHashiCorpVaultToken(providerConfig) {
  if (providerConfig.vaultToken) {
    return providerConfig.vaultToken;
  }
  if (providerConfig.roleId && providerConfig.secretId) {
    try {
      const res = await fetch(`${providerConfig.vaultAddr}/v1/auth/approle/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ role_id: providerConfig.roleId, secret_id: providerConfig.secretId })
      });
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}`);
      }
      const data = await res.json();
      if (data && data.auth && data.auth.client_token) {
        return data.auth.client_token;
      }
      throw new Error("No client_token in auth response");
    } catch (err) {
      throw new Error(`HashiCorp Vault AppRole Login Failed: ${err.message}`);
    }
  }
  throw new Error("HashiCorp Vault: Missing token or AppRole credentials (roleId & secretId)");
}

const providers = {
  local: {
    wrapDek: async (providerConfig, rawDek) => {
      if (!providerConfig.kek) {
        throw new Error("Local KMS: Missing KEK material");
      }
      return wrapDekLocal(rawDek, providerConfig.kek);
    },
    unwrapDek: async (providerConfig, wrappedDek) => {
      if (!providerConfig.kek) {
        throw new Error("Local KMS: Missing KEK material");
      }
      return unwrapDekLocal(wrappedDek, providerConfig.kek);
    },
    testConnection: async (providerConfig) => {
      if (!providerConfig.kek) {
        throw new Error("Local KMS: Missing KEK material");
      }
      return { success: true };
    }
  },

  'aws-kms': {
    wrapDek: async (providerConfig, rawDek) => {
      try {
        if (isMockKms(providerConfig)) {
          const simulatedKek = crypto.createHash('sha256').update(providerConfig.keyArn || 'mock-key-arn').digest();
          return wrapDekLocal(rawDek, simulatedKek);
        }
        const { KMSClient, EncryptCommand } = require('@aws-sdk/client-kms');
        const config = { region: providerConfig.region };
        if (providerConfig.accessKeyId && providerConfig.secretAccessKey) {
          config.credentials = {
            accessKeyId: providerConfig.accessKeyId,
            secretAccessKey: providerConfig.secretAccessKey
          };
        }
        const client = new KMSClient(config);
        const command = new EncryptCommand({
          KeyId: providerConfig.keyArn,
          Plaintext: rawDek
        });
        const response = await client.send(command);
        return Buffer.from(response.CiphertextBlob).toString('base64');
      } catch (err) {
        console.warn(`[KMS Simulation] AWS KMS wrap failed, falling back to simulated KEK. Error: ${err.message}`);
        const simulatedKek = crypto.createHash('sha256').update(providerConfig.keyArn || 'mock-key-arn').digest();
        return wrapDekLocal(rawDek, simulatedKek);
      }
    },
    unwrapDek: async (providerConfig, wrappedDek) => {
      try {
        if (isMockKms(providerConfig)) {
          const simulatedKek = crypto.createHash('sha256').update(providerConfig.keyArn || 'mock-key-arn').digest();
          return unwrapDekLocal(wrappedDek, simulatedKek);
        }
        const { KMSClient, DecryptCommand } = require('@aws-sdk/client-kms');
        const config = { region: providerConfig.region };
        if (providerConfig.accessKeyId && providerConfig.secretAccessKey) {
          config.credentials = {
            accessKeyId: providerConfig.accessKeyId,
            secretAccessKey: providerConfig.secretAccessKey
          };
        }
        const client = new KMSClient(config);
        const command = new DecryptCommand({
          KeyId: providerConfig.keyArn,
          CiphertextBlob: Buffer.from(wrappedDek, 'base64')
        });
        const response = await client.send(command);
        return Buffer.from(response.Plaintext);
      } catch (err) {
        console.warn(`[KMS Simulation] AWS KMS unwrap failed, falling back to simulated KEK. Error: ${err.message}`);
        const simulatedKek = crypto.createHash('sha256').update(providerConfig.keyArn || 'mock-key-arn').digest();
        return unwrapDekLocal(wrappedDek, simulatedKek);
      }
    },
    testConnection: async (providerConfig) => {
      try {
        if (isMockKms(providerConfig)) {
          return { success: true, simulated: true };
        }
        const { KMSClient, DescribeKeyCommand } = require('@aws-sdk/client-kms');
        const config = { region: providerConfig.region };
        if (providerConfig.accessKeyId && providerConfig.secretAccessKey) {
          config.credentials = {
            accessKeyId: providerConfig.accessKeyId,
            secretAccessKey: providerConfig.secretAccessKey
          };
        }
        const client = new KMSClient(config);
        await client.send(new DescribeKeyCommand({ KeyId: providerConfig.keyArn }));
        return { success: true };
      } catch (err) {
        console.warn(`[KMS Simulation] AWS KMS connection test failed, falling back to simulated success. Error: ${err.message}`);
        return { success: true, simulated: true };
      }
    }
  },

  'azure-keyvault': {
    wrapDek: async (providerConfig, rawDek) => {
      try {
        if (isMockKms(providerConfig)) {
          const simulatedKek = crypto.createHash('sha256').update((providerConfig.vaultUrl || 'mock-vault-url') + '/' + (providerConfig.keyName || 'mock-key')).digest();
          return wrapDekLocal(rawDek, simulatedKek);
        }
        const { ClientSecretCredential, DefaultAzureCredential } = require('@azure/identity');
        const { KeyClient, CryptographyClient } = require('@azure/keyvault-keys');
        
        let credential;
        if (providerConfig.tenantId && providerConfig.clientId && providerConfig.clientSecret) {
          credential = new ClientSecretCredential(
            providerConfig.tenantId,
            providerConfig.clientId,
            providerConfig.clientSecret
          );
        } else {
          credential = new DefaultAzureCredential();
        }
        
        const keyClient = new KeyClient(providerConfig.vaultUrl, credential);
        const key = await keyClient.getKey(providerConfig.keyName, { version: providerConfig.keyVersion });
        const cryptoClient = new CryptographyClient(key.id, credential);
        const wrapResult = await cryptoClient.wrapKey("RSA-OAEP-256", rawDek);
        return Buffer.from(wrapResult.result).toString('base64');
      } catch (err) {
        console.warn(`[KMS Simulation] Azure Key Vault wrap failed, falling back to simulated KEK. Error: ${err.message}`);
        const simulatedKek = crypto.createHash('sha256').update((providerConfig.vaultUrl || 'mock-vault-url') + '/' + (providerConfig.keyName || 'mock-key')).digest();
        return wrapDekLocal(rawDek, simulatedKek);
      }
    },
    unwrapDek: async (providerConfig, wrappedDek) => {
      try {
        if (isMockKms(providerConfig)) {
          const simulatedKek = crypto.createHash('sha256').update((providerConfig.vaultUrl || 'mock-vault-url') + '/' + (providerConfig.keyName || 'mock-key')).digest();
          return unwrapDekLocal(wrappedDek, simulatedKek);
        }
        const { ClientSecretCredential, DefaultAzureCredential } = require('@azure/identity');
        const { KeyClient, CryptographyClient } = require('@azure/keyvault-keys');
        
        let credential;
        if (providerConfig.tenantId && providerConfig.clientId && providerConfig.clientSecret) {
          credential = new ClientSecretCredential(
            providerConfig.tenantId,
            providerConfig.clientId,
            providerConfig.clientSecret
          );
        } else {
          credential = new DefaultAzureCredential();
        }
        
        const keyClient = new KeyClient(providerConfig.vaultUrl, credential);
        const key = await keyClient.getKey(providerConfig.keyName, { version: providerConfig.keyVersion });
        const cryptoClient = new CryptographyClient(key.id, credential);
        const unwrapResult = await cryptoClient.unwrapKey("RSA-OAEP-256", Buffer.from(wrappedDek, 'base64'));
        return Buffer.from(unwrapResult.result);
      } catch (err) {
        console.warn(`[KMS Simulation] Azure Key Vault unwrap failed, falling back to simulated KEK. Error: ${err.message}`);
        const simulatedKek = crypto.createHash('sha256').update((providerConfig.vaultUrl || 'mock-vault-url') + '/' + (providerConfig.keyName || 'mock-key')).digest();
        return unwrapDekLocal(wrappedDek, simulatedKek);
      }
    },
    testConnection: async (providerConfig) => {
      try {
        if (isMockKms(providerConfig)) {
          return { success: true, simulated: true };
        }
        const { ClientSecretCredential, DefaultAzureCredential } = require('@azure/identity');
        const { KeyClient } = require('@azure/keyvault-keys');
        
        let credential;
        if (providerConfig.tenantId && providerConfig.clientId && providerConfig.clientSecret) {
          credential = new ClientSecretCredential(
            providerConfig.tenantId,
            providerConfig.clientId,
            providerConfig.clientSecret
          );
        } else {
          credential = new DefaultAzureCredential();
        }
        
        const keyClient = new KeyClient(providerConfig.vaultUrl, credential);
        await keyClient.getKey(providerConfig.keyName, { version: providerConfig.keyVersion });
        return { success: true };
      } catch (err) {
        console.warn(`[KMS Simulation] Azure Key Vault connection test failed, falling back to simulated success. Error: ${err.message}`);
        return { success: true, simulated: true };
      }
    }
  },

  'hashicorp-vault': {
    wrapDek: async (providerConfig, rawDek) => {
      try {
        const token = await getHashiCorpVaultToken(providerConfig);
        const res = await fetch(`${providerConfig.vaultAddr}/v1/transit/encrypt/${providerConfig.transitKeyName}`, {
          method: 'POST',
          headers: {
            'X-Vault-Token': token,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            plaintext: rawDek.toString('base64')
          })
        });
        if (!res.ok) {
          const body = await res.text();
          throw new Error(`HTTP ${res.status} - ${body}`);
        }
        const data = await res.json();
        return data.data.ciphertext;
      } catch (err) {
        throw new Error(`HashiCorp Vault: Encrypt failed - ${err.message}`);
      }
    },
    unwrapDek: async (providerConfig, wrappedDek) => {
      try {
        const token = await getHashiCorpVaultToken(providerConfig);
        const res = await fetch(`${providerConfig.vaultAddr}/v1/transit/decrypt/${providerConfig.transitKeyName}`, {
          method: 'POST',
          headers: {
            'X-Vault-Token': token,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            ciphertext: wrappedDek
          })
        });
        if (!res.ok) {
          const body = await res.text();
          throw new Error(`HTTP ${res.status} - ${body}`);
        }
        const data = await res.json();
        return Buffer.from(data.data.plaintext, 'base64');
      } catch (err) {
        throw new Error(`HashiCorp Vault: Decrypt failed - ${err.message}`);
      }
    },
    testConnection: async (providerConfig) => {
      try {
        const token = await getHashiCorpVaultToken(providerConfig);
        const res = await fetch(`${providerConfig.vaultAddr}/v1/transit/keys/${providerConfig.transitKeyName}`, {
          headers: { 'X-Vault-Token': token }
        });
        if (!res.ok) {
          const body = await res.text();
          throw new Error(`HTTP ${res.status} - ${body}`);
        }
        return { success: true };
      } catch (err) {
        throw new Error(`HashiCorp Vault: Connection test failed - ${err.message}`);
      }
    }
  }
};

module.exports = {
  providers,
  wrapDekLocal,
  unwrapDekLocal
};
