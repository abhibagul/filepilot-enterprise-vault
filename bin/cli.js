#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline/promises');
const { stdin: input, stdout: output } = require('process');

const DATA_DIR = process.env.VAULT_DATA_DIR || process.cwd();
const KEY_FILE = path.join(DATA_DIR, '.vault_key');
const configPath = path.join(DATA_DIR, 'config.json');

async function ask(rl, query, defaultValue) {
  const displayQuery = defaultValue !== undefined ? `${query} [${defaultValue}]: ` : `${query}: `;
  const answer = await rl.question(displayQuery);
  return answer.trim() || defaultValue;
}

async function askPassword(rl, query) {
  if (!process.stdin.isTTY) {
    const answer = await rl.question(query + ': ');
    return answer.trim();
  }
  
  return new Promise((resolve) => {
    process.stdout.write(query + ': ');
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');
    
    let password = '';
    const onData = (char) => {
      char = char.toString();
      if (char === '\n' || char === '\r' || char === '\u0004') {
        process.stdin.setRawMode(false);
        process.stdin.removeListener('data', onData);
        process.stdout.write('\n');
        resolve(password.trim());
      } else if (char === '\u0003') {
        process.exit();
      } else if (char === '\u0008' || char === '\u007f') {
        if (password.length > 0) {
          password = password.slice(0, -1);
          process.stdout.write('\b \b');
        }
      } else {
        password += char;
        process.stdout.write('*');
      }
    };
    process.stdin.on('data', onData);
  });
}

async function runCliWizard() {
  console.log('==================================================');
  console.log('  FilePilot Enterprise Vault Installation Wizard  ');
  console.log('==================================================\n');

  const rl = readline.createInterface({ input, output });

  try {
    // 1. Check if already installed
    const envFilePath = path.join(DATA_DIR, '.env');
    if (fs.existsSync(envFilePath) || fs.existsSync(configPath)) {
      const overwrite = await ask(rl, 'A configuration already exists. Do you want to overwrite it? (y/n)', 'n');
      if (overwrite.toLowerCase() !== 'y') {
        console.log('Initialization aborted.');
        rl.close();
        return false;
      }
    }

    // Ensure data directory exists
    fs.mkdirSync(DATA_DIR, { recursive: true });

    // 2. Database dialect selection
    let dialect = '';
    while (true) {
      dialect = await ask(rl, 'Database dialect (sqlite / postgres / mysql)', 'sqlite');
      dialect = dialect.toLowerCase();
      if (['sqlite', 'postgres', 'mysql'].includes(dialect)) {
        break;
      }
      console.log('Invalid dialect. Please choose sqlite, postgres, or mysql.');
    }

    let dbConfig = { dialect };

    if (dialect === 'sqlite') {
      const defaultDbPath = path.join(DATA_DIR, 'vault.db');
      const dbStorage = await ask(rl, `SQLite database file storage path`, defaultDbPath);
      dbConfig.storage = path.resolve(dbStorage);
    } else {
      const defaultPort = dialect === 'postgres' ? '5432' : '3306';
      dbConfig.host = await ask(rl, 'Database host', 'localhost');
      dbConfig.port = parseInt(await ask(rl, 'Database port', defaultPort)) || parseInt(defaultPort);
      dbConfig.username = await ask(rl, 'Database username', 'vault_admin');
      dbConfig.password = await askPassword(rl, 'Database password');
      dbConfig.database = await ask(rl, 'Database name', 'filepilot_vault');
      
      const sslRequired = await ask(rl, 'Enable SSL/TLS for database connection? (y/n)', 'n');
      if (sslRequired.toLowerCase() === 'y') {
        dbConfig.ssl = true;
      }
    }

    // 3. Encryption key setup
    console.log('\n--- Encryption Key Setup ---');
    console.log('1. Generate a new random 256-bit key (Recommended)');
    console.log('2. Enter a custom key');
    const keyChoice = await ask(rl, 'Choose an option', '1');

    let masterKeyStr;
    if (keyChoice === '2') {
      const customKey = await askPassword(rl, 'Enter your 256-bit Master Key (hex, base64 or plaintext)');
      masterKeyStr = customKey;
    } else {
      masterKeyStr = crypto.randomBytes(32).toString('hex');
      console.log(`Generated new master key: ${masterKeyStr}`);
      console.log('This key will be written to your .env file.');
    }

    // 4. Create Administrator Account
    console.log('\n--- Create Administrator Account ---');
    const adminUsername = await ask(rl, 'Admin username', 'admin');
    let adminPassword = '';
    while (true) {
      adminPassword = await askPassword(rl, 'Admin password');
      if (adminPassword.length < 8) {
        console.log('Password must be at least 8 characters long.');
        continue;
      }
      const confirmPassword = await askPassword(rl, 'Confirm admin password');
      if (adminPassword === confirmPassword) {
        break;
      }
      console.log('Passwords do not match. Please try again.');
    }

    // 5. Write env configurations
    console.log('\nWriting configurations...');
    
    const envContent = [
      `# FilePilot Corporate Vault Environment Configuration`,
      `VAULT_MASTER_KEY=${masterKeyStr}`,
      `DB_DIALECT=${dbConfig.dialect}`,
      `DB_HOST=${dbConfig.host || 'localhost'}`,
      `DB_PORT=${dbConfig.port || ''}`,
      `DB_USERNAME=${dbConfig.username || ''}`,
      `DB_PASSWORD=${dbConfig.password || ''}`,
      `DB_NAME=${dbConfig.database || ''}`,
      `DB_STORAGE=${dbConfig.storage || ''}`,
      `DB_SSL=${dbConfig.ssl || 'false'}`
    ].join('\n');

    fs.writeFileSync(envFilePath, envContent, 'utf8');
    console.log(`Saved configuration to: ${envFilePath}`);

    // Clean up legacy files to avoid confusion
    if (fs.existsSync(configPath)) {
      try { fs.unlinkSync(configPath); } catch (_) {}
    }
    if (fs.existsSync(KEY_FILE)) {
      try { fs.unlinkSync(KEY_FILE); } catch (_) {}
    }

    // Set environment variables so the database library loads them correctly
    process.env.VAULT_DATA_DIR = DATA_DIR;
    process.env.VAULT_MASTER_KEY = masterKeyStr;
    process.env.DB_DIALECT = dbConfig.dialect;
    process.env.DB_HOST = dbConfig.host || 'localhost';
    if (dbConfig.port) process.env.DB_PORT = String(dbConfig.port);
    if (dbConfig.username) process.env.DB_USERNAME = dbConfig.username;
    if (dbConfig.password) process.env.DB_PASSWORD = dbConfig.password;
    if (dbConfig.database) process.env.DB_NAME = dbConfig.database;
    if (dbConfig.storage) process.env.DB_STORAGE = dbConfig.storage;
    process.env.DB_SSL = dbConfig.ssl ? 'true' : 'false';

    // 6. Connect and run database setup
    console.log('Initializing database models and schema...');
    try {
      const dbPath = require.resolve(path.join(__dirname, '..', 'db.cjs'));
      delete require.cache[dbPath];
    } catch (_) {}
    const db = require(path.join(__dirname, '..', 'db.cjs'));
    
    db.updateDbConnection(dbConfig);
    await db.initDb();

    // 7. Seed Admin user
    const adminHash = crypto.createHash('sha256').update(adminPassword).digest('hex');
    let adminUser = await db.User.findOne({ where: { username: adminUsername } });
    if (adminUser) {
      adminUser.passwordHash = adminHash;
      adminUser.role = 'admin';
      await adminUser.save();
    } else {
      await db.User.create({
        username: adminUsername,
        passwordHash: adminHash,
        role: 'admin'
      });
    }

    // 8. Seed default configurations
    await db.SystemConfig.findOrCreate({ where: { key: 'siem_webhook_url' }, defaults: { value: '' } });
    await db.SystemConfig.findOrCreate({ where: { key: 'siem_webhook_secret' }, defaults: { value: crypto.randomBytes(32).toString('hex') } });
    await db.SystemConfig.findOrCreate({ where: { key: 'audit_logging_enabled' }, defaults: { value: 'true' } });

    console.log('\n==================================================');
    console.log('  Installation Completed Successfully!           ');
    console.log('==================================================\n');
    return true;
  } catch (err) {
    console.error('\nInstallation failed:', err);
    return false;
  } finally {
    rl.close();
  }
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] || 'start';

  if (command === 'init') {
    await runCliWizard();
  } else if (command === 'start') {
    console.log('Starting FilePilot Enterprise Vault Server...');
    process.env.RUN_VAULT_SERVER = 'true';
    process.env.VAULT_DATA_DIR = DATA_DIR;
    // Require server.cjs to run the server in the current process
    require('../server.cjs');
  } else {
    console.log('Usage: filepilot-vault [init | start]');
    console.log('\nCommands:');
    console.log('  init   - Run interactive installation wizard to configure the vault');
    console.log('  start  - Start the vault server');
  }
}

if (require.main === module) {
  main().catch(console.error);
}

module.exports = { runCliWizard };
