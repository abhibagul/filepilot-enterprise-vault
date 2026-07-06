const { Sequelize } = require('sequelize');
const path = require('path');

const sequelize = new Sequelize({
  dialect: 'sqlite',
  storage: 'D:\\personalproj\\filepilot\\corporate-vault-integration\\vault.db',
  logging: false
});

async function clean() {
  try {
    console.log("Cleaning database tables...");
    await sequelize.query("DROP TABLE IF EXISTS `AccessKeys`;");
    await sequelize.query("DROP TABLE IF EXISTS `TransferLogs`;");
    await sequelize.query("DROP TABLE IF EXISTS `AdminSessions`;");
    console.log("Cleanup finished successfully!");
    process.exit(0);
  } catch (err) {
    console.error("Cleanup failed:", err);
    process.exit(1);
  }
}

clean();
