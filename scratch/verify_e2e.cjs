const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const assert = require('assert');
const WebSocket = require('ws');

const PORT = '8200';

// Load seeded setup info
const setupInfoPath = path.join(__dirname, 'e2e_setup_info.json');
if (!fs.existsSync(setupInfoPath)) {
  console.error("Seeded setup info not found. Please run run_e2e_setup.cjs first.");
  process.exit(1);
}

const { groupId, token, syncUrl } = JSON.parse(fs.readFileSync(setupInfoPath, 'utf8'));
const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

async function run() {
  try {
    console.log("--- 1. Authenticating Admin Console ---");
    const loginRes = await fetch(`http://127.0.0.1:${PORT}/admin/api/verify-auth`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'vault-admin-pass' })
    });
    const cookie = loginRes.headers.get('set-cookie').split(';')[0];
    const { csrfToken } = await loginRes.json();
    const adminHeaders = {
      'Cookie': cookie,
      'X-CSRF-Token': csrfToken,
      'Content-Type': 'application/json'
    };

    console.log("--- 2. Simulating Client Profile Sync ---");
    console.log(`Syncing from URL: ${syncUrl} with token: ${token}`);
    const syncRes = await fetch(syncUrl, {
      headers: { 'X-Vault-Token': token }
    });
    
    assert.strictEqual(syncRes.status, 200, `Sync failed: ${syncRes.status}`);
    const syncData = await syncRes.json();
    console.log("Sync response keys:", Object.keys(syncData));
    console.log("Vault Name:", syncData.vault_name);
    assert.ok(syncData.profiles, "Sync data must contain profiles");
    
    const sftpProfile = syncData.profiles.find(p => p.name === 'Walkthrough SFTP');
    assert.ok(sftpProfile, "Profiles list must contain 'Walkthrough SFTP'");
    console.log("Synced profile details successfully:", {
      name: sftpProfile.name,
      protocol: sftpProfile.protocol,
      host: sftpProfile.host,
      port: sftpProfile.port,
      username: sftpProfile.username
    });

    console.log("--- 3. Connecting Client WebSocket ---");
    const wsUrl = `ws://127.0.0.1:${PORT}/?token=${token}`;
    const ws = new WebSocket(wsUrl);

    let wsMessages = [];
    let wsClosed = false;

    ws.on('open', () => {
      console.log("WebSocket connected successfully!");
    });

    ws.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      console.log("[WebSocket Received]:", msg);
      wsMessages.push(msg);
    });

    ws.on('close', () => {
      console.log("WebSocket connection closed.");
      wsClosed = true;
    });

    // Wait 2 seconds for WS registration
    await new Promise(r => setTimeout(r, 2000));

    console.log("--- 4. Revoking Scoped Token ---");
    const revokeRes = await fetch(`http://127.0.0.1:${PORT}/admin/api/tokens`, {
      method: 'POST',
      headers: adminHeaders,
      body: JSON.stringify({
        token_hash: tokenHash,
        user: 'walkthrough_user',
        groupId,
        status: 'blocked'
      })
    });
    
    assert.strictEqual(revokeRes.status, 200, "Revoke token request failed");
    console.log("Token revoked in Admin panel.");

    // Wait 2 seconds for WS revocation notice
    await new Promise(r => setTimeout(r, 2000));

    assert.ok(wsClosed, "WebSocket should have closed automatically on token revocation");
    const revokeMsg = wsMessages.find(m => m.type === 'revoked');
    assert.ok(revokeMsg, "WebSocket must have received a 'revoked' payload before closing");
    console.log("✅ WebSocket connection terminated with 'revoked' payload.");

    console.log("--- 5. Verifying Subsequent Sync Attempts Fail ---");
    const syncResAfterRevocation = await fetch(syncUrl, {
      headers: { 'X-Vault-Token': token }
    });
    assert.ok(
      syncResAfterRevocation.status === 401 || syncResAfterRevocation.status === 403,
      `Sync should be blocked after revocation, but got status ${syncResAfterRevocation.status}`
    );
    console.log("✅ Subsequent sync attempt was blocked with status:", syncResAfterRevocation.status);

    console.log("--- 6. Re-enabling Token for Reversion Test ---");
    const enableRes = await fetch(`http://127.0.0.1:${PORT}/admin/api/tokens`, {
      method: 'POST',
      headers: adminHeaders,
      body: JSON.stringify({
        token_hash: tokenHash,
        user: 'walkthrough_user',
        groupId,
        status: 'active'
      })
    });
    assert.strictEqual(enableRes.status, 200, "Token reactivation failed");

    console.log("--- 7. Uploading a File Version ---");
    const testContent = "This is the rolled-back content from the corporate vault!";
    const uploadRes = await fetch(`http://127.0.0.1:${PORT}/v1/files/version`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token,
        connectionId: 'CONN_WALKTHROUGH',
        profileName: 'Walkthrough SFTP',
        filePath: '/test_walkthrough.txt',
        size: testContent.length,
        content: testContent,
        modifiedBy: 'walkthrough_user'
      })
    });
    assert.strictEqual(uploadRes.status, 200, "Version upload failed");
    const uploadData = await uploadRes.json();
    console.log("Uploaded version number:", uploadData.version);

    console.log("--- 8. Connecting Client WebSocket Again ---");
    const ws2 = new WebSocket(wsUrl);
    let ws2Messages = [];
    let ws2Closed = false;

    ws2.on('open', () => {
      console.log("WebSocket 2 connected successfully!");
    });

    ws2.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      console.log("[WebSocket 2 Received]:", msg);
      ws2Messages.push(msg);
    });

    ws2.on('close', () => {
      ws2Closed = true;
    });

    await new Promise(r => setTimeout(r, 2000));

    console.log("--- 9. Simulating Remote Rollback / Reversion ---");
    // Fetch version list to find the restore target version ID
    const versionsRes = await fetch(`http://127.0.0.1:${PORT}/admin/api/versions`, { headers: adminHeaders });
    const versionsList = await versionsRes.json();
    const targetVer = versionsList.find(v => v.connectionId === 'CONN_WALKTHROUGH' && v.filePath === '/test_walkthrough.txt');
    assert.ok(targetVer, "Should find the uploaded file version in the list");
    console.log(`Restoring File Version ID: ${targetVer.id}`);

    // Trigger restore
    const restoreRes = await fetch(`http://127.0.0.1:${PORT}/admin/api/versions/restore`, {
      method: 'POST',
      headers: adminHeaders,
      body: JSON.stringify({
        versionId: targetVer.id
      })
    });
    assert.strictEqual(restoreRes.status, 200, `Restore request failed: ${restoreRes.status}`);
    console.log("Restore triggered successfully.");

    // Wait 2 seconds for WS reversion delivery
    await new Promise(r => setTimeout(r, 2000));

    const reversionMsg = ws2Messages.find(m => m.type === 'write_file');
    assert.ok(reversionMsg, "WebSocket must have received a 'write_file' rollback command");
    assert.strictEqual(reversionMsg.connectionId, 'CONN_WALKTHROUGH', "Reversion connectionId mismatch");
    assert.strictEqual(reversionMsg.filePath, '/test_walkthrough.txt', "Reversion filePath mismatch");
    assert.strictEqual(reversionMsg.content, testContent, "Reversion content mismatch");
    console.log("✅ WebSocket received remote write_file reversion successfully.");

    ws2.close();
    console.log("\n🎉 ALL E2E CLIENT-VAULT INTEGRATION TESTS PASSED CLEANLY! 🎉\n");
    process.exit(0);
  } catch (err) {
    console.error("❌ E2E INTEGRATION TEST FAILED:", err);
    process.exit(1);
  }
}

run();
