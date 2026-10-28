// Browser tests against a real server with the built UI (build it first: `trunk build` in crates/hast-web).
// Local runs can use an installed browser instead of downloading one: PW_CHANNEL=msedge (or chrome) npx playwright test
const { defineConfig } = require('@playwright/test');
const fs = require('fs');
const path = require('path');

const tmp = path.join(__dirname, '.tmp');
// the config is loaded by every worker too; only the main process starts from an empty database
if (!process.env.TEST_WORKER_INDEX) {
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.mkdirSync(tmp, { recursive: true });
}

module.exports = defineConfig({
  testDir: 'tests',
  timeout: 120_000,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://localhost:8123',
    channel: process.env.PW_CHANNEL || undefined,
  },
  webServer: {
    command: 'cargo run -q -p hast-server',
    cwd: path.join(__dirname, '..'),
    url: 'http://localhost:8123/health',
    timeout: 15 * 60_000, // includes compiling the server on a cold cache
    reuseExistingServer: false,
    env: {
      PORT: '8123',
      HAST_DB: path.join(tmp, 'e2e.db'),
      HAST_STATIC_DIR: 'crates/hast-web/dist',
      HAST_HISTORY_FILE: path.join(tmp, 'no-history.jsonl'),
      HAST_MESSAGING_STORE: path.join(tmp, 'messaging.json'),
      // each test browser claims its own address (see newPage), so the per-address signup limit is not hit
      HAST_TRUSTED_PROXIES: '127.0.0.1,::1',
    },
  },
});
