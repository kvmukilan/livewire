import { defineConfig } from '@playwright/test';
const remoteURL = process.env.SITE_TEST_URL;
const basePath = process.env.PUBLIC_BASE_PATH || '/';
if (!/^\/(?:[A-Za-z0-9_-]+\/)*$/.test(basePath)) throw new Error('Invalid PUBLIC_BASE_PATH');
const baseURL = new URL(basePath, remoteURL || 'http://127.0.0.1:4321').href;
if (remoteURL) {
  const url = new URL(remoteURL);
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('SITE_TEST_URL must be an HTTPS origin with no credentials, path, query, or fragment');
  }
}
export default defineConfig({
  testDir: './tests',
  outputDir: process.env.SITE_TEST_OUTPUT || './test-results',
  fullyParallel: true,
  workers: process.env.CI ? 2 : 4,
  use: { baseURL, browserName: 'chromium', trace: 'retain-on-failure' },
  // Playwright owns this process. Astro's agent auto-backgrounding would exit
  // the launcher before Playwright can observe or stop its server.
  webServer: remoteURL ? undefined : { command: 'npm run preview -- --port 4321 --ignore-lock', url: baseURL, reuseExistingServer: false },
});
