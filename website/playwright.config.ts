import { defineConfig } from '@playwright/test';
const remoteURL = process.env.SITE_TEST_URL;
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
  use: { baseURL: remoteURL || 'http://127.0.0.1:4321', browserName: 'chromium', trace: 'retain-on-failure' },
  webServer: remoteURL ? undefined : { command: 'npm run preview -- --port 4321', url: 'http://127.0.0.1:4321', reuseExistingServer: false },
});
