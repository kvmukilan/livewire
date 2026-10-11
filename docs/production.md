# Website deployment checks

PR CI now builds and runs the browser, accessibility, link, and responsive checks for both `/` and the production `/livewire/` base path. Changes to the Pages workflow also trigger these checks. Playwright launches a foreground preview process even when Astro detects a coding agent, so the test runner owns its lifetime.

Locally, run `PUBLIC_SITE_URL=https://kvmukilan.github.io PUBLIC_BASE_PATH=/livewire/ npm run build` and the same environment with `npm test` from `website/`. Run `npx playwright install chromium` first.

The Pages workflow accepts deployment only from main, including manual dispatch, and publishes the exact verified static output. Inspect the published site and retain the previous Pages deployment for rollback. These changes preserve the existing binary release and field-qualification gates; no release qualification is claimed by website tests.
