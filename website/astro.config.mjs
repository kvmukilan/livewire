import { defineConfig } from 'astro/config';

// Set PUBLIC_SITE_URL to the verified production origin when deploying.
const site = process.env.PUBLIC_SITE_URL;
if (site && (!URL.canParse(site) || new URL(site).protocol !== 'https:')) {
  throw new Error('PUBLIC_SITE_URL must be an absolute HTTPS URL');
}
export default defineConfig({
  site,
  output: 'static',
  trailingSlash: 'always',
  devToolbar: { enabled: false },
  markdown: { shikiConfig: { theme: 'github-dark-high-contrast' } },
});
