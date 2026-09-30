import { defineConfig } from 'astro/config';

// Keep the production origin separate from the optional project path.
const site = process.env.PUBLIC_SITE_URL;
if (site && (!URL.canParse(site) || new URL(site).protocol !== 'https:' || new URL(site).pathname !== '/' || new URL(site).search || new URL(site).hash || new URL(site).username || new URL(site).password)) {
  throw new Error('PUBLIC_SITE_URL must be an HTTPS origin without a path, credentials, query, or fragment');
}
const base = process.env.PUBLIC_BASE_PATH || '/';
if (!/^\/(?:[A-Za-z0-9_-]+\/)*$/.test(base)) throw new Error('PUBLIC_BASE_PATH must be / or an absolute path with a trailing slash, such as /livewire/');
export default defineConfig({
  site,
  base,
  output: 'static',
  trailingSlash: 'always',
  devToolbar: { enabled: false },
  markdown: { shikiConfig: { theme: 'github-dark-high-contrast' } },
});
