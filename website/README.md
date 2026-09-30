# Livewire website

Static Astro product and operator documentation site. No capture upload, replay
API, telemetry, remote font request, or credential collection is included.

## Local checks

Use Node 22.x, at least 22.12 (tested with 22.22.2), and npm 10.9.7:

```sh
npm ci
npm run build
npx playwright install chromium
npm test
npm run dev
```

`build` runs Astro type checks, creates the static site, and verifies internal
links, download names, documentation provenance, local fonts, and the JavaScript
size budget. Browser checks cover WCAG rules, four responsive sizes, keyboard
navigation, copy feedback, no-JavaScript operation, and the custom 404. Screenshots
are generated under ignored `test-results/` for visual review. Automated checks
do not replace a human accessibility audit.

For a deployed preview, set `SITE_TEST_URL` to its HTTPS origin before running
`npm test`. This disables the local preview server and runs the same checks
against that origin. `SITE_TEST_OUTPUT` selects a separate ignored artifact
directory for remote screenshots and failure traces. Never put credentials or
private claim URLs in these variables or reports.

The build and browser checks must receive the same `PUBLIC_BASE_PATH`. They
check all internal links and assets against that prefix, verify canonical and
sitemap URLs, and exercise the custom 404 and reference guides at mobile and
desktop sizes. `SITE_TEST_URL` is always the origin; the configured base is
added by the test runner.

## Reviewed content boundary

The only release metadata is `src/data/release.json`. Promote it only after the
release and artifacts have been verified. `packetCommand` and `contract` keep
published command behavior explicit. In v1.1.0, `live` creates fresh sessions,
`reproduce` sends recorded packets, and `replay` is its compatibility alias.
The historical v1.0.x `reproduce` command used application replay; migrate those
workflows to `live`. Never promote these metadata before verifying the release.

Six operator guides are imported from the immutable `docsRef` tag by
`npm run docs:sync`. The explicit allowlist is in `scripts/sync-docs.mjs`; the
generated Markdown and SHA-256 provenance are committed. Builds do not fetch or
silently import in-flight repository documentation. Never add captures, key logs,
private fixtures, or the qualification evidence tree to the site. The TLS capture
guide distinguishes handshake-only replay without secrets from application
replay with embedded TLSK secrets or an explicit matching key log. A fresh
handshake is not an application response match.

## Vercel

Use `website/` as the project root, the Astro preset, `npm ci`, and `npm run build`.
The deployment output is `website/dist/`. No server adapter is required. Deploy
only this site directory/output, never the repository's capture evidence tree.

Set `PUBLIC_SITE_URL` to the final verified HTTPS origin (without a path) for canonical URLs,
the sitemap, and crawlable robots policy. Without it, robots disallows crawling
and canonical URLs are omitted. A temporary preview is not a permanent owned
production domain. Deployment and account ownership are handled separately.

## GitHub Pages project site

Following [Astro's GitHub Pages guidance](https://docs.astro.build/en/guides/deploy/github/),
use a separate origin and project base. Set these environment variables for both
`npm run build` and `npm test`:

```yaml
PUBLIC_SITE_URL: https://kvmukilan.github.io
PUBLIC_BASE_PATH: /livewire/
```

The resulting canonical home URL is `https://kvmukilan.github.io/livewire/`.
Upload only `website/dist/` using the reviewed Pages workflow. `.nojekyll` is
included. Navigation, public assets, imported reference links, sitemap entries,
and the custom `404.html` retain the project prefix. No browser-side router or
fallback to an application page is used.

For root-path Vercel hosting, leave `PUBLIC_BASE_PATH` unset (it defaults to `/`)
and set `PUBLIC_SITE_URL` to that verified origin. GitHub Pages controls its own
HTTP response headers; Vercel's `vercel.json` header rules do not apply there.
The project-local `robots.txt` is published under `/livewire/`; ownership of the
account-root robots policy is separate. Preview builds without a production
origin include `noindex` and never invent a canonical domain.

Design: slate/navy surfaces, green state indicators, local IBM Plex Sans and
JetBrains Mono fonts, native links/details, visible keyboard focus, minimal
client-side JavaScript, and reduced-motion support.

The redistributed fonts' license notices are included in `public/` and the
built site as `ibm-plex-sans-LICENSE.txt` and `jetbrains-mono-LICENSE.txt`.
