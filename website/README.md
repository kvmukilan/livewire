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

## Reviewed content boundary

The only release metadata is `src/data/release.json`. Promote it only after the
release and artifacts have been verified. `packetCommand` and `contract` keep
published command behavior distinct from the planned corrected contract. The
initial published v1.0.1 metadata deliberately uses `replay` for stateless packet
examples because that binary's `reproduce` is application replay.

Five operator guides are imported from the immutable `docsRef` tag by
`npm run docs:sync`. The explicit allowlist is in `scripts/sync-docs.mjs`; the
generated Markdown and SHA-256 provenance are committed. Builds do not fetch or
silently import in-flight repository documentation. Never add captures, key logs,
private fixtures, or the qualification evidence tree to the site.

## Vercel

Use `website/` as the project root, the Astro preset, `npm ci`, and `npm run build`.
The deployment output is `website/dist/`. No server adapter is required. Deploy
only this site directory/output, never the repository's capture evidence tree.

Set `PUBLIC_SITE_URL` to the final verified HTTPS origin for canonical URLs,
the sitemap, and crawlable robots policy. Without it, robots disallows crawling
and canonical URLs are omitted. A temporary preview is not a permanent owned
production domain. Deployment and account ownership are handled separately.

Design: slate/navy surfaces, green state indicators, local IBM Plex Sans and
JetBrains Mono fonts, native links/details, visible keyboard focus, minimal
client-side JavaScript, and reduced-motion support.

The redistributed fonts' license notices are included in `public/` and the
built site as `ibm-plex-sans-LICENSE.txt` and `jetbrains-mono-LICENSE.txt`.
