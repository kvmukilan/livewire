# Livewire website on Vercel

## Purpose and scope

The public product and documentation site is implemented in `website/`.
It is static: it explains the workflows, links verified
GitHub downloads, and expose the supported protocol matrix and qualification
boundaries. Captures, TLS key logs and credentials stay on the operator's machine.
The existing `livewire web` dashboard remains the local replay interface.

## Pages

| Page | Content and acceptance criteria |
|---|---|
| Home | Explain fresh live sessions and stateless packet replay, show one working example of each, link installation and downloads. |
| Install | Windows/Linux steps, packet-driver versus socket prerequisites, checksums and provenance verification. |
| Workflows | Stateful `live`, stateless `reproduce` from 1.1, compatibility `replay`, selection, preview, repeated attempts, fault expectations and recovery. |
| Secure replay | TLS/keylog example, fresh certificate verification, FTPS/SSH requirements, explicit unsupported cases. |
| Protocols | Supported application families, transport-only behavior, evidence links and limits; no claims of universal protocol or hardware support. |
| Releases | Version-pinned links to GitHub releases, checksum manifests and qualification evidence. |
| Troubleshooting | Missing keys, unknown TCP, capture gaps, permissions, response divergence and redacted support reports. |

## Implementation decisions

The implementation uses Astro with static output in `website/`, a committed dependency lockfile,
locally hosted fonts and minimal client JavaScript. Vercel documents native
[Astro deployment support](https://vercel.com/docs/frameworks/frontend/astro).
Documentation is generated from an explicit allowlist of five version-pinned Markdown
guides; do not copy captures, private qualification fixtures or the full evidence
tree into the website build. Keep download/version metadata in one reviewed
file updated only after release verification. Imported guides retain source
paths, the immutable release tag and content SHA-256 values; ordinary site
builds use these reviewed committed files without reading the working CLI docs.

Set the Vercel project root to `website/`, use the Astro preset, and connect the
GitHub repository. Vercel supports branch previews and production deployments
from the configured production branch; use previews for review before merging
site changes. See [Vercel Git deployment](https://vercel.com/docs/git) and
[project configuration](https://vercel.com/docs/project-configuration).

Use the initial Vercel domain until a custom domain is chosen. Account linking
is required for a permanent owned deployment. Temporary previews are explicitly
identified as temporary and do not establish production ownership.

## Checks and deployment

`npm ci`, `npm run build` and `npm test` are the repeatable local checks.
The website CI workflow runs the production build and Chromium suite. Checks
cover static links/assets, release filenames, source provenance, local fonts,
JavaScript size, WCAG rules, keyboard navigation, copy buttons, no-JavaScript
operation, four responsive widths and the custom 404, including reference
guides. Desktop and mobile screenshots are retained privately for visual review.

Only `website/` and its static output are deployment inputs. `.vercelignore`
excludes local dependencies, generated test output and environment files. The
CLI capture/evidence tree is never part of the deployment.

On 2026-09-30 a tested preview was deployed with Vercel's unauthenticated
temporary-deployment feature. Vercel assigned it a one-hour expiry. No Vercel
account login was available in this environment; permanent production hosting
remains dependent on connecting the owner's account. Ownership claim credentials
are private, ignored local files and are not published in this repository.

The initial site correctly pins published v1.0.1 and explains its older command
contract. Promote the release metadata and imported guides to v1.1 only after
the corrected CLI's qualification and published artifacts pass verification.
Set `PUBLIC_SITE_URL` to the permanent verified HTTPS origin to enable canonical
URLs, sitemap entries and indexing. Temporary previews disallow crawling.

Launch is complete when a new operator can install a checksum-verified binary,
preview a capture, run a local synthetic live example, understand the keylog
requirement, and distinguish a verified response from stateless transmission.

The implementation and temporary deployment are complete; a permanent Vercel
account deployment and final release-metadata promotion remain separate steps.
