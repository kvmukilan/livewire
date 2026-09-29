# Livewire website on Vercel

## Purpose and scope

Create a public product and documentation site after the replay release is
qualified. Keep the first version static: explain the workflows, link verified
GitHub downloads, and expose the supported protocol matrix and qualification
boundaries. Captures, TLS key logs and credentials stay on the operator's machine.
The existing `livewire web` dashboard remains the local replay interface.

## Pages

| Page | Content and acceptance criteria |
|---|---|
| Home | Explain fresh live sessions and stateless packet replay, show one working example of each, link installation and downloads. |
| Install | Windows/Linux steps, packet-driver versus socket prerequisites, checksums and provenance verification. |
| Workflows | `live`, `reproduce`, stateless `replay`, selection, preview, repeated attempts, fault expectations and recovery. |
| Secure replay | TLS/keylog example, fresh certificate verification, FTPS/SSH requirements, explicit unsupported cases. |
| Protocols | Supported application families, transport-only behavior, evidence links and limits; no claims of universal protocol or hardware support. |
| Releases | Version-pinned links to GitHub releases, checksum manifests and qualification evidence. |
| Troubleshooting | Missing keys, unknown TCP, capture gaps, permissions, response divergence and redacted support reports. |

## Implementation decisions

Use Astro with static output in `website/`, a committed dependency lockfile,
locally hosted fonts and minimal client JavaScript. Vercel documents native
[Astro deployment support](https://vercel.com/docs/frameworks/frontend/astro).
Generate documentation from an explicit allowlist of the existing Markdown
guides; do not copy captures, private qualification fixtures or the full evidence
tree into the website build. Keep download/version metadata in one reviewed
file updated only after release verification.

Set the Vercel project root to `website/`, use the Astro preset, and connect the
GitHub repository. Vercel supports branch previews and production deployments
from the configured production branch; use previews for review before merging
site changes. See [Vercel Git deployment](https://vercel.com/docs/git) and
[project configuration](https://vercel.com/docs/project-configuration).

Use the initial Vercel domain until a custom domain is chosen. Account linking
and any paid-plan choice belong to the deployment step; this plan does not
create a project or incur hosting charges.

## Build and launch sequence

1. Finish and verify the CLI release; pin the site's initial release metadata.
2. Scaffold the static site and import reviewed operator documentation.
3. Add CI for production build, internal links, examples, accessibility and
   checks that download links agree with the release metadata.
4. Review mobile/desktop layouts, keyboard navigation, contrast, copy buttons
   and the TLS workflow in a Vercel preview.
5. Connect the selected Vercel account, publish the approved site, then verify
   HTTPS, canonical URLs, sitemap, redirects, 404 behavior and download links.

Launch is complete when a new operator can install a checksum-verified binary,
preview a capture, run a local synthetic live example, understand the keylog
requirement, and distinguish a verified response from stateless transmission.

This is an implementation-ready plan; no website deployment is claimed.
