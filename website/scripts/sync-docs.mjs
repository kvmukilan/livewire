import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = fileURLToPath(new URL('../', import.meta.url));
const release = JSON.parse(readFileSync(path.join(root, 'src/data/release.json'), 'utf8'));
const allowlist = [
  ['SETUP.md', 'setup', 'Installation reference', 'Complete platform setup instructions for the pinned release.'],
  ['COMMANDS.md', 'commands', 'Command reference', 'Flags, replay outcomes, and compatibility commands for the pinned release.'],
  ['WORKFLOW.md', 'workflow', 'Workflow reference', 'Capture inspection, session selection, and replay planning.'],
  ['RELIABILITY_IMPLEMENTATION.md', 'reliability', 'Reliability reference', 'Replay state, supported protocols, durable progress, and verification boundaries.'],
  ['PRODUCTION.md', 'operations', 'Operations reference', 'Operational diagnostics, recovery, and qualification requirements.'],
  ['TLS_CAPTURE_REPLAY.md', 'tls-capture', 'TLS capture reference', 'Fresh TLS handshakes from public metadata and application replay with matching captured secrets.'],
];
const out = path.join(root, 'src/pages/reference');
mkdirSync(out, { recursive: true });
const manifest = { ref: release.docsRef, files: [] };
for (const [file, slug, title, description] of allowlist) {
  const sourcePath = `docs/${file}`;
  const bytes = execFileSync('git', ['show', `${release.docsRef}:${sourcePath}`], { cwd: root });
  let markdown = bytes.toString('utf8').replaceAll('\r\n', '\n').replace(/^# [^\n]+\n/, '');
  markdown = markdown.replace(/\]\(([^\s)]+)\)/g, (match, target) => {
    if (/^(?:[a-z]+:|#|\/)/i.test(target)) return match;
    const resolved = path.posix.normalize(path.posix.join('docs', target));
    return `](${release.repository}/blob/${release.docsRef}/${resolved})`;
  });
  const frontmatter = { layout: '../../layouts/Reference.astro', title, description, sourcePath, sourceRef: release.docsRef };
  const generated = `---\n${Object.entries(frontmatter).map(([k,v]) => `${k}: ${JSON.stringify(v)}`).join('\n')}\n---\n\n${markdown.trimEnd()}\n`;
  writeFileSync(path.join(out, `${slug}.md`), generated);
  manifest.files.push({ source: sourcePath, sourceSHA256: createHash('sha256').update(bytes).digest('hex'), output: `src/pages/reference/${slug}.md`, generatedSHA256: createHash('sha256').update(generated).digest('hex') });
}
writeFileSync(path.join(root, 'src/data/docs-provenance.json'), JSON.stringify(manifest, null, 2) + '\n');
console.log(`Imported ${allowlist.length} explicitly allowed guides from ${release.docsRef}; no captures, key files, or qualification trees imported.`);
