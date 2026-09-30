import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import assert from 'node:assert/strict';

const root = fileURLToPath(new URL('../', import.meta.url));
const dist = path.join(root, 'dist');
const release = JSON.parse(readFileSync(path.join(root, 'src/data/release.json'), 'utf8'));
assert.match(release.version, /^\d+\.\d+\.\d+$/);
assert.equal(release.docsRef, `v${release.version}`);
assert.equal(release.packetCommand, release.contract === 'legacy-dual-application' ? 'replay' : 'reproduce');
assert.ok(['legacy-dual-application', 'live-stateful-reproduce-stateless'].includes(release.contract));
const walk = dir => readdirSync(dir).flatMap(name => statSync(path.join(dir, name)).isDirectory() ? walk(path.join(dir, name)) : [path.join(dir, name)]);
const files = walk(dist);
const htmlFiles = files.filter(file => file.endsWith('.html'));
assert.equal(htmlFiles.length, 13, 'Expected seven main pages, five reference pages, and 404');
const hashes = new Map();
let maxInlineJS = 0;
for (const file of htmlFiles) {
  const html = readFileSync(file, 'utf8');
  assert.match(html, /<html lang="en"/);
  assert.match(html, /name="description"/);
  assert.match(html, /href="#main"/);
  assert.equal((html.match(/<h1(?:\s|>)/g) || []).length, 1);
  assert.ok(!/https:\/\/(?:fonts\.googleapis|fonts\.gstatic|www\.googletagmanager)/.test(html), 'Unexpected third-party runtime');
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(m => m[1]));
  hashes.set(file, ids);
  const inlineJS = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)].reduce((total, match) => total + Buffer.byteLength(match[1]), 0);
  maxInlineJS = Math.max(maxInlineJS, inlineJS);
}
let checkedLinks = 0;
for (const file of htmlFiles) {
  const html = readFileSync(file, 'utf8');
  for (const match of html.matchAll(/(?:href|src)="([^"]+)"/g)) {
    const href = match[1].replaceAll('&amp;', '&');
    if (/^(https?:|mailto:|data:)/.test(href)) {
      if (href.includes('/releases/download/')) {
        assert.ok(href.startsWith(`${release.repository}/releases/download/v${release.version}/`), `Unpinned download ${href}`);
        const fileName = href.split('/').pop();
        assert.ok([...release.binaries.map(b => b.file), 'SHA256SUMS', `livewire-${release.version}.cdx.json`].includes(fileName), `Unexpected asset ${fileName}`);
      }
      continue;
    }
    if (href.startsWith('javascript:')) throw Error('JavaScript navigation is forbidden');
    const [pathname, hash] = href.split('#');
    let target = pathname ? path.resolve(pathname.startsWith('/') ? dist : path.dirname(file), `.${pathname.startsWith('/') ? '' : '/'}${pathname}`) : file;
    if (pathname && !path.extname(pathname)) target = path.join(target, 'index.html');
    assert.ok(existsSync(target), `${path.relative(dist, file)} → missing ${href}`);
    if (hash && hashes.has(target)) assert.ok(hashes.get(target).has(decodeURIComponent(hash)), `${file}: missing anchor ${href}`);
    checkedLinks++;
  }
}
const forbidden = files.filter(file => /\.(?:pcap|pcapng|pem|key|log|zip|exe)$/i.test(file));
assert.deepEqual(forbidden, [], 'Private or executable artifacts must never ship in the site');
const provenance = JSON.parse(readFileSync(path.join(root, 'src/data/docs-provenance.json'), 'utf8'));
assert.equal(provenance.ref, release.docsRef);
assert.equal(provenance.files.length, 5);
for (const doc of provenance.files) {
  assert.equal(createHash('sha256').update(readFileSync(path.join(root, doc.output))).digest('hex'), doc.generatedSHA256, `Reference changed without provenance: ${doc.output}`);
}
const js = files.filter(file => file.endsWith('.js'));
const jsBytes = js.reduce((total,file) => total + statSync(file).size, 0);
assert.ok(jsBytes + maxInlineJS < 15000, `Client JS exceeded 15KB: ${jsBytes + maxInlineJS}`);
assert.ok(files.some(file => file.endsWith('.woff2')), 'Local fonts missing');
for (const font of ['ibm-plex-sans', 'jetbrains-mono']) assert.ok(existsSync(path.join(dist, `${font}-LICENSE.txt`)), `Font license missing: ${font}`);
console.log(`Verified ${htmlFiles.length} pages, ${checkedLinks} local links/assets, release v${release.version}, five pinned guides, local fonts, ${jsBytes} external JS bytes and at most ${maxInlineJS} inline JS bytes/page.`);
