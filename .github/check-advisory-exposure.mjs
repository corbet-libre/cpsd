// Retain only reviewed non-transport exceptions; repaired TLS is mandatory.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const metadata = JSON.parse(readFileSync('dependency-metadata.json', 'utf8'));
const reviewed = {
  'RUSTSEC-2024-0388': ['derivative', '2.2.0'],
  'RUSTSEC-2024-0436': ['paste', '1.0.15'],
  'RUSTSEC-2026-0173': ['proc-macro-error2', '2.0.1'],
  'RUSTSEC-2025-0055': ['tracing-subscriber', '0.2.25'],
};
const policy = readFileSync('deny.toml', 'utf8');
for (const [, id] of policy.matchAll(/id = "(RUSTSEC-[0-9-]+)"/g)) {
  assert.ok(reviewed[id], `Unreviewed advisory exception: ${id}`);
  const [name, version] = reviewed[id];
  assert.ok(metadata.packages.some(p => p.name === name && p.version === version),
    `Remove or reassess obsolete exception: ${id}`);
}
for (const pkg of metadata.packages) {
  assert.ok(!['rustls-pemfile', 'native-tls'].includes(pkg.name), 'Legacy TLS dependency returned');
  const [major, minor, patch] = pkg.version.split('.').map(Number);
  if (pkg.name === 'hyper') assert.ok(major >= 1, 'Legacy hyper returned');
  if (pkg.name === 'h2') assert.ok(major > 0 || minor > 4 || (minor === 4 && patch >= 16), 'Vulnerable h2 returned');
  if (pkg.name === 'rustls') assert.ok(major > 0 || minor >= 23, 'Legacy rustls returned');
  if (pkg.name === 'rustls-webpki') assert.ok(major > 0 || minor > 103 || (minor === 103 && patch >= 13), 'Vulnerable webpki returned');
}
console.log('Repaired transport and remaining reviewed advisory versions checked');
