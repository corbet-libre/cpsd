// No advisory exemptions; repaired transport remains mandatory.
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
const metadata = JSON.parse(readFileSync(process.env.DEPENDENCY_METADATA || 'dependency-metadata.json', 'utf8'));
const policy = readFileSync('deny.toml', 'utf8');
assert.doesNotMatch(policy, /\bignore\s*=|RUSTSEC-[0-9-]+/, 'Advisory exemptions forbidden');
for (const pkg of metadata.packages) {
  assert.ok(!['rustls-pemfile', 'native-tls'].includes(pkg.name), 'Legacy TLS dependency returned');
  const [major, minor, patch] = pkg.version.split('.').map(Number);
  if (pkg.name === 'hyper') assert.ok(major >= 1, 'Legacy hyper returned');
  if (pkg.name === 'h2') assert.ok(major > 0 || minor > 4 || (minor === 4 && patch >= 16), 'Vulnerable h2 returned');
  if (pkg.name === 'rustls') assert.ok(major > 0 || minor >= 23, 'Legacy rustls returned');
  if (pkg.name === 'rustls-webpki') assert.ok(major > 0 || minor > 103 || (minor === 103 && patch >= 13), 'Vulnerable webpki returned');
}
console.log('Repaired transport and absence of advisory exemptions checked');
