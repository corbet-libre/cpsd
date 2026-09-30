// Advisory exceptions are tied to reviewed versions and concrete upstream code.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import assert from 'node:assert/strict';
const metadata = JSON.parse(readFileSync('dependency-metadata.json', 'utf8'));
const versions = {
  derivative: '2.2.0', paste: '1.0.15', 'proc-macro-error2': '2.0.1',
  'rustls-pemfile': '2.2.0', h2: '0.3.27', 'rustls-webpki': '0.102.8',
  'tracing-subscriber': '0.2.25', libsql: '0.9.30'
};
for (const [name, version] of Object.entries(versions)) {
  const entries = metadata.packages.filter(p => p.name === name);
  assert.equal(entries.length, 1, `Reassess advisory exposure for ${name}`);
  assert.equal(entries[0].version, version, `Reassess advisory exposure for ${name}`);
}
const libsql = metadata.packages.find(p => p.name === 'libsql');
const source = readFileSync(join(dirname(libsql.manifest_path), 'src/database.rs'));
assert.equal(createHash('sha256').update(source).digest('hex'),
  '4491e0e52b1d0e88662d633075d9a60f7144c7a2cb52c5b4f3df10a6d488a26b',
  'Reassess libSQL HTTP/1 and default TLS/CRL configuration');
assert.match(source.toString(), /\.with_native_roots\(\)[\s\S]*?\.enable_http1\(\)\s*\.wrap_connector\(http\)/);
assert.doesNotMatch(source.toString(), /enable_http2|with_crls/);
const policy = readFileSync('deny.toml', 'utf8');
const ids = [...policy.matchAll(/id = "(RUSTSEC-[0-9-]+)"/g)].map(m => m[1]).sort();
assert.deepEqual(ids, [
  'RUSTSEC-2024-0388', 'RUSTSEC-2024-0436', 'RUSTSEC-2025-0055', 'RUSTSEC-2025-0134',
  'RUSTSEC-2026-0049', 'RUSTSEC-2026-0098', 'RUSTSEC-2026-0099', 'RUSTSEC-2026-0104',
  'RUSTSEC-2026-0173', 'RUSTSEC-2026-0258'
]);
console.log('Reviewed advisory versions and libSQL connector source checked; documented TLS risks remain open');
