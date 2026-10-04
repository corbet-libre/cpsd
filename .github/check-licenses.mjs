// Reviewed expressions from the locked graph. Unknown licenses require review.
// For dual licenses, select the permissive alternative (including self_cell).
import { readFileSync } from 'node:fs';

const allowed = new Set([
  "(MIT OR Apache-2.0) AND NCSA",
  "(MIT OR Apache-2.0) AND Unicode-3.0",
  "0BSD",
  "0BSD OR MIT OR Apache-2.0",
  "Apache-2.0",
  "Apache-2.0 / MIT",
  "Apache-2.0 AND ISC",
  "Apache-2.0 OR GPL-2.0-only",
  "Apache-2.0 OR ISC OR MIT",
  "Apache-2.0 OR MIT",
  "Apache-2.0 WITH LLVM-exception",
  "Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT",
  "Apache-2.0/MIT",
  "BSD-2-Clause OR Apache-2.0 OR MIT",
  "BSD-2-Clause OR MIT OR Apache-2.0",
  "BSD-3-Clause",
  "BSL-1.0",
  "CC0-1.0",
  "CC0-1.0 OR MIT-0 OR Apache-2.0",
  "CDLA-Permissive-2.0",
  "ISC",
  "ISC AND (Apache-2.0 OR ISC)",
  "ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0)",
  "LGPL-3.0-only WITH LGPL-3.0-linking-exception",
  "MIT",
  "MIT OR Apache-2.0",
  "MIT OR Apache-2.0 OR Zlib",
  "MIT OR Apache-2.0 OR BSD-1-Clause",
  "MIT OR Apache-2.0 OR LGPL-2.1-or-later",
  "MIT OR Apache-2.0 WITH LLVM-exception",
  "MIT OR Zlib OR Apache-2.0",
  "MIT/Apache-2.0",
  "Unicode-3.0",
  "Unlicense OR MIT",
  "Unlicense/MIT",
  "Zlib",
  "Zlib OR Apache-2.0 OR MIT"
]);
const metadata = JSON.parse(readFileSync(process.env.DEPENDENCY_METADATA || 'dependency-metadata.json', 'utf8'));
const rejected = metadata.packages.filter(p => !allowed.has(p.license));
for (const p of rejected) {
  console.error(`Unreviewed license: ${p.name} ${p.version}: ${p.license ?? 'missing'}`);
}
if (rejected.length) process.exit(1);
console.log(`Reviewed license expressions for ${metadata.packages.length} locked packages`);
