// Fail if a workflow introduces a movable action ref or drops the audit policy.
import { readFileSync, readdirSync } from 'node:fs';
import assert from 'node:assert/strict';
for (const file of readdirSync('.github/workflows')) {
  const text = readFileSync(`.github/workflows/${file}`, 'utf8');
  for (const [, action] of text.matchAll(/uses:\s*([^\s#]+)/g)) {
    assert.match(action, /^[\w-]+\/[\w./-]+@[0-9a-f]{40}$/, `Unpinned action: ${action}`);
  }
}
const ci = readFileSync('.github/workflows/ci.yml', 'utf8');
assert.match(ci, /cargo deny --locked check advisories licenses/);
assert.match(ci, /cargo fuzz run decode_encode/);
const policy = readFileSync('deny.toml', 'utf8');
assert.match(policy, /\[advisories\]/);
assert.match(policy, /\[licenses\]/);
assert.doesNotMatch(policy, /"(?:A?GPL-[^"]*)"/);
console.log('Action pins, advisory/license policy and fuzz gate checked');
