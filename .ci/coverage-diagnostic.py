"""Run the original strict coverage gate over the executed native lock snapshot."""
import hashlib
import json
import os
from pathlib import Path
import shutil

from acceptance import locks, nightly, require, run, sha


def main():
    require(os.environ.get('CI') == 'crow', 'Crow diagnostic only')
    require(os.environ.get('CHECKS') == 'coverage-diagnostic', 'exact diagnostic selector required')
    require(os.environ.get('CARGO_BUILD_JOBS') == '2' and os.environ.get('RUST_TEST_THREADS') == '2',
            'two jobs and two test threads required')
    root = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
    require(not root.is_relative_to(Path.cwd().resolve()), 'external artifacts required')
    require(Path(os.environ['CPSD_FUZZ_CORPUS']).resolve(strict=True) == root / 'fuzz-corpus',
            'genuine corpus must stay with diagnostic artifacts')
    reference_path = Path('.ci/native-vector-reference.json')
    reference = json.loads(reference_path.read_text())
    before = locks()
    require(before == reference['locks'], 'locks differ from executed native reference')
    inputs = [Path('Cargo.toml')] + sorted(Path('src').rglob('*.rs')) + sorted(Path('tests').rglob('*.rs'))
    identity = {str(path): sha(path) for path in inputs}
    implementation = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(implementation == reference['implementation_sha256'], 'implementation differs from executed native reference')
    setup = Path(os.environ['CI_ACCEPTANCE_COVERAGE_SETUP'])
    require(str(setup).startswith('/nix/store/'), 'immutable nightly setup required')
    require(sha(setup) == os.environ['CI_ACCEPTANCE_COVERAGE_SHA256'], 'nightly setup hash differs')
    retained = root / 'locks'
    (retained / 'fuzz').mkdir(parents=True)
    for path in before:
        shutil.copyfile(path, retained / path)
    shutil.copyfile(reference_path, root / 'native-vector-reference.json')
    status = 'coverage-diagnostic-failed'
    try:
        run(nightly(['bash', '-euo', 'pipefail', '-c',
                     'rustc -Vv; cargo -V; cargo llvm-cov --version']), root / 'tool-versions.log')
        # GNU timeout bounds the whole command group; preserve the failed log
        # and diagnostic receipt even if compilation/coverage exceeds its budget.
        run(['timeout', '--signal=TERM', '--kill-after=15s', '1800s',
             *nightly(['bash', '.ci/check.sh', 'coverage'])], root / 'coverage.log')
        require(locks() == before, 'coverage mutated locks')
        status = 'coverage-diagnostic-passed'
    finally:
        after = locks()
        if after != before:
            status = 'coverage-diagnostic-failed'
        files = {str(path.relative_to(root)): sha(path) for path in root.rglob('*') if path.is_file()}
        receipt = {'schema': 1, 'status': status,
                   'source_commit': os.environ['CI_COMMIT_SHA'],
                   'source_archive_sha256': os.environ['SOURCE_SHA256'],
                   'dependency_closure_sha256': os.environ['DEPENDENCY_SOURCE_SHA256'],
                   'locks_before': before, 'locks_after': after,
                   'implementation_sha256': implementation,
                   'native_reference_sha256': sha(reference_path), 'artifacts': files,
                   'promotion': 'Coverage diagnostic only; no fuzz execution or full acceptance'}
        (root / 'coverage-diagnostic.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'coverage_diagnostic_receipt': str(root / 'coverage-diagnostic.json'),
                          'sha256': sha(root / 'coverage-diagnostic.json')}), flush=True)
        require(after == before, 'coverage mutated locks')


if __name__ == '__main__':
    main()
