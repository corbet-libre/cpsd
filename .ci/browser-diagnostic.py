"""Run the existing browser selector against a verified native dependency snapshot."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from acceptance import locks, require, run, sha, vectors


def main():
    require(os.environ.get('CI') == 'crow', 'Crow diagnostic only')
    require(os.environ.get('CHECKS') == 'browser-diagnostic', 'exact diagnostic selector required')
    require(os.environ.get('CARGO_BUILD_JOBS') == '2' and os.environ.get('RUST_TEST_THREADS') == '2',
            'two jobs and two test threads required')
    root = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
    require(not root.is_relative_to(Path.cwd().resolve()), 'external artifacts required')
    reference_path = Path('.ci/native-vector-reference.json')
    reference = json.loads(reference_path.read_text())
    before = locks()
    require(before == reference['locks'], 'locks differ from executed native reference')
    inputs = [Path('Cargo.toml')] + sorted(Path('src').rglob('*.rs')) + sorted(Path('tests').rglob('*.rs'))
    identity = {str(path): sha(path) for path in inputs}
    implementation = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    require(implementation == reference['implementation_sha256'], 'implementation differs from executed native reference')
    retained = root / 'locks'
    (retained / 'fuzz').mkdir(parents=True)
    for path in before:
        shutil.copyfile(path, retained / path)
    shutil.copyfile(reference_path, root / 'native-vector-reference.json')
    libdir = subprocess.check_output(['rustc', '--print', 'target-libdir', '--target',
                                     'wasm32-unknown-unknown'], text=True).strip()
    require(list(Path(libdir).glob('libstd-*.rlib')), 'stable Wasm stdlib missing')
    run(['bash', '-euo', 'pipefail', '-c', 'rustc -Vv; cargo -V; chromium --version; chromedriver --version'],
        root / 'tool-versions.log')
    run(['bash', '.ci/wasm-runner.sh'], root / 'runner-acquisition.log')
    os.environ['PATH'] = str(root / 'runner') + os.pathsep + os.environ['PATH']
    os.environ['CPSD_MATCHED_RUNNER'] = '1'
    webdriver = root / 'webdriver.json'
    webdriver.write_text(json.dumps({'goog:chromeOptions': {
        'binary': shutil.which('chromium'), 'args': ['--disable-dev-shm-usage']}}) + '\n')
    os.environ['WASM_BINDGEN_TEST_WEBDRIVER_JSON'] = str(webdriver)
    require(locks() == before, 'runner preparation mutated locks')
    run(['bash', '.ci/check.sh', 'browser'], root / 'browser.log')
    require(locks() == before, 'browser mutated locks')
    actual = vectors(root / 'browser.log')
    require(actual == reference['proof_vectors'], 'executed native/browser proof bytes differ')
    files = {str(path.relative_to(root)): sha(path) for path in root.rglob('*') if path.is_file()}
    receipt = {'schema': 1, 'status': 'browser-diagnostic-passed',
               'source_commit': os.environ['CI_COMMIT_SHA'],
               'source_archive_sha256': os.environ['SOURCE_SHA256'],
               'dependency_closure_sha256': os.environ['DEPENDENCY_SOURCE_SHA256'],
               'locks': before, 'implementation_sha256': implementation,
               'native_reference_sha256': sha(reference_path), 'proof_vectors': actual,
               'artifacts': files, 'promotion': 'Not full acceptance; independent review required'}
    (root / 'browser-diagnostic.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print(json.dumps({'browser_diagnostic_receipt': str(root / 'browser-diagnostic.json'),
                      'sha256': sha(root / 'browser-diagnostic.json')}), flush=True)


if __name__ == '__main__':
    main()
