#!/usr/bin/env python3
"""Original CPSD gate union over the resolver's frozen root AND fuzz graphs."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

PHASES = ('native', 'wasm', 'browser', 'coverage', 'fuzz', 'dependency-policy')
LOCKS = ('Cargo.lock', 'fuzz/Cargo.lock')


def require(ok, message):
    if not ok:
        raise RuntimeError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def locks():
    return {path: sha(path) for path in LOCKS}


def nightly(command):
    return ['bash', '-euo', 'pipefail', '-c',
            'printf "%s  %s\\n" "$CI_ACCEPTANCE_COVERAGE_SHA256" '
            '"$CI_ACCEPTANCE_COVERAGE_SETUP" | sha256sum --check --strict; '
            '. "$CI_ACCEPTANCE_COVERAGE_SETUP"; "$@"', 'nightly', *command]


def run(command, log):
    with log.open('x') as output:
        result = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT)
    print(json.dumps({'log': str(log), 'sha256': sha(log), 'exit': result.returncode}), flush=True)
    if result.returncode:
        # Preserve the complete original log; Crow stdout must stay bounded.
        with log.open('rb') as stream:
            stream.seek(max(0, log.stat().st_size - 16384))
            tail = stream.read().decode('utf-8', errors='replace')
        for line in tail.splitlines():
            print(line[:512], flush=True)
        raise subprocess.CalledProcessError(result.returncode, command)


def preflight(root):
    for program in ('cargo', 'rustc', 'python3', 'node', 'curl', 'tar', 'sha256sum', 'chromium', 'chromedriver'):
        require(shutil.which(program), 'required tool missing: ' + program)
    libdir = subprocess.check_output(['rustc', '--print', 'target-libdir', '--target',
                                     'wasm32-unknown-unknown'], text=True).strip()
    require(list(Path(libdir).glob('libstd-*.rlib')), 'stable Wasm stdlib missing')
    before = locks()
    for name, command in (
        ('stable', ['rustc', '-Vv']), ('cargo', ['cargo', '-V']),
        ('deny', ['cargo', 'deny', '--version']), ('browser', ['chromium', '--version']),
        ('driver', ['chromedriver', '--version']), ('nightly', nightly(['rustc', '-Vv'])),
        ('coverage', nightly(['cargo', 'llvm-cov', '--version'])),
        ('fuzz', nightly(['cargo', 'fuzz', '--version'])),
        ('first-party', ['python3', '.github/check-first-party.py', '--archive']),
        ('coverage-parser', ['python3', '.github/test-source-coverage.py']),
        ('pin-parser', ['node', '--test', '.github/check-pins.test.mjs']),
    ):
        run(command, root / ('preflight-' + name + '.log'))
    require(locks() == before, 'preflight mutated locks')
    # Dependency-changing source may have intentionally stale baseline locks.
    # The original resolver owns baseline metadata and compatibility receipts.
    (root / 'baseline-locks.json').write_text(json.dumps(before, sort_keys=True) + '\n')


def vectors(path):
    found = re.findall(r'CPSD_VECTOR (issuance-v3|shared-v3|independent-v3) ([0-9a-f]{128})', path.read_text())
    require(len(found) == 3 and len(dict(found)) == 3, 'missing or duplicate executed proof vectors')
    return dict(found)


def acceptance(root):
    before = locks()
    (root / 'candidate-locks.json').write_text(json.dumps(before, sort_keys=True) + '\n')
    retained = root / 'locks'
    (retained / 'fuzz').mkdir(parents=True)
    for path in LOCKS:
        shutil.copyfile(path, retained / path)
    # Fetch the fuzz graph before the offline fuzz run, without changing it.
    run(['cargo', 'fetch', '--locked', '--manifest-path', 'fuzz/Cargo.toml'], root / 'fuzz-fetch.log')
    run(['bash', '.ci/wasm-runner.sh'], root / 'runner-acquisition.log')
    require(locks() == before, 'candidate preparation mutated locks')
    os.environ['PATH'] = str(root / 'runner') + os.pathsep + os.environ['PATH']
    os.environ['CPSD_MATCHED_RUNNER'] = '1'
    webdriver = root / 'webdriver.json'
    webdriver.write_text(json.dumps({'goog:chromeOptions': {
        'binary': shutil.which('chromium'), 'args': ['--disable-dev-shm-usage']}}) + '\n')
    os.environ['WASM_BINDGEN_TEST_WEBDRIVER_JSON'] = str(webdriver)
    phases = []
    (root / 'phases.json').write_text('[]\n')
    for phase in PHASES:
        require(locks() == before, 'lock changed before ' + phase)
        command = ['bash', '.ci/check.sh', phase]
        if phase in ('coverage', 'fuzz'):
            command = nightly(command)
        log = root / (phase + '.log')
        run(command, log)
        require(locks() == before, 'lock changed after ' + phase)
        if phase == 'browser':
            require(vectors(root / 'native.log') == vectors(log), 'native/browser proof bytes differ')
        phases.append({'name': phase, 'status': 'passed', 'locks_before': before,
                       'locks_after': before, 'log': log.name, 'log_sha256': sha(log)})
        (root / 'phases.json').write_text(json.dumps(phases, indent=2) + '\n')
    names = [p['log'] for p in phases] + [
        'candidate-locks.json', 'phases.json', 'webdriver.json', 'fuzz-inputs.json',
        'coverage.json', 'coverage.lcov', 'coverage.txt', 'dependency-metadata.json',
        'fuzz-metadata.json', 'native-features.txt', 'runner-acquisition.log',
        'runner/runner-version.txt', 'runner/runner-artifact.sha256',
        'locks/Cargo.lock', 'locks/fuzz/Cargo.lock']
    files = {name: sha(root / name) for name in names}
    receipt = {'schema': 1, 'status': 'owner-gates-passed', 'phases': phases,
               'locks': before, 'artifacts': files,
               'source_commit': os.environ['CI_COMMIT_SHA'],
               'source_archive_sha256': os.environ['SOURCE_SHA256'],
               'dependency_closure_sha256': os.environ['DEPENDENCY_SOURCE_SHA256'],
               'promotion': 'Requires original aggregate resolver, exact source/tool/Crow verification and independent review'}
    (root / 'owner-acceptance.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')


def main():
    require(os.environ.get('CI') == 'crow', 'Crow only')
    require(not os.environ.get('CHECKS'), 'caller-selected acceptance phases forbidden')
    require(sys.argv[1:] in (['preflight'], ['run']), 'exact selector required')
    require(os.environ.get('CARGO_BUILD_JOBS') == '2' and os.environ.get('RUST_TEST_THREADS') == '2',
            'two jobs and two test threads required')
    root = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
    require(not root.is_relative_to(Path.cwd().resolve()), 'external artifacts required')
    for name in ('STABLE', 'BROWSER', 'COVERAGE'):
        setup = Path(os.environ['CI_ACCEPTANCE_' + name + '_SETUP'])
        require(str(setup).startswith('/nix/store/'), 'immutable tool setup required')
        require(sha(setup) == os.environ['CI_ACCEPTANCE_' + name + '_SHA256'], 'tool setup hash differs')
    (preflight if sys.argv[1] == 'preflight' else acceptance)(root)


if __name__ == '__main__':
    main()
