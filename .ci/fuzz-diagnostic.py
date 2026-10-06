"""Run the original fuzz command with a verified, job-local upstream CLI."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

from acceptance import locks, nightly, require, run, sha

TOOL = {
    'version': '0.13.2',
    'upstream_commit': '984c861c8dfea28055254c5f1d2659ab2cd63f76',
    'asset_id': 442959815,
    'url': 'https://github.com/rust-fuzz/cargo-fuzz/releases/download/0.13.2/'
           'cargo-fuzz-0.13.2-x86_64-unknown-linux-musl.tar.gz',
    'archive_bytes': 899208,
    'archive_sha256': 'b5b704018b63e0f151c17a057ac53b5111e1db545d1b9f72fee79f08a545931c',
}


def prepare_and_fuzz(root):
    """Child: all network, tool execution and fuzz work share one timeout."""
    tools = root / 'tools'
    tools.mkdir()
    archive = tools / 'cargo-fuzz.tar.gz'
    run(['curl', '--fail', '--location', '--retry', '2', '--max-time', '60',
         '--max-filesize', str(TOOL['archive_bytes']), '--output', str(archive), TOOL['url']],
        root / 'tool-acquisition.log')
    require(archive.stat().st_size == TOOL['archive_bytes'], 'cargo-fuzz archive size differs')
    require(sha(archive) == TOOL['archive_sha256'], 'cargo-fuzz archive digest differs')
    # The upstream release packages one regular file. Never extract archive
    # paths, links, permissions or ownership into the worker filesystem.
    executable = tools / 'cargo-fuzz'
    with tarfile.open(archive, 'r:gz') as package:
        members = package.getmembers()
        require(len(members) == 1, 'unexpected cargo-fuzz archive members')
        member = members[0]
        require(member.name == 'cargo-fuzz' and member.isfile()
                and not member.issym() and not member.islnk()
                and 0 < member.size <= 64 * 1024 * 1024,
                'invalid cargo-fuzz executable member')
        with package.extractfile(member) as source, executable.open('xb') as destination:
            shutil.copyfileobj(source, destination)
        require(executable.stat().st_size == member.size, 'truncated cargo-fuzz executable')
    executable.chmod(0o700)
    os.environ['PATH'] = str(tools) + os.pathsep + os.environ['PATH']
    run(['cargo', 'fuzz', '--version'], root / 'cargo-fuzz-version.log')
    version = (root / 'cargo-fuzz-version.log').read_text().strip()
    require(version == 'cargo-fuzz ' + TOOL['version'], 'cargo-fuzz version differs')
    (root / 'tool-receipt.json').write_text(json.dumps({
        **TOOL, 'binary_sha256': sha(executable), 'reported_version': version,
    }, indent=2, sort_keys=True) + '\n')
    run(['bash', '-euo', 'pipefail', '-c', 'rustc -Vv; cargo -V'], root / 'tool-versions.log')
    # Same frozen-graph preparation as original acceptance, before its offline
    # fuzz execution. Nothing resolves or updates either product lock.
    run(['cargo', 'fetch', '--locked', '--manifest-path', 'fuzz/Cargo.toml'],
        root / 'fuzz-fetch.log')
    require(locks() == json.loads((root / 'locks-before.json').read_text()),
            'tool preparation mutated locks')
    with (root / 'dependency-metadata.json').open('w') as output, \
            (root / 'metadata.stderr').open('w') as errors:
        subprocess.run(['cargo', 'metadata', '--locked', '--format-version', '1'],
                       stdout=output, stderr=errors, check=True)
    run(['bash', '.ci/check.sh', 'fuzz'], root / 'fuzz.log')


def main():
    root = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
    require(not root.is_relative_to(Path.cwd().resolve()), 'external artifacts required')
    before = locks()
    receipt = {
        'schema': 1, 'status': 'fuzz-diagnostic-failed',
        'source_commit': os.environ['CI_COMMIT_SHA'],
        'source_archive_sha256': os.environ['SOURCE_SHA256'],
        'dependency_closure_sha256': os.environ['DEPENDENCY_SOURCE_SHA256'],
        'locks_before': before, 'tool_expected': TOOL,
        'promotion': 'Original bounded fuzz diagnostic only; no full acceptance',
    }
    try:
        require(os.environ.get('CI') == 'crow', 'Crow diagnostic only')
        require(os.environ.get('CHECKS') == 'fuzz-diagnostic', 'exact selector required')
        require(os.environ.get('CARGO_BUILD_JOBS') == '2'
                and os.environ.get('RUST_TEST_THREADS') == '2', 'two jobs and test threads required')
        reference_path = Path('.ci/native-vector-reference.json')
        corpus_path = Path('.ci/native-fuzz-corpus-reference.json')
        reference = json.loads(reference_path.read_text())
        corpus = json.loads(corpus_path.read_text())
        require(before == reference['locks'], 'locks differ from executed native reference')
        inputs = [Path('Cargo.toml')] + sorted(Path('src').rglob('*.rs')) + sorted(Path('tests').rglob('*.rs'))
        identity = {str(path): sha(path) for path in inputs}
        implementation = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        require(implementation == reference['implementation_sha256'], 'implementation differs from native')
        require(set(corpus) == {'source_commit', 'implementation_sha256', 'files'}, 'invalid corpus reference')
        require(corpus['implementation_sha256'] == implementation
                and corpus['source_commit'] == reference['source_commit']
                and re.fullmatch(r'[0-9a-f]{40}', corpus['source_commit']), 'corpus/native binding differs')
        require(isinstance(corpus['files'], dict) and corpus['files'], 'empty corpus reference')
        for name, digest in corpus['files'].items():
            require(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_.-]+', name)
                    and name not in ('.', '..') and isinstance(digest, str)
                    and re.fullmatch(r'[0-9a-f]{64}', digest), 'invalid seed identity')
        native = Path(os.environ['CARGO_TARGET_DIR']) / 'cpsd-qualification' / corpus['source_commit'] / 'fuzz-corpus'
        require(native.is_dir() and not native.is_symlink(), 'native corpus missing or linked')
        entries = list(native.iterdir())
        require(all(path.is_file() and not path.is_symlink() for path in entries), 'nonregular native seed')
        require({path.name: sha(path) for path in entries} == corpus['files'], 'native corpus differs')
        seeds = root / 'fuzz-corpus'
        require(Path(os.environ['CPSD_FUZZ_CORPUS']).resolve() == seeds, 'external corpus required')
        seeds.mkdir()
        for name, digest in corpus['files'].items():
            shutil.copyfile(native / name, seeds / name)
            require(sha(seeds / name) == digest, 'copied seed differs')
        setup = Path(os.environ['CI_ACCEPTANCE_COVERAGE_SETUP'])
        require(str(setup).startswith('/nix/store/'), 'immutable nightly setup required')
        require(sha(setup) == os.environ['CI_ACCEPTANCE_COVERAGE_SHA256'], 'nightly setup digest differs')
        (root / 'locks' / 'fuzz').mkdir(parents=True)
        for path in before:
            shutil.copyfile(path, root / 'locks' / path)
        shutil.copyfile(reference_path, root / reference_path.name)
        shutil.copyfile(corpus_path, root / corpus_path.name)
        (root / 'locks-before.json').write_text(json.dumps(before, sort_keys=True) + '\n')
        receipt.update(implementation_sha256=implementation,
                       native_reference_sha256=sha(reference_path), corpus_reference_sha256=sha(corpus_path),
                       corpus_before=corpus['files'], nightly_setup_sha256=sha(setup))
        run(['timeout', '--signal=TERM', '--kill-after=15s', '1800s',
             *nightly(['python3', '.ci/fuzz-diagnostic.py', '--execute'])], root / 'execution.log')
        require(locks() == before, 'fuzz mutated locks')
        receipt['status'] = 'fuzz-diagnostic-passed'
    finally:
        after = locks()
        receipt['locks_after'] = after
        if after != before:
            receipt['status'] = 'fuzz-diagnostic-failed'
        receipt['artifacts'] = {str(path.relative_to(root)): sha(path)
                                for path in root.rglob('*') if path.is_file()}
        output = root / 'fuzz-diagnostic.json'
        output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        print(json.dumps({'fuzz_diagnostic_receipt': str(output), 'sha256': sha(output)}), flush=True)
        require(after == before, 'fuzz mutated locks')


if __name__ == '__main__':
    if sys.argv[1:] == ['--execute']:
        prepare_and_fuzz(Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True))
    else:
        require(not sys.argv[1:], 'unexpected arguments')
        main()
