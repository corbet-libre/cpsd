#!/usr/bin/env python3
"""Run the original fuzz target in an exact external copy of the frozen source.

Cargo-fuzz always creates fuzz/artifacts even with an explicit artifact prefix.
The copy preserves the original relative path dependency and both lockfiles.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def inventory(root):
    found = {}
    for path in root.rglob('*'):
        if path.is_symlink():
            raise RuntimeError('fuzz source symlink unsupported')
        if path.is_file():
            with path.open('rb') as stream:
                found[str(path.relative_to(root))] = hashlib.file_digest(stream, 'sha256').hexdigest()
    return found


def main():
    source = Path.cwd().resolve()
    artifacts = Path(os.environ['CI_ACCEPTANCE_ARTIFACTS']).resolve(strict=True)
    if artifacts.is_relative_to(source):
        raise RuntimeError('fuzz artifacts must be outside source')
    before = inventory(source)
    copy = artifacts / 'fuzz-source'
    shutil.copytree(source, copy)
    if inventory(copy) != before:
        raise RuntimeError('fuzz copy differs from frozen source')
    (artifacts / 'fuzz-inputs.json').write_text(json.dumps(before, sort_keys=True) + '\n')
    env = dict(os.environ, CARGO_NET_OFFLINE='true')
    result = subprocess.run([
        'cargo', 'fuzz', 'run', 'decode_encode', str(artifacts / 'fuzz-corpus'),
        '--target', 'x86_64-unknown-linux-gnu', '--target-dir',
        str(Path(os.environ['CARGO_TARGET_DIR']) / 'fuzz'), '--',
        '-max_total_time=30', '-max_len=262144'], cwd=copy, env=env)
    after = inventory(copy)
    if any(after.get(path) != digest for path, digest in before.items()):
        raise RuntimeError('fuzz execution changed source or a frozen lock')
    if any(not path.startswith('fuzz/artifacts/') for path in after.keys() - before.keys()):
        raise RuntimeError('unexpected fuzz output outside original artifacts directory')
    if inventory(source) != before:
        raise RuntimeError('original source changed during fuzz execution')
    result.check_returncode()


if __name__ == '__main__':
    main()
