#!/usr/bin/env python3
"""Regenerate public certificate/KRL fixtures using existing test keys and ssh-keygen.

Run from any directory. This creates no production credentials. Private test keys
are copied into a temporary directory because ssh-keygen requires mode 0600.
"""
import base64
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile

OUT = Path(__file__).resolve().parent
RESOURCES = OUT.parent


def run(*args):
    subprocess.run(['ssh-keygen', *map(str, args)], check=True, capture_output=True)


def ssh_string(value):
    return struct.pack('>I', len(value)) + value


with tempfile.TemporaryDirectory() as directory:
    tmp = Path(directory)
    authorities = {}
    for kind, source in [('ed25519', 'ed25519'), ('rsa', 'rsa'), ('ecdsa', 'ecdsa256')]:
        key = tmp / ('ca-' + kind)
        shutil.copyfile(RESOURCES / 'keys' / (source + '_unencrypted'), key)
        key.chmod(0o600)
        authorities[kind] = key
        shutil.copyfile(RESOURCES / 'keys' / (source + '_unencrypted.pub'), OUT / ('ca-' + kind + '.pub'))

    leaves = {
        'ed25519': RESOURCES / 'openssh-server/test_ed25519.pub',
        'rsa': RESOURCES / 'keys/rsa_unencrypted.pub',
        'ecdsa256': RESOURCES / 'keys/ecdsa256_unencrypted.pub',
        'ecdsa384': RESOURCES / 'keys/ecdsa384_unencrypted.pub',
        'ecdsa521': RESOURCES / 'keys/ecdsa521_unencrypted.pub',
    }
    # Synthetic SK public keys use existing software test keys, so integration
    # tests can emulate assertion signatures without FIDO hardware or CTAP.
    for kind, source, algorithm in [
        ('sk-ed25519', leaves['ed25519'], 'sk-ssh-ed25519@openssh.com'),
        ('sk-ecdsa256', leaves['ecdsa256'], 'sk-ecdsa-sha2-nistp256@openssh.com'),
    ]:
        fields = source.read_text().split()
        raw = base64.b64decode(fields[1])
        blob = ssh_string(algorithm.encode()) + raw[4 + len(fields[0]):] + ssh_string(b'ssh:test')
        key = tmp / (kind + '.pub')
        key.write_text(algorithm + ' ' + base64.b64encode(blob).decode() + '\n')
        leaves[kind] = key

    def sign(name, source, role, serial, ca='ed25519', options=(), validity='20200101000000Z:20400101000000Z'):
        public = tmp / (name + '.pub')
        shutil.copyfile(source, public)
        run('-q', '-s', authorities[ca], '-I', name, '-n',
            'localhost,*.example.test' if role == 'host' else 'certificate-access',
            '-V', validity, '-z', serial, *(['-h'] if role == 'host' else []), *options, public)
        # ssh-keygen uses the input path as a comment when the key has none.
        # Keep only the algorithm and blob so temporary paths never escape.
        certificate = (tmp / (name + '-cert.pub')).read_text().split()
        (OUT / (name + '-cert.pub')).write_text(' '.join(certificate[:2]) + '\n')

    for index, (kind, leaf) in enumerate(leaves.items()):
        sign('user-' + kind, leaf, 'user', 101 + index)
        if not kind.startswith('sk-'):
            sign('host-' + kind, leaf, 'host', 201 + index)
    for ca in ['rsa', 'ecdsa']:
        sign('host-ed25519-ca-' + ca, leaves['ed25519'], 'host', 201, ca)
    sign('host-expired', leaves['ed25519'], 'host', 300, validity='20000101Z:20010101Z')
    sign('host-critical', leaves['ed25519'], 'host', 301, options=('-O', 'critical:unsupported@example.test=restriction'))
    sign('user-high-serial', leaves['ed25519'], 'user', 2**63 + 17)
    sign('user-forever', leaves['ed25519'], 'user', 0, validity='always:forever')

    sign('user-max-serial', leaves['ed25519'], 'user', 2**64 - 1)
    sign('user-restricted', leaves['ed25519'], 'user', 310, options=('-O', 'force-command=printf certificate-restriction'))
    sign('user-expired', leaves['ed25519'], 'user', 311, validity='20000101Z:20010101Z')

    def krl(name, specification, ca='ed25519'):
        spec = tmp / (name + '.txt')
        spec.write_text(specification)
        output = tmp / (name + '.krl')
        run('-q', '-k', '-f', output, '-s', OUT / ('ca-' + ca + '.pub'), spec)
        shutil.copyfile(output, OUT / output.name)

    krl('serial-list', 'serial: 201\nserial: 9223372036854775825\n')
    krl('serial-range', 'serial: 200-250\n')
    krl('serial-bitmap', ''.join('serial: %d\n' % x for x in range(201, 240, 2)))
    krl('key-id', 'id: host-ed25519\n')
    krl('serial-high-bitmap', ''.join('serial: %d\n' % x for x in range(2**63 + 17, 2**63 + 56, 2)))
    krl('serial-high-range', 'serial: 9223372036854775808-18446744073709551615\n')
    # OpenSSH's on-disk format also permits a certificate section for all CAs.
    header = b'SSHKRL\n\x00' + struct.pack('>IQQQ', 1, 0, 0, 0) + ssh_string(b'') + ssh_string(b'')
    section = ssh_string(b'') + ssh_string(b'') + bytes([0x21]) + ssh_string(struct.pack('>QQ', 201, 201))
    (OUT / 'all-ca-serial.krl').write_bytes(header + bytes([1]) + ssh_string(section))
    key_line = leaves['ed25519'].read_text().strip()
    for directive in ['key', 'sha1', 'sha256']:
        krl(directive, directive + ': ' + key_line + '\n')
    krl('ca-key', 'key: ' + (OUT / 'ca-ed25519.pub').read_text().strip() + '\n')

    # Confirm the generated revocations against the OpenSSH reference query.
    for name in ['serial-list', 'serial-range', 'serial-bitmap', 'key-id', 'key', 'sha1', 'sha256', 'ca-key']:
        result = subprocess.run(['ssh-keygen', '-Q', '-f', str(OUT / (name + '.krl')), str(OUT / 'host-ed25519-cert.pub')], capture_output=True)
        assert result.returncode == 1 and b'REVOKED' in result.stdout, (name, result.stdout, result.stderr)
