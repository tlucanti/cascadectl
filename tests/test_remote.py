import base64
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from support import config, key, state
from lib import remote
import bootstrap


class RemoteActionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.old = remote.ROOT
        remote.ROOT = Path(self.temp.name)
        self.addCleanup(setattr, remote, 'ROOT', self.old)
        self.generated = 0
        def fake(args, data=None, **kwargs):
            if args[-1] in ['genkey', 'genpsk']:
                self.generated += 1
                out = key(10 + self.generated) + '\n'
            elif args[-1] == 'pubkey':
                out = base64.b64encode(hashlib.sha256(data.encode()).digest()).decode() + '\n'
            else:
                out = ''
            return subprocess.CompletedProcess(args, 0, out, '')
        self.command = patch.object(remote, 'command', side_effect=fake)
        self.command.start();self.addCleanup(self.command.stop)
        for p in ['/etc/cascade/keys', '/etc/cascade/profiles', '/etc/amnezia/amneziawg']:
            remote.path(p).mkdir(parents=True, exist_ok=True)

    def test_existing_private_keys_and_shared_headers_survive_rerun(self):
        first = remote.keys({'role': 'entry'})
        shared = remote.shared({'role': 'entry'})
        private = remote.path('/etc/cascade/keys/entry.key').read_bytes()
        remote.save_json('/etc/cascade/state.json', state())
        generated = self.generated
        self.assertEqual(remote.keys({'role': 'entry'}), first)
        self.assertEqual(remote.shared({'role': 'entry'}), shared)
        self.assertEqual(remote.path('/etc/cascade/keys/entry.key').read_bytes(), private)
        self.assertEqual(generated, self.generated)
        self.assertNotIn('entry_obfuscation', shared)

    def test_existing_install_with_missing_key_is_not_regenerated(self):
        remote.save_json('/etc/cascade/state.json', state())
        with self.assertRaisesRegex(ValueError, 'restore'):
            remote.keys({'role': 'entry'})
        self.assertEqual(self.generated, 0)

    def test_exit_shared_mismatch_does_not_replace_saved_psk(self):
        remote.atomic(remote.path('/etc/cascade/keys/hop.psk'), key(8) + '\n')
        with self.assertRaises(ValueError):
            remote.shared({'role': 'exit', 'shared': {'psk': key(9) + '\n', 'obfuscation': 'Jc = 4\n'}})
        self.assertEqual(remote.path('/etc/cascade/keys/hop.psk').read_text(), key(8) + '\n')

    def test_file_bundle_checksum_validated_before_any_write(self):
        a = bootstrap.encoded_file('/etc/cascade/a', 'first', 0o600)
        b = bootstrap.encoded_file('/etc/cascade/b', 'second', 0o600)
        b['sha256'] = 'bad'
        with self.assertRaises(ValueError):remote.write({'files': [a, b]})
        self.assertFalse(remote.path('/etc/cascade/a').exists())

    def test_file_protocol_cannot_write_unrelated_paths(self):
        payload = bootstrap.encoded_file('/etc/shadow', 'bad')
        with self.assertRaises(ValueError):remote.write({'files': [payload]})

    def test_configure_preserves_clients_and_rotated_endpoint(self):
        remote.keys({'role': 'entry'})
        remote.shared({'role': 'entry'})
        clients = [{'name': 'existing', 'private_key': 'saved'}]
        remote.save_json('/etc/cascade/clients.json', clients)
        s = state();s['eu_ipv6'] = '2001:db8:200::abcd'
        remote.save_json('/etc/cascade/state.json', s)
        remote.configure({'role': 'entry', 'state': s, 'peer_public_key': key(3), 'clients': ['existing']})
        self.assertEqual(remote.read_json('/etc/cascade/clients.json'), clients)
        cfg = remote.path('/etc/amnezia/amneziawg/awg-eu.conf').read_text()
        self.assertIn('Endpoint = [2001:db8:200::abcd]:51821', cfg)
        self.assertIn('AllowedIPs = 0.0.0.0/0', cfg)

    def test_key_authorization_preserves_other_users_and_deduplicates_own_key(self):
        folder = remote.path('/root/.ssh');folder.mkdir(parents=True)
        authorized = folder/'authorized_keys';authorized.write_text('ssh-ed25519 other-user other\n')
        hostkey = remote.path('/etc/ssh/ssh_host_ed25519_key.pub');hostkey.parent.mkdir(parents=True)
        hostkey.write_text('ssh-ed25519 hostkey host\n')
        payload = {'public_key': 'ssh-ed25519 newkey cascade-ipv6-rotation',
                   'entry_ipv4': config()['entry']['ipv4'], 'entry_ipv6': config()['entry']['ipv6']}
        remote.authorize(payload);remote.authorize(payload)
        body = authorized.read_text()
        self.assertIn('other-user', body)
        self.assertEqual(body.count('cascade-ipv6-rotation'), 1)
        self.assertIn('restrict,command="/usr/local/sbin/cascadectl remote-alias"', body)
        self.assertEqual(authorized.stat().st_mode & 0o777, 0o600)
