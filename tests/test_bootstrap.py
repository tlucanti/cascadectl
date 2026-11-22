import argparse
import base64
import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from support import config, key, public_keys, snapshot
import bootstrap


class FakeRemote:
    log = []
    instances = {}
    existing = False

    def __init__(self, role, ssh, *args):
        self.role = role
        self.files = {}
        self.__class__.instances[role] = self

    def python(self, source, payload, **kwargs):
        action = payload['action']
        self.log.append((self.role, action))
        if action == 'inspect':
            data = snapshot(self.role)
            if self.existing:
                from lib.config import state_for
                data['state'] = state_for(config(), self.role, public_keys())
                if self.role == 'entry':data['state']['eu_ipv6'] = '2001:db8:200::abcd'
                else:
                    data['state']['eu_active_ipv6'] = '2001:db8:200::abcd'
                    data['aliases'] = ['2001:db8:200::abcd']
            return json.dumps(data)
        if action == 'claim':return json.dumps({'backup': '/root/baseline.tar.gz'})
        if action in ['build', 'versions']:
            return json.dumps({n: hashlib.sha256(n.encode()).hexdigest() for n in ['amneziawg-go', 'awg', 'awg-quick']})
        if action == 'keys':return json.dumps(public_keys()[self.role])
        if action == 'shared':return json.dumps({'psk': key(4), 'obfuscation': 'Jc = 4\n'})
        if action == 'write':
            for item in payload['files']:
                raw = base64.b64decode(item['data'])
                assert hashlib.sha256(raw).hexdigest() == item['sha256']
                self.files[item['path']] = raw
        if action == 'configure':self.saved_state = payload['state']
        if action == 'rotation-key':return json.dumps({'public_key': 'ssh-ed25519 key cascade-ipv6-rotation'})
        if action == 'authorize':return json.dumps({'host_key': 'ssh-ed25519 trusted-exit-host-key'})
        return '{}'

    def execute(self, script, *, binary=False, **kwargs):
        self.log.append((self.role, script))
        if script.startswith('ip -j -6 route get'):
            out = json.dumps([{'prefsrc': config()['entry']['ipv6']}])
        elif script.startswith('cat /usr/local/bin/'):
            out = script.rsplit('/', 1)[1]
        elif script.endswith('backup'):
            out = '/root/current.tar.gz\n'
        else:
            out = '{}'
        return subprocess.CompletedProcess([], 0, out.encode() if binary else out, '')

    def close(self):pass


class BootstrapFlowTests(unittest.TestCase):
    def setUp(self):
        FakeRemote.log = [];FakeRemote.instances = {};FakeRemote.existing = False

    def options(self, *args):
        return bootstrap.parser().parse_args(['--config', 'unused'] + list(args))

    def test_read_only_check_never_claims_or_installs(self):
        with contextlib.redirect_stdout(io.StringIO()):
            bootstrap.provision(config(), self.options('--check'), FakeRemote)
        actions = [action for _,action in FakeRemote.log]
        self.assertNotIn('claim', actions)
        self.assertNotIn('packages', actions)
        self.assertNotIn('keys', actions)

    def test_full_bootstrap_orders_exit_before_entry_activation(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            bootstrap.provision(config(), self.options(), FakeRemote)
        exit_start = next(i for i,(r,a) in enumerate(FakeRemote.log) if r == 'exit' and a.startswith('systemctl enable --now'))
        entry_start = next(i for i,(r,a) in enumerate(FakeRemote.log) if r == 'entry' and a.startswith('systemctl enable --now'))
        self.assertLess(exit_start, entry_start)
        self.assertNotIn(key(4), output.getvalue())
        self.assertIn('/etc/cascade/eu_known_hosts', FakeRemote.instances['entry'].files)
        self.assertNotIn('reboot', ' '.join(str(a) for _,a in FakeRemote.log))

    def test_rerun_retains_rotated_address_and_client_names_are_additive(self):
        FakeRemote.existing = True
        with contextlib.redirect_stdout(io.StringIO()):
            bootstrap.provision(config(), self.options('--skip-build'), FakeRemote)
        s = FakeRemote.instances['entry'].saved_state
        self.assertEqual(s['eu_ipv6'], '2001:db8:200::abcd')
        self.assertEqual(FakeRemote.instances['exit'].saved_state['eu_active_ipv6'], s['eu_ipv6'])

    def test_private_profile_export_into_source_tree_is_rejected(self):
        with self.assertRaises(ValueError):
            bootstrap.provision(config(), self.options('--profiles-dir', str(bootstrap.PROJECT)), FakeRemote)
        self.assertEqual(FakeRemote.log, [])
