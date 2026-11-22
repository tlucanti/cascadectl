import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from support import PROJECT, config, public_keys, snapshot, state
from lib.config import compatible, load_config, state_for
import bootstrap


class ConfigurationTests(unittest.TestCase):
    def load(self, change):
        data = json.loads((PROJECT / 'examples/cascade.example.json').read_text())
        change(data)
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'config.json'
            p.write_text(json.dumps(data))
            return load_config(p)

    def test_bad_ports_and_names_are_rejected(self):
        for change in [lambda d: d.update(hop_port=53), lambda d: d.update(hop_port=443),
                       lambda d: d.update(entry_port=True), lambda d: d.update(clients=['same', 'same']),
                       lambda d: d.update(clients=['../../file']), lambda d: d.update(clients=['x' * 16]),
                       lambda d: d['entry'].update(wan='ens3;reboot'),
                       lambda d: d['exit'].update(ipv6_prefix='2001:db8:200::/48')]:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.load(change)

    def test_unknown_fields_reject_inline_passwords(self):
        with self.assertRaises(ValueError):
            self.load(lambda d: d['entry']['ssh'].update(password='do-not-accept-inline'))

    def test_password_paths_are_not_read_during_plan(self):
        c = config()
        c['entry']['ssh']['password_file'] = '/does/not/exist'
        options = bootstrap.parser().parse_args(['--config', 'unused', '--plan'])
        with contextlib.redirect_stdout(io.StringIO()) as output:
            bootstrap.provision(c, options, remote_factory=lambda *a: self.fail('Plan attempted SSH'))
        self.assertNotIn('/does/not/exist', output.getvalue())
        self.assertIn('automatic_reboot', output.getvalue())

    def test_existing_rotated_endpoint_and_alias_are_preserved(self):
        previous = state()
        previous['eu_ipv6'] = '2001:db8:200::abcd'
        updated = state_for(config(), 'entry', public_keys(), previous)
        self.assertEqual(updated['eu_ipv6'], previous['eu_ipv6'])
        exit_previous = state('exit')
        exit_previous['eu_active_ipv6'] = previous['eu_ipv6']
        exit_updated = state_for(config(), 'exit', public_keys(), exit_previous)
        self.assertEqual(exit_updated['eu_active_ipv6'], previous['eu_ipv6'])

    def test_live_address_or_mtu_migrations_are_not_implicit(self):
        previous = state()
        changed = config()
        changed['mtu'] = 1300
        with self.assertRaises(ValueError):
            compatible(changed, 'entry', previous)

    def test_preflight_accepts_plain_hosts_and_docker_exit(self):
        for role in ['entry', 'exit']:
            bootstrap.preflight(config(), role, snapshot(role))
        s = snapshot('exit')
        s.update(docker_active=True, docker_user=True)
        s['chains'] = [{'family': 'ip', 'table': 'filter', 'name': 'FORWARD', 'hook': 'forward', 'policy': 'drop'}]
        bootstrap.preflight(config(), 'exit', s)

    def test_preflight_refuses_conflicts_before_mutation(self):
        cases = [lambda s: s.update(root_ssh_disabled=True),
                 lambda s: s.update(unmanaged=True),
                 lambda s: s['rules'].append({'priority': 10010, 'table': 220}),
                 lambda s: s['routes220'].append({'dst': 'default'}),
                 lambda s: s['routes4'].append({'dst': '10.77.0.0/16', 'dev': 'other'}),
                 lambda s: s['listeners'].append({'protocol': 'udp', 'port': 51821, 'managed_awg': False}),
                 lambda s: s['chains'].append({'hook': 'input', 'policy': 'drop', 'name': 'ufw', 'table': 'filter'}),
                 lambda s: s['addresses'][0].update(mtu=1300)]
        for change in cases:
            s = snapshot('exit')
            change(s)
            with self.subTest(change=change), self.assertRaises(ValueError):
                bootstrap.preflight(config(), 'exit', s)

    def test_managed_interface_routes_do_not_look_like_conflicts(self):
        s = snapshot()
        s['state'] = state()
        s['routes4'].append({'dst': '10.77.0.0/24', 'dev': 'awg-clients'})
        bootstrap.preflight(config(), 'entry', s)

    def test_docker_startup_hook_is_optional(self):
        plain = [f['path'] for f in bootstrap.project_files('exit', False)]
        docker = [f['path'] for f in bootstrap.project_files('exit', True)]
        self.assertNotIn('/etc/systemd/system/docker.service.d/cascade.conf', plain)
        self.assertIn('/etc/systemd/system/docker.service.d/cascade.conf', docker)
