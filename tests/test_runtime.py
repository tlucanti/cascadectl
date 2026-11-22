import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from support import config, key, runtime, state


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.m = runtime()
        self.m.BASE = Path(self.temp.name) / 'etc'
        self.m.CONF = Path(self.temp.name) / 'conf'
        self.m.BASE.mkdir(); self.m.CONF.mkdir()
        self.m.writej(self.m.BASE / 'state.json', state())
        self.m.writej(self.m.BASE / 'clients.json', [])
        self.m.writej(self.m.BASE / 'overrides.json', {'always_europe': [], 'always_russia': []})

    def test_atomic_files_are_private(self):
        p = self.m.BASE / 'private'
        self.m.atomic(p, 'secret')
        self.assertEqual(p.stat().st_mode & 0o777, 0o600)

    def test_client_remove_rolls_back_when_live_sync_fails(self):
        client = {'name': 'phone', 'private_key': key(4), 'public_key': key(5), 'psk': key(6),
                  'ipv4': '10.77.0.10', 'ipv6': 'fd67:a2e4:9b01:1::a'}
        self.m.writej(self.m.BASE / 'clients.json', [client])
        (self.m.BASE / 'profiles').mkdir()
        (self.m.BASE / 'profiles/phone.conf').write_text('existing-profile')
        (self.m.CONF / 'awg-clients.conf').write_text('original-interface')
        with patch.object(self.m, 'sync_clients', side_effect=RuntimeError('rejected')):
            with self.assertRaises(RuntimeError):
                self.m.client('remove', 'phone')
        self.assertEqual(self.m.readj(self.m.BASE / 'clients.json'), [client])
        self.assertEqual((self.m.CONF / 'awg-clients.conf').read_text(), 'original-interface')
        self.assertTrue((self.m.BASE / 'profiles/phone.conf').exists())

    def test_override_failure_restores_saved_configuration(self):
        # A real public network is needed because reserved overrides are prohibited.
        original = (self.m.BASE / 'overrides.json').read_text()
        with patch.object(self.m, 'firewall', side_effect=RuntimeError('nft validation failed')):
            with self.assertRaises(RuntimeError):
                self.m.override('add', 'europe', '1.1.1.1/32')
        self.assertEqual((self.m.BASE / 'overrides.json').read_text(), original)

    def test_alias_outside_allocation_never_executes_ip(self):
        self.m.writej(self.m.BASE / 'state.json', state('exit'))
        self.m.writej(self.m.BASE / 'eu-aliases.json', [])
        with patch.object(self.m, 'run') as command:
            with self.assertRaises(ValueError):self.m.alias('prepare', '2001:db8:999::1')
            command.assert_not_called()

    def test_scoped_alias_is_rejected_before_adding_it(self):
        self.m.writej(self.m.BASE / 'state.json', state('exit'))
        self.m.writej(self.m.BASE / 'eu-aliases.json', [])
        with patch.object(self.m, 'run') as command:
            with self.assertRaises(ValueError):self.m.alias('prepare', '2001:db8:200::abcd%invalid')
            command.assert_not_called()

    def test_activation_pins_source_and_resets_sticky_endpoint_without_state_write(self):
        s = state('exit');self.m.writej(self.m.BASE / 'state.json', s)
        self.m.writej(self.m.BASE / 'eu-aliases.json', [])
        socket = self.m.BASE / 'awg-ru.sock';socket.touch()
        normal_path = Path
        calls = []
        def fake_path(value):
            return socket if str(value) == '/var/run/amneziawg/awg-ru.sock' else normal_path(value)
        def fake(args, *a, **kw):
            calls.append(args)
            if args[:5] == ['ip', '-j', '-6', 'address', 'show']:
                out = json.dumps([{'addr_info': [{'local': s['eu_ipv6']}]}])
            elif args[:5] == ['ip', '-j', '-6', 'route', 'show']:
                out = json.dumps([{'gateway': '2001:db8:ffff::1', 'metric': 100}])
            elif args[-1] == 'peers':out = key(2)
            else:out = ''
            return subprocess.CompletedProcess(args, 0, out, '')
        with patch.object(self.m, 'Path', side_effect=fake_path), patch.object(self.m, 'run', side_effect=fake), patch.object(self.m, 'writej', side_effect=AssertionError('ProtectedSystem state write')), contextlib.redirect_stdout(io.StringIO()):
            self.m.alias('activate', s['eu_ipv6'])
        self.assertTrue(any(args[:4] == ['ip', '-6', 'route', 'replace'] and 'src' in args and s['eu_ipv6'] in args for args in calls))
        self.assertTrue(any(args[:2] == ['/usr/local/bin/awg', 'set'] and 'endpoint' in args for args in calls))

    def test_failed_rotation_restores_both_sources_and_saved_config(self):
        old = state()['eu_ipv6'];candidate = '2001:db8:200::abcd'
        self.m.CONF.joinpath('awg-eu.conf').write_text('Endpoint = [' + old + ']:51821\n')
        live = {'entry_endpoint': old, 'exit_source': old}
        def ssh(s, action, address):
            if action == 'activate':live['exit_source'] = address
        def fake(args, *a, **kwargs):
            if args[:2] == ['/usr/local/bin/awg', 'set']:
                live['entry_endpoint'] = args[-1].split(']')[0][1:]
            success = live['entry_endpoint'] == old and live['exit_source'] == old
            if args[0] == 'ping':return subprocess.CompletedProcess(args, 0 if success else 1, '', '')
            text = key(3) + '\t[' + live['entry_endpoint'] + ']:51821'
            return subprocess.CompletedProcess(args, 0, text, '')
        with patch.object(self.m, 'run', side_effect=fake), patch.object(self.m, 'ssh_alias', side_effect=ssh), patch.object(self.m, 'endpoint_set'), patch.object(self.m, 'firewall'), patch.object(self.m.time, 'sleep'):
            with self.assertRaisesRegex(RuntimeError, 'New endpoint failed the authenticated'):
                self.m.rotate(candidate)
        self.assertEqual(live, {'entry_endpoint': old, 'exit_source': old})
        self.assertEqual(self.m.state()['eu_ipv6'], old)
        self.assertEqual(self.m.CONF.joinpath('awg-eu.conf').read_text(), 'Endpoint = [' + old + ']:51821\n')

    def test_active_alias_cannot_be_retired(self):
        s = state('exit');s['eu_active_ipv6'] = '2001:db8:200::abcd'
        self.m.writej(self.m.BASE / 'state.json', s)
        self.m.writej(self.m.BASE / 'eu-aliases.json', [s['eu_active_ipv6']])
        with self.assertRaises(ValueError):self.m.alias('drop', s['eu_active_ipv6'])

    def test_unmanaged_assigned_alias_is_not_claimed(self):
        self.m.writej(self.m.BASE / 'state.json', state('exit'))
        self.m.writej(self.m.BASE / 'eu-aliases.json', [])
        reply = subprocess.CompletedProcess([], 0, json.dumps([{'addr_info': [{'local': '2001:db8:200::abcd'}]}]), '')
        with patch.object(self.m, 'run', return_value=reply):
            with self.assertRaisesRegex(ValueError, 'another service'):
                self.m.alias('prepare', '2001:db8:200::abcd')

    def test_restricted_key_rejects_shell_commands(self):
        with patch.object(self.m.os, 'geteuid', return_value=0), patch.dict(self.m.os.environ, {'SSH_ORIGINAL_COMMAND': 'id; touch /tmp/unwanted'}), patch.object(self.m, 'alias') as alias:
            with self.assertRaises(ValueError):self.m.main(['remote-alias'])
            alias.assert_not_called()

    def test_missing_interface_is_a_health_failure(self):
        empty = subprocess.CompletedProcess([], 1, '', 'not found')
        with patch.object(self.m, 'run', return_value=empty):
            with self.assertRaisesRegex(RuntimeError, 'unavailable'):
                self.m.status(health=True)

    def test_help_is_available_without_root_or_state(self):
        with patch.object(self.m.os, 'geteuid', return_value=1000), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as error:self.m.main(['--help'])
        self.assertEqual(error.exception.code, 0)

    def test_nonstandard_exit_ssh_port_and_ipv6_fallback(self):
        s = state();s['eu_ssh_port'] = 2222
        calls = []
        def fake(args, **kwargs):
            calls.append(args)
            if len(calls) == 1:raise RuntimeError('IPv4 blocked')
            return subprocess.CompletedProcess(args, 0, 'prepared', '')
        with patch.object(self.m, 'run', side_effect=fake):self.m.ssh_alias(s, 'prepare', '2001:db8:200::abcd')
        self.assertEqual(calls[0][1:3], ['-p', '2222'])
        self.assertIn('root@' + s['eu_primary_ipv6'], calls[1])

    def test_country_download_failure_keeps_cache(self):
        cached = self.m.BASE / 'ru4.zone';cached.write_text('77.88.8.0/24\n')
        with patch.object(self.m.urllib.request, 'urlopen', side_effect=OSError('offline')):
            with self.assertRaises(OSError):self.m.geo_update()
        self.assertEqual(cached.read_text(), '77.88.8.0/24\n')

    def test_firewall_enforces_fail_closed_guards_and_loose_rpf_is_disabled(self):
        (self.m.BASE / 'ru4.zone').write_text('77.88.8.0/24\n')
        calls = []
        def fake(args, data=None, **kwargs):
            calls.append((args, data))
            rc = 1 if args[:4] == ['nft', 'list', 'table', 'inet'] else 0
            out = '0: from all lookup local\n32766: from all lookup main\n' if args[:4] == ['ip', '-4', 'rule', 'show'] else ''
            return subprocess.CompletedProcess(args, rc, out, '')
        with patch.object(self.m, 'run', side_effect=fake):self.m.firewall()
        batch = next(data for args,data in calls if args == ['nft', '-f', '-'])
        self.assertIn('ct mark & 0x300 == 0x200 oifname "awg-eu"', batch)
        self.assertIn('udp sport 51821 counter drop', batch)
        self.assertIn('net.ipv4.conf.all.rp_filter=0', ' '.join(' '.join(args) for args,_ in calls))
        self.assertTrue(any('unreachable' in args and '220' in args for args,_ in calls))
        self.assertTrue(any('10020' in args and 'unreachable' in args for args,_ in calls))
