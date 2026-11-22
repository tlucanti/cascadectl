from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from support import config
from lib.transport import Remote


class TransportTests(unittest.TestCase):
    def test_password_is_stdin_only_and_never_in_command_or_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            password = root / 'password';password.write_text('synthetic-test-password\n');password.chmod(0o600)
            ssh = config()['entry']['ssh'];ssh['password_file'] = str(password)
            calls = []
            def fake(argv, **kwargs):
                calls.append((argv, kwargs))
                code = 1 if 'sudo -n true' in argv[-1] else 0
                return subprocess.CompletedProcess(argv, code, b'', b'')
            with patch('lib.transport.subprocess.run', side_effect=fake):
                remote = Remote('entry', ssh, root / 'known_hosts')
                try:remote.execute('python3 -c pass', data='{"payload":true}')
                finally:remote.close()
            actual = next((a,k) for a,k in calls if k.get('input', b'').startswith(b'synthetic-test-password'))
            argv, options = actual
            self.assertEqual(options['input'], b'synthetic-test-password\n{"payload":true}')
            self.assertNotIn('synthetic-test-password', str(argv))
            self.assertNotIn('synthetic-test-password', str(options['env']))
            self.assertIn('StrictHostKeyChecking=yes', argv)
            self.assertIn('ForwardAgent=no', argv)
            self.assertIn('ClearAllForwardings=yes', argv)

    def test_passwordless_sudo_does_not_prepend_input(self):
        with tempfile.TemporaryDirectory() as directory, patch('lib.transport.subprocess.run') as run:
            run.side_effect = lambda *a, **k: subprocess.CompletedProcess([], 0, b'', b'')
            remote = Remote('entry', config()['entry']['ssh'], Path(directory) / 'known_hosts')
            try:remote.execute('python3 -c pass', data='{"payload":true}')
            finally:remote.close()
            inputs = [c.kwargs.get('input') for c in run.call_args_list if 'input' in c.kwargs]
            self.assertEqual(inputs, [b'', b'{"payload":true}'])
