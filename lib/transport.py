"""Native OpenSSH transport. Passwords travel through askpass or stdin, never argv."""
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import tempfile

ASKPASS = '''#!/usr/bin/env python3
import os,sys
from pathlib import Path
if len(sys.argv)!=2 or "password" not in sys.argv[1].lower():
    sys.exit(1)
sys.stdout.buffer.write(Path(os.environ["AWG_CASCADE_PASSWORD_FILE"]).read_bytes().rstrip(b"\\r\\n")+b"\\n")
'''


def redact(text):
    return re.sub(r'[A-Za-z0-9+/]{43}=', '<redacted-key>', text)


class Remote:
    def __init__(self, role, ssh, known_hosts, accept_new=False):
        self.role = role
        self.config = ssh
        self.directory = tempfile.TemporaryDirectory(prefix='awg-cascade-ssh-')
        private = Path(self.directory.name)
        self.askpass = private / 'askpass'
        self.askpass.write_text(ASKPASS)
        self.askpass.chmod(0o700)
        self.control = private / 'connection'
        self.known_hosts = Path(known_hosts).expanduser().resolve()
        self.known_hosts.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not self.known_hosts.exists():
            self.known_hosts.touch(mode=0o600)
        self.env = dict(os.environ)
        self.password = None
        password_file = ssh.get('password_file')
        if password_file:
            path = Path(password_file)
            info = path.stat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError(f'{role}: password file must be owned by you and have mode 0600 or 0400')
            self.password = path.read_bytes().rstrip(b'\r\n')
            if not self.password or len(self.password) > 4096 or any(x in self.password for x in [b'\n', b'\r', b'\0']):
                raise ValueError(f'{role}: password file must contain one nonempty password line')
            self.env.update({'SSH_ASKPASS': str(self.askpass), 'SSH_ASKPASS_REQUIRE': 'force',
                             'DISPLAY': self.env.get('DISPLAY', 'awg-cascade:0'),
                             'AWG_CASCADE_PASSWORD_FILE': str(path)})
        self.options = [
            '-T', '-p', str(ssh['port']), '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=3',
            '-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes',
            '-o', 'ControlMaster=auto', '-o', 'ControlPersist=30',
            '-o', 'ControlPath=' + str(self.control),
            '-o', 'UserKnownHostsFile=' + str(self.known_hosts),
            '-o', 'StrictHostKeyChecking=' + ('accept-new' if accept_new else 'yes'),
            '-o', 'NumberOfPasswordPrompts=1',
        ]
        if not password_file:
            self.options += ['-o', 'BatchMode=yes']
        if ssh.get('identity_file'):
            self.options += ['-i', ssh['identity_file'], '-o', 'IdentitiesOnly=yes']
        self.target = ssh['user'] + '@' + ssh['host']
        self.sudo_password_required = None

    def execute(self, script, *, root=True, data=None, timeout=120, check=True, binary=False):
        command = 'env LC_ALL=C sh -c ' + shlex.quote(script)
        payload = data if isinstance(data, bytes) else (data.encode() if data is not None else b'')
        if root and self.config['user'] != 'root':
            if self.sudo_password_required is None:
                probe = self.execute('sudo -n true', root=False, check=False)
                self.sudo_password_required = probe.returncode != 0
            if self.sudo_password_required:
                if self.password is None:
                    raise RuntimeError(f'{self.role}: passwordless sudo or ssh.password_file is required')
                command = "sudo -S -p '' -- " + command
                payload = self.password + b'\n' + payload
            else:
                command = 'sudo -n -- ' + command
        result = subprocess.run(['ssh'] + self.options + [self.target, command], input=payload,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=self.env, timeout=timeout)
        error = result.stderr.decode(errors='replace')
        if self.password:
            error = error.replace(self.password.decode(errors='replace'), '<redacted-password>')
        if check and result.returncode:
            raise RuntimeError(f'{self.role}: remote command failed ({result.returncode}): {redact(error).strip()}')
        if not binary:
            result.stdout = result.stdout.decode(errors='replace')
        result.stderr = redact(error)
        return result

    def python(self, source, data=None, *, timeout=120):
        payload = json.dumps(data or {}).encode()
        return self.execute('python3 -c ' + shlex.quote(source), data=payload, timeout=timeout).stdout

    def close(self):
        subprocess.run(['ssh'] + self.options + ['-O', 'exit', self.target],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=self.env, timeout=10)
        self.directory.cleanup()
