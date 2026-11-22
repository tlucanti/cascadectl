"""Trusted root-side bootstrap actions, sent over an authenticated SSH session.

ROOT is only replaced by the local test harness. The remote protocol never accepts
an alternate filesystem root or arbitrary executable code from configuration.
"""
import base64
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path('/')


def path(value):
    return ROOT / str(value).lstrip('/')


def command(args, data=None, check=True, timeout=120):
    try:
        p = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
    except FileNotFoundError:
        if check:
            raise RuntimeError('Required executable is missing: ' + args[0])
        return subprocess.CompletedProcess(args, 127, '', '')
    if check and p.returncode:
        detail = re.sub(r'[A-Za-z0-9+/]{43}=', '<redacted-key>', p.stderr.strip())
        raise RuntimeError(f'{args[0]} failed ({p.returncode}): {detail}')
    return p


def atomic(target, data, mode=0o600):
    target = Path(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.awg-cascade-', dir=target.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, 'wb') as f:
            f.write(data.encode() if isinstance(data, str) else data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, target)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def read_json(name, default=None):
    p = path(name)
    return json.loads(p.read_text()) if p.exists() else default


def save_json(name, value):
    atomic(path(name), json.dumps(value, indent=2) + '\n')


def valid_key(value):
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (ValueError, TypeError):
        return False


def inspect(_):
    release = {}
    for line in path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            release[key] = value.strip('"')
    state = read_json('/etc/cascade/state.json')
    installation = read_json('/etc/cascade/installation.json')
    base = path('/etc/cascade')
    unmanaged = base.exists() and any(base.iterdir()) and not state and not installation
    addresses = json.loads(command(['ip', '-j', 'address', 'show']).stdout)
    routes4 = json.loads(command(['ip', '-j', '-4', 'route', 'show', 'table', 'main']).stdout)
    routes6 = json.loads(command(['ip', '-j', '-6', 'route', 'show', 'default']).stdout)
    routes220 = json.loads(command(['ip', '-j', '-4', 'route', 'show', 'table', '220'], check=False).stdout or '[]')
    rules = json.loads(command(['ip', '-j', '-4', 'rule', 'show']).stdout)
    nft = command(['nft', '-j', 'list', 'ruleset'], check=False)
    chains = [x['chain'] for x in json.loads(nft.stdout or '{"nftables":[]}').get('nftables', []) if 'chain' in x]
    listeners = []
    for line in command(['ss', '-H', '-lntup']).stdout.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] in ['tcp', 'udp']:
            local = parts[4]
            address, _, port = local.rpartition(':')
            if port.isdigit():
                listeners.append({'protocol': parts[0], 'address': address.strip('[]'), 'port': int(port),
                                  'managed_awg': 'amneziawg-go' in line})
    docker_active = command(['systemctl', 'is-active', 'docker.service'], check=False).returncode == 0
    docker_user = command(['iptables', '-S', 'DOCKER-USER'], check=False).returncode == 0
    unbound_installed = command(['dpkg-query', '-W', '-f=${db:Status-Status}', 'unbound'], check=False).stdout == 'installed'
    return {'os': release, 'architecture': command(['uname', '-m']).stdout.strip(),
            'tun': path('/dev/net/tun').exists(), 'systemd': path('/run/systemd/system').exists(),
            'state': state, 'installation': installation, 'unmanaged': unmanaged,
            'aliases': read_json('/etc/cascade/eu-aliases.json', []),
            'addresses': addresses, 'routes4': routes4, 'routes6': routes6, 'routes220': routes220, 'rules': rules,
            'chains': chains, 'listeners': listeners, 'docker_active': docker_active,
            'docker_user': docker_user, 'unbound_installed': unbound_installed,
            'root_ssh_disabled': 'permitrootlogin no' in command(['/usr/sbin/sshd', '-T'], check=False).stdout,
            'free_bytes': shutil.disk_usage(path('/')).free}


def claim(data):
    base = path('/etc/cascade')
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    base.chmod(0o700)
    existing = read_json('/etc/cascade/installation.json')
    if existing and existing['identity'] != data['identity']:
        raise ValueError('This directory belongs to a different deployment')
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    backup = path('/root/awg-cascade-backups') / (stamp + '-baseline.tar.gz')
    backup.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    targets = ['/etc/cascade', '/etc/amnezia/amneziawg', '/etc/netplan', '/etc/sysctl.d/90-cascade.conf',
               '/usr/local/sbin/cascadectl', '/etc/unbound/cascade.conf',
               '/etc/systemd/system/docker.service.d/cascade.conf']
    with os.fdopen(fd, 'wb') as output, tarfile.open(fileobj=output, mode='w:gz') as archive:
        for name in targets:
            p = path(name)
            if p.exists():
                archive.add(p, arcname=name.lstrip('/'))
        for p in path('/etc/systemd/system').glob('cascade-*'):
            archive.add(p, arcname='etc/systemd/system/' + p.name)
    for args, filename in [(['nft', 'list', 'ruleset'], 'nftables.txt'),
                           (['ip', '-4', 'rule', 'show'], 'rules.txt'),
                           (['ip', '-4', 'route', 'show', 'table', 'all'], 'routes.txt')]:
        atomic(backup.parent / (stamp + '-' + filename), command(args, check=False).stdout)
    if not existing:
        save_json('/etc/cascade/installation.json', {'identity': data['identity'], 'status': 'preparing',
                  'unbound_owned_service': not data.get('unbound_preexisting', False)})
    return {'backup': str(backup)}


def packages(data):
    names = ['nftables', 'iproute2', 'iptables', 'curl', 'ca-certificates', 'python3',
             'dnsutils', 'openssh-client', 'tar']
    if data['role'] == 'exit':
        names += ['unbound', 'unbound-anchor']
        if data.get('build', True):
            names += ['build-essential', 'git', 'golang-go']
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l')
    for args in [['apt-get', 'update', '-qq'], ['apt-get', 'install', '-y', '--no-install-recommends'] + names]:
        result = subprocess.run(args, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)
        if result.returncode:
            raise RuntimeError('APT failed; inspect the server package logs: ' + result.stdout[-3000:])
    return {'packages_installed': True}


def binary_manifest():
    return {name: hashlib.sha256(path('/usr/local/bin/' + name).read_bytes()).hexdigest()
            for name in ['amneziawg-go', 'awg', 'awg-quick']}


def build(data):
    versions = data['versions']
    env = dict(os.environ, GOMAXPROCS='1', GOGC='50', GOTOOLCHAIN='auto', CGO_ENABLED='0')
    source = path('/opt/awg-cascade/src')
    source.mkdir(parents=True, exist_ok=True)
    for name, binary in [('amneziawg_go', 'amneziawg-go'), ('amneziawg_tools', 'awg')]:
        pin = versions[name]
        directory = source / (name + '-' + pin['commit'][:12])
        if not directory.exists():
            command(['git', 'clone', '--no-checkout', pin['repository'], str(directory)], timeout=180)
        origin = command(['git', '-C', str(directory), 'remote', 'get-url', 'origin']).stdout.strip()
        if origin != pin['repository']:
            raise ValueError('Existing source checkout has a different origin')
        command(['git', '-C', str(directory), 'fetch', '--depth', '1', 'origin', 'tag', pin['tag']], timeout=180)
        commit = command(['git', '-C', str(directory), 'rev-parse', pin['tag'] + '^{}']).stdout.strip()
        if commit != pin['commit']:
            raise ValueError('Upstream tag does not match the pinned commit: ' + name)
        command(['git', '-C', str(directory), 'checkout', '--detach', pin['commit']])
        working = directory if name == 'amneziawg_go' else directory / 'src'
        result = subprocess.run(['make', '-j1'], cwd=working, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=900)
        if result.returncode:
            raise RuntimeError('Pinned build failed: ' + result.stdout[-3000:])
        built = working / ('amneziawg-go' if name == 'amneziawg_go' else 'wg')
        atomic(path('/usr/local/bin/' + binary), built.read_bytes(), 0o755)
        if name == 'amneziawg_tools':
            atomic(path('/usr/local/bin/awg-quick'), (working / 'wg-quick/linux.bash').read_bytes(), 0o755)
    save_json('/etc/cascade/build.json', versions)
    return binary_manifest()


def versions(data):
    for binary, name in [('amneziawg-go', 'amneziawg_go'), ('awg', 'amneziawg_tools')]:
        output = command(['/usr/local/bin/' + binary, '--version']).stdout
        if data['versions'][name]['tag'] not in output:
            raise ValueError('Installed binary version differs from pin: ' + binary)
    if not path('/usr/local/bin/awg-quick').is_file():
        raise ValueError('awg-quick is missing')
    return binary_manifest()


def keys(data):
    for name in ['/etc/cascade/keys', '/etc/cascade/profiles', '/etc/amnezia/amneziawg']:
        path(name).mkdir(parents=True, exist_ok=True, mode=0o700)
        path(name).chmod(0o700)
    names = ['entry', 'hop'] if data['role'] == 'entry' else ['hop']
    previous = read_json('/etc/cascade/state.json')
    result = {}
    for name in names:
        keyfile = path('/etc/cascade/keys/' + name + '.key')
        if not keyfile.exists():
            if previous:
                raise ValueError('Existing installation has lost a server private key; restore its backup')
            atomic(keyfile, command(['/usr/local/bin/awg', 'genkey']).stdout)
        private = keyfile.read_text().strip()
        if not valid_key(private):
            raise ValueError('Invalid saved server key: ' + name)
        keyfile.chmod(0o600)
        result[name] = command(['/usr/local/bin/awg', 'pubkey'], private + '\n').stdout.strip()
    return result


def obfuscation(header, padding):
    return f'''Jc = 4
Jmin = 40
Jmax = 128
S1 = {padding}
S2 = {padding}
S3 = {padding}
S4 = {padding}
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = {header}
ContentPaddingAddition = 0-32
RandomTrailers = on
RekeyAfterTime = 110-130
RekeyTimeout = 5-7
RejectAfterTime = 180-200
KeepaliveTimeout = 10-15
MaxHandshakeAttempts = 18-22
'''


def shared(data):
    if data['role'] == 'entry':
        paths = {'psk': '/etc/cascade/keys/hop.psk', 'obfuscation': '/etc/cascade/hop-obfuscation.conf',
                 'entry_obfuscation': '/etc/cascade/entry-obfuscation.conf'}
        for name, filename in paths.items():
            p = path(filename)
            if not p.exists():
                if read_json('/etc/cascade/state.json'):
                    raise ValueError('Existing installation is missing shared key material: ' + name)
                if name == 'psk':
                    body = command(['/usr/local/bin/awg', 'genpsk']).stdout
                else:
                    header = command(['/usr/local/bin/awg', 'genkey']).stdout.strip()
                    body = obfuscation(header, 32 if name == 'entry_obfuscation' else 24)
                atomic(p, body)
        return {name: path(filename).read_text() for name, filename in paths.items() if name != 'entry_obfuscation'}
    secret = data['shared']
    if not valid_key(secret['psk'].strip()):
        raise ValueError('Invalid interserver preshared key')
    for name, body in [('keys/hop.psk', secret['psk']),
                       ('hop-obfuscation.conf', re.sub(r'^Jc\s*=.*$', 'Jc = 0', secret['obfuscation'], flags=re.M))]:
        p = path('/etc/cascade/' + name)
        if p.exists() and p.read_text().strip() != body.strip():
            raise ValueError('Existing exit shared material differs from the entry; refusing to replace it')
        if not p.exists():
            atomic(p, body)
    return {'shared_material_matches': True}


def write(data):
    # All paths come from the trusted bootstrap source, not directly from JSON config.
    decoded = []
    for item in data['files']:
        name = item['path']
        allowed = (name.startswith('/etc/cascade/') or name.startswith('/etc/amnezia/amneziawg/')
                   or name.startswith('/etc/systemd/system/cascade-') or name.startswith('/usr/local/bin/')
                   or name in ['/usr/local/sbin/cascadectl', '/etc/sysctl.d/90-cascade.conf',
                               '/etc/unbound/cascade.conf', '/etc/systemd/system/docker.service.d/cascade.conf'])
        if not allowed or '..' in Path(name).parts:
            raise ValueError('Unexpected installation path')
        raw = base64.b64decode(item['data'], validate=True)
        if hashlib.sha256(raw).hexdigest() != item['sha256']:
            raise ValueError('File transfer checksum mismatch')
        decoded.append((path(name), raw, item['mode']))
    for target, raw, mode in decoded:
        atomic(target, raw, mode)
    return {'files_installed': len(decoded)}


def configure(data):
    s = data['state']
    role = data['role']
    clients = path('/etc/cascade/clients.json')
    if role == 'entry':
        if not clients.exists():
            if read_json('/etc/cascade/state.json'):
                raise ValueError('Existing client database is missing; refusing to reset it')
            atomic(clients, '[]\n')
        overrides = path('/etc/cascade/overrides.json')
        if not overrides.exists():
            atomic(overrides, '{"always_russia": [], "always_europe": []}\n')
    else:
        aliases = path('/etc/cascade/eu-aliases.json')
        if not aliases.exists():
            if read_json('/etc/cascade/state.json'):
                raise ValueError('Existing exit alias registry is missing; restore its backup')
            atomic(aliases, '[]\n')
    save_json('/etc/cascade/state.json', s)
    interface = 'awg-eu' if role == 'entry' else 'awg-ru'
    address = '10.78.0.1/30' if role == 'entry' else '10.78.0.2/30'
    allowed = '0.0.0.0/0' if role == 'entry' else '10.77.0.0/24, 10.78.0.1/32'
    raw = f'''[Interface]
PrivateKey = {path('/etc/cascade/keys/hop.key').read_text().strip()}
Address = {address}
ListenPort = {s['hop_port']}
MTU = {s.get('mtu', 1280)}
Table = off
''' + path('/etc/cascade/hop-obfuscation.conf').read_text() + f'''
[Peer]
PublicKey = {data['peer_public_key']}
PresharedKey = {path('/etc/cascade/keys/hop.psk').read_text().strip()}
AllowedIPs = {allowed}
'''
    if role == 'entry':
        raw += f'Endpoint = [{s["eu_ipv6"]}]:{s["hop_port"]}\nPersistentKeepalive = 25\n'
    atomic(path('/etc/amnezia/amneziawg/' + interface + '.conf'), raw)
    if role == 'entry':
        command(['/usr/local/sbin/cascadectl', 'sync-clients'])
        existing = {c['name'] for c in read_json('/etc/cascade/clients.json', [])}
        for name in data['clients']:
            if name not in existing:
                command(['/usr/local/sbin/cascadectl', 'client', 'add', name])
    else:
        user = pwd.getpwnam('unbound')
        anchor = path('/var/lib/unbound/cascade-root.key')
        if not anchor.exists():
            default = path('/var/lib/unbound/root.key')
            if default.exists():
                atomic(anchor, default.read_bytes(), 0o644)
            else:
                p = command(['unbound-anchor', '-4', '-a', str(anchor)], check=False)
                if not anchor.exists():
                    raise RuntimeError('Failed to initialize DNS trust anchor: ' + p.stderr)
        os.chown(anchor, user.pw_uid, user.pw_gid)
        command(['unbound-checkconf', '/etc/unbound/cascade.conf'])
        if read_json('/etc/cascade/installation.json')['unbound_owned_service']:
            command(['systemctl', 'disable', '--now', 'unbound.service'])
    return {'configured': role}


def rotation_key(_):
    private = path('/etc/cascade/rotation_ed25519')
    if not private.exists():
        command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'cascade-ipv6-rotation', '-f', str(private)])
    private.chmod(0o600)
    public = private.with_suffix('.pub')
    if not public.exists():
        atomic(public, command(['ssh-keygen', '-y', '-f', str(private)]).stdout + ' cascade-ipv6-rotation\n', 0o644)
    return {'public_key': public.read_text().strip()}


def authorize(data):
    key = data['public_key'].split()
    if len(key) < 2 or key[0] != 'ssh-ed25519':
        raise ValueError('Rotation requires an Ed25519 public key')
    ip4 = str(ipaddress.IPv4Address(data['entry_ipv4']))
    ip6 = str(ipaddress.IPv6Address(data['entry_ipv6']))
    line = f'from="{ip4},{ip6}",restrict,command="/usr/local/sbin/cascadectl remote-alias" ' + ' '.join(key[:2]) + ' cascade-ipv6-rotation'
    ssh = path('/root/.ssh')
    ssh.mkdir(exist_ok=True, mode=0o700)
    ssh.chmod(0o700)
    authorized = ssh / 'authorized_keys'
    lines = authorized.read_text().splitlines() if authorized.exists() else []
    lines = [x for x in lines if not x.endswith(' cascade-ipv6-rotation')]
    atomic(authorized, '\n'.join(lines + [line]) + '\n')
    atomic(path('/etc/cascade/rotation-authorized-key'), line + '\n')
    hostkey = path('/etc/ssh/ssh_host_ed25519_key.pub')
    if not hostkey.exists():
        raise ValueError('Exit requires an Ed25519 SSH host key')
    return {'host_key': ' '.join(hostkey.read_text().split()[:2])}


def finish(_):
    record = read_json('/etc/cascade/installation.json')
    record['status'] = 'ready'
    save_json('/etc/cascade/installation.json', record)
    return {'ready': True}


ACTIONS = {'inspect': inspect, 'claim': claim, 'packages': packages, 'build': build, 'versions': versions,
           'keys': keys, 'shared': shared, 'write': write, 'configure': configure,
           'rotation-key': rotation_key, 'authorize': authorize, 'finish': finish}


def main():
    if os.geteuid() != 0:
        raise RuntimeError('Bootstrap actions require root')
    payload = json.load(sys.stdin)
    action = payload.pop('action')
    if action not in ACTIONS:
        raise ValueError('Unsupported bootstrap action')
    print(json.dumps(ACTIONS[action](payload)))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        message = re.sub(r'[A-Za-z0-9+/]{43}=', '<redacted-key>', str(error))
        print('bootstrap: ' + message, file=sys.stderr)
        sys.exit(1)
