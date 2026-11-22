"""Strict, public deployment configuration. Secret values are never accepted inline."""
import ipaddress
import json
from pathlib import Path
import re

DEFAULT_CLIENTS = ['android-01', 'android-02', 'android-03']


def integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f'{name} must be an integer between {low} and {high}')
    return value


def reject_unknown(value, allowed, name):
    unknown = set(value) - set(allowed)
    if unknown:
        raise ValueError(f'Unknown {name} fields: {", ".join(sorted(unknown))}')


def load_config(path):
    source = Path(path).expanduser().resolve()
    data = json.loads(source.read_text())
    reject_unknown(data, ['entry', 'exit', 'entry_port', 'hop_port', 'mtu', 'clients'], 'configuration')
    result = {}
    for role in ['entry', 'exit']:
        host = data[role]
        reject_unknown(host, ['ssh', 'ipv4', 'ipv6', 'ipv6_prefix', 'wan'], role)
        ipv4 = str(ipaddress.IPv4Address(host['ipv4']))
        ipv6 = str(ipaddress.IPv6Address(host['ipv6']))
        if '%' in ipv6 or ipaddress.IPv6Address(ipv6).ipv4_mapped:
            raise ValueError(f'{role}.ipv6 must be an unscoped native IPv6 address')
        wan = host['wan']
        if not re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', wan):
            raise ValueError(f'{role}.wan must be a Linux interface name, up to 15 characters')
        if wan in ['lo', 'awg-clients', 'awg-eu', 'awg-ru']:
            raise ValueError('WAN must not be a loopback or a project tunnel interface')
        ssh = dict(host.get('ssh', {}))
        reject_unknown(ssh, ['host', 'user', 'port', 'identity_file', 'password_file'], role + '.ssh')
        ssh['host'] = str(ipaddress.ip_address(ssh.get('host', ipv4)))
        ssh['user'] = ssh.get('user', 'root')
        if not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}', ssh['user']):
            raise ValueError(f'Invalid {role} SSH user')
        ssh['port'] = integer(ssh.get('port', 22), 1, 65535, role + '.ssh.port')
        for name in ['identity_file', 'password_file']:
            value = ssh.get(name)
            if value:
                p = Path(value).expanduser()
                ssh[name] = str((source.parent / p).resolve() if not p.is_absolute() else p.resolve())
            else:
                ssh[name] = None
        result[role] = {'ipv4': ipv4, 'ipv6': ipv6, 'wan': wan, 'ssh': ssh}
    prefix = ipaddress.IPv6Network(data['exit']['ipv6_prefix'], strict=True)
    if '%' in str(prefix):
        raise ValueError('The exit prefix must be unscoped')
    if prefix.prefixlen != 64 or ipaddress.IPv6Address(result['exit']['ipv6']) not in prefix:
        raise ValueError('exit.ipv6_prefix must be the allocated /64 containing exit.ipv6')
    if ipaddress.IPv6Address(result['exit']['ipv6']) == prefix.network_address:
        raise ValueError('The exit IPv6 must be a host address, not the subnet-router address')
    result['exit']['ipv6_prefix'] = str(prefix)
    if result['entry']['ipv4'] == result['exit']['ipv4']:
        raise ValueError('The two roles require different VPSs')
    result['entry_port'] = integer(data.get('entry_port', 443), 1, 65535, 'entry_port')
    result['hop_port'] = integer(data.get('hop_port', 51821), 1, 65535, 'hop_port')
    if result['entry_port'] == result['hop_port']:
        raise ValueError('entry_port and hop_port must differ')
    if result['hop_port'] == 53:
        raise ValueError('hop_port 53 conflicts with the private DNS resolver')
    result['mtu'] = integer(data.get('mtu', 1280), 1280, 1420, 'mtu')
    names = data.get('clients', DEFAULT_CLIENTS)
    if not isinstance(names, list) or len(names) > 230:
        raise ValueError('clients must be a list of at most 230 profile names')
    if any(not isinstance(x, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,15}', x) for x in names):
        raise ValueError('Client names require 1-15 letters, digits, underscores or hyphens')
    if len(names) != len(set(names)):
        raise ValueError('Client names must be unique')
    result['clients'] = names
    return result


def state_for(config, role, public_keys, previous=None, docker=False):
    """Retain a rotated endpoint and aliases when re-rendering an existing install."""
    s = dict(previous or {})
    entry, exit = config['entry'], config['exit']
    s.update({
        'role': 'ru' if role == 'entry' else 'eu',
        'wan': config[role]['wan'], 'public_ipv4': config[role]['ipv4'],
        'ru_ipv6': entry['ipv6'], 'eu_prefix': exit['ipv6_prefix'],
        'eu_primary_ipv6': exit['ipv6'], 'eu_admin_ipv4': exit['ipv4'],
        'eu_ssh_port': exit['ssh']['port'], 'entry_port': config['entry_port'],
        'hop_port': config['hop_port'], 'mtu': config['mtu'],
        'entry_public_key': public_keys['entry']['entry'],
        'eu_public_key': public_keys['exit']['hop'], 'docker_managed': docker,
    })
    if role == 'entry':
        s['eu_ipv6'] = s.get('eu_ipv6', exit['ipv6'])
    else:
        s['eu_ipv6'] = exit['ipv6']
        s['eu_active_ipv6'] = s.get('eu_active_ipv6', exit['ipv6'])
    return s


def compatible(config, role, previous):
    if not previous:
        return
    expected = {
        'role': 'ru' if role == 'entry' else 'eu',
        'public_ipv4': config[role]['ipv4'], 'wan': config[role]['wan'],
        'ru_ipv6': config['entry']['ipv6'], 'eu_prefix': config['exit']['ipv6_prefix'],
        'entry_port': config['entry_port'], 'hop_port': config['hop_port'],
    }
    for name, value in expected.items():
        if previous.get(name) != value:
            raise ValueError(f'{role}: existing {name} differs; bootstrap will not migrate a live deployment implicitly')
    if previous.get('mtu', 1280) != config['mtu']:
        raise ValueError(f'{role}: changing MTU requires a planned client configuration migration')
    primary = previous.get('eu_primary_ipv6') if role == 'entry' else previous.get('eu_ipv6')
    if primary is not None and primary != config['exit']['ipv6']:
        raise ValueError(f'{role}: the primary exit IPv6 differs from the existing deployment')
