import base64
import copy
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sys

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))


def runtime():
    loader = importlib.machinery.SourceFileLoader('cascade_runtime', str(PROJECT / 'bin/cascadectl'))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def config():
    from lib.config import load_config
    return load_config(PROJECT / 'examples/cascade.example.json')


def key(n=1):
    return base64.b64encode(bytes([n]) * 32).decode()


def public_keys():
    return {'entry': {'entry': key(1), 'hop': key(2)}, 'exit': {'hop': key(3)}}


def state(role='entry'):
    from lib.config import state_for
    return state_for(config(), role, public_keys())


def snapshot(role='entry'):
    c = config()[role]
    return {'os': {'ID': 'ubuntu', 'VERSION_ID': '24.04'}, 'architecture': 'x86_64',
            'tun': True, 'systemd': True, 'unmanaged': False, 'state': None, 'installation': None,
            'free_bytes': 4 * 1024**3, 'root_ssh_disabled': False,
            'addresses': [{'ifname': c['wan'], 'mtu': 1500,
                           'addr_info': [{'family': 'inet', 'local': c['ipv4'], 'prefixlen': 24},
                                         {'family': 'inet6', 'local': c['ipv6'], 'prefixlen': 64}]}],
            'routes4': [{'dst': 'default', 'dev': c['wan']}],
            'routes6': [{'dst': 'default', 'dev': c['wan'], 'gateway': '2001:db8:ffff::1'}],
            'routes220': [], 'rules': [{'priority': 0, 'table': 'local'}],
            'docker_active': False, 'docker_user': False, 'unbound_installed': False,
            'chains': [], 'listeners': []}
