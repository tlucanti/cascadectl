#!/usr/bin/env python3
"""Provision a two-VPS AmneziaWG cascade. --plan never connects to either host."""
import argparse
import base64
import contextlib
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sys
import time

from lib.config import compatible, load_config, state_for
from lib.transport import Remote

PROJECT = Path(__file__).resolve().parent
PRIVATE_NETWORKS = [ipaddress.IPv4Network('10.77.0.0/24'), ipaddress.IPv4Network('10.78.0.0/30')]
INTERFACES = ['awg-clients', 'awg-eu', 'awg-ru']


def load_versions():
    versions = json.loads((PROJECT / 'config/versions.json').read_text())
    expected = {'amneziawg_go': 'https://github.com/amnezia-vpn/amneziawg-go.git',
                'amneziawg_tools': 'https://github.com/amnezia-vpn/amneziawg-tools.git'}
    if set(versions) != set(expected):
        raise ValueError('Version pins must describe both official implementations')
    for name, pin in versions.items():
        if pin['repository'] != expected[name] or not re.fullmatch(r'[a-f0-9]{40}', pin['commit']):
            raise ValueError('Invalid official source pin: ' + name)
        if not re.fullmatch(r'v[0-9][0-9.]+', pin['tag']):
            raise ValueError('Invalid release tag')
    return versions


def identity(config):
    public = {k: {n: v for n, v in config[k].items() if n != 'ssh'} for k in ['entry', 'exit']}
    public.update({k: config[k] for k in ['entry_port', 'hop_port', 'mtu']})
    return hashlib.sha256(json.dumps(public, sort_keys=True).encode()).hexdigest()


def preflight(config, role, snapshot):
    host = config[role]
    if snapshot['os'].get('ID') != 'ubuntu' or snapshot['os'].get('VERSION_ID') != '24.04':
        raise ValueError(f'{role}: bootstrap supports Ubuntu 24.04 LTS')
    if snapshot['architecture'] not in ['x86_64', 'aarch64']:
        raise ValueError(f'{role}: unsupported architecture')
    if not snapshot['tun'] or not snapshot['systemd']:
        raise ValueError(f'{role}: a systemd VPS with /dev/net/tun is required')
    if snapshot['unmanaged']:
        raise ValueError(f'{role}: /etc/cascade contains unrecognized files; inspect it before bootstrapping')
    required_mib = 512 if role == 'entry' else 2048
    if snapshot['free_bytes'] < required_mib * 1024 * 1024:
        raise ValueError(f'{role}: less than {required_mib} MiB of free disk space')
    compatible(config, role, snapshot['state'])
    if role == 'exit' and snapshot['state']:
        active = snapshot['state'].get('eu_active_ipv6', snapshot['state']['eu_ipv6'])
        if active != config['exit']['ipv6'] and active not in snapshot.get('aliases', []):
            raise ValueError('exit: the active alias is missing from its persistent registry; restore the registry before bootstrapping')
    marker = snapshot.get('installation')
    if marker and marker['identity'] != identity(config):
        raise ValueError(f'{role}: existing bootstrap marker belongs to a different deployment')
    if role == 'exit' and snapshot['root_ssh_disabled']:
        raise ValueError('exit: PermitRootLogin no prevents the restricted rotation key; allow root public-key login first')
    interface = next((x for x in snapshot['addresses'] if x['ifname'] == host['wan']), None)
    if interface is None:
        raise ValueError(f'{role}: WAN interface is missing')
    if config['mtu'] + 128 > interface.get('mtu', 1500):
        raise ValueError(f'{role}: configured tunnel MTU leaves insufficient WAN encapsulation headroom')
    assigned = {str(ipaddress.ip_address(x['local'])) for x in interface.get('addr_info', [])}
    if host['ipv4'] not in assigned or host['ipv6'] not in assigned:
        raise ValueError(f'{role}: configured native IPv4 and IPv6 must already be assigned to the WAN')
    if not any(x.get('dev') == host['wan'] for x in snapshot['routes6']):
        raise ValueError(f'{role}: native IPv6 default route is missing')
    for route in snapshot['routes4']:
        if route.get('dst', 'default') == 'default' or route.get('dev') in INTERFACES:
            continue
        network = ipaddress.IPv4Network(route['dst'], strict=False)
        if any(network.overlaps(reserved) for reserved in PRIVATE_NETWORKS):
            raise ValueError(f'{role}: existing route {network} overlaps the fixed tunnel address plan')
    managed = snapshot['state'] is not None
    if not managed and any(x['ifname'] in INTERFACES for x in snapshot['addresses']):
        raise ValueError(f'{role}: a reserved interface name is already in use by an unmanaged tunnel')
    for rule in snapshot['rules']:
        if not managed and (rule.get('priority') in [10000, 10010, 10020] or rule.get('table') == 220):
            raise ValueError(f'{role}: routing table 220 or project policy priorities are already in use')
    if not managed and snapshot.get('routes220'):
        raise ValueError(f'{role}: routing table 220 is already populated')
    if role == 'entry' and snapshot['docker_active']:
        raise ValueError('entry: this bootstrap expects a dedicated entry without Docker forwarding rules')
    if role == 'exit' and snapshot['docker_active'] and not snapshot['docker_user']:
        raise ValueError('exit: Docker must expose its iptables DOCKER-USER chain; the nftables Docker backend needs manual integration')
    if role == 'exit' and snapshot['state'] and snapshot['state'].get('docker_managed') and not snapshot['docker_active']:
        raise ValueError('exit: start the existing managed Docker service before rerunning bootstrap')
    ula = ipaddress.IPv6Network('fd67:a2e4:9b01:1::/64')
    for item in snapshot['addresses']:
        if item['ifname'] in INTERFACES:
            continue
        for address in item.get('addr_info', []):
            if address.get('family') == 'inet6' and ipaddress.IPv6Address(address['local']) in ula:
                raise ValueError(f'{role}: another interface already uses the client IPv6 capture prefix')
    for chain in snapshot['chains']:
        if chain.get('hook') not in ['input', 'forward'] or chain.get('policy') != 'drop':
            continue
        if chain.get('family') == 'ip6' and chain.get('hook') == 'forward':
            continue  # The outer IPv6 tunnel terminates locally; client payload is IPv4.
        docker = (role == 'exit' and snapshot['docker_user'] and chain.get('family') == 'ip'
                  and chain.get('table') == 'filter' and chain.get('name') == 'FORWARD')
        if not docker:
            raise ValueError(f'{role}: existing {chain.get("table")}/{chain["name"]} drop policy needs explicit firewall integration')
    ports = [config['hop_port']] + ([config['entry_port']] if role == 'entry' else [])
    for listener in snapshot['listeners']:
        if listener['protocol'] == 'udp' and listener['port'] in ports:
            if not (managed and listener['managed_awg']):
                raise ValueError(f'{role}: UDP port {listener["port"]} is already in use')
        if role == 'exit' and listener['port'] == 53 and listener['address'] in ['*', '0.0.0.0', '::']:
            raise ValueError('exit: a wildcard DNS listener conflicts with the private resolver')


def encoded_file(destination, body, mode=0o644):
    raw = body if isinstance(body, bytes) else body.encode()
    return {'path': destination, 'data': base64.b64encode(raw).decode(),
            'sha256': hashlib.sha256(raw).hexdigest(), 'mode': mode}


def project_files(role, docker):
    units = ['cascade-awg@.service', 'cascade-firewall.service']
    if role == 'entry':
        units += ['cascade-geo-update.service', 'cascade-geo-update.timer',
                  'cascade-health.service', 'cascade-health.timer']
        sysctls = 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=0\nnet.ipv4.conf.default.rp_filter=0\n'
    else:
        units += ['cascade-ipv6.service', 'cascade-dns.service', 'cascade-awg@awg-ru.service.d/ipv6.conf']
        if docker:
            units += ['cascade-docker-allow.service', 'docker.service.d/cascade.conf']
        sysctls = 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=2\n'
    files = [encoded_file('/usr/local/sbin/cascadectl', (PROJECT / 'bin/cascadectl').read_bytes(), 0o755),
             encoded_file('/etc/sysctl.d/90-cascade.conf', sysctls)]
    files += [encoded_file('/etc/systemd/system/' + name, (PROJECT / 'systemd' / name).read_bytes()) for name in units]
    if role == 'exit':
        files += [encoded_file('/etc/unbound/cascade.conf', (PROJECT / 'templates/unbound.conf').read_bytes())]
    return files


def activate(remote, role, docker, restart=False):
    if role == 'exit':
        units = ['cascade-firewall.service', 'cascade-ipv6.service']
        if docker:
            units += ['cascade-docker-allow.service']
        units += ['cascade-awg@awg-ru.service', 'cascade-dns.service']
    else:
        units = ['cascade-firewall.service', 'cascade-awg@awg-eu.service', 'cascade-awg@awg-clients.service']
    remote.execute('systemctl daemon-reload\nsystemd-analyze verify /etc/systemd/system/cascade-awg@.service /etc/systemd/system/cascade-firewall.service')
    remote.execute('/usr/local/sbin/cascadectl firewall')
    remote.execute('systemctl enable --now ' + shlex.join(units), timeout=90)
    if restart:
        interfaces = ['awg-ru'] if role == 'exit' else ['awg-eu', 'awg-clients']
        remote.execute('systemctl restart ' + shlex.join(['cascade-awg@' + x + '.service' for x in interfaces]), timeout=90)
    if role == 'entry':
        remote.execute('systemctl enable --now cascade-health.timer cascade-geo-update.timer')


def plan(config, versions):
    hosts = {}
    for role in ['entry', 'exit']:
        h = config[role]
        hosts[role] = {k: v for k, v in h.items() if k != 'ssh'}
        hosts[role]['ssh'] = f'{h["ssh"]["user"]}@{h["ssh"]["host"]}:{h["ssh"]["port"]}'
    return {'hosts': hosts, 'entry_port': config['entry_port'], 'hop_port': config['hop_port'],
            'mtu': config['mtu'], 'client_names_to_ensure': config['clients'], 'versions': versions,
            'steps': ['read-only preflight', 'private baseline backups', 'install required packages',
                      'build pinned official sources on exit; checksum and copy binaries to entry',
                      'preserve or generate keys and shared material', 'install scoped services and firewall manager',
                      'configure restricted rotation key with pinned exit host key',
                      'start exit, then entry, verify tunnel/DNS; create private backups'],
            'automatic_reboot': False}


def provision(config, options, remote_factory=Remote):
    versions = load_versions()
    if options.plan:
        print(json.dumps(plan(config, versions), indent=2))
        return
    if options.profiles_dir:
        destination = Path(options.profiles_dir).expanduser().resolve()
        if destination == PROJECT or PROJECT in destination.parents:
            permitted = [PROJECT / '.local', PROJECT / 'profiles']
            if not any(destination == p or p in destination.parents for p in permitted):
                raise ValueError('Inside the checkout, export private profiles only under .local/ or profiles/')
    if not shutil.which('ssh'):
        raise RuntimeError('Install an OpenSSH client on the control machine')
    source = (PROJECT / 'lib/remote.py').read_text()
    with contextlib.ExitStack() as stack:
        hosts = {}
        for role in ['entry', 'exit']:
            remote = remote_factory(role, config[role]['ssh'], options.known_hosts, options.accept_new_host_keys)
            stack.callback(remote.close)
            hosts[role] = remote
        def call(which, action, **payload):
            output = hosts[which].python(source, dict(action=action, **payload), timeout=options.timeout)
            return json.loads(output)
        snapshots = {}
        for role in ['entry', 'exit']:
            print(f'[{role}] Read-only preflight', flush=True)
            snapshots[role] = call(role, 'inspect')
            preflight(config, role, snapshots[role])
        if snapshots['entry']['architecture'] != snapshots['exit']['architecture']:
            raise ValueError('Entry and exit must have matching CPU architectures for the binary transfer')
        previous_entry, previous_exit = snapshots['entry']['state'], snapshots['exit']['state']
        if previous_entry and previous_exit:
            active = previous_exit.get('eu_active_ipv6', previous_exit['eu_ipv6'])
            if previous_entry['eu_ipv6'] != active:
                raise ValueError('Entry endpoint and exit source disagree; complete or revert the interrupted rotation before bootstrapping')
        # Check the actual route's IPv6 source before installing the exit whitelist.
        route = hosts['entry'].execute('ip -j -6 route get ' + shlex.quote(config['exit']['ipv6'])).stdout
        if json.loads(route)[0].get('prefsrc', json.loads(route)[0].get('src')) != config['entry']['ipv6']:
            raise ValueError('Entry IPv6 route selects a different source; configure its preferred native source first')
        if options.check:
            print('Preflight passed; no server changes made.')
            return
        for role in ['entry', 'exit']:
            print(f'[{role}] Back up existing configuration and install packages', flush=True)
            backup = call(role, 'claim', identity=identity(config),
                          unbound_preexisting=snapshots[role]['unbound_installed'])
            print(f'[{role}] Baseline: {backup["backup"]}', flush=True)
            call(role, 'packages', role=role, build=not options.skip_build)
        print('[exit] Verify pinned binaries' if options.skip_build else '[exit] Build pinned upstream sources', flush=True)
        manifest = call('exit', 'versions' if options.skip_build else 'build', versions=versions)
        # Transfer binary bytes through native SSH. Private server keys never leave either VPS.
        binaries = []
        for name, digest in manifest.items():
            raw = hosts['exit'].execute('cat /usr/local/bin/' + name, binary=True).stdout
            if hashlib.sha256(raw).hexdigest() != digest:
                raise ValueError('Downloaded binary checksum mismatch: ' + name)
            binaries.append(encoded_file('/usr/local/bin/' + name, raw, 0o755))
        call('entry', 'write', files=binaries + [encoded_file('/etc/cascade/build.json', json.dumps(versions) + '\n', 0o600)])
        call('entry', 'versions', versions=versions)
        public = {role: call(role, 'keys', role=role) for role in ['entry', 'exit']}
        for role in ['entry', 'exit']:
            previous = snapshots[role]['state']
            if previous and (previous.get('entry_public_key') != public['entry']['entry']
                             or previous.get('eu_public_key') != public['exit']['hop']):
                raise ValueError(f'{role}: saved server public keys do not match; restore or plan an explicit migration')
        shared = call('entry', 'shared', role='entry')
        call('exit', 'shared', role='exit', shared=shared)
        del shared
        for role in ['entry', 'exit']:
            docker = role == 'exit' and snapshots[role]['docker_active']
            print(f'[{role}] Install services and preserve saved peers', flush=True)
            files = project_files(role, docker)
            files += [encoded_file('/etc/cascade/build.json', json.dumps(versions) + '\n', 0o600),
                      encoded_file('/etc/cascade/build-binaries.json', json.dumps(manifest) + '\n', 0o600)]
            if role == 'entry':
                files.append(encoded_file('/etc/sysctl.d/90-cascade.conf',
                             'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=0\nnet.ipv4.conf.default.rp_filter=0\n'
                             + 'net.ipv4.conf.' + config[role]['wan'] + '.rp_filter=0\n'))
            call(role, 'write', files=files)
            state = state_for(config, role, public, snapshots[role]['state'], docker)
            peer = public['exit']['hop'] if role == 'entry' else public['entry']['hop']
            call(role, 'configure', role=role, state=state, peer_public_key=peer, clients=config['clients'])
        rotation = call('entry', 'rotation-key')
        trusted = call('exit', 'authorize', public_key=rotation['public_key'],
                       entry_ipv4=config['entry']['ipv4'], entry_ipv6=config['entry']['ipv6'])
        port = config['exit']['ssh']['port']
        known = f'cascade-eu,[cascade-eu]:{port} {trusted["host_key"]}\n'
        call('entry', 'write', files=[encoded_file('/etc/cascade/eu_known_hosts', known, 0o600)])
        # Verify the forced-command key, not just the control machine's SSH login.
        rotation_options = ['ssh', '-p', str(port), '-i', '/etc/cascade/rotation_ed25519',
                            '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                            '-o', 'StrictHostKeyChecking=yes', '-o', 'HostKeyAlias=cascade-eu',
                            '-o', 'UserKnownHostsFile=/etc/cascade/eu_known_hosts', '-o', 'ConnectTimeout=5']
        for address in [config['exit']['ipv4'], config['exit']['ipv6']]:
            probe = shlex.join(rotation_options + ['root@' + address, 'prepare ' + config['exit']['ipv6']])
            if hosts['entry'].execute(probe, timeout=20, check=False).returncode == 0:
                break
        else:
            raise RuntimeError('The restricted entry-to-exit rotation key failed over IPv4 and IPv6; check root public-key login and source restrictions')
        print('[entry] Refresh destination prefixes', flush=True)
        hosts['entry'].execute('/usr/local/sbin/cascadectl geo-update', timeout=60)
        print('[exit] Start services', flush=True)
        activate(hosts['exit'], 'exit', snapshots['exit']['docker_active'], options.restart)
        print('[entry] Start services and check tunnel/DNS', flush=True)
        activate(hosts['entry'], 'entry', False, options.restart)
        last = None
        for _ in range(5):
            result = hosts['entry'].execute('/usr/local/sbin/cascadectl health', timeout=30, check=False)
            if result.returncode == 0:
                break
            last = result.stderr
            time.sleep(2)
        else:
            raise RuntimeError('Services are installed but tunnel/DNS checks failed; check provider UDP filtering and journals: ' + str(last))
        if options.profiles_dir:
            target = Path(options.profiles_dir).expanduser().resolve()
            target.mkdir(mode=0o700, parents=True, exist_ok=True)
            for name in config['clients']:
                body = hosts['entry'].execute('cat /etc/cascade/profiles/' + name + '.conf').stdout
                destination = target / (name + '.conf')
                fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, 'w') as output:
                    output.write(body)
                print('Private client profile: ' + str(destination), flush=True)
        for role in ['entry', 'exit']:
            call(role, 'finish')
            snapshot = hosts[role].execute('/usr/local/sbin/cascadectl backup').stdout.strip()
            print(f'[{role}] Current private backup: {snapshot}', flush=True)
        print('Bootstrap complete. Run sudo cascadectl status/health on the entry. No VPS was rebooted.')


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--config', required=True, help='Deployment JSON; see examples/cascade.example.json')
    modes = p.add_mutually_exclusive_group()
    modes.add_argument('--plan', action='store_true', help='Print a public plan without SSH or credential reads')
    modes.add_argument('--check', action='store_true', help='Read-only SSH preflight; no server changes')
    p.add_argument('--known-hosts', default=str(PROJECT / '.local/known_hosts'))
    p.add_argument('--accept-new-host-keys', action='store_true', help='Trust first-seen SSH host keys; changed keys still fail')
    p.add_argument('--skip-build', action='store_true', help='Require the exact pinned binaries already installed on exit')
    p.add_argument('--restart', action='store_true', help='Restart project tunnels to apply updated binaries/service settings')
    p.add_argument('--profiles-dir', help='Explicit destination for exported private client configs')
    p.add_argument('--timeout', type=int, default=1800, help='Maximum seconds per remote bootstrap action')
    return p


def main(argv=None):
    options = parser().parse_args(argv)
    config = load_config(options.config)
    provision(config, options)


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as error:
        print('bootstrap: ' + str(error), file=sys.stderr)
        sys.exit(1)
