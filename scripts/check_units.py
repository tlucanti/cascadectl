#!/usr/bin/env python3
"""Verify real systemd unit parsing/ordering against a temporary, inert root."""
from pathlib import Path
import shutil
import subprocess
import tempfile

PROJECT = Path(__file__).resolve().parents[1]


def main():
    if not shutil.which('systemd-analyze'):
        print('Optional systemd verification skipped: systemd-analyze is unavailable')
        return 0
    with tempfile.TemporaryDirectory(prefix='awg-cascade-units-') as directory:
        root = Path(directory)
        units = root / 'etc/systemd/system'
        units.mkdir(parents=True)
        shutil.copytree(PROJECT / 'systemd', units, dirs_exist_ok=True)
        for name in ['sysinit.target', 'basic.target', 'shutdown.target', 'network-online.target',
                     'multi-user.target', 'timers.target', 'sockets.target', 'paths.target']:
            (units / name).write_text('[Unit]\nDescription=Verification fixture\n')
        (units / 'system.slice').write_text('[Unit]\nDescription=Verification fixture\n[Slice]\n')
        (units / 'docker.service').write_text('[Service]\nType=oneshot\nExecStart=/bin/true\nRemainAfterExit=yes\n')
        for name in ['usr/local/sbin/cascadectl', 'usr/local/bin/amneziawg-go', 'usr/sbin/unbound', 'bin/true']:
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('#!/bin/sh\nexit 0\n')
            p.chmod(0o755)
        (root / 'run').mkdir()
        names = ['cascade-awg@awg-clients.service', 'cascade-awg@awg-eu.service',
                 'cascade-awg@awg-ru.service', 'cascade-firewall.service', 'cascade-ipv6.service',
                 'cascade-dns.service', 'cascade-docker-allow.service', 'cascade-health.service',
                 'cascade-geo-update.service', 'cascade-health.timer', 'cascade-geo-update.timer']
        result = subprocess.run(['systemd-analyze', '--root=' + str(root), '--man=no', 'verify'] + names)
        if result.returncode == 0:
            print('Systemd unit syntax and ordering verified in an inert temporary root')
        return result.returncode


if __name__ == '__main__':
    raise SystemExit(main())
