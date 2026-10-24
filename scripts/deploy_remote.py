#!/usr/bin/env python3
"""Remote Debian 12 deployment. Invoked over SSH; stdout may contain client secrets."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import pwd
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import time
import zipfile

from proxy_config import ARTIFACTS, PORTS, client_config, dump, firewall, new_state, server_configs, unit

ROOT = Path('/root/proxy-vps-deploy')
STATE = ROOT / 'state.json'
SERVICES = ['proxy-vps-xray', 'proxy-vps-sing-box']


def run(args, **kw):
    # Keep command output private: Xray validators and key generation can include credentials.
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, **kw).stdout


def write(p, text, mode=0o600):
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(mode)


def audit():
    return {'os': Path('/etc/os-release').read_text(), 'arch': platform.machine(),
            'listeners': run(['ss', '-lntup']),
            'firewall': run(['nft', 'list', 'ruleset']) if shutil.which('nft') else None,
            'ssh': '\n'.join(l for l in run(['/usr/sbin/sshd', '-T']).splitlines()
                             if l.split()[0] in ['port', 'permitrootlogin', 'passwordauthentication']),
            'managed': STATE.exists()}


def preflight(ssh_port):
    info = audit()
    if ssh_port in [PORTS['reality'], PORTS['anytls']]:
        raise RuntimeError('SSH listener conflicts with a default proxy TCP port; choose non-conflicting proxy ports before deployment')
    if 'ID=debian' not in info['os'] or 'VERSION_ID="12"' not in info['os'] or info['arch'] != 'x86_64':
        raise RuntimeError('Bundled recipe supports Debian 12 x86_64 only; no changes applied')
    if info['firewall'] and not STATE.exists():
        raise RuntimeError('Existing firewall found: audit and integrate manually; refusing to replace it')
    if STATE.exists():
        # A mixed-purpose host must not lose independently managed firewall tables.
        tables = re.findall(r'^table\s+\w+\s+(\S+)', info['firewall'] or '', re.M)
        if any(t != 'proxy_vps' for t in tables):
            raise RuntimeError('Foreign firewall tables found; manual integration required')
        return
    for line in info['listeners'].splitlines()[1:]:
        cells = line.split()
        if len(cells) < 5:
            continue
        addr = cells[4]
        port = addr.rsplit(':', 1)[-1]
        if addr.startswith(('127.', '[::1]:', '::1:')) or port in [str(ssh_port), '5355']:
            continue
        raise RuntimeError('Existing public listener found; inspect host before deployment: ' + addr)
    for name in ['xray-public', 'sing-box-public', *SERVICES]:
        if subprocess.run(['systemctl', 'is-active', '--quiet', name]).returncode == 0:
            raise RuntimeError('Existing proxy installation found; refusing credential/service replacement')
    for binary in ['xray', 'sing-box']:
        if Path('/usr/local/bin', binary).exists():
            raise RuntimeError('Unmanaged binary exists: ' + binary)
    for p in ['/etc/xray/config.json', '/etc/sing-box/config.json']:
        if Path(p).exists():
            raise RuntimeError('Unmanaged configuration exists: ' + p)


def install_binaries():
    for key, (url, digest) in ARTIFACTS.items():
        archive = ROOT / (key + '.download')
        run(['curl', '-fLsS', '--retry', '2', '--connect-timeout', '15', '--max-time', '300',
             url, '-o', str(archive)])
        if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
            raise RuntimeError('SHA256 mismatch for ' + key + '; refusing execution')
        if key == 'xray':
            with zipfile.ZipFile(archive) as z:
                write('/usr/local/bin/xray', '', 0o755)
                Path('/usr/local/bin/xray').write_bytes(z.read('xray'))
        else:
            with tarfile.open(archive) as t:
                members = [m for m in t.getmembers() if m.isfile() and m.name.endswith('/sing-box')]
                if len(members) != 1:
                    raise RuntimeError('Unexpected sing-box release layout')
                Path('/usr/local/bin/sing-box').write_bytes(t.extractfile(members[0]).read())
                Path('/usr/local/bin/sing-box').chmod(0o755)
        archive.unlink()


def apply_firewall(ssh_port, ports):
    backup = ROOT / 'firewall-backup'
    backup.mkdir(exist_ok=True)
    # Never extend/overwrite an unverified transaction on repeated invocation.
    if (ROOT / 'pending-firewall').exists():
        raise RuntimeError('Previous firewall transaction pending; commit or roll back first')
    old = run(['nft', 'list', 'ruleset'])
    write(backup / 'restore.nft', 'flush ruleset\n' + old)
    conf = Path('/etc/nftables.conf')
    if conf.exists():
        shutil.copy2(conf, backup / 'nftables.conf')
    else:
        write(backup / 'nftables.conf', 'flush ruleset\n')
    candidate = ROOT / 'firewall-candidate.nft'
    write(candidate, firewall(ssh_port, ports))
    run(['nft', '-c', '-f', str(candidate)])
    rollback = ROOT / 'rollback-firewall.sh'
    write(rollback, '#!/bin/sh\nset -e\n/usr/sbin/nft -f ' + str(backup / 'restore.nft') +
          '\ncp ' + str(backup / 'nftables.conf') + ' /etc/nftables.conf\n' +
          'rm -f ' + str(ROOT / 'pending-firewall') + '\n', 0o700)
    # Long enough for all local end-to-end checks, bounded and cancelled only after verification.
    subprocess.run(['systemctl', 'reset-failed', 'proxy-vps-firewall-rollback.service'],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run(['systemd-run', '--unit=proxy-vps-firewall-rollback', '--on-active=600', str(rollback)])
    write(ROOT / 'pending-firewall', str(time.time()))
    run(['nft', '-f', str(candidate)])
    shutil.copy2(candidate, conf)


def deploy(host, ssh_port, quic):
    preflight(ssh_port)
    ROOT.mkdir(mode=0o700, exist_ok=True)
    ROOT.chmod(0o700)
    if (ROOT / 'pending-firewall').exists():
        raise RuntimeError('Pending firewall transaction exists; inspect before rerunning')
    if STATE.exists():
        s = json.loads(STATE.read_text())
        # Retain identities; reapply/verify firewall after a prior rollback.
        run(['systemctl', 'is-active', *SERVICES])
        apply_firewall(ssh_port, s['ports'])
        return {'client': client_config(s, host, quic), 'managed': True, 'firewall_pending': True}
    run(['apt-get', 'update', '-qq'])
    env = dict(os.environ, DEBIAN_FRONTEND='noninteractive')
    run(['apt-get', 'install', '-y', '-qq', 'ca-certificates', 'curl', 'openssl', 'nftables'], env=env)
    install_binaries()
    for user in ['xray', 'sing-box']:
        try:
            pwd.getpwnam(user)
        except KeyError:
            run(['useradd', '--system', '--no-create-home', '--shell', '/usr/sbin/nologin', user])
    Path('/etc/xray').mkdir(exist_ok=True)
    Path('/etc/sing-box').mkdir(exist_ok=True)
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '3650',
         '-keyout', '/etc/sing-box/server.key', '-out', '/etc/sing-box/server.crt',
         '-subj', '/CN=proxy.local', '-addext', 'subjectAltName=DNS:proxy.local'])
    cert = Path('/etc/sing-box/server.crt').read_text()
    fp = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert)).hexdigest()
    keys = dict(line.split(': ', 1) for line in run(['/usr/local/bin/xray', 'x25519']).strip().splitlines() if ': ' in line)
    private = keys.get('PrivateKey')
    public = next((v for k, v in keys.items() if 'public' in k.lower() or 'password' in k.lower()), None)
    if not private or not public:
        raise RuntimeError('Unknown Xray key format')
    s = new_state(private, public, fp)
    x, sing = server_configs(s)
    write('/etc/xray/config.json', dump(x))
    write('/etc/sing-box/config.json', dump(sing))
    for folder, user in [('/etc/xray', 'xray'), ('/etc/sing-box', 'sing-box')]:
        u = pwd.getpwnam(user)
        for f in Path(folder).iterdir():
            if f.name not in ['config.json', 'server.crt', 'server.key']:
                continue
            os.chown(f, u.pw_uid, u.pw_gid)
            f.chmod(0o600)
    run(['/usr/local/bin/xray', 'run', '-test', '-config', '/etc/xray/config.json'])
    run(['/usr/local/bin/sing-box', 'check', '-c', '/etc/sing-box/config.json'])
    for name, user, argv in [
        (SERVICES[0], 'xray', '/usr/local/bin/xray run -config /etc/xray/config.json'),
        (SERVICES[1], 'sing-box', '/usr/local/bin/sing-box run -c /etc/sing-box/config.json')]:
        write('/etc/systemd/system/' + name + '.service', unit(user, argv), 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', '--now', *SERVICES])
    run(['systemctl', 'is-active', *SERVICES])
    write(STATE, dump(s))
    # Close LLMNR/mDNS; keep local stub DNS and SSH authentication untouched.
    resolved = Path('/etc/systemd/resolved.conf.d/90-proxy-vps.conf')
    if resolved.exists():
        raise RuntimeError('Unexpected managed resolver drop-in exists; inspect before replacement')
    write(resolved, '[Resolve]\nLLMNR=no\nMulticastDNS=no\n', 0o644)
    if subprocess.run(['systemctl', 'is-active', '--quiet', 'systemd-resolved']).returncode == 0:
        run(['systemctl', 'restart', 'systemd-resolved'])
    apply_firewall(ssh_port, s['ports'])
    return {'client': client_config(s, host, quic), 'managed': True, 'firewall_pending': True}


def commit():
    if not STATE.exists():
        raise RuntimeError('No managed deployment')
    pending = ROOT / 'pending-firewall'
    if not pending.exists() or time.time() - float(pending.read_text()) >= 600:
        raise RuntimeError('Firewall transaction expired or absent; reapply and verify before committing')
    if pending.exists():
        # Persistent startup is committed only after the caller has verified a fresh SSH login.
        run(['systemctl', 'enable', 'nftables'])
        run(['systemctl', 'start', 'nftables'])
        run(['systemctl', 'stop', 'proxy-vps-firewall-rollback.timer'])
        (ROOT / 'pending-firewall').unlink()
    run(['systemctl', 'is-active', *SERVICES])
    return {'committed': True, 'firewall': run(['nft', 'list', 'ruleset'])}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('action', choices=['audit', 'deploy', 'commit'])
    p.add_argument('--host')
    p.add_argument('--ssh-port', type=int, default=22)
    p.add_argument('--quic', choices=['google', 'global', 'off'], default='global')
    a = p.parse_args()
    if os.geteuid() != 0:
        p.error('Root SSH account required for this recipe')
    try:
        # SSH may be forwarded/NATed: firewall the server's listening port, not the external port.
        connection = os.environ.get('SSH_CONNECTION', '').split()
        ssh_port = int(connection[-1]) if len(connection) == 4 else a.ssh_port
        result = audit() if a.action == 'audit' else commit() if a.action == 'commit' else deploy(a.host, ssh_port, a.quic)
        print(dump(result))
    except subprocess.CalledProcessError as e:
        # Do not echo validators' private config/key output.
        print(dump({'error': 'Remote command failed', 'command': e.cmd[0], 'returncode': e.returncode}), file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(dump({'error': str(e)}), file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
