#!/usr/bin/env python3
"""SSH orchestration; requires only Python stdlib, OpenSSH, curl and a Mihomo core."""
import argparse
import getpass
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import sys
import tempfile

from verify import find_core, verify

HERE = Path(__file__).resolve().parent
REMOTE = '/root/proxy-vps-deploy'


def valid_host(s):
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        if re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', s):
            return s
    raise argparse.ArgumentTypeError('Expected an IP or hostname, not a URL or shell expression')


class SSH:
    def __init__(self, args, password=None):
        self.a = args
        self.temp = tempfile.TemporaryDirectory(prefix='proxy-ssh-')
        self.root = Path(self.temp.name)
        self.sock = str(self.root / 'control')
        self.base = ['ssh', '-p', str(args.port), '-l', args.user,
                     '-o', 'ConnectTimeout=12', '-o', 'StrictHostKeyChecking=accept-new']
        if args.identity:
            self.base += ['-i', str(Path(args.identity).expanduser()), '-o', 'IdentitiesOnly=yes']
        self.env = dict(os.environ)
        if password is not None:
            secret = self.root / 'password'
            secret.write_text(password)
            secret.chmod(0o600)
            helper = self.root / 'askpass'
            helper.write_text('#!' + sys.executable + '\nfrom pathlib import Path\nprint(Path(' + repr(str(secret)) + ').read_text())\n')
            helper.chmod(0o700)
            self.env.update(SSH_ASKPASS=str(helper), SSH_ASKPASS_REQUIRE='force', DISPLAY='proxy-deploy')
        else:
            self.base += ['-o', 'BatchMode=yes']

    def connect(self):
        r = subprocess.run(self.base + ['-o', 'ControlPath=' + self.sock,
            '-o', 'ControlPersist=600', '-o', 'NumberOfPasswordPrompts=1', '-fNM', self.a.host],
            env=self.env, stdin=subprocess.DEVNULL, capture_output=True)
        if r.returncode:
            raise RuntimeError('SSH authentication/host-key check failed; inspect host/port/account and known_hosts. No automatic repeated password attempts.')
        # Password remains available only for the fresh, non-multiplexed verification below.

    def run(self, command, fresh=False):
        cp = 'none' if fresh else self.sock
        r = subprocess.run(self.base + ['-o', 'ControlPath=' + cp,
            '-o', 'NumberOfPasswordPrompts=1', self.a.host, command],
            stdin=subprocess.DEVNULL, env=self.env, capture_output=True, text=True)
        if r.returncode:
            # Only the remote wrapper's sanitized error object may be surfaced.
            try:
                error = json.loads(r.stderr).get('error', 'Remote action failed')
            except (ValueError, AttributeError):
                error = 'Remote command/SSH failed; inspect the private deployment logs'
            raise RuntimeError(error)
        return r.stdout

    def upload(self):
        self.run('umask 077; mkdir -p ' + REMOTE + '; chmod 700 ' + REMOTE)
        for f in ['proxy_config.py', 'deploy_remote.py']:
            # Base64 avoids shell interpolation and external SFTP-subsystem assumptions.
            import base64
            data = base64.b64encode((HERE / f).read_bytes()).decode()
            code = 'import base64; from pathlib import Path; p=Path(%r); p.write_bytes(base64.b64decode(%r)); p.chmod(0o600)' % (REMOTE + '/' + f, data)
            self.run('python3 -c ' + shlex.quote(code))

    def remote(self, action):
        return json.loads(self.run(shlex.join(['python3', REMOTE + '/deploy_remote.py', action,
            '--host', self.a.host, '--ssh-port', str(self.a.port), '--quic', self.a.quic])))

    def close(self):
        subprocess.run(self.base + ['-o', 'ControlPath=' + self.sock, '-O', 'exit', self.a.host],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.temp.cleanup()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['audit', 'deploy'])
    p.add_argument('--host', required=True, type=valid_host)
    p.add_argument('--port', type=int, default=22)
    p.add_argument('--user', default='root')
    p.add_argument('--identity', help='Existing SSH private key path; never copied remotely')
    p.add_argument('--password-stdin', action='store_true', help='Read one password from stdin; do not log shell pipelines')
    p.add_argument('--quic', choices=['google', 'global', 'off'], default='global')
    p.add_argument('--output-dir')
    p.add_argument('--core')
    a = p.parse_args()
    if a.user != 'root' or not 1 <= a.port <= 65535:
        p.error('This recipe requires root and a valid SSH port')
    if a.action == 'deploy' and not (a.core or find_core()):
        p.error('Mihomo/Clash Verge core is required for end-to-end verification before deployment')
    password = sys.stdin.readline().rstrip('\r\n') if a.password_stdin else None
    if not a.identity and password is None:
        password = getpass.getpass('SSH password (blank to use existing SSH agent): ') or None
    ssh = SSH(a, password)
    try:
        ssh.connect()
        ssh.upload()
        if a.action == 'audit':
            print(json.dumps(ssh.remote('audit'), ensure_ascii=False, indent=2))
            return
        out = Path(a.output_dir).expanduser() if a.output_dir else Path.home() / '.config/proxy-vps-deploy' / (a.host.replace(':', '_') + '-' + str(a.port))
        out.mkdir(parents=True, exist_ok=True)
        out.chmod(0o700)
        # Audit output contains infrastructure information but no passwords/private keys.
        audit = ssh.remote('audit')
        (out / 'audit.json').write_text(json.dumps(audit, ensure_ascii=False, indent=2))
        payload = ssh.remote('deploy')
        client = payload.pop('client')
        profile = out / 'proxy.yaml'
        profile.write_text(json.dumps(client, ensure_ascii=False, indent=2))
        profile.chmod(0o600)
        # Fresh SSH must cross the new firewall; never validate only an established master.
        ssh.run('true', fresh=True)
        results = verify(client, a.core)
        (out / 'verification.json').write_text(json.dumps(results, indent=2))
        if not all(r['passed'] for r in results):
            raise RuntimeError('A protocol failed end-to-end validation. Firewall auto-rolls back within 10 minutes if pending. Do not claim completion; inspect verification.json and repair before retrying.')
        summary = ssh.remote('commit')
        (out / 'deployment.json').write_text(json.dumps(summary, indent=2))
        print(json.dumps({'profile': str(profile), 'results': results,
                          'firewall_committed': summary['committed'],
                          'ssh_authentication': 'unchanged'}, ensure_ascii=False, indent=2))
    finally:
        ssh.close()


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, subprocess.SubprocessError) as e:
        print('ERROR: ' + str(e), file=sys.stderr)
        sys.exit(1)
