#!/usr/bin/env python3
"""Export a local Reality URI (optional offline QR). Does not create a new user."""
import argparse
import json
import os
from pathlib import Path
import urllib.parse


def reality_uri(p):
    if p.get('type') != 'vless' or not p.get('reality-opts'):
        raise ValueError('Expected a VLESS Reality node')
    host = p['server']
    if ':' in host:
        host = '[' + host + ']'
    q = {'encryption': 'none', 'security': 'reality', 'type': 'tcp',
         'sni': p['servername'], 'fp': p.get('client-fingerprint', 'chrome'),
         'pbk': p['reality-opts']['public-key'], 'sid': p['reality-opts']['short-id'],
         'flow': p.get('flow', 'xtls-rprx-vision')}
    return 'vless://%s@%s:%s?%s#%s' % (p['uuid'], host, p['port'],
        urllib.parse.urlencode(q), urllib.parse.quote(p['name'], safe=''))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('profile')
    p.add_argument('--output-dir', required=True)
    a = p.parse_args()
    text = Path(a.profile).read_text()
    try:
        d = json.loads(text)
    except ValueError:
        try:
            import yaml
        except ImportError:
            p.error('Non-JSON YAML requires PyYAML; deploy.py generated profiles need no extra dependencies')
        d = yaml.safe_load(text)
    node = next(n for n in d['proxies'] if n.get('type') == 'vless' and n.get('reality-opts'))
    out = Path(a.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    out.chmod(0o700)
    link = out / 'reality.vless.txt'
    link.write_text(reality_uri(node) + '\n')
    link.chmod(0o600)
    result = {'uri_file': str(link), 'new_identity_created': False}
    try:
        import qrcode
        path = out / 'reality-qr.png'
        qrcode.make(reality_uri(node)).save(path)
        path.chmod(0o600)
        result['qr_file'] = str(path)
    except ImportError:
        result['qr_file'] = None
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
