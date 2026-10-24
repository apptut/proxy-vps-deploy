#!/usr/bin/env python3
"""Offline security/regression checks; all credentials here are generated dummy data."""
import base64
import secrets
import unittest
import urllib.parse
from proxy_config import new_state, server_configs, client_config, firewall, GLOBAL_QUIC_RULE
from export_share import reality_uri


class ConfigTests(unittest.TestCase):
    def setUp(self):
        key = lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
        self.s = new_state(key(), key(), secrets.token_hex(32))

    def test_independent_authentication_and_no_machine_binding(self):
        other = new_state('dummy', 'dummy', 'dummy')
        self.assertNotEqual(self.s['uuid'], other['uuid'])
        self.assertEqual(len({self.s[k] for k in ['hy2_password', 'obfs_password', 'anytls_password']}), 3)
        x, s = server_configs(self.s)
        self.assertNotIn('sendThrough', x['outbounds'][0])
        self.assertNotIn('inet4_bind_address', s['outbounds'][0])
        self.assertEqual(len(x['inbounds']), 1)  # no unneeded XHTTP listener

    def test_hysteria_obfuscation_and_tls_are_synchronized(self):
        _, server = server_configs(self.s)
        client = client_config(self.s, 'example.invalid')
        for node in client['proxies']:
            if node['type'] in ['hysteria2', 'anytls']:
                self.assertFalse(node['skip-cert-verify'])
                self.assertEqual(node['fingerprint'], self.s['fingerprint'])
        hy = client['proxies'][1]
        inbound = server['inbounds'][0]
        self.assertEqual(hy['password'], inbound['users'][0]['password'])
        self.assertEqual(hy['obfs'], inbound['obfs']['type'])
        self.assertEqual(hy['obfs-password'], inbound['obfs']['password'])

    def test_global_quic_preserves_direct_and_covers_forced_domains(self):
        d = client_config(self.s, 'example.invalid')
        rules = d['rules']
        self.assertLess(rules.index('GEOIP,CN,DIRECT'), rules.index(GLOBAL_QUIC_RULE))
        self.assertLess(rules.index(GLOBAL_QUIC_RULE), rules.index('MATCH,VPS Proxy'))
        forced_override = next(i for i, r in enumerate(rules) if 'DST-PORT,443' in r and 'GEOSITE,cloudflare' in r)
        self.assertLess(forced_override, rules.index('GEOSITE,cloudflare,VPS Proxy'))
        self.assertLess(rules.index('IP-CIDR,10.0.0.0/8,DIRECT,no-resolve'), forced_override)
        self.assertNotIn('DST-PORT,443,VPS Hysteria2', rules)  # never hijack TCP443

    def test_optional_quic_modes(self):
        off = client_config(self.s, 'example.invalid', 'off')
        self.assertFalse(any('DST-PORT,443' in r for r in off['rules']))
        google = client_config(self.s, 'example.invalid', 'google')
        self.assertTrue(any('GEOSITE,google' in r for r in google['rules']))
        self.assertNotIn(GLOBAL_QUIC_RULE, google['rules'])

    def test_firewall_preserves_actual_ssh_and_reply_traffic(self):
        f = firewall(2222, self.s['ports'])
        self.assertIn('tcp dport { 2053, 2096, 2222 }', f)
        self.assertIn('udp dport 443 counter accept', f)
        self.assertIn('ct state established,related accept', f)
        self.assertIn('table inet', f)
        self.assertIn('ipv6-icmp', f)
        self.assertNotIn('8443', f)
        self.assertNotIn('5355', f)
        self.assertNotIn('tcp dport 443', f)

    def test_share_link_contains_client_identity_not_private_key(self):
        p = client_config(self.s, '2001:db8::2')['proxies'][0]
        link = reality_uri(p)
        parsed = urllib.parse.urlsplit(link)
        q = urllib.parse.parse_qs(parsed.query)
        self.assertEqual(parsed.hostname, '2001:db8::2')
        self.assertEqual(q['pbk'], [self.s['public_key']])
        self.assertEqual(parsed.username, self.s['uuid'])
        self.assertNotIn(self.s['private_key'], link)


if __name__ == '__main__':
    unittest.main()
