"""Pure configuration builders. No network, credentials embedded, or host mutations."""
import json
import secrets
import uuid

XRAY_VERSION = '26.3.27'
SING_VERSION = '1.14.2'
ARTIFACTS = {
    'xray': ('https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip',
             '23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae'),
    'sing-box': ('https://github.com/SagerNet/sing-box/releases/download/v1.14.2/sing-box-1.14.2-linux-amd64.tar.gz',
                 'a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6'),
}
PORTS = {'reality': 2053, 'hysteria2': 443, 'anytls': 2096}
NAMES = ['VPS Reality', 'VPS Hysteria2', 'VPS AnyTLS']
GOOGLE_RULE = 'AND,((NETWORK,UDP),(DST-PORT,443),(GEOSITE,google)),VPS Hysteria2'
# Inserted AFTER direct rules: domestic/private UDP remains direct.
GLOBAL_QUIC_RULE = 'AND,((NETWORK,UDP),(DST-PORT,443)),VPS Hysteria2'
PRIVATE = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
           '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '224.0.0.0/4',
           '::/128', '::1/128', 'fc00::/7', 'fe80::/10', 'ff00::/8']


def new_state(private_key, public_key, fingerprint):
    return dict(schema=1, uuid=str(uuid.uuid4()), private_key=private_key,
                public_key=public_key, short_id=secrets.token_hex(8),
                hy2_password=secrets.token_urlsafe(32),
                obfs_password=secrets.token_urlsafe(32),
                anytls_password=secrets.token_urlsafe(32), fingerprint=fingerprint,
                target='www.yahoo.com', ports=dict(PORTS))


def server_configs(s):
    p = s['ports']
    xray = {
        'log': {'loglevel': 'warning'},
        'inbounds': [{'tag': 'reality', 'listen': '0.0.0.0', 'port': p['reality'],
                      'protocol': 'vless', 'settings': {'clients': [
                          {'id': s['uuid'], 'flow': 'xtls-rprx-vision'}], 'decryption': 'none'},
                      'streamSettings': {'network': 'raw', 'security': 'reality',
                          'realitySettings': {'show': False, 'target': s['target'] + ':443',
                              'xver': 0, 'serverNames': [s['target']],
                              'privateKey': s['private_key'], 'shortIds': [s['short_id']]}}}],
        'outbounds': [{'protocol': 'freedom', 'tag': 'direct',
                       'streamSettings': {'sockopt': {'domainStrategy': 'ForceIPv4'}}},
                      {'protocol': 'blackhole', 'tag': 'block'}],
        'routing': {'rules': [{'type': 'field', 'ip': PRIVATE, 'outboundTag': 'block'}]},
    }
    tls = {'enabled': True, 'server_name': 'proxy.local',
           'certificate_path': '/etc/sing-box/server.crt', 'key_path': '/etc/sing-box/server.key'}
    sing = {'log': {'level': 'warn'},
            'dns': {'servers': [{'type': 'local', 'tag': 'local'}]},
            'inbounds': [
                {'type': 'hysteria2', 'tag': 'hy2', 'listen': '0.0.0.0', 'listen_port': p['hysteria2'],
                 'users': [{'name': 'client', 'password': s['hy2_password']}],
                 'obfs': {'type': 'salamander', 'password': s['obfs_password']}, 'tls': dict(tls)},
                {'type': 'anytls', 'tag': 'anytls', 'listen': '0.0.0.0', 'listen_port': p['anytls'],
                 'users': [{'name': 'client', 'password': s['anytls_password']}], 'tls': dict(tls)}],
            'outbounds': [{'type': 'direct', 'tag': 'direct',
                          'domain_resolver': {'server': 'local', 'strategy': 'ipv4_only'}}],
            'route': {'rules': [{'ip_is_private': True, 'action': 'reject'}], 'final': 'direct'}}
    return xray, sing


def client_config(s, host, quic='global'):
    p = s['ports']
    tls = {'server': host, 'sni': 'proxy.local', 'fingerprint': s['fingerprint'],
           'skip-cert-verify': False, 'udp': True}
    proxies = [
        {'name': NAMES[0], 'type': 'vless', 'server': host, 'port': p['reality'],
         'uuid': s['uuid'], 'tls': True, 'udp': True, 'network': 'tcp',
         'flow': 'xtls-rprx-vision', 'servername': s['target'], 'client-fingerprint': 'chrome',
         'packet-encoding': 'xudp', 'reality-opts': {'public-key': s['public_key'], 'short-id': s['short_id']}},
        dict(tls, name=NAMES[1], type='hysteria2', port=p['hysteria2'],
             password=s['hy2_password'], obfs='salamander', **{'obfs-password': s['obfs_password']}),
        dict(tls, name=NAMES[2], type='anytls', port=p['anytls'], password=s['anytls_password']),
    ]
    rules = ['IP-CIDR,127.0.0.0/8,DIRECT,no-resolve', 'IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
             'IP-CIDR,172.16.0.0/12,DIRECT,no-resolve', 'IP-CIDR,192.168.0.0/16,DIRECT,no-resolve']
    forced = ['cloudflare', 'anthropic', 'openai']
    if quic == 'global':
        conditions = ','.join('(GEOSITE,' + tag + ')' for tag in forced)
        rules += ['AND,((NETWORK,UDP),(DST-PORT,443),(OR,(' + conditions + '))),VPS Hysteria2']
    if quic == 'google':
        rules += [GOOGLE_RULE]
    rules += ['GEOSITE,' + tag + ',VPS Proxy' for tag in forced]
    rules += ['GEOSITE,cn,DIRECT', 'GEOIP,CN,DIRECT']
    if quic == 'global':
        rules += [GLOBAL_QUIC_RULE]
    rules += ['MATCH,VPS Proxy']
    return {'mixed-port': 7897, 'allow-lan': False, 'mode': 'rule', 'log-level': 'info',
            'proxies': proxies, 'proxy-groups': [{'name': 'VPS Proxy', 'type': 'select', 'proxies': NAMES}],
            'dns': {'enable': True, 'ipv6': False, 'enhanced-mode': 'fake-ip',
                    'nameserver': ['https://1.1.1.1/dns-query#VPS Proxy', 'https://8.8.8.8/dns-query#VPS Proxy'],
                    'proxy-server-nameserver': ['system'],
                    'nameserver-policy': {'geosite:cn': ['system'], '+.lan': ['system'], '+.local': ['system']}},
            'rules': rules}


def firewall(ssh_port, ports):
    tcp = ', '.join(str(n) for n in sorted({ssh_port, ports['reality'], ports['anytls']}))
    return '''#!/usr/sbin/nft -f
flush ruleset
table inet proxy_vps {
 chain input {
  type filter hook input priority filter; policy drop;
  iifname "lo" accept
  ct state established,related accept
  ct state invalid drop
  meta l4proto { icmp, ipv6-icmp } accept
  udp sport 67 udp dport 68 accept
  ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept
  tcp dport { %s } ct state new counter accept
  udp dport %d counter accept
  counter drop
 }
 chain forward { type filter hook forward priority filter; policy drop; }
 chain output { type filter hook output priority filter; policy accept; }
}
''' % (tcp, ports['hysteria2'])


def unit(user, argv):
    return '''[Unit]
Description=Managed Proxy VPS %s
After=network-online.target
Wants=network-online.target
[Service]
User=%s
Group=%s
ExecStart=%s
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
[Install]
WantedBy=multi-user.target
''' % (user, user, user, argv)


def dump(obj):
    return json.dumps(obj, ensure_ascii=False, indent=2) + '\n'
