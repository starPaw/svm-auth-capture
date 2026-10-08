#!/usr/bin/env python3
"""Render and validate isolated dev host assets; never activate services or submit payments."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess


ASSETS = Path(__file__).resolve().parents[1] / 'integration/deploy/dev'
GENESIS = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG'


def hostname(value):
    if len(value) > 253 or not re.fullmatch(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}', value):
        raise ValueError('a plain lower-case DNS hostname is required')
    if value in {'capture402.xyz', 'www.capture402.xyz'}:
        raise ValueError('the live hostname cannot be used for development')
    return value


def access_config(addresses):
    # No arbitrary nginx text or open-wide defaults; prevent configuration injection.
    networks = ['127.0.0.1', '::1']
    for address in addresses:
        net = ipaddress.ip_network(address, strict=False)
        if net.prefixlen == 0:
            raise ValueError('an unrestricted tester network is forbidden')
        networks.append(str(net))
    return ''.join(f'allow {network};\n' for network in dict.fromkeys(networks)) + 'deny all;\n'


def render(host, addresses=()):
    host = hostname(host)
    files = {p.name: p.read_text().replace('@DEV_HOST@', host) for p in ASSETS.iterdir() if p.is_file()}
    files['nginx-access.conf'] = access_config(addresses)
    return files


def write_assets(output, files):
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, content in files.items():
        destination = output / name
        # A reviewable render never overwrites another prepared configuration.
        with destination.open('x') as file:
            file.write(content)
        destination.chmod(0o600)


def verify_layout(files):
    for name in ['capture402-dev-facilitator.service', 'capture402-dev-restaurant.service']:
        unit = files[name]
        if 'WorkingDirectory=/opt/capture402-dev/current/integration\n' not in unit:
            raise ValueError('dev unit must use the dedicated release')
        if 'Restart=no\n' not in unit or 'ReadWritePaths=/var/lib/capture402-dev/' not in unit:
            raise ValueError('explicit restart and isolated durable state are required')
        if 'NoNewPrivileges=true\n' not in unit or 'ProtectSystem=strict\n' not in unit:
            raise ValueError('dev runtime filesystem protection is required')
    routes = files['nginx-routes.conf']
    upstreams = set(re.findall(r'proxy_pass\s+(\S+);', routes))
    if upstreams != {'http://127.0.0.1:18888'}:
        raise ValueError('only the dev restaurant may be exposed through nginx')
    if 'proxy_next_upstream off;' not in routes:
        raise ValueError('the proxy must not retry payment requests')
    if not files['nginx-access.conf'].endswith('deny all;\n'):
        raise ValueError('the dev ingress allowlist must fail closed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--tester-network', action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    files = render(args.hostname, args.tester_network)
    verify_layout(files)
    write_assets(args.output, files)
    print(json.dumps({'hostname': args.hostname, 'files': sorted(files),
                      'ports': {'facilitator': 18887, 'restaurant': 18888},
                      'servicesActivated': False, 'transactionsSubmitted': False}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, FileExistsError) as error:
        raise SystemExit(str(error))
