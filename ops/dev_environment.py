#!/usr/bin/env python3
"""Render and validate isolated dev host assets; never activate services or submit payments."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import secrets


ASSETS = Path(__file__).resolve().parents[1] / 'integration/deploy/dev'
PROJECT = Path(__file__).resolve().parents[1]
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


def render(host, addresses=(), *, profile="dev"):
    host = hostname(host)
    files = {p.name: p.read_text().replace('@DEV_HOST@', host) for p in ASSETS.iterdir() if p.is_file()}
    if profile not in {'dev', 'e2e'}:
        raise ValueError('unknown environment profile')
    if profile == 'dev' and host == 'e2e.capture402.xyz':
        raise ValueError('E2E hostname requires the E2E profile')
    if profile == 'e2e':
        if host != 'e2e.capture402.xyz':
            raise ValueError('E2E profile requires e2e.capture402.xyz')
        files = {name.replace('capture402-dev', 'capture402-e2e'): content
                 .replace('capture402-dev', 'capture402-e2e')
                 .replace('18887', '28887').replace('18888', '28888')
                 .replace('19227', '29227').replace('19228', '29228')
                 .replace('X-Capture402-Environment development', 'X-Capture402-Environment e2e')
                 for name, content in files.items()}
        # Deny both legacy environments, including their release and private roots.
        for name in ['capture402-e2e-facilitator.service', 'capture402-e2e-restaurant.service']:
            files[name] = files[name].replace('InaccessiblePaths=/etc/sac006 ',
                'InaccessiblePaths=/etc/capture402-dev /var/lib/capture402-dev /opt/capture402-dev /home/capture402-dev /etc/sac006 ')
        # E2E has no debugger or unattended startup surface.
        files.pop('debug-facilitator.conf')
        files.pop('debug-restaurant.conf')
        for name in ['capture402-e2e-facilitator.service', 'capture402-e2e-restaurant.service']:
            files[name] = files[name].replace('[Install]\nWantedBy=multi-user.target\n', '')
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


def validate_private_output(output):
    if output.resolve().is_relative_to(PROJECT.resolve()):
        raise ValueError('private generated environment must be outside the Git checkout')


def verify_layout(files, *, profile="dev"):
    if profile == 'e2e':
        expected = render('e2e.capture402.xyz', profile='e2e')
        if set(files) != set(expected):
            raise ValueError('E2E asset inventory differs from the fixed profile')
        for name in expected:
            if name != 'nginx-access.conf' and files[name] != expected[name]:
                raise ValueError('E2E asset differs from the isolated profile: ' + name)
        lines = files['nginx-access.conf'].splitlines()
        if not lines or lines[-1] != 'deny all;' or any(not line.startswith('allow ') or not line.endswith(';') for line in lines[:-1]):
            raise ValueError('E2E ingress must fail closed')
        if access_config([line[6:-1] for line in lines[2:-1]]) != files['nginx-access.conf']:
            raise ValueError('E2E allowlist must be canonical and bounded')
        return
    if profile != 'dev':
        raise ValueError('unknown environment profile')
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


def private_environments(host, identities, bearer, merchant, *, profile="dev"):
    """Separate credentials and role identities; never prints the private result."""
    required = ['sponsor', 'merchant', 'payer', 'mint']
    for role in required:
        value = identities.get(role)
        if not isinstance(value, str) or not re.fullmatch(r'[1-9A-HJ-NP-Za-km-z]{32,44}', value):
            raise ValueError('four valid public dev identities are required')
    if len({identities[role] for role in required}) != 4:
        raise ValueError('dev signer roles and mint must be distinct')
    if bearer == merchant or any(not re.fullmatch(r'[A-Za-z0-9_-]{43,128}', value) for value in [bearer, merchant]):
        raise ValueError('independent strong private credentials are required')
    files = render(host, profile=profile)
    common = {'SAC006_BEARER_TOKEN': bearer}
    values = {
        'facilitator': {**common, 'SAC006_ALLOWLIST_MERCHANT': identities['merchant'], 'SAC006_ALLOWLIST_MINT': identities['mint']},
        'restaurant': {**common, 'SAC006_MERCHANT_TOKEN': merchant, 'SAC006_FEE_PAYER': identities['sponsor'], 'SAC006_ASSET_MINT': identities['mint']},
    }
    result = {}
    for role in ['facilitator', 'restaurant']:
        lines = []
        for line in files[f'{role}.env.example'].splitlines():
            key = line.split('=', 1)[0]
            if key in values[role]: line = key + '=' + values[role][key]
            if '=' in line and not line.startswith('#') and not line.split('=', 1)[1]:
                raise ValueError('private environment cannot contain a blank required assignment')
            lines.append(line)
        result[role+'.env'] = '\n'.join(lines)+'\n'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hostname', required=True)
    parser.add_argument('--profile', choices=['dev', 'e2e'], default='dev')
    parser.add_argument('--tester-network', action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--private-identities', type=Path,
                        help='Generate private env files from fresh dev public identities; output stays operator-only.')
    args = parser.parse_args()
    files = render(args.hostname, args.tester_network, profile=args.profile)
    verify_layout(files, profile=args.profile)
    if args.private_identities:
        validate_private_output(args.output)
        identities = json.loads(args.private_identities.read_text())
        files.update(private_environments(args.hostname, identities, secrets.token_urlsafe(48), secrets.token_urlsafe(48), profile=args.profile))
    write_assets(args.output, files)
    print(json.dumps({'hostname': args.hostname, 'files': sorted(files),
                      'profile': args.profile,
                      'ports': {'facilitator': 28887 if args.profile == 'e2e' else 18887, 'restaurant': 28888 if args.profile == 'e2e' else 18888},
                      'servicesActivated': False, 'transactionsSubmitted': False}))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, FileExistsError) as error:
        raise SystemExit(str(error))
