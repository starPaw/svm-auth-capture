"""Dev routing, authority and isolation configuration regressions; no live operations."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import dev_environment as dev


class DevEnvironmentTests(unittest.TestCase):
    def test_private_generation_cannot_write_secrets_into_git(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with mock.patch.object(dev, 'PROJECT', root/'checkout'):
                with self.assertRaises(ValueError): dev.validate_private_output(root/'checkout/private')
                dev.validate_private_output(root/'operator-private')

    def test_private_environment_binds_only_dev_roles_and_separate_credentials(self):
        identities = {role: char*32 for role, char in zip(['sponsor', 'merchant', 'payer', 'mint'], '1234')}
        files = dev.private_environments('dev.capture402.xyz', identities, 'f'*64, 'm'*64)
        self.assertIn('SAC006_FEE_PAYER='+identities['sponsor'], files['restaurant.env'])
        self.assertIn('SAC006_ALLOWLIST_MERCHANT='+identities['merchant'], files['facilitator.env'])
        self.assertIn('SAC006_MERCHANT_TOKEN='+'m'*64, files['restaurant.env'])
        self.assertNotIn('SAC006_MERCHANT_TOKEN=', files['facilitator.env'])
        with self.assertRaises(ValueError): dev.private_environments('dev.capture402.xyz', identities, 'f'*64, 'f'*64)
        with self.assertRaises(ValueError): dev.private_environments('dev.capture402.xyz', identities, 'weak', 'also-weak')
        identities['payer'] = identities['sponsor']
        with self.assertRaises(ValueError): dev.private_environments('dev.capture402.xyz', identities, 'f'*64, 'm'*64)

    def test_render_dev_only_ports_and_origin(self):
        files = dev.render('dev.capture402.xyz')
        dev.verify_layout(files)
        self.assertIn('SAC006_PORT=18887\n', files['facilitator.env.example'])
        self.assertIn('SAC006_RESOURCE_PORT=18888\n', files['restaurant.env.example'])
        self.assertIn('SAC006_PUBLIC_ORIGIN=https://dev.capture402.xyz\n', files['restaurant.env.example'])
        self.assertIn('SAC006_FACILITATOR_URL=http://127.0.0.1:18887\n', files['restaurant.env.example'])

    def test_reject_live_hostname_and_nginx_injection(self):
        for host in ['capture402.xyz', 'www.capture402.xyz', 'dev.capture402.xyz; return 200;',
                     'dev.capture402.xyz\nserver {}', 'https://dev.capture402.xyz', '../example.com', '']:
            with self.subTest(host=host), self.assertRaises(ValueError):
                dev.render(host)

    def test_access_allowlist_is_private_by_default(self):
        self.assertEqual(dev.access_config([]), 'allow 127.0.0.1;\nallow ::1;\ndeny all;\n')
        self.assertIn('allow 192.0.2.2/32;\n', dev.access_config(['192.0.2.2']))
        for net in ['0.0.0.0/0', '::/0', '192.0.2.1; allow all']:
            with self.subTest(net=net), self.assertRaises(ValueError):
                dev.access_config([net])

    def test_refuses_live_or_facilitator_upstream(self):
        for port in [8788, 8787, 18887]:
            files = dev.render('dev.capture402.xyz')
            files['nginx-routes.conf'] = files['nginx-routes.conf'].replace(':18888', f':{port}')
            with self.subTest(port=port), self.assertRaises(ValueError):
                dev.verify_layout(files)

    def test_missing_proxy_retry_guard_is_refused(self):
        files = dev.render('dev.capture402.xyz')
        files['nginx-routes.conf'] = files['nginx-routes.conf'].replace('proxy_next_upstream off;', '')
        with self.assertRaises(ValueError): dev.verify_layout(files)

    def test_service_roles_and_key_access_are_separate(self):
        files = dev.render('dev.capture402.xyz')
        facilitator = files['capture402-dev-facilitator.service']
        restaurant = files['capture402-dev-restaurant.service']
        self.assertIn('User=capture402-dev-facilitator\n', facilitator)
        self.assertIn('User=capture402-dev-restaurant\n', restaurant)
        self.assertIn('/etc/capture402-dev/keys/sponsor.json', restaurant)
        self.assertIn('/etc/capture402-dev/keys/merchant.json', facilitator)
        for unit in [facilitator, restaurant]:
            self.assertIn('Slice=capture402-dev.slice\n', unit)
            self.assertIn('InaccessiblePaths=/etc/sac006 /var/lib/sac006 /opt/capture402 /opt/svm-auth-capture\n', unit)
            self.assertNotIn('--inspect=', unit)

    def test_debugger_bindings_are_loopback_and_opt_in(self):
        files = dev.render('dev.capture402.xyz')
        self.assertIn('--inspect=127.0.0.1:19227', files['debug-facilitator.conf'])
        self.assertIn('--inspect=127.0.0.1:19228', files['debug-restaurant.conf'])

    def test_prepare_cannot_overwrite_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'prepared'
            files = dev.render('dev.capture402.xyz')
            dev.write_assets(output, files)
            self.assertEqual((output/'nginx-site.conf').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): dev.write_assets(output, files)


if __name__ == '__main__': unittest.main()
