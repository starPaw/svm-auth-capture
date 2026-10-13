"""Stock approval/custody gates. No VPS, credentials or systemd mutation."""
import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('stock_verifier',Path(__file__).with_name('faucet-stock-verify.py'))
stock=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stock)

class StockApprovalTests(unittest.TestCase):
    def approval(self):
        return {'schema':1,'sourceRevision':'a'*40,'sponsor':'5mkvwgKeWMYrFppGm8ugLzQC9Wff4vduqWphsGhQNigX',
            'mint':'91wxVDcTEf5kRRRFmkUKohdNLFRAh5tw9YqWxV8FYvJp','browser':'93PtawNdAfDn7oTjRrbrJJMSgaFTjGS3wjtkrZSNGn74',
            'genesisHash':'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',
            'campaignReference':'owner-policy-2026-10-12-existing-10-sol-spend-cap-1-sol',
            'amount':'100000000000','maximumSpend':'2139280','admissionMaximum':600,
            'actions':{'quote':'read-only preparation'},'issueApprovalReference':'proposal-only-not-live-consent'}
    def test_quote_approval_does_not_grant_issuance_or_observation_writes(self):
        a=self.approval()
        stock.validate_approval(a,'a'*40,'quote')
        for action in ('issue','observe','retry'):
            with self.subTest(action=action),self.assertRaises(RuntimeError):stock.validate_approval(a,'a'*40,action)
    def test_changed_source_amount_identity_or_limit_refuses_before_credentials(self):
        for field in ('schema','sourceRevision','mint','sponsor','browser','genesisHash','amount','maximumSpend','admissionMaximum','campaignReference','issueApprovalReference'):
            a=self.approval();a[field]=''
            with self.subTest(field=field),self.assertRaises(RuntimeError):stock.validate_approval(a,'a'*40,'quote')
    def test_private_custody_refuses_symlink_hardlink_mode_and_owner_changes(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'record';p.write_text('synthetic');p.chmod(0o600)
            stock.private(p,os.getuid(),os.getgid(),0o600)
            with self.assertRaises(RuntimeError):stock.private(p,os.getuid()+1,os.getgid(),0o600)
            p.chmod(0o644)
            with self.assertRaises(RuntimeError):stock.private(p,os.getuid(),os.getgid(),0o600)
            p.chmod(0o600);os.link(p,Path(d)/'hardlink')
            with self.assertRaises(RuntimeError):stock.private(p,os.getuid(),os.getgid(),0o600)
            link=Path(d)/'link';link.symlink_to(p)
            with self.assertRaises(RuntimeError):stock.private(link,os.getuid(),os.getgid(),0o600)
    def test_live_writer_blocks_mint_credential_delivery(self):
        live=subprocess.CompletedProcess([],0,stdout='ActiveState=active\nMainPID=42\nControlPID=0\n')
        with patch.object(stock.subprocess,'run',return_value=live),self.assertRaises(RuntimeError):stock.require_stopped_writers()
    def test_same_uid_background_process_blocks_credentials_even_with_stopped_units(self):
        stopped=subprocess.CompletedProcess([],0,stdout='ActiveState=inactive\nMainPID=0\nControlPID=0\n')
        process=unittest.mock.MagicMock();process.name='42';(process/'status').read_text.return_value='Uid:\t989\t989\t989\t989\n'
        with patch.object(stock.subprocess,'run',return_value=stopped),patch.object(stock.Path,'iterdir',return_value=iter([process])),self.assertRaises(RuntimeError):stock.require_stopped_writers()

if __name__=='__main__':unittest.main()
