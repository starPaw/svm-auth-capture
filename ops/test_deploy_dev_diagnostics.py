"""Read-only Dev diagnostics: no journal mutations, signatures or private RPC output."""
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import deploy_dev as dev


SIGNATURE = "CtjzX9n2oXAaG26kBd4ifxJmgsqRcnjJYsn8smGzkGJYNAW3AcuW4zx8Q9YSgZkjnM1cFud4aVjzxCYh19oxyfF"
BLOCKHASH = "11111111111111111111111111111111"
PAYMENT = "54eSMWXhSAEoAZxySBgwgs4TwEPJ8z8TJXDSxU7AhRro"
SECRET_URL = "https://rpc.invalid/?api-key=DO_NOT_PRINT"


class DiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.journal = self.root / "journal"
        self.journal.mkdir()
        self.entry = {
            "signature": SIGNATURE, "operation": "authorize",
            "blockhash": BLOCKHASH, "payment": PAYMENT,
            "attempts": [{"outcome": {"result": "unresolved"}}],
            "transactionBase64": "DO_NOT_PRINT_WIRE",
        }
        self.path = self.journal / (SIGNATURE + ".json")
        self.path.write_text(json.dumps(self.entry))
        self.patches = [
            mock.patch.object(dev, "state_paths", return_value=(self.journal,)),
            mock.patch.object(dev, "rpc"),
            mock.patch.object(dev.host, "env_value", return_value=SECRET_URL),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)

    def run_inspection(self, status=None, valid=False, account=None):
        def rpc_call(_url, method, _params):
            if method == "getSignatureStatuses": return {"value": [status]}
            if method == "isBlockhashValid": return {"value": valid, "context": {"slot": 509274469}}
            if method == "getAccountInfo": return {"value": account, "context": {"slot": 509274469}}
            raise AssertionError(method)
        output = io.StringIO()
        before = self.path.read_bytes()
        with mock.patch.object(dev, "_dev_rpc_call", side_effect=rpc_call), redirect_stdout(output):
            dev.inspect_tx(SIGNATURE)
        self.assertEqual(self.path.read_bytes(), before)
        text = output.getvalue()
        for forbidden in ("DO_NOT_PRINT", SECRET_URL):
            self.assertNotIn(forbidden, text)
        return text

    def test_missing_history_invalid_hash_absent_pda_remains_inconclusive(self):
        result = self.run_inspection()
        self.assertIn("NOT FOUND (not proof of no execution)", result)
        self.assertIn("Blockhash valid at finalized bank: False", result)
        self.assertIn("Payment account: ABSENT", result)
        self.assertIn("Verdict: INCONCLUSIVE", result)
        self.assertIn("No broadcast, journal write or recovery was performed", result)

    def test_additive_relay_observation_remains_read_only_and_not_finality(self):
        self.entry['lifetimeProvenance'] = {
            'version': 1, 'messageHash': 'a' * 64, 'blockhash': BLOCKHASH,
            'observation': {'state': 'recorded', 'source': 'request', 'value': {
                'version': 1, 'messageHash': 'a' * 64, 'blockhash': BLOCKHASH,
                'lastValidBlockHeight': '18446744073709551615', 'contextSlot': '9007199254740993',
                'commitment': 'finalized', 'network': 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
                'genesisHash': 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG'}},
            'origin': {'state': 'unverified', 'reason': 'lookup-unavailable'}}
        self.path.write_text(json.dumps(self.entry))
        result = self.run_inspection()
        self.assertIn('Verdict: INCONCLUSIVE', result)
        self.assertIn('Blockhash origin slot: NOT RECORDED', result)
        self.assertIn('Last valid block height: NOT RECORDED', result)
        self.assertNotIn('18446744073709551615', result)

    def test_finalized_receipt_does_not_mutate_original_journal(self):
        result = self.run_inspection({"confirmationStatus": "finalized", "err": None, "slot": 509274400},
                                     account={"owner": "Unverified"})
        self.assertIn("RPC signature finalized; verify original binding/account evidence", result)
        self.assertIn("PRESENT (identity not validated)", result)

    def test_rpc_unavailable_fails_closed_without_private_response(self):
        before = self.path.read_bytes()
        out = io.StringIO()
        with mock.patch.object(dev, "_dev_rpc_call", side_effect=RuntimeError("secret key DO_NOT_PRINT")), redirect_stdout(out):
            dev.inspect_tx(SIGNATURE)
        self.assertIn("RPC evidence: UNAVAILABLE", out.getvalue())
        self.assertNotIn("DO_NOT_PRINT", out.getvalue())
        self.assertEqual(before, self.path.read_bytes())

    def test_signature_parameter_rejects_path_traversal_before_any_rpc(self):
        with mock.patch.object(dev, "_dev_rpc_call") as rpc_call:
            with self.assertRaises(RuntimeError):
                dev.inspect_tx("../facilitator/journal/" + SIGNATURE)
            rpc_call.assert_not_called()

    def test_symlink_entry_refused(self):
        self.path.unlink()
        target = self.root / "target.json"
        target.write_text(json.dumps(self.entry))
        self.path.symlink_to(target)
        with self.assertRaises(RuntimeError):
            dev.inspect_tx(SIGNATURE)

    def test_genuine_pre_post_identity_and_authentication_report(self):
        before = self.path.read_bytes()
        with mock.patch.object(dev, '_validate_original_wire', return_value=('a' * 64, 'genesis', 'program')), mock.patch.object(dev, '_dev_rpc_call', side_effect=RuntimeError(SECRET_URL)), mock.patch.object(dev.source, 'write_json', side_effect=AssertionError('diagnostic write')), mock.patch.object(dev, 'reconcile_original', side_effect=AssertionError('recovery')), redirect_stdout(io.StringIO()):
            r = dev.inspect_tx(SIGNATURE)
        import hashlib
        self.assertEqual(r['before']['sha256'], hashlib.sha256(before).hexdigest())
        self.assertEqual(r['before'], r['after'])
        self.assertEqual(r['authentication'], 'authenticated')
        self.assertEqual(r['consistency'], 'unchanged')
        self.assertIn('cannot reproduce', r['rawBytes'])

    def test_concurrent_replacement_same_bytes_is_changed_not_frozen(self):
        def change(*args):
            replacement = self.root / 'replacement'
            replacement.write_bytes(self.path.read_bytes())
            replacement.replace(self.path)
            raise RuntimeError(SECRET_URL)
        with mock.patch.object(dev, '_dev_rpc_call', side_effect=change), redirect_stdout(io.StringIO()):
            r = dev.inspect_tx(SIGNATURE)
        self.assertEqual(r['before']['sha256'], r['after']['sha256'])
        self.assertNotEqual(r['before']['identity'], r['after']['identity'])
        self.assertEqual(r['consistency'], 'changed')

    def test_concurrent_content_change_and_symlink_post_are_inconsistent(self):
        def change(*args):
            self.path.write_text('{"new":"private"}')
            raise RuntimeError(SECRET_URL)
        with mock.patch.object(dev, '_dev_rpc_call', side_effect=change), redirect_stdout(io.StringIO()):
            r = dev.inspect_tx(SIGNATURE)
        self.assertEqual(r['consistency'], 'changed')
        self.path.write_text(json.dumps(self.entry))
        def replace(*args):
            self.path.unlink(); self.path.symlink_to(self.root / 'private')
            raise RuntimeError(SECRET_URL)
        with mock.patch.object(dev, '_dev_rpc_call', side_effect=replace), redirect_stdout(io.StringIO()):
            r = dev.inspect_tx(SIGNATURE)
        self.assertEqual(r['consistency'], 'inconsistent')
        self.assertIsNone(r['after'])

    def test_diagnostic_report_retained_durably_outside_selected_store(self):
        before = self.path.read_bytes()
        with mock.patch.object(dev, 'BASE', self.root), mock.patch.object(dev, 'trusted'), mock.patch.object(dev, '_dev_rpc_call', side_effect=RuntimeError(SECRET_URL)), redirect_stdout(io.StringIO()):
            r = dev.inspect_tx(SIGNATURE)
        self.assertEqual(r['retention'], 'stored')
        record = self.root / 'diagnostics' / r['id'] / 'record.json'
        self.assertEqual(json.loads(record.read_text()), r)
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        self.assertEqual(record.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.path.read_bytes(), before)
        self.assertNotIn('DO_NOT_PRINT', record.read_text())

    def test_diagnostic_reporting_failure_keeps_observation_and_original_unchanged(self):
        before = self.path.read_bytes()
        with mock.patch.object(dev, 'BASE', self.root), mock.patch.object(dev, 'trusted'), mock.patch.object(dev.host, 'atomic_bytes', side_effect=OSError(28, SECRET_URL)), mock.patch.object(dev, '_dev_rpc_call', side_effect=RuntimeError(SECRET_URL)), redirect_stdout(io.StringIO()):
            r = dev.inspect_tx(SIGNATURE)
        self.assertEqual(r['retention'], 'unavailable')
        self.assertEqual(r['consistency'], 'unchanged')
        self.assertEqual(self.path.read_bytes(), before)
        self.assertNotIn('DO_NOT_PRINT', json.dumps(r))

    def test_replacement_during_bounded_read_refused(self):
        original = dev.os.read
        def change(fd, length):
            data = original(fd, length)
            replacement = self.root / 'replacement'
            replacement.write_bytes(self.path.read_bytes())
            replacement.replace(self.path)
            return data
        with mock.patch.object(dev.os, 'read', side_effect=change):
            with self.assertRaisesRegex(RuntimeError, 'changed during read'): dev.stable_bytes(self.path, 4096)

    def test_repeated_diagnosis_is_byte_identical_no_authority_calls(self):
        before = self.path.read_bytes()
        with mock.patch.object(dev, '_validate_original_wire', side_effect=RuntimeError(SECRET_URL)), mock.patch.object(dev.source, 'write_json', side_effect=AssertionError('write')), mock.patch.object(dev, 'reconcile_original', side_effect=AssertionError('recovery')):
            for _ in range(3):
                self.run_inspection()
        self.assertEqual(self.path.read_bytes(), before)

    def test_rpc_slots_private_strings_never_published(self):
        def response(url, method, params):
            if method == 'getSignatureStatuses': return {'context': {'slot': SECRET_URL}, 'value': [None]}
            return {'context': {'slot': SECRET_URL}, 'value': False if method == 'isBlockhashValid' else None}
        out = io.StringIO()
        with mock.patch.object(dev, '_dev_rpc_call', side_effect=response), redirect_stdout(out):
            r = dev.inspect_tx(SIGNATURE)
        self.assertNotIn('DO_NOT_PRINT', out.getvalue())
        self.assertTrue(all(value is None for value in r['rpcSlots'].values()))

    def test_doctor_identifies_unresolved_without_modifying_state(self):
        checks = {
            "current": mock.patch.object(dev, "current", return_value="a" * 40),
            "units": mock.patch.object(dev, "units"),
            "health": mock.patch.object(dev, "health"),
            "production": mock.patch.object(dev, "production", return_value="private-digest"),
            "clean_operations": mock.patch.object(dev, "clean_operations", side_effect=RuntimeError("DO_NOT_PRINT")),
        }
        for patch in checks.values():
            patch.start()
            self.addCleanup(patch.stop)
        with mock.patch.object(dev, "PENDING", self.root / "transaction.json"):
            before = self.path.read_bytes()
            out = io.StringIO()
            with redirect_stdout(out):
                dev.doctor()
            self.assertEqual(before, self.path.read_bytes())
        self.assertIn("BLOCKED: Payment journals", out.getvalue())
        self.assertIn("UNRESOLVED authorize " + SIGNATURE, out.getvalue())
        self.assertNotIn("DO_NOT_PRINT", out.getvalue())
        self.assertIn("No recovery or journal modification was performed", out.getvalue())


if __name__ == "__main__":
    unittest.main()
