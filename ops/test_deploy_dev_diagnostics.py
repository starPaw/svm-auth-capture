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

    def test_finalized_receipt_does_not_mutate_original_journal(self):
        result = self.run_inspection({"confirmationStatus": "finalized", "err": None, "slot": 509274400},
                                     account={"owner": "Unverified"})
        self.assertIn("finalized; verify binding/account evidence", result)
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
