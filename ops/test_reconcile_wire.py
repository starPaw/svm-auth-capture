"""Real signed-wire regressions for immutable, finalized-only Dev reconciliation."""
import copy
import hashlib
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import deploy_dev as dev

PROGRAM = "992QmwmwCebawRJsTCgvc8qnzGivbFaD39ZQE7VhHp7o"
RUNTIME = Path(__file__).resolve().parents[1] / "integration"
FINALIZED = {"confirmationStatus": "finalized", "slot": 123, "err": None}

# Ephemeral fixture keys live only in this child. Only public signed transactions
# leave it. Build using the existing client, then independently check signatures
# with Node crypto before generating the adversarial variants.
FIXTURES = r'''
import { createHash, createPublicKey, verify } from 'node:crypto';
import * as k from '@solana/kit';
import { getTransferSolInstruction } from '@solana-program/system';
import * as a from './src/program.ts';
import * as t from './src/transactions.ts';
const [sponsor, payer, server, mintKey] = await Promise.all(Array.from({length:4}, () => k.generateKeyPairSigner()));
const programId = '992QmwmwCebawRJsTCgvc8qnzGivbFaD39ZQE7VhHp7o';
const salt = new Uint8Array(32).fill(9);
const lifetime = { blockhash: '11111111111111111111111111111111', lastValidBlockHeight: 1n };
const common = { programId, payer: payer.address, server: server.address, mint: mintKey.address,
    payment: await a.paymentAddress(programId, payer.address, salt), funder: sponsor.address };
const authorize = await t.authorizeInstruction({...common, salt, maximum:100n, captureDeadline:200n, refundDeadline:300n});
const capture = await t.captureInstruction(common, 1n, false, 100n, 0n);
const instructions = { authorize, capture, void:await t.voidInstruction(common, 99n, 1n),
    refund:await t.refundInstruction(common, 1n, 99n, 1n) };
const entries = {};
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const journal = (tx, operation) => ({ signature:k.getSignatureFromTransaction(tx), messageHash:hash(tx.messageBytes),
    transactionBase64:k.getBase64EncodedWireTransaction(tx), blockhash:lifetime.blockhash,
    operation, payment:common.payment, payer:payer.address,
    expectedHeld:operation === 'authorize' ? '0' : operation === 'capture' ? '100' : '99',
    expectedRefundable:operation === 'authorize' || operation === 'capture' ? '0' : '1',
    attempts:[{outcome:{result:'unresolved'}}] });
function independentlyVerify(tx) {
    for (const [address, signature] of Object.entries(tx.signatures)) {
        const der = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(k.getAddressEncoder().encode(address))]);
        if (!verify(null, tx.messageBytes, createPublicKey({key:der, format:'der', type:'spki'}), signature)) throw new Error('fixture signature invalid');
    }
}
async function signMessage(message, original) {
    const signatures = Object.fromEntries(original.staticAccounts.slice(0, original.header.numSignerAccounts).map(key => [key, null]));
    const signers = [sponsor, payer, server].filter(s => s.address in signatures);
    return k.partiallySignTransaction(signers.map(s => s.keyPair), {messageBytes:message, signatures});
}
async function changed(entry, update, suffix = []) {
    const tx = k.getTransactionDecoder().decode(Buffer.from(entry.transactionBase64, 'base64'));
    const m = k.getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
    update(m);
    const bytes = Buffer.concat([Buffer.from(k.getCompiledTransactionMessageEncoder().encode(m)), Buffer.from(suffix)]);
    const signed = await signMessage(bytes, m);
    independentlyVerify(signed);
    return {...entry, signature:k.getSignatureFromTransaction(signed), messageHash:hash(bytes), transactionBase64:k.getBase64EncodedWireTransaction(signed)};
}
for (const [operation, instruction] of Object.entries(instructions)) {
    const tx = await t.buildTransaction({feePayer:sponsor.address, instructions:[instruction],
        signers:[sponsor, operation === 'authorize' ? payer : server], lifetime});
    independentlyVerify(tx);
    entries[operation] = journal(tx, operation);
}
entries.compute = await changed(entries.authorize, m => {
    const index = m.staticAccounts.length;
    m.staticAccounts.push('ComputeBudget111111111111111111111111111111');
    m.header.numReadonlyNonSignerAccounts++;
    m.instructions.unshift({programAddressIndex:index, accountIndices:[], data:Uint8Array.of(2, 0x40, 0x0d, 3, 0)});
});
entries.duplicateCompute = await changed(entries.compute, m => m.instructions.unshift(m.instructions[0]));
entries.trailing = await changed(entries.authorize, () => {}, [0]);
entries.invalidIndex = await changed(entries.authorize, m => m.instructions[0].accountIndices[0] = 255);
entries.wrongAuthority = await changed(entries.authorize, m => m.instructions[0].accountIndices[0] = 0);
entries.wrongRole = await changed(entries.authorize, m => m.header.numReadonlySignerAccounts = 1);
entries.badHeader = await changed(entries.authorize, m => m.header.numReadonlyNonSignerAccounts = 255);
entries.malformedData = await changed(entries.authorize, m => m.instructions[0].data = Uint8Array.of(0));
entries.duplicateOperation = await changed(entries.authorize, m => m.instructions.push(m.instructions[0]));
entries.v0 = await changed(entries.authorize, m => {m.version = 0; m.addressTableLookups = [];});
// Original fee-payer signature retained over a different, still canonical message.
entries.changedMessage = {...entries.capture};
{
    const tx = k.getTransactionDecoder().decode(Buffer.from(entries.capture.transactionBase64, 'base64'));
    const m = k.getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
    m.instructions[0].data[1] = 2;
    const bytes = k.getCompiledTransactionMessageEncoder().encode(m);
    const altered = {...tx, messageBytes:bytes};
    entries.changedMessage.messageHash = hash(bytes);
    entries.changedMessage.transactionBase64 = k.getBase64EncodedWireTransaction(altered);
    try { independentlyVerify(altered); throw new Error('changed message accidentally valid'); }
    catch (error) { if (error.message !== 'fixture signature invalid') throw error; }
}
entries.economicSignature = {...entries.authorize};
{
    const raw = Buffer.from(entries.authorize.transactionBase64, 'base64');
    raw[65] ^= 1;
    entries.economicSignature.transactionBase64 = raw.toString('base64');
}
entries.envelopeCount = {...entries.authorize};
{
    const raw = Buffer.from(entries.authorize.transactionBase64, 'base64');
    raw[0] = 1;
    entries.envelopeCount.transactionBase64 = raw.toString('base64');
}
entries.noncanonicalLength = {...entries.authorize};
{
    const raw = Buffer.from(entries.authorize.transactionBase64, 'base64');
    entries.noncanonicalLength.transactionBase64 = Buffer.concat([Buffer.from([0x82,0]),raw.subarray(1)]).toString('base64');
}
// The review's signed System transfer with the accepted program as an unused key.
{
    const tx = await t.buildTransaction({feePayer:sponsor.address, lifetime, signers:[sponsor,payer],
        instructions:[getTransferSolInstruction({source:payer, destination:server.address, amount:1n})]});
    entries.unusedProgram = await changed(journal(tx, 'authorize'), m => {
        m.staticAccounts.push(programId); m.header.numReadonlyNonSignerAccounts++;
    });
}
process.stdout.write(JSON.stringify(entries));
'''


class RecoveryFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.node = shutil.which('node')
        # Required, not skipped: reconciliation verification must run real crypto.
        if not cls.node:
            raise RuntimeError('Node >=22 with installed integration dependencies is required')
        result = subprocess.run([cls.node, '--experimental-strip-types', '--input-type=module', '--eval', FIXTURES],
                                cwd=RUNTIME, capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError('signed fixture generation failed: ' + result.stderr[-2000:])
        cls.fixtures = json.loads(result.stdout)

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.paths = [self.root / p for p in ('journal', 'operations', 'reclaim', 'orders')]
        for path in self.paths:
            path.mkdir()
        self.set_entry(self.fixtures['authorize'])
        run = subprocess.run

        def local_validator(args, **kwargs):
            # Only replace the Linux privilege-drop boundary on this local fixture;
            # run the production validator itself, without mocking its result.
            self.assertEqual(args[:7], ['runuser', '-u', 'capture402-deploy', '--', '/usr/bin/env', '-i',
                                        'PATH=/usr/local/bin:/usr/bin:/bin'])
            self.assertEqual(args[7], 'node')
            return run([self.node, *args[8:]], env={'PATH': os.defpath}, **kwargs)

        patches = [
            mock.patch.object(dev, 'BASE', self.root),
            mock.patch.object(dev, 'RECONCILED', self.root / 'reconciled'),
            mock.patch.object(dev, 'PENDING', self.root / 'transaction.json'),
            mock.patch.object(dev, 'state_paths', return_value=self.paths),
            mock.patch.object(dev, '_proof_identity', return_value=('devnet', PROGRAM)),
            mock.patch.object(dev, '_wire_runtime', return_value=RUNTIME),
            mock.patch.object(dev.subprocess, 'run', side_effect=local_validator),
            mock.patch.object(dev, 'rpc'),
            mock.patch.object(dev.host, 'env_value', return_value='https://secret.invalid/DO_NOT_PRINT'),
            mock.patch.object(dev, 'trusted', side_effect=lambda p, directory=False:
                              (_ for _ in ()).throw(RuntimeError('unsafe symlink')) if p.is_symlink() else None),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def set_entry(self, entry):
        for path in self.paths[0].iterdir():
            path.unlink()
        self.entry = copy.deepcopy(entry)
        self.signature = self.entry['signature']
        self.journal_path = self.paths[0] / (self.signature + '.json')
        self.journal_path.write_text(json.dumps(self.entry))
        self.receipt = self.root / 'reconciled' / (self.signature + '.json')

    def reconcile_status(self, status, *, record=True):
        with (mock.patch.object(dev, '_dev_rpc_call', return_value={'value': [status]}),
              redirect_stdout(io.StringIO()) as output):
            result = dev.reconcile_original(self.signature, record=record)
        self.assertNotIn('DO_NOT_PRINT', output.getvalue())
        return result, output.getvalue()

    def assert_authentication_blocked(self):
        before = self.journal_path.read_bytes()
        with mock.patch.object(dev, '_dev_rpc_call', return_value={'value': [FINALIZED]}) as rpc:
            with self.assertRaises(RuntimeError):
                dev.reconcile_original(self.signature, record=True)
            rpc.assert_not_called()
        self.assertEqual(self.journal_path.read_bytes(), before)
        self.assertFalse(self.receipt.exists())
        with self.assertRaisesRegex(RuntimeError, 'unresolved dev submission'):
            dev.clean_operations()

    def test_unknown_signature_never_records_or_unblocks(self):
        original = self.journal_path.read_bytes()
        result, output = self.reconcile_status(None, record=False)
        self.assertFalse(result)
        with self.assertRaisesRegex(RuntimeError, 'finalized status unavailable'):
            self.reconcile_status(None)
        self.assertIn('INCONCLUSIVE', output)
        self.assertEqual(self.journal_path.read_bytes(), original)
        self.assertFalse(self.receipt.exists())
        with self.assertRaisesRegex(RuntimeError, 'unresolved dev submission'):
            dev.clean_operations()

    def test_readonly_finalized_is_not_recorded(self):
        result, output = self.reconcile_status(FINALIZED, record=False)
        self.assertTrue(result)
        self.assertIn('READ ONLY', output)
        self.assertFalse(self.receipt.exists())
        with self.assertRaisesRegex(RuntimeError, 'unresolved dev submission'):
            dev.clean_operations()

    def test_real_signed_operations_allow_gate_and_preserve_original(self):
        for operation in ('authorize', 'capture', 'void', 'refund', 'compute'):
            with self.subTest(operation=operation):
                self.set_entry(self.fixtures[operation])
                before = self.journal_path.read_bytes()
                result, _ = self.reconcile_status(FINALIZED)
                self.assertTrue(result)
                proof = json.loads(self.receipt.read_text())
                self.assertEqual(proof['version'], 2)
                self.assertEqual(proof['verdict'], 'finalized-succeeded')
                self.assertEqual(proof['journalSha256'], hashlib.sha256(before).hexdigest())
                self.assertEqual(self.receipt.stat().st_mode & 0o777, 0o600)
                dev.clean_operations()
                receipt = self.receipt.read_bytes()
                with self.assertRaises(FileExistsError):
                    self.reconcile_status(FINALIZED)
                self.assertEqual(self.receipt.read_bytes(), receipt)
                self.assertEqual(self.journal_path.read_bytes(), before)
                self.receipt.unlink()  # Test isolation only, never operator behavior.

    def test_finalized_failure_receipt_allows_gate(self):
        result, _ = self.reconcile_status({**FINALIZED, 'err': {'Custom': 1}})
        self.assertTrue(result)
        self.assertEqual(json.loads(self.receipt.read_text())['verdict'], 'finalized-failed')
        dev.clean_operations()

    def test_real_signature_cannot_authenticate_changed_message_or_other_wire(self):
        for kind in ('changedMessage', 'economicSignature', 'unusedProgram', 'envelopeCount', 'noncanonicalLength',
                     'trailing', 'invalidIndex', 'wrongAuthority', 'wrongRole', 'badHeader', 'malformedData',
                     'duplicateOperation', 'duplicateCompute', 'v0'):
            with self.subTest(kind=kind):
                self.set_entry(self.fixtures[kind])
                self.assert_authentication_blocked()

    def test_signed_wire_must_bind_each_journal_claim(self):
        for operation in ('authorize', 'capture', 'void', 'refund'):
            for field, value in (('operation', 'void' if operation == 'authorize' else 'authorize'),
                                 ('signature', self.fixtures['capture' if operation == 'authorize' else 'authorize']['signature']),
                                 ('payment', PROGRAM), ('payer', PROGRAM), ('expectedHeld', '999'),
                                 ('expectedRefundable', '999'), ('blockhash', PROGRAM), ('messageHash', '0' * 64)):
                with self.subTest(operation=operation, field=field):
                    entry = copy.deepcopy(self.fixtures[operation])
                    entry[field] = value
                    self.set_entry(entry)
                    self.assert_authentication_blocked()

    def test_setup_and_reclaim_are_explicitly_unsupported(self):
        for operation in ('setup', 'reclaim'):
            with self.subTest(operation=operation):
                self.entry['operation'] = operation
                self.journal_path.write_text(json.dumps(self.entry))
                self.assert_authentication_blocked()

    def test_changed_journal_cannot_use_prior_receipt(self):
        self.reconcile_status(FINALIZED)
        self.entry['expectedHeld'] = '99'
        self.journal_path.write_text(json.dumps(self.entry))
        with self.assertRaisesRegex(RuntimeError, 'unresolved dev submission'):
            dev.clean_operations()

    def test_old_or_mismatched_receipt_cannot_unblock(self):
        self.reconcile_status(FINALIZED)
        original = json.loads(self.receipt.read_text())
        for field, value in (('version', 1), ('journalSha256', '0' * 64), ('wireSha256', '0' * 64),
                             ('payer', PROGRAM), ('slot', True), ('genesis', 'other'), ('programId', 'other')):
            with self.subTest(field=field):
                proof = {**original, field: value}
                self.receipt.write_text(json.dumps(proof))
                with self.assertRaisesRegex(RuntimeError, 'unresolved dev submission'):
                    dev.clean_operations()

    def test_symlink_receipt_refused(self):
        self.reconcile_status(FINALIZED)
        other = self.root / 'original'
        self.receipt.rename(other)
        self.receipt.symlink_to(other)
        with self.assertRaisesRegex(RuntimeError, 'unsafe symlink'):
            dev.clean_operations()

    def test_nonfinal_or_malformed_status_never_records(self):
        for status in ({**FINALIZED, 'confirmationStatus': 'processed'}, {**FINALIZED, 'confirmationStatus': 'confirmed'},
                       {**FINALIZED, 'slot': True}, {**FINALIZED, 'slot': -1},
                       {'confirmationStatus': 'finalized', 'slot': 123}):
            with self.subTest(status=status):
                result, output = self.reconcile_status(status, record=False)
                self.assertFalse(result)
                with self.assertRaisesRegex(RuntimeError, 'finalized status unavailable'):
                    self.reconcile_status(status)
                self.assertIn('INCONCLUSIVE', output)
                self.assertFalse(self.receipt.exists())

    def test_child_failure_or_timeout_never_reaches_rpc(self):
        for failure in (OSError('DO_NOT_PRINT'), subprocess.TimeoutExpired('node', 15)):
            with self.subTest(failure=type(failure).__name__):
                with (mock.patch.object(dev.subprocess, 'run', side_effect=failure),
                      mock.patch.object(dev, '_dev_rpc_call') as rpc):
                    with self.assertRaises((OSError, subprocess.TimeoutExpired)):
                        dev.reconcile_original(self.signature, record=True)
                    rpc.assert_not_called()
                self.assertFalse(self.receipt.exists())


if __name__ == '__main__':
    unittest.main()
