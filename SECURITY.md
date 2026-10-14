# Security policy

This repository is a reference implementation. Public source, green CI and
historical Devnet examples do not establish readiness to handle real funds.

For a suspected vulnerability or exposed credential, use GitHub's private
vulnerability reporting feature on this repository. Do not put secrets, signed
private state, seed phrases, key files or exploitable details in a public issue.
If private reporting is unavailable, contact the repository owner through their
GitHub profile to arrange a private channel before sharing sensitive material.

Preserve original transaction wires, signatures, journals and reservations when
reporting an uncertain payment. Do not resend, replace, clear a lock, or infer
non-execution from missing history. Describe the exact revision, operation and
observable behavior with sensitive values removed.

Contributor checks reject personal workstation paths and inspect complete Git
history for secrets and private filenames. Security-sensitive changes to custody,
signing, authentication, replay, settlement or recovery require review of the
exact resulting revision. Merge, deployment and economic execution require their
own explicit authorization.
